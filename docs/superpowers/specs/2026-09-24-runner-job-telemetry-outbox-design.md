# Runner job telemetry durable local outbox 設計

## Status

High-level direction approved in conversation on 2026-09-24 for issue #3151.
This document is the implementation design and remains subject to review before
product-code changes begin.

## Goal

在 Runner 與 Monitor 之間發生短暫 network、TLS 或 Monitor unavailable 時，
保留 `job.started`、`job.heartbeat`、`job.progress`、`job.finished` 等已通過
schema-v1 validation 的 telemetry，讓後續 invocation 可在 process restart 後
replay。既有 telemetry delivery fail-open 行為與 CI job exit semantics 必須
維持不變。

## Non-goals

- 不在本 slice 部署或修改兩台實際 Windows Runner，也不變更 ACL、service
  account、certificate trust 或 hosts mapping。
- 不把 bearer token、endpoint、raw exception、raw log 或未驗證 payload 寫入
  outbox 或 dead-letter。
- 不改變 Monitor ingest contract、event schema-v1 或既有 duplicate idempotency
  semantics。
- 不自動啟用全機預設 spool path；呼叫端必須明確提供 outbox directory，避免
  在未驗證 ACL 的既有 Runner 上靜默產生持久資料。
- 不在本 slice 建立 background Windows service；replay 由下一次 `emit` 或
  明確的 `flush` invocation 觸發。

## Design decisions

### File-based outbox boundary

新增 `src/runner_observability/outbox.py`，以 `DurableOutbox` 封裝 queue
storage、capacity、idempotent enqueue、drain 與 dead-letter movement。選用
file-per-event 而非 SQLite，因為 Runner agent 不需要新增 database dependency，
且可沿用既有 state/config 的 temporary-file + `fsync` + atomic replace pattern。

Outbox root 由呼叫端明確指定，目錄結構固定為：

```text
<outbox-root>/pending/<event_id>.json
<outbox-root>/dead-letter/<event_id>.json
```

pending 檔案內容只包含 `queued_at` 與原始的 validated schema-v1 event；不包含
token 或 failure metadata。dead-letter 檔案另外包含固定 allowlist 內的
`dead_letter_reason`。`event_id` 是 filename 的唯一 key，重複 enqueue 回報
`duplicate`，不新增第二份 event。pending 事件依 `(queued_at, event_id)` 排序
drain；同一 event 的 replay 永遠使用原始 event_id。

寫入流程為：建立目錄、以同一目錄的暫存檔寫入 JSON、flush/fsync、再以
`os.replace` 取代目標檔。任何 partial temporary file 在失敗後清除。讀取到
無法 parse 或不再通過 validation 的 pending file 時，只以
`outbox_corrupt_event` 記錄 diagnostic 並跳過該檔案；不把未驗證內容複製到
dead-letter、不輸出檔案內容，也不因單一 corrupt file 阻止其他 event replay。

### Capacity and retention

預設限制為最多 1,000 個 pending/dead-letter event、總大小 32 MiB；
`OutboxLimits` 允許測試與受控部署覆寫。容量計算以 queue-owned JSON files
為準，enqueue 在寫檔前保留新檔大小，超限回傳 stable
`outbox_capacity_exceeded`，不覆蓋或刪除既有 event。dead-letter 檔案保留原
event 供人工診斷，並持續佔用 outbox quota；清理策略不由本 slice 自動決定。

### Delivery and replay flow

保留現有 direct path：未指定 outbox directory 時，`emit` 完全沿用目前的
validation、bounded retry 與 fail-open delivery。

指定 outbox directory 時，`emit` 流程為：

1. 先 validation，再以 event_id enqueue；validation failure 不產生檔案。
2. 在單次 invocation 的 bounded drain window 內，先送出 pending queue，包含
   新 enqueue 的 event。
3. 既有 `deliver_event` 回傳 delivered 時刪除 pending file。
4. `temporary_network_failure`、`temporary_http_failure` 與 transport timeout
   保留 pending，等待下次 replay。
5. stable permanent rejection（例如非 retryable HTTP response）移到
   dead-letter，寫入 stable reason，不 retry poison event。
6. queue、delivery 或 replay failure 只產生 redacted diagnostic，CLI 仍回傳
   0；validation 與既有 `emit` semantics 不變。

新增 `flush` command 只 drain 已存在的 pending files，不要求新的 event payload；
它使用 `--token-file` 讀取 credential，避免 replay command 將 token 放在
command line。`emit --outbox-dir` 與 `flush --outbox-dir` 共用同一個 bounded
drain seam，避免以 CI job 的單次 invocation 觸發無限 replay。單次 drain 的最大
event 數與時間 budget 都是可測試的設定，預設最多 100 events、5 秒 wall-clock。

### CLI and compatibility

新增 optional `--outbox-dir`；未傳入時不建立目錄、不改變既有 command line
contract。既有 `emit --token` 保持相容；新增 `flush` subcommand 需要 endpoint、
`--token-file` 與 outbox directory。token 只在 process memory 使用，絕不寫入
queue、dead-letter、diagnostic 或 command output。

Runbook 會說明：outbox directory 必須位於受保護的 Runner-owned data root，
不可放在 secrets root；ACL 與 target deployment evidence 仍由後續 HITL 流程
確認。

## Error handling and security

- Queue reason、dead-letter reason 與 diagnostics 使用固定 allowlist；不保留
  exception text、HTTP body、endpoint 或 token。
- Atomic rename 保證 reader 只看完整 JSON file；drain 只在成功送達後刪除
  pending file。
- Enqueue duplicate 是成功的 idempotent no-op；如果同名 event file 內容
  不一致，回報 stable `outbox_event_conflict`，不覆蓋原始 event。
- Outbox filesystem failure、capacity exceeded、dead-letter movement failure
  不得讓 caller 的 CI process 變成 telemetry failure；由 status/diagnostic
  供 operator 觀察。
- Outbox 不會讀取或儲存 credential file 內容；token 仍由既有 credentials
  boundary 讀取。

## Implementation seams

- `DurableOutbox.enqueue(event)`：validate、capacity check、atomic persist、
  duplicate/conflict result。
- `DurableOutbox.drain(deliver, endpoint, token, ...)`：排序、bounded budget、
  success removal、transient retention、permanent dead-letter。
- `agent.main`：保留 direct mode，接入 optional `--outbox-dir` 與 `flush`。
- 共用 `_json_payload`／safe reason code path，避免 queue 自行實作另一套
  secret filtering。
- `docs/runbook.md`：補充 outbox directory、replay、capacity 與 redacted
  inspection guidance，不提供 token-bearing command example。

## Testing and verification

新增 runner-independent tests，先以 failing tests 驗證每個 seam：

- 新 event 能 atomic enqueue，重啟新的 `DurableOutbox` instance 後仍可列出。
- 相同 event_id 是 duplicate no-op；不同內容是 conflict，原檔不被覆蓋。
- successful delivery 移除 pending；temporary failure 保留並可由下一次 drain
  replay；permanent rejection 移到 dead-letter。
- capacity count/bytes 在 enqueue 前阻擋新檔，且不刪除舊檔。
- malformed pending file 只產生 stable `outbox_corrupt_event` diagnostic，跳過
  該檔案且不洩漏內容。
- `emit`/`flush` 在 queue 或 delivery failure 時仍維持 exit code 0；未指定
  outbox 的 direct path regression tests 保持通過。
- queue/dead-letter/status/diagnostics 不含 token、endpoint、payload 外 secret
  或 raw exception text。
- 既有 affected tests、完整 unittest suite、`compileall` 與 `git diff --check`
  都必須重新執行；既有 `test_deployment_docs.py:836` baseline failure 若仍
  存在，需單獨列出，不得被新測試隱藏。

## Out-of-scope follow-up

完成本地 outbox slice 後，仍需另一個 target-side HITL window 驗證：實際 Runner
帳號對 outbox root 的 ACL、active release 的 job telemetry invocation、Monitor
暫時不可用後的真實 replay，以及 dead-letter 的 operator retention/cleanup
policy。這些 evidence 取得前，不把 issue #3151 標為完成或將 Project 移至 Done。
