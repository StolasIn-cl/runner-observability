# Monitor Windows Service 與安全啟動設計

## 目標

把目前以前景 Python process 執行的 Monitor，交付成可由 Windows Service
Control Manager 管理的部署邊界：可安裝、啟動、停止、查詢、重啟與移除；
服務異常退出時由 SCM recovery policy 重啟；token、TLS private key、
database 與 service 設定檔由 ACL 保護；TCP 8765 只建立給指定 Runner 位址
的 inbound allow rule。

本票交付可執行的 service host、管理腳本、設定/ACL/Firewall wiring、local
runner-independent tests 與 operator runbook。真實 Monitor Host、Runner A/B、
實際 service account、TLS trust、Firewall effective policy、reboot 與
production-ready decision 仍由 #6 HITL 產生證據。

## 設計決策

### Service host

新增 `src/runner_observability/service.py` 作為 Windows-only SCM adapter，
使用 optional `pywin32` 依賴實作 `ServiceFramework`。SCM 啟動的是這個
host；host 讀取不含 secret value 的 JSON 設定檔，spawn 現有的
`python -m runner_observability serve` child process，並負責：

- 將 token 以 `--token-file <path>` 傳給 child，絕不把 token value 放進
  service command line、設定檔、diagnostic 或 log。
- 收到 SCM stop 時先回報 `STOP_PENDING`，要求 child 結束，等待 bounded
  timeout，逾時才強制終止，最後回報 stopped。
- child 非預期退出時回報 service failure 並結束 host，讓 SCM 的 recovery
  policy 負責重啟，而不是在 host 內無限重試。
- 非 Windows 或未安裝 `pywin32` 時只回傳 stable reason code；不影響現有
  local monitor/agent tests。

`serve --token <value>` 保留給既有 local compatibility path；新增
`serve --token-file <path>`，兩者互斥。token file 只讀取、不回顯，空檔案、
無法讀取或格式不合法只產生 stable redacted reason。

### Service 設定與命令列

Service 設定檔只包含 service name、Python executable、database path、
token file path、TLS cert/key path、host、port 與 release root 等非 secret
設定。設定檔以同目錄暫存檔加 atomic rename 寫入。

SCM `binPath` 只包含：

```text
<python.exe> -m runner_observability.service run --config <service-config.json>
```

因此 command line 不會出現 bearer token。service manager 會拒絕 partial
TLS pair、缺少 token/config/database 路徑或不合法 port，並只輸出 stable
reason code。

### PowerShell service manager

新增 `scripts/RunnerObservability.Service.psm1` 作為可測試的 PowerShell
adapter，統一封裝：

- `sc.exe create/config/start/stop/query/delete` 的 service lifecycle。
- `sc.exe failure` 的 bounded recovery policy。
- `icacls` 的最小權限 ACL：SYSTEM 與 Administrators 保留完整管理權；
  service account 對 token、TLS cert/key、設定檔為 read；對 database 與
  database directory 為 modify。
- `New-NetFirewallRule` 的固定 display name、TCP port、Domain/Private
  profile 與指定 Runner address allow list；移除動作只針對本票固定 rule
  name，不刪除其他規則。

新增 `scripts/Install-RunnerObservabilityService.ps1`，提供
`Install/Start/Stop/Status/Restart/Uninstall` actions，並以 operator 傳入
的 service account、Runner address、token/TLS/database paths 產生設定、
套用 ACL 與 Firewall rule。service account 預設使用
`NT AUTHORITY\\LocalService`；#6 可在 deployment window 以 operator 決策
改用其他 identity，腳本不接受或記錄該帳號密碼。

### Pinned release 與 rollback

既有 `Install-RunnerObservability.ps1` / `Update-RunnerObservability.ps1`
的 pinned revision、staging、atomic activation 與 smoke test contract
保留。當提供 service integration 參數時，更新流程為：

1. 驗證設定、credential/certificate file presence 與 release source。
2. 停止現有 service 並確認 stopped。
3. stage 新 revision，atomic switch `current-release.txt`。
4. 以新 revision 的 service command/config 執行 bounded smoke check。
5. 啟動 service 並確認 SCM reports running。
6. 任一步驟失敗，atomic restore 舊 revision；若舊 revision 存在，重新
   啟動舊 service；若不存在，維持 stopped/deactivated 並輸出
   `rollback_target_missing`。

不提供 service integration 參數時，現有 runner-independent deployment
simulation 行為完全維持，避免 local tests 偷假設真實 SCM 或 Firewall。

### Firewall 與 ACL 安全邊界

腳本只會操作固定的 Runner Observability rule 和明確傳入的檔案路徑；不讀、
輸出或保存 token/private key 內容。Firewall 的有效性、其他本機規則造成的
例外、實際 certificate trust 與 ACL 在目標主機上的結果，都必須在 #6
保存 sanitized operator evidence，local tests 不宣告這些事實已發生。

## 測試與驗證

新增或修改以下 public seams：

- `serve --token-file`：成功讀取、partial token options、missing/empty file
  與 redacted diagnostics。
- service command builder/config loader：命令包含 config/token path 但不含
  token value；TLS pair 與 port validation 可觀察。
- service host：用 fake child process / fake SCM callbacks 驗證 stop、bounded
  wait、forced termination 與 unexpected child exit。
- PowerShell adapter：以 script-shape/command-runner seam 驗證 lifecycle、
  ACL、Firewall、recovery 與 uninstall 命令；不呼叫真實 SCM、icacls 或
  NetSecurity API。
- deployment integration：以 injected service adapter 驗證 stop → activate →
  smoke/start 與 rollback ordering；既有無 service 參數的 local contract
  測試保持通過。

完整 unittest suite 是 local evidence；它不能取代 #6 的 boot、real service
  status、real ACL/process inspection、effective Firewall、TLS trust、Runner
  reconnect 或 reboot evidence。

## 不在本票範圍

- 不實際部署 Monitor Host、Runner A 或 Runner B。
- 不選定 production TLS issuer、credential rotation window 或最終 service
  identity；這些由 #6 operator window 確認，腳本只提供可驗證的輸入邊界。
- 不修改 CI workflow 的 job progress/fallback mapping。
- 不把 local tests 或 service script dry-run 寫成 production-ready verdict。

