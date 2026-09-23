# Runner observability

這是 Windows Monitor 與 GitHub Actions Runner 的最短操作手冊。完整的
低階部署、更新、rollback 與故障排除流程請看
[`docs/runbook.md`](docs/runbook.md)。

## 先記住三件事

- 每台電腦先做 read-only inventory，再決定是新安裝、clean rebuild、update
  或 troubleshooting。`CONTEXT.md` 只是上次快照，不是目前狀態。
- Runner 只接收 `monitor-token.txt` 與必要的公開 `monitor.crt`；永遠不要把
  `monitor.key` 複製到 Runner，也不要在 command line、log 或 README 印出 token。
- Clean rebuild 只移除本工具管理的 install root、heartbeat service、observability
  machine environment 與舊 secrets；不會刪除 `C:\actions-runner` 或解除 GitHub
  Actions Runner registration。

## 0. 每台目標機器先做 inventory

在實際目標電腦、以系統管理員 PowerShell 執行：

```powershell
$root = 'C:\runner-observability-agent'
$secretRoot = 'C:\runner-observability-secrets'

[pscustomobject]@{
    Computer = $env:COMPUTERNAME
    User = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    RunnerRootExists = Test-Path 'C:\actions-runner'
    InstallRootExists = Test-Path $root
    ActiveRelease = if (Test-Path (Join-Path $root 'current-release.txt')) {
        (Get-Content -Raw (Join-Path $root 'current-release.txt')).Trim()
    } else { 'none' }
    SecretRootExists = Test-Path $secretRoot
    Python = (Get-Command python -ErrorAction SilentlyContinue).Source
}

Get-Service -Name 'RunnerObservabilityMonitor','RunnerObservabilityHeartbeat' `
    -ErrorAction SilentlyContinue |
    Select-Object Name, Status, StartType
```

如果 `current-release.txt` 存在，不要把新安裝流程套在既有安裝上；請看
`docs/runbook.md` 的 update 流程。

## 1. 從 0 重建 Monitor

以下流程只用於要丟棄 Monitor 的舊 service、token、certificate、private key、
config 與 telemetry database 的乾淨環境。先在 Monitor Host 的系統管理員
PowerShell 確認實際 Monitor IPv4 與 Runner IPv4：

```powershell
Get-NetIPConfiguration |
    Where-Object { $_.NetAdapter.Status -eq 'Up' } |
    Select-Object InterfaceAlias,
        @{Name='IPv4'; Expression={
            (@($_.IPv4Address | ForEach-Object { $_.IPAddress }) -join ', '
        }},
        IPv4DefaultGateway

Get-NetTCPConnection -State Listen -LocalPort 8765 -ErrorAction SilentlyContinue |
    Select-Object LocalAddress, LocalPort, OwningProcess
```

確認路由可達的 Monitor IPv4 與每台 Runner 的 IPv4 後，執行下面的完整重建。
這段只刪除列出的 Monitor-owned 檔案，不會刪除 GitHub Runner registration：

```powershell
$monitorScript = '.\scripts\Install-RunnerObservabilityMonitor.ps1'
$config = 'C:\runner-observability\service-config.json'
$database = 'C:\runner-observability-data\monitor.sqlite'
$secretRoot = 'C:\runner-observability-secrets'
$runnerIp = '<CONFIRMED_RUNNER_IPV4>'
$ownedFiles = @(
    (Join-Path $secretRoot 'monitor-token.txt'),
    (Join-Path $secretRoot 'monitor.crt'),
    (Join-Path $secretRoot 'monitor.key'),
    $config,
    $database,
    ($database + '-wal'),
    ($database + '-shm')
)

& $monitorScript -Action Status -ConfigPath $config -DatabasePath $database -SecretRoot $secretRoot
& $monitorScript -Action Uninstall -ConfigPath $config -DatabasePath $database -SecretRoot $secretRoot

$confirmation = Read-Host 'Type RESET-MONITOR to delete the listed Monitor files'
if ($confirmation -cne 'RESET-MONITOR') {
    throw 'Monitor clean rebuild cancelled'
}

$existing = @($ownedFiles | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf })
if ($existing.Count -gt 0) {
    Remove-Item -LiteralPath $existing -Force
}
if (@($ownedFiles | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf }).Count -gt 0) {
    throw 'Monitor clean rebuild did not remove every listed file'
}

& $monitorScript -Action Install `
    -ConfigPath $config `
    -DatabasePath $database `
    -SecretRoot $secretRoot `
    -CertificateMode SelfSigned `
    -AllowDevSelfSigned `
    -TrustSelfSignedCertificate `
    -RunnerAddress $runnerIp

& $monitorScript -Action Start -ConfigPath $config -DatabasePath $database -SecretRoot $secretRoot
```

這會由腳本自動尋找可用的 Python。若回報 `python_not_found` 或
`python_import_failed`，先從公司核准來源安裝 Python 3.11+/pywin32，再重跑；
不要把固定 Python path 寫進 README。`SelfSigned` 僅限核准的測試環境；正式環境
應改用既有受信任的 certificate pair。Monitor 產生的 `monitor-token.txt`、
`monitor.crt` 與 `monitor.key` 留在 Monitor Host，只有前兩者稍後會傳到 Runner。

Monitor 啟動後確認：

```powershell
curl.exe -k -sS https://127.0.0.1:8765/api/health
Get-NetTCPConnection -LocalPort 8765 -State Listen
```

## 2. 從 0 重建 Runner

Monitor first; Runner second. 取得並確認 Monitor 的實際 IPv4 後，在 Runner
的系統管理員 PowerShell 執行：

```powershell
git pull --ff-only origin codex/runner-observability

.\scripts\Initialize-RunnerObservabilityRunner.ps1 `
    -CleanRebuild `
    -MonitorIp '<CONFIRMED_MONITOR_IP>' `
    -CertificateTrustModel SelfSigned `
    -AllowHostsChange
```

安裝會從唯一執行中的 `Runner.Listener.exe` 解析 direct Runner 帳號，並只授予
該帳號讀取 token 的權限；若 listener 尚未啟動、同時有多個不同帳號，請明確傳入
`-RunnerAccount 'DOMAIN\runner-user'`。不要改用 `Everyone` 或整個 Users 群組。

腳本會自動尋找可用的 Python 3.11+ 與 Windows service runtime。若找不到，請
先從公司核准來源安裝 Python/pywin32；不需要把固定的 Python path 寫進標準命令。

流程中的重要停點：

1. 檢查 inventory 與 Monitor port。
2. 輸入 `RESET-RUNNER`。
3. 顯示 `status=WAITING_FOR_MONITOR_FILES` 後，透過核准的安全管道複製：
   - `monitor-token.txt`
   - `monitor.crt`
4. 不要複製 `monitor.key`。
5. 驗證 certificate fingerprint，輸入 `TRUST-CERTIFICATE`。
6. 安裝會同時設定 token 檔案的 direct Runner 帳號讀取權與 secrets 父目錄 traverse
   權限；heartbeat service 仍使用 `NT AUTHORITY\LocalService`。
7. 看到 `status=OK`、`heartbeat_service=Running` 後，依提示重啟實際的
   `Runner.Listener.exe`；輸出中的 `runner_listener_restart=manual_required`
   是預期結果。

After the full-clean reset, do not run this transfer block outside the wizard.
The reset removes the old token/certificate pair; transfer the newly generated current pair only after `WAITING_FOR_MONITOR_FILES`。腳本會 stage the current immutable release，並保留原本的 Runner registration。

## 3. Monitor service 操作

這些命令在 Monitor Host 執行；預設值使用目前約定的 config、database、secret
root 與 service name。每次操作仍會先 inventory。

```powershell
$monitorScript = '.\scripts\Install-RunnerObservabilityMonitor.ps1'

& $monitorScript -Action Status
& $monitorScript -Action Start
& $monitorScript -Action Stop
& $monitorScript -Action Restart
```

第一次安裝或重建 Monitor 才需要 `Install`。`SelfSigned` 僅限核准的測試用途；
腳本使用 Windows `CertificateRequest`（必要時回報
`certificate_generation_unavailable`），且永遠不會把 `monitor.key` 發給 Runner。

Monitor 服務啟動後驗證：

```powershell
curl.exe -k -sS https://127.0.0.1:8765/api/health
Get-NetTCPConnection -LocalPort 8765 -State Listen
```

若重新產生 token、certificate、Monitor Python 或 dashboard static files，請
依實際啟動方式重啟 Monitor service/process。

## 4. Runner heartbeat service 操作

這些命令在 Runner Host 執行。這個 service 只負責送
`runner.heartbeat`，不是 GitHub Actions 的 `Runner.Listener.exe`。

```powershell
$runnerScript = '.\scripts\Install-RunnerObservabilityRunner.ps1'

& $runnerScript -Action Status
& $runnerScript -Action Start
& $runnerScript -Action Stop
& $runnerScript -Action Restart
```

必要時檢查 Windows SCM：

```powershell
sc.exe queryex RunnerObservabilityHeartbeat
```

不要把 `Runner.Listener.exe` 當成這個 service。已知 Runner 啟動模式是直接執行
listener；machine environment 第一次設定或變更後，才需要用實際 launch method
手動重啟 listener，不需要整台 Windows reboot。

若既有 Runner 仍收到 `token_read` 或 `UnauthorizedAccessException`，先以實際
Runner 帳號（非提升權限的管理員 shell）做不回顯內容的讀取檢查，再執行修復：

```powershell
$tokenPath = 'C:\runner-observability-secrets\monitor-token.txt'
$stream = $null
try {
    $stream = [IO.File]::OpenRead($tokenPath)
    'runner_token_read=PASS'
}
catch {
    'runner_token_read=FAIL error_type=' + $_.Exception.GetType().Name
}
finally {
    if ($null -ne $stream) { $stream.Dispose() }
}

.\scripts\Install-RunnerObservabilityRunner.ps1 `
    -Action RepairPermissions `
    -RunnerAccount 'DOMAIN\runner-user'
```

`-RunnerAccount` 可省略以重新解析唯一執行中的 listener owner。修復後確認
heartbeat config 的 endpoint 是 `https://<monitor-host>:8765/v1/events`；CI helper
與 heartbeat 會使用同一個 ingest route，不會再產生 `/v1/events/v1/events` 或 base URL 404。

## 5. 完成驗證

在 Runner 確認 service、config、stable identity 與 heartbeat state：

```powershell
$root = 'C:\runner-observability-agent'
$config = Get-Content -Raw (Join-Path $root 'heartbeat-config.json') | ConvertFrom-Json

[pscustomobject]@{
    Service = (Get-Service 'RunnerObservabilityHeartbeat').Status
    Endpoint = $config.endpoint
    RunnerId = $config.runner_id
    TokenExists = Test-Path $config.token_file
    StateExists = Test-Path (Join-Path $root 'state\heartbeat.json')
}
```

在 Monitor 確認 Dashboard API 能看到 active Runner：

```powershell
$dashboard = curl.exe -k -sS https://127.0.0.1:8765/api/dashboard |
    ConvertFrom-Json

$dashboard.active_runners |
    Select-Object alias, runner_id, liveness, last_received_at, last_heartbeat_at
```

最後執行一個真實 CI job，確認 telemetry、job association 與 Dashboard active
狀態都正確。只有 local test pass 或 Windows service `Running`，都不代表已完成
端到端驗證。

## 6. 常見限制

- `monitor-test.local` 必須解析到確認過的 Monitor IP；若組織 DNS 沒有提供，使用
  `-AllowHostsChange` 讓 wizard 維護一筆 hosts mapping。
- Monitor 的 `-RunnerAddress` 是 Windows Firewall 的來源 IP allowlist；需包含每台
  Runner 的實際 IPv4。
- Runner 使用作業系統 certificate trust。把 `monitor.crt` 放在 secrets directory
  不會自動建立 trust；SelfSigned/PrivateCa 流程會明確處理 trust。
- 不要刪除 `runner-id.txt`、heartbeat state、Monitor database 或 GitHub Runner
  registration 作為第一個 troubleshooting 動作。

進階 ACL、手動 `Preflight`/`Configure`/`RepairPermissions`、`Uninstall`、update、
rollback 與故障排除請使用 [`docs/runbook.md`](docs/runbook.md)，並遵守
[`AGENTS.md`](AGENTS.md) 的操作順序。
