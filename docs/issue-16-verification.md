# Issue 16 verification record

Status: implementation complete; live Monitor/Runner acceptance remains
operator-owned. Keep issue 16 open until the real Monitor and Runner checks
are recorded.

## Local verification

- Targeted onboarding/service suite: 72 tests passed.
- PowerShell parser: Monitor, Runner, shared Bootstrap, Monitor service, and
  Heartbeat service scripts all parsed successfully.
- Monitor `Preflight` was executed on `STOLASIN-DT2` with the inventory-confirmed
  Python, config/data/secret paths, existing certificate pair, and confirmed
  Runner DNS addresses; result: `preflight_passed`.
- Monitor `Status` was executed read-only; result: `service_state=running`.
- The current terminal is not elevated, so ACL-protected service/config/key
  mutation could not be executed by this session. Run the live block below
  from an elevated PowerShell prompt on the Monitor Host.

## Known baseline

The full repository suite retains one pre-existing deployment smoke-test
failure caused by the globally installed `runner_observability` package being
visible to a synthetic empty release. Do not count that failure as issue-16
behavior and do not hide it.

## Live Monitor block

Run Step 0 again, compare it with `CONTEXT.md`, then use the confirmed paths.
The following removes only the named Monitor service/firewall rule first;
delete the three secret files only when the operator explicitly wants fresh
material. Do not print their contents.

```powershell
.\scripts\Install-RunnerObservabilityMonitor.ps1 -Action Uninstall -ServiceName 'RunnerObservabilityMonitor'
Remove-Item -LiteralPath 'C:\runner-observability-secrets\monitor-token.txt','C:\runner-observability-secrets\monitor.crt','C:\runner-observability-secrets\monitor.key' -Force
.\scripts\Install-RunnerObservabilityMonitor.ps1 -Action Install `
  -PythonPath 'C:\Users\stolas_in\AppData\Local\Programs\Python\Python311\python.exe' `
  -ConfigPath 'C:\runner-observability\service-config.json' `
  -DatabasePath 'C:\runner-observability-data\monitor.sqlite' `
  -SecretRoot 'C:\runner-observability-secrets' `
  -CertificateMode SelfSigned -AllowDevSelfSigned `
  -RunnerAddress '192.168.24.78','192.168.24.46'
.\scripts\Install-RunnerObservabilityMonitor.ps1 -Action Start -ServiceName 'RunnerObservabilityMonitor'
.\scripts\Install-RunnerObservabilityMonitor.ps1 -Action Status -ServiceName 'RunnerObservabilityMonitor'
Get-NetTCPConnection -LocalPort 8765 -State Listen
Invoke-WebRequest -Uri 'https://127.0.0.1:8765/api/health' -SkipCertificateCheck
```

Record only service state, listener PID, HTTP status/body health fields,
certificate fingerprint/expiry metadata, and firewall remote addresses.
