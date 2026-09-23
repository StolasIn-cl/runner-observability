# Issue 16 verification record

Status: implementation complete; live Monitor/Runner acceptance remains
operator-owned. Keep issue 16 open until the real Monitor and Runner checks
are recorded.

## Local verification

- Targeted onboarding/service suite: 76 tests passed.
- PowerShell parser: Monitor, Runner, shared Bootstrap, Monitor service, and
  Heartbeat service scripts all parsed successfully.
- Monitor `Preflight` was executed on `STOLASIN-DT2` with the inventory-confirmed
  Python, config/data/secret paths, existing certificate pair, and confirmed
  Runner DNS addresses; result: `preflight_passed`.
- Monitor `Status` was executed read-only; result: `service_state=running`.
- The Monitor self-signed generator was exercised in a clean temporary
  directory with ACL calls stubbed only for this local seam check under
  Windows PowerShell 5.1: generated PEM certificate/key, RSA key size 2048,
  64-character SHA-256 fingerprint, and expiry metadata all verified without
  printing key contents. Python's TLS loader also accepted the generated pair.
- The current terminal is not elevated, so ACL-protected service/config/key
  mutation could not be executed by this session. Run the live block below
  from an elevated PowerShell prompt on the Monitor Host.

## Live acceptance attempts

- The operator successfully removed the named Monitor service and the three
  requested secret files, then attempted a clean `SelfSigned` install.
- The install stopped at `certificate_generation_unavailable` under Windows
  PowerShell 5.1 because the previous implementation required the unavailable
  `ExportPkcs8PrivateKey` API. The subsequent `Start`, `Status`, and port
  checks therefore observed the expected absent-service state.
- The implementation now encodes PKCS#8 from exportable RSA parameters and has
  a Windows PKI fallback for older hosts. Re-run the live block after pulling
  this change; do not reuse the removed secret files.
- A subsequent live attempt generated all three secret files but returned the
  generic `monitor_onboarding_failed`; the existing `service-config.json` was
  unchanged, and neither the Firewall rule nor Service was registered. The
  installer now maps `service_config_write_failed` explicitly and repairs the
  ACL of a preserved config before the atomic reinstall write. The shared
  atomic writer now supplies a temporary backup path because Windows PowerShell
  5.1 rejects a null `File.Replace` backup argument.

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
  -TrustSelfSignedCertificate `
  -RunnerAddress '192.168.24.78','192.168.24.46'
.\scripts\Install-RunnerObservabilityMonitor.ps1 -Action Start -ServiceName 'RunnerObservabilityMonitor'
.\scripts\Install-RunnerObservabilityMonitor.ps1 -Action Status -ServiceName 'RunnerObservabilityMonitor'
Get-NetTCPConnection -LocalPort 8765 -State Listen
curl.exe -k -i https://127.0.0.1:8765/api/health
```

For the browser check, confirm `monitor-test.local` resolves to this Monitor
Host and open `https://monitor-test.local:8765/`. The install switch imports
the generated public certificate into the installing user's
`Cert:\CurrentUser\Root`; it never imports `monitor.key`. The `curl.exe -k`
form remains useful for a PowerShell 5.1 health check because it does not rely
on browser trust.

The `curl.exe -k` form works in Windows PowerShell 5.1 for this local
self-signed health check. PowerShell 7 may alternatively use
`Invoke-WebRequest -Uri 'https://127.0.0.1:8765/api/health' -SkipCertificateCheck`.

Record only service state, listener PID, HTTP status/body health fields,
certificate fingerprint/expiry metadata, and firewall remote addresses.
