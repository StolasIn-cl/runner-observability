# Runner observability -- operator runbook

This is the single document an operator needs to install, update, roll
back, and perform first triage of the local, fail-open telemetry monitor
for self-hosted CI runners -- without reading the original design ticket or
implementation plan.

## Scope: what this runbook covers, and what it explicitly does not

This runbook and the scripts it describes
(`scripts/Install-RunnerObservability.ps1`,
`scripts/Update-RunnerObservability.ps1`,
`scripts/Invoke-RunnerPreflight.ps1`) implement and exercise the
**deployment/rollback contract** only: pinned-revision installs, a
preflight check battery, an atomic activation switch, a post-activation
smoke test, and automatic rollback on failure. Every one of those has been
proven against local fixture directories and injected/mocked checks (see
`tests/test_deployment_docs.py`); none of it has ever opened a socket to a
real host, touched a real certificate store, or called a real Windows
Service or firewall API.

Real production deployment work is explicitly **issue #6's responsibility,
and has not happened as part of this task**:

- Installing and starting a real Windows Service (Monitor Host or a
  runner agent) has **not** been done here.
- Issuing or trusting a real TLS certificate has **not** been done here.
- Configuring a real Windows Firewall rule has **not** been done here.
- Deploying to a real Monitor Host, Runner A, or Runner B has **not** been
  done here.
- Running a real GitHub Actions workflow end to end against a live
  deployment has **not** been done here.

If you are looking for that evidence, it belongs in
`docs/canary-evidence-template.md`, filled in only by a human operator
running the real issue #6 HITL checklist against real hardware -- not by
any script or test in this repository.

## Prerequisites

- Python 3.11 or newer on the target host (`python --version`). The monitor
  core uses the standard library; the Windows Service host additionally
  requires the optional `windows-service` extra (`pywin32`).
- PowerShell 5.1 or newer (Windows built-in `powershell.exe` is fine).
- A built copy of this repository (or a specific pinned revision's
  contents) available as a local source directory to install from. This
  runbook does not describe how you obtained that copy (git clone,
  artifact download, etc.) -- only what to do with it once you have it
  locally.
- A place to install to (`-InstallRoot`): an empty or already-managed
  directory this runbook's scripts own. Do not point it at a directory
  with unrelated content; `Update-RunnerObservability.ps1` only manages
  what it created.

## Monitor Host onboarding (run this before Runner onboarding)

Run the shared Step 0 inventory on the actual Monitor Host first and compare
the result with `CONTEXT.md`. The Monitor entry point starts with the same
read-only inventory before every operation and supports `-WhatIf` without
creating files, changing ACLs, touching the firewall, or changing SCM state.

### Confirm the Monitor IPv4 address and ingest listener (read-only)

Run this on the Monitor Host after Step 0. Select the IPv4 address that the
Runner can route to; do not use loopback, APIPA, or a disconnected interface.
If the Monitor has multiple usable addresses, use the address on the network
shared with the Runner:

```powershell
Get-NetIPConfiguration |
    Where-Object { $_.NetAdapter.Status -eq 'Up' } |
    Select-Object InterfaceAlias,
        @{Name='IPv4'; Expression={
            (@($_.IPv4Address | ForEach-Object { $_.IPAddress }) -join ', ')
        }},
        IPv4DefaultGateway

Get-NetTCPConnection -State Listen -LocalPort 8765 -ErrorAction SilentlyContinue |
    Select-Object LocalAddress, LocalPort, OwningProcess
```

Record the selected value as the confirmed Monitor IPv4. Before Runner
configuration, run this from the Runner to prove that the selected address is
reachable:

```powershell
$monitorIp = '<CONFIRMED_MONITOR_IP>'
Test-NetConnection -ComputerName $monitorIp -Port 8765
```

Use the same confirmed value for `-MonitorIp`, the endpoint, and the optional
`monitor-test.local` hosts mapping. Keep the Monitor firewall scope
(`-RunnerAddress`) based on the separately confirmed Runner IPv4 address.
Never copy a placeholder address from this runbook.

The following uses an existing, operator-supplied certificate pair. `PublicCa`,
`PrivateCa`, and `Existing` all require both `-TlsCertPath` and `-TlsKeyPath`;
they never silently replace those files.

```powershell
$python = 'C:\Python311\python.exe'
$config = 'C:\runner-observability\service-config.json'
$database = 'C:\runner-observability-data\monitor.sqlite'
$secretRoot = 'C:\runner-observability-secrets'
$token = Join-Path $secretRoot 'monitor-token.txt'
$cert = Join-Path $secretRoot 'monitor.crt'
$key = Join-Path $secretRoot 'monitor.key'
$runnerIp = '192.0.2.10' # replace with the confirmed Runner IPv4 address

.\scripts\Install-RunnerObservabilityMonitor.ps1 `
    -Action Preflight -PythonPath $python -ConfigPath $config `
    -DatabasePath $database -SecretRoot $secretRoot -TokenPath $token `
    -TlsCertPath $cert -TlsKeyPath $key -CertificateMode Existing `
    -RunnerAddress $runnerIp

.\scripts\Install-RunnerObservabilityMonitor.ps1 `
    -Action Install -PythonPath $python -ConfigPath $config `
    -DatabasePath $database -SecretRoot $secretRoot -TokenPath $token `
    -TlsCertPath $cert -TlsKeyPath $key -CertificateMode Existing `
    -RunnerAddress $runnerIp
```

For development/test only, `SelfSigned` requires the explicit
`-AllowDevSelfSigned` switch. Missing parent directories are created before
generation. The script uses Windows/.NET `CertificateRequest` and a 2048-bit
RSA key when the modern export APIs are available. Windows PowerShell 5.1 does
not expose `ExportPkcs8PrivateKey`, so the script uses the Windows PKI
`New-SelfSignedCertificate` capability or the available RSA provider and the
same in-script PKCS#8 encoder. It exports the certificate as PEM, does not
invoke OpenSSL, and stops with the stable reason
`certificate_generation_unavailable` only when neither Windows generation path
is available. It does not start the service after that failure.

```powershell
.\scripts\Install-RunnerObservabilityMonitor.ps1 `
    -Action Install -PythonPath $python -ConfigPath $config `
    -DatabasePath $database -SecretRoot $secretRoot -TokenPath $token `
    -TlsCertPath $cert -TlsKeyPath $key -CertificateMode SelfSigned `
    -AllowDevSelfSigned -TrustSelfSignedCertificate `
    -RunnerAddress $runnerIp
```

For a clean development/test Monitor install, `-TrustSelfSignedCertificate`
imports only the generated public certificate into
`Cert:\CurrentUser\Root` for the installing user. It does not copy or import
`monitor.key`, and it is not an existing-install repair action. Confirm that
`monitor-test.local` resolves to the Monitor Host, then open the Dashboard at
`https://monitor-test.local:8765/`. Omitting the switch preserves the secure
default of not changing the Windows trust store and leaves the browser warning
expected for a self-signed certificate.

The Monitor script generates the token when absent and writes it atomically
with restrictive ACLs. A token value is never a parameter, command-line
argument, config value, or output. The service is configured through a path;
the runtime uses `--token-file`. `monitor.key` stays on the Monitor Host and
is never copied to a Runner. Output is limited to service state, paths,
certificate fingerprint/expiry metadata, and stable reason codes.

`Install` refuses an existing Monitor service, registers a stopped service,
and scopes the fixed inbound firewall rule to the confirmed Runner addresses.
Use the bounded lifecycle actions below; each reads back actual SCM state.

```powershell
.\scripts\Install-RunnerObservabilityMonitor.ps1 -Action RepairPermissions `
    -PythonPath $python -ConfigPath $config -DatabasePath $database `
    -SecretRoot $secretRoot -TokenPath $token -TlsCertPath $cert `
    -TlsKeyPath $key -RunnerAddress $runnerIp
.\scripts\Install-RunnerObservabilityMonitor.ps1 -Action Status -ServiceName 'RunnerObservabilityMonitor'
.\scripts\Install-RunnerObservabilityMonitor.ps1 -Action Start -ServiceName 'RunnerObservabilityMonitor'
.\scripts\Install-RunnerObservabilityMonitor.ps1 -Action Stop -ServiceName 'RunnerObservabilityMonitor'
.\scripts\Install-RunnerObservabilityMonitor.ps1 -Action Restart -ServiceName 'RunnerObservabilityMonitor'
.\scripts\Install-RunnerObservabilityMonitor.ps1 -Action Uninstall -ServiceName 'RunnerObservabilityMonitor'
```

`Uninstall` removes only the named Monitor service and owned firewall rule.
It preserves the token, certificate, private key, config, database, releases,
Runner identity, and Runner state. After the Monitor checks are complete,
continue with Runner onboarding and then one real CI job/dashboard
association check. Local tests do not prove live service, TLS trust,
firewall, or CI acceptance.

## Runner Host onboarding (after Monitor validation)

If this is the explicit full-clean Runner rebuild, complete the full-clean
reset in the `README.md` procedure before running the transfer below. The
reset removes the old Runner token/certificate pair; copy the newly generated
current pair only after the reset has finished. Step 0 inventory remains
mandatory in either case.

For the normal clean rebuild, use the Runner-side wizard after updating the
checkout with the approved `git pull --ff-only` procedure:

```powershell
.\scripts\Initialize-RunnerObservabilityRunner.ps1 `
    -CleanRebuild -MonitorIp '192.168.24.141' `
    -CertificateTrustModel SelfSigned -AllowHostsChange
```

Omit `-MonitorIp` to enter it interactively, or add `-WhatIf` for a read-only
plan. The wizard inventories first, verifies TCP/8765, requires
`RESET-RUNNER`, removes only the managed Runner observability state, and pauses
with `status=WAITING_FOR_MONITOR_FILES` for the operator to copy the new
`monitor-token.txt` and public `monitor.crt` through the approved remote-control
channel. It never copies `monitor.key`, prints token contents, deletes
`C:\actions-runner`, or unregisters the Runner. It stages the current checkout
HEAD and runs `Preflight`, `Configure`, and Heartbeat `Start` before reporting
`status=OK`. A direct `Runner.Listener.exe` process still needs one manual
restart after machine environment changes, followed by a real CI job.

Transfer only the token file and, for a private-CA/self-signed trust model,
the public `monitor.crt`. Never copy `monitor.key`. The Monitor administrator
should perform the transfer from an elevated administrative PowerShell; the operator does not
need to display or read the token value:

```powershell
$monitorSecretRoot = 'C:\runner-observability-secrets'       # Monitor Step 0 confirmed
$runnerHost = '<CONFIRMED_RUNNER_HOST>'
$runnerSecretRoot = "\\$runnerHost\C$\runner-observability-secrets" # Runner Step 0 confirmed

if (Test-Path -LiteralPath (Join-Path $runnerSecretRoot 'monitor.key') -PathType Leaf) {
    throw 'Unexpected monitor.key on Runner; stop before copying anything'
}

New-Item -ItemType Directory -Force -Path $runnerSecretRoot | Out-Null
foreach ($name in @('monitor-token.txt', 'monitor.crt')) {
    $source = Join-Path $monitorSecretRoot $name
    if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
        throw ("Missing Monitor source file: {0}" -f $name)
    }
    Copy-Item -LiteralPath $source -Destination $runnerSecretRoot -Force
}

$sourceCert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
    (Join-Path $monitorSecretRoot 'monitor.crt'))
$runnerCert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
    (Join-Path $runnerSecretRoot 'monitor.crt'))
if ($sourceCert.Thumbprint -ne $runnerCert.Thumbprint) {
    throw 'Runner monitor.crt thumbprint does not match the Monitor source'
}

Get-Item -LiteralPath (Join-Path $runnerSecretRoot 'monitor-token.txt'),
    (Join-Path $runnerSecretRoot 'monitor.crt') |
    Select-Object Name, Length
Write-Output 'transfer.certificate=match'
```

This copies only the token and public certificate. It never places the token
in a command-line argument or output. If the copy reports `Access Denied` even
in the elevated Monitor shell, inspect the ACLs of the two exact source files.
When the files belong to this deployment, run the existing permission repair
with the inventory-confirmed Monitor paths, then retry the copy:

```powershell
.\scripts\Install-RunnerObservabilityMonitor.ps1 `
    -Action RepairPermissions -PythonPath $python -ConfigPath $config `
    -DatabasePath $database -SecretRoot $monitorSecretRoot `
    -TokenPath (Join-Path $monitorSecretRoot 'monitor-token.txt') `
    -TlsCertPath (Join-Path $monitorSecretRoot 'monitor.crt') `
    -TlsKeyPath (Join-Path $monitorSecretRoot 'monitor.key')
```

Do not grant `Everyone`, recursively open the secrets directory, or copy
`monitor.key`. If the ACL is not deployment-owned, stop and use the
organization's exact-file ACL recovery process.

Run the Runner entry point after substituting the confirmed Monitor address:

```powershell
$python = 'C:\Python311\python.exe'
$installRoot = 'C:\runner-observability-agent'
$endpoint = 'https://monitor-test.local:8765'
$token = 'C:\runner-observability-secrets\monitor-token.txt'
$monitorIp = '192.0.2.20' # replace with the confirmed Monitor IPv4 address

.\scripts\Install-RunnerObservabilityRunner.ps1 `
    -Action Preflight -PythonPath $python -InstallRoot $installRoot `
    -Endpoint $endpoint -TokenPath $token -MonitorHost 'monitor-test.local' `
    -MonitorIp $monitorIp -CertificateTrustModel PublicCa

.\scripts\Install-RunnerObservabilityRunner.ps1 `
    -Action Configure -PythonPath $python -InstallRoot $installRoot `
    -Endpoint $endpoint -TokenPath $token -MonitorHost 'monitor-test.local' `
    -MonitorIp $monitorIp -CertificateTrustModel PublicCa
```

For `PrivateCa` or `SelfSigned`, pass only the public certificate and the
operator-confirmed SHA-256 fingerprint; `-ImportCertificate` verifies that
fingerprint before touching the Windows trust store. `-AllowHostsChange` is a
separate explicit gate and preserves unrelated hosts entries. If the token
file is absent, `Configure` prompts using `Read-Host -AsSecureString` and
creates an ACL-protected file. The token value is never a parameter or
service argument, and `monitor.key` is rejected on a Runner.

Use the Runner entry point for lifecycle and repair actions. The uninstall
action removes only the named Heartbeat service and preserves persistent data:

```powershell
.\scripts\Install-RunnerObservabilityRunner.ps1 -Action RepairPermissions -InstallRoot $installRoot -TokenPath $token
.\scripts\Install-RunnerObservabilityRunner.ps1 -Action Status -ServiceName 'RunnerObservabilityHeartbeat'
.\scripts\Install-RunnerObservabilityRunner.ps1 -Action Start -ServiceName 'RunnerObservabilityHeartbeat'
.\scripts\Install-RunnerObservabilityRunner.ps1 -Action Stop -ServiceName 'RunnerObservabilityHeartbeat'
.\scripts\Install-RunnerObservabilityRunner.ps1 -Action Restart -ServiceName 'RunnerObservabilityHeartbeat'
.\scripts\Install-RunnerObservabilityRunner.ps1 -Action Uninstall -ServiceName 'RunnerObservabilityHeartbeat'
```

## Concepts: pinned revisions, releases, and the atomic switch

- Every install/update names an explicit **pinned revision** (a version
  tag or commit-ish string, e.g. `1.4.0` or a short commit hash) -- never
  `latest` or any other floating reference you did not choose yourself.
- Each revision's files are copied into
  `<InstallRoot>\releases\<revision>\` (**staged**). Staging never deletes
  any other revision's directory, which is what makes rollback possible.
  Old release directories accumulate; disk cleanup of unused old releases
  is a manual operator decision, not something these scripts do
  automatically.
- Exactly one revision is **active** at a time, recorded in a single
  plain-text pointer file, `<InstallRoot>\current-release.txt`. Switching
  which revision is active is **atomic**: the new pointer content is
  written to a temporary file in the same directory and then swapped in
  with a single rename, so a crash mid-switch can never leave the pointer
  half-written -- it always reads either the old revision or the new one,
  never a mix.

## Install (first-time setup)

Run from an elevated PowerShell prompt if the target install directory
requires elevated permissions to create; the scripts themselves do not
require elevation on their own.

```powershell
./scripts/Install-RunnerObservability.ps1 `
    -Revision "1.0.0" `
    -Source "C:\path\to\built\1.0.0" `
    -InstallRoot "C:\runner-observability" `
    -TlsCertPath "C:\path\to\tls-cert.pem" `
    -TlsKeyPath "C:\path\to\tls-key.pem" `
    -AuthTokenPath "C:\path\to\auth-token.txt" `
    -FirewallResult Pass `
    -HostReachableResult Pass
```

All four of `-TlsCertPath`, `-AuthTokenPath`, `-FirewallResult`, and
`-HostReachableResult` are **required for this command to get past
preflight** -- the preflight battery below has five checks, and omitting
any of these four leaves the corresponding check unconfigured, which fails
closed (see "Preflight checks" below). `-TlsCertPath`/`-AuthTokenPath` must
point at real files that already exist locally; `-FirewallResult` and
`-HostReachableResult` must be the outcome of a real check an operator (or
an issue #6 process) already performed out of band for the actual target
environment -- these two flags never trigger a real check themselves, they
only pass through a result you already have. `-TlsKeyPath` is optional but
strongly recommended (see "Preflight checks" below): without it, the TLS
check only proves a cert *file* is present, not that it is a real,
loadable certificate that will actually be used for encryption.

What this does:

1. Runs the full preflight check battery (see "Preflight checks" below).
   If any check fails, installation stops before anything is written to
   `-InstallRoot`, and the script prints only the stable diagnostic
   reason(s) -- never a raw exception, a file path, or a credential value.
2. Stages the revision's files under
   `<InstallRoot>\releases\1.0.0\`.
3. Atomically activates it (`current-release.txt` now reads `1.0.0`).
4. Runs a local smoke test: invokes the newly staged release's own CLI
   entrypoint (`python -m runner_observability --help`) to confirm it
   imports and runs cleanly. This does **not** start a real Windows
   Service and does **not** open any socket.
5. If the smoke test fails, the install is rolled back: since this was a
   first install, there is no previous revision to restore, so
   `current-release.txt` is removed and the install ends in a clean,
   "nothing active" state rather than a half-installed one. Re-run after
   fixing the underlying issue.

Starting the monitor itself (once you trust the installed revision) uses
the same CLI surface documented in `README.md`:

```powershell
python -m runner_observability serve --token <token> --database <path> `
    --tls-cert <path\to\tls-cert.pem> --tls-key <path\to\tls-key.pem>
```

`--tls-cert`/`--tls-key` are optional but must be given as a pair --
supplying only one is a controlled, redacted error and the monitor never
starts. Omitting both (as in `docs/canary-evidence-template.md`-free local
testing and the Local Verification Gate) keeps the monitor on plain HTTP,
exactly as before this ticket. When both are given, the monitor wraps its
listening socket with a real `ssl.SSLContext` and serves genuine HTTPS --
this is the actual encryption boundary; the preflight "TLS certificate"
check (see "Preflight checks" below, even in its strengthened form) only
ever predicts whether this step *will* succeed, it never substitutes for
it.

or, to send one event (the fail-open agent path):

```powershell
python -m runner_observability emit --endpoint <url> --token <token> --event-json <json>
```

This runbook does not repeat the full schema/CLI reference; see
`README.md`'s "Schema-v1 boundary" section for that.

## Windows Service startup (issue #8)

Issue #8 supplies the SCM host and the operator scripts. The service host
reads the bearer credential from `-TokenPath` and starts the monitor child
with `--token-file`; the token value is never placed in `sc.exe` arguments,
the service config, logs, or evidence. Install the optional Windows extra in
the Python environment that will run the service, then run the install action
from an elevated PowerShell prompt:

```powershell
python -m pip install ".[windows-service]"
./scripts/Install-RunnerObservabilityService.ps1 `
    -Action Install `
    -ConfigPath "C:\runner-observability\service-config.json" `
    -PythonPath "C:\Python311\python.exe" `
    -TokenPath "C:\secure\runner-observability-token.txt" `
    -DatabasePath "C:\runner-observability\data\monitor.sqlite" `
    -TlsCertPath "C:\secure\monitor-cert.pem" `
    -TlsKeyPath "C:\secure\monitor-key.pem" `
    -RunnerAddress "192.168.24.141", "192.168.24.142"
```

The install action writes the non-secret config atomically, applies read ACLs
to the token/TLS/config files, grants the service account modify access to the
database directory, registers automatic SCM recovery, and creates the fixed
`Runner Observability Monitor TCP 8765` Firewall allow rule for the supplied
Runner addresses. The module's concrete Windows operations are the equivalent
of `icacls` ACL grants and `New-NetFirewallRule`/`Remove-NetFirewallRule` rule
replacement; the install action does not accept a service-account password.

Use the same script for lifecycle operations; each operation targets only the
named service and the fixed Firewall rule:

```powershell
./scripts/Install-RunnerObservabilityService.ps1 -Action Status
./scripts/Install-RunnerObservabilityService.ps1 -Action Start
./scripts/Install-RunnerObservabilityService.ps1 -Action Stop
./scripts/Install-RunnerObservabilityService.ps1 -Action Restart
./scripts/Install-RunnerObservabilityService.ps1 -Action Uninstall
```

For a pinned release update of an already-installed service, pass its service
name to the existing update script. The update flow stops the service before
the atomic release switch, runs the staged smoke test, starts the service, and
restores the previous release if service start fails:

```powershell
./scripts/Update-RunnerObservability.ps1 `
    -Revision "1.1.0" `
    -Source "C:\path\to\built\1.1.0" `
    -InstallRoot "C:\runner-observability" `
    -ServiceName "RunnerObservabilityMonitor" `
    -TlsCertPath "C:\secure\monitor-cert.pem" `
    -TlsKeyPath "C:\secure\monitor-key.pem" `
    -AuthTokenPath "C:\secure\runner-observability-token.txt" `
    -FirewallResult Pass `
    -HostReachableResult Pass
```

The scripts and tests provide the implementation contract only. A real
service status after boot/reboot, effective ACL inspection, effective
Firewall behavior, TLS trust, Runner reconnect, and production-ready
decision must be timestamped by the #6 HITL operator checklist.

## Runner Heartbeat Service (issue #9)

Issue #9 supplies the Runner Heartbeat Service and its SCM lifecycle script.
It is separate from the Monitor Host service in issue #8: the Runner service
only sends outbound `runner.heartbeat` telemetry and never changes a CI
process exit code. The service waits for the Monitor endpoint to become
network-ready, sends one heartbeat immediately, then schedules the next
heartbeat every 60 seconds from a monotonic deadline so delivery time does
not accumulate drift.

Install the optional Windows service dependency into the inventory-confirmed
machine Python runtime on the Runner, then run the install action from an
elevated PowerShell prompt. `ModulePath` must point at the active managed
release's `src` directory; the service launcher uses that path so a global
installation of `runner_observability` is not required. The token is read from
a file; it is never placed in the service command line or heartbeat state file:

```powershell
python -m pip install ".[windows-service]"
./scripts/Install-RunnerHeartbeatService.ps1 `
    -Action Install `
    -ConfigPath "C:\runner-observability\heartbeat-config.json" `
    -PythonPath "C:\Python311\python.exe" `
    -ModulePath "C:\runner-observability-agent\releases\<revision>\src" `
    -Endpoint "https://<monitor-host>:8765" `
    -TokenPath "C:\secure\runner-observability-token.txt" `
    -RunnerId "<runner-uuid>" `
    -StatePath "C:\runner-observability\runner-heartbeat-state.json"
```

The configuration and state writes are atomic. Each Runner has its own
`runner_id`, `producer_id`, `producer_epoch`, sequence, and local state file;
do not copy a state file from another Runner. The service account receives
read access to the config/token files and modify access to the state-file
directory. Use the same script for `Status`, `Start`, `Stop`, `Restart`, and
`Uninstall`; uninstall removes only the named service and leaves the token,
state, and evidence files for operator cleanup.

```powershell
./scripts/Install-RunnerHeartbeatService.ps1 -Action Status
./scripts/Install-RunnerHeartbeatService.ps1 -Action Start
./scripts/Install-RunnerHeartbeatService.ps1 -Action Stop
./scripts/Install-RunnerHeartbeatService.ps1 -Action Restart
./scripts/Install-RunnerHeartbeatService.ps1 -Action Uninstall
```

Local tests cover state isolation, atomic persistence, drift-free scheduling,
network-ready startup, bounded delivery, fail-open diagnostics, configuration
redaction, and SCM/script shape. They do not claim that a real Runner reboot,
Windows SCM status, certificate trust, ACL, reconnect, or Monitor restart was
observed. Those timestamped facts remain issue #6's HITL evidence boundary.

## Runner canary script (issue #6, using issue #7 HTTPS)

After issue #7, the monitor can serve genuine HTTPS when it is started with
`--tls-cert` and `--tls-key`. The canary script therefore requires an
`https://` endpoint by default and relies on the Runner's normal Windows
certificate trust store. It reads the bearer token from a file, never places
the token in the PowerShell command line, and keeps its producer epoch and
next sequence in `%LOCALAPPDATA%\RunnerObservability\canary-state.json`.

Pull the repository on the Runner, then run these commands from its root:

```powershell
git pull --ff-only
python --version
$runnerId = "<runner-uuid>"
$monitor = "https://<monitor-host>:8765"
$tokenFile = "C:\secure\runner-observability-token.txt"

.\scripts\Invoke-RunnerCanary.ps1 `
    -Mode Smoke `
    -Endpoint $monitor `
    -RunnerId $runnerId `
    -TokenPath $tokenFile
```

Expected result: one `[PASS]` line. If the Monitor Host is intentionally
plain HTTP for a local-only test, add `-AllowInsecureHttp`; do not use that
switch for the issue #6 HTTPS evidence.

Run the remaining checks in this order:

1. `Smoke`: confirms Runner-to-Monitor HTTPS, authentication, event ingest,
   and an online dashboard projection.
2. `Auth`: sends one heartbeat with an invalid token and confirms HTTP 401,
   then sends a valid heartbeat and confirms the runner is online again.
3. `OfflineRecovery`: sends a baseline heartbeat, sends nothing for the
   default 601 seconds, confirms `offline` with
   `offline_reason=heartbeat_timeout`, then sends a newer heartbeat and
   confirms recovery to `online`. Stop every other heartbeat producer for
   this Runner during the wait; otherwise another producer can keep it alive.
4. `NetworkFailure`: stop the Monitor Host first, then run the command below.
   The expected result is `[PASS]` because the endpoint failure is observed
   without printing a token. Start the Monitor Host again before continuing.

```powershell
.\scripts\Invoke-RunnerCanary.ps1 `
    -Mode Auth `
    -Endpoint $monitor `
    -RunnerId $runnerId `
    -TokenPath $tokenFile

.\scripts\Invoke-RunnerCanary.ps1 `
    -Mode OfflineRecovery `
    -Endpoint $monitor `
    -RunnerId $runnerId `
    -TokenPath $tokenFile

.\scripts\Invoke-RunnerCanary.ps1 `
    -Mode NetworkFailure `
    -Endpoint $monitor `
    -RunnerId $runnerId `
    -TokenPath $tokenFile
```

For a fast, non-destructive connectivity failure check without stopping the
Monitor Host, point `-FailureEndpoint` at an unused local HTTPS port, for
example `https://127.0.0.1:1`. This checks the canary's failure observation
path; the existing Python agent tests and the manual `emit` procedure still
cover the agent's fail-open delivery behavior. If you intentionally use an
HTTP failure endpoint, add `-AllowInsecureHttp` explicitly.

Use the default `runner-canary` producer id. Do not run this script with the
same `-ProducerId` as a live agent at the same time, because producer
sequence ordering is intentionally monotonic per producer epoch. The state
file must not contain a token and should stay local to the Runner; do not
copy one Runner's state file to another Runner.

## Update (upgrading an existing install)

```powershell
./scripts/Update-RunnerObservability.ps1 `
    -Revision "1.1.0" `
    -Source "C:\path\to\built\1.1.0" `
    -InstallRoot "C:\runner-observability" `
    -TlsCertPath "C:\path\to\tls-cert.pem" `
    -TlsKeyPath "C:\path\to\tls-key.pem" `
    -AuthTokenPath "C:\path\to\auth-token.txt" `
    -FirewallResult Pass `
    -HostReachableResult Pass
```

As with install above, all four of `-TlsCertPath`, `-AuthTokenPath`,
`-FirewallResult`, and `-HostReachableResult` are required for this command
to get past preflight.

Same sequence as install, with one difference: because a previous revision
is already active, any failure -- preflight, or the post-activation smoke
test -- **retains the previous version as active**. The upgrade attempt
leaves `current-release.txt` reading the old revision, unchanged, and
prints the stable failure reason. This is repeatable: re-running a still-
failing update reaches the same safe "previous version still active"
state every time, never a partially-switched or corrupted one.

This automatic rollback depends on the previous revision's staged files
still being present under `<InstallRoot>\releases\<previous-revision>\`.
If that directory has been manually removed (see "Old release directories"
under Rollback below), a failed update cannot restore it; the script
deactivates instead of leaving the broken new revision active, and prints
the distinct `rollback_target_missing` reason so you know manual recovery
(re-staging the previous revision, or fixing and retrying the new one) is
needed.

## Rollback

Rollback is not a separate script -- it is the automatic, guaranteed
outcome of any failed `Update-RunnerObservability.ps1` run (see above). If
you need to manually revert to a specific earlier revision that is still
staged on disk (e.g. after successfully upgrading to a revision you now
want to back out of for an unrelated reason), re-run
`Update-RunnerObservability.ps1` with `-Revision` set back to the earlier
revision and the matching `-Source` for it. The atomic-switch and smoke-
test/rollback contract applies identically in that direction.

Old release directories under `<InstallRoot>\releases\` are never deleted
automatically, specifically so a previously active revision stays
available for exactly this kind of manual rollback. **Do not manually
delete the directory for the currently-active (or most recently active)
revision** -- if you prune it and a later update then fails, automatic
rollback has nothing to restore and will deactivate instead of recovering
the previous version (see `rollback_target_missing` in "First triage"
below). Pruning older, no-longer-relevant release directories once you no
longer need to roll back to them is fine.

## Preflight checks

`Invoke-RunnerPreflight.ps1` (also run automatically as the first step of
install/update) runs a fixed battery of checks and reports only a stable,
actionable diagnostic per check -- never a raw exception, traceback, or
secret value:

| Check | What it confirms | Failure diagnostic |
| --- | --- | --- |
| Python version | The local Python interpreter meets the minimum supported version (3.11) | `unsupported_python_version` |
| TLS certificate | Without `-TlsKeyPath`: only that a certificate file is configured and present on disk (its contents are never read) -- this does **not** prove the file is a valid certificate or that it will ever actually be used for encryption. With `-TlsKeyPath` also supplied, this check is strengthened: it attempts to load the pair into a real `ssl.SSLContext` (`load_cert_chain`), the exact call the monitor's `serve --tls-cert/--tls-key` makes to actually turn on HTTPS -- proving the file is a loadable certificate whose key really matches it, without ever starting a server or opening a socket | `tls_certificate_file_missing` (no cert configured, or the file is missing/empty), or, only when `-TlsKeyPath` was supplied, `tls_certificate_invalid` (the pair failed to load: missing/unreadable key, malformed content, or a mismatched key) |
| Auth credential | A credential/token file is configured and present on disk (its contents are never read) | `auth_credential_file_missing` |
| Firewall | The ingest port is reachable through the local firewall configuration, via an operator-supplied check | `firewall_check_not_configured` (no check wired up) or `firewall_port_blocked` (checked and blocked) |
| Host reachability | The target Monitor Host responds, retried up to 3 times with a short pause between attempts -- never retried indefinitely | `host_reachability_check_not_configured` (no check wired up) or `monitor_host_unreachable` (retried and still unreachable) |

All five checks must pass before `Install-RunnerObservability.ps1` or
`Update-RunnerObservability.ps1` will write anything -- there is no
"skip the firewall/host check" mode. Two of these checks (firewall, host
reachability) require the operator to supply a real check for the actual
target environment via `-FirewallResult`/`-HostReachableResult`; this
repository intentionally ships no default that reaches out over a real
network on its own, so **omitting either flag is a hard block, not a
warning** -- you must determine that result out of band (a real firewall
rule check, a real ping/connect to the Monitor Host, etc.) and pass it in
explicitly. Wiring up those real checks for a specific Monitor Host, TLS
issuance and trust, real Windows Firewall rules, and real Windows Service
installation/credentials are all issue #6 (HITL) responsibilities -- see
the "Scope" section above.

```powershell
./scripts/Invoke-RunnerPreflight.ps1 `
    -TlsCertPath "C:\path\to\tls-cert.pem" `
    -TlsKeyPath "C:\path\to\tls-key.pem" `
    -AuthTokenPath "C:\path\to\auth-token.txt" `
    -FirewallResult Pass `
    -HostReachableResult Pass
```

## First triage

Use this table when something looks wrong. Every diagnostic named here is
a stable reason code you will see printed by the scripts above -- never a
raw exception message, stack trace, absolute path, or token value.

| Symptom / diagnostic | Likely cause | What to do |
| --- | --- | --- |
| `unsupported_python_version` | The host's Python interpreter is older than 3.11 | Install/upgrade Python 3.11+ on the target host and re-run |
| `tls_certificate_file_missing` | No cert file configured, or the configured path does not exist / is empty | Confirm `-TlsCertPath` points at a real, non-empty file. Issuing/trusting the certificate itself is issue #6's job, not this script's |
| `tls_certificate_invalid` | `-TlsKeyPath` was also supplied, and the cert/key pair could not be loaded into a real `SSLContext` -- the key file is missing/empty, the cert content is malformed, or the key does not match the certificate | Confirm `-TlsCertPath`/`-TlsKeyPath` point at a real, matching PEM certificate and private key pair (the same files you intend to pass to `serve --tls-cert`/`--tls-key`). This check never reports the file contents or which specific rule failed |
| `auth_credential_file_missing` | No credential file configured, or the configured path does not exist / is empty | Confirm `-AuthTokenPath` points at a real, non-empty file. This check never reads or reports the token's value |
| `firewall_check_not_configured` | `-FirewallResult` was omitted -- this check is **required**, not optional, for install/update to proceed | Determine the real firewall outcome for the target environment out of band and pass `-FirewallResult Pass` or `-FirewallResult Fail` explicitly. There is no way to skip this check |
| `firewall_port_blocked` | A real firewall check was wired up and reported the port is blocked | Open the ingest port for the Monitor Host per your organization's firewall change process (issue #6) |
| `host_reachability_check_not_configured` | `-HostReachableResult` was omitted -- this check is **required**, not optional, for install/update to proceed | Determine the real Monitor Host reachability outcome out of band and pass `-HostReachableResult Pass` or `-HostReachableResult Fail` explicitly. There is no way to skip this check |
| `monitor_host_unreachable` | A real reachability check was wired up and the host did not respond within 3 attempts | Confirm the Monitor Host process is running and the network path to it is up; this check never retries beyond 3 attempts, so a transient blip should simply be re-run manually |
| `service_start_failed` | A service-enabled update could not start the named existing Windows Service after the new release smoke test | The previous release is restored and the service start is retried against that release; if the previous release was pruned, the update deactivates rather than leaving the broken revision active. Real boot/reboot and effective SCM evidence remains #6 HITL work |
| `smoke_test_failed` | The newly activated revision's own CLI entrypoint did not run cleanly (`python -m runner_observability --help` failed or timed out) | The previous revision (or "nothing active", on a first install) has already been automatically restored; re-run the newly staged revision's smoke test manually to investigate before retrying the update |
| `rollback_target_missing` | A post-activation check failed, but the previous revision's `releases\<revision>\` directory was manually removed, so automatic rollback could not restore it | The broken new revision has been deactivated (not left active) -- `current-release.txt` now reflects "nothing active" or the last state before this attempt. Re-stage the previous revision's files (re-run `Update-RunnerObservability.ps1` with its `-Revision`/`-Source`) to restore it, or fix and retry the new revision |
| `source_unavailable` | `-Source` does not exist, is not readable, or is otherwise unusable when staging began | Confirm `-Source` points at a real, readable local directory containing the revision's built files, then re-run |
| `install_root_unwritable` | `-InstallRoot` (or a path under it) could not be written to -- for example, insufficient permissions | Confirm you have write access to `-InstallRoot` (an elevated prompt may be required), then re-run |
| `unexpected_deploy_error` | A failure occurred that does not match any diagnostic above | Nothing is left half-written to disk, and no raw exception or path was printed. Re-run with verbose local troubleshooting (e.g. inspect `-InstallRoot` by hand) before escalating |
| Dashboard shows a runner/job as offline unexpectedly | Normal liveness behavior -- see `README.md`; not a deployment-script issue | Check the 10-minute heartbeat timeout behavior described in `README.md`, not this runbook |

If a diagnostic is not in this table, do not guess at its cause from the
name alone -- treat it as an unhandled failure and escalate; do not infer
that a deploy or rollback succeeded from a diagnostic you do not
recognize.

## Local Verification Gate vs. this runbook

Before using this runbook's install/update scripts against any real
target, `scripts/Invoke-VerificationGate.ps1` (issue #5) should already be
passing locally. That gate proves the monitor's own event/store/dashboard
logic and isolated fault recovery; it is a prerequisite, not a
replacement, for the deployment contract this runbook describes. Neither
this runbook's local install/update simulation nor issue #5's gate is
sufficient evidence for a production-ready decision -- see
`docs/canary-evidence-template.md` and issue #6.
