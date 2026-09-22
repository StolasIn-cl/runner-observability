# Runner observability

This repository contains a local, fail-open telemetry monitor for self-hosted
CI runners. It uses Python 3.11+ and the standard library only.

## Start here: safe onboarding order

This project is deployed across multiple Windows machines. Read
[`AGENTS.md`](AGENTS.md) and [`CONTEXT.md`](CONTEXT.md) before operating on a
host. `CONTEXT.md` is a last-known snapshot, not live discovery.

The first command on every new or existing Runner is the read-only inventory
below. Do not run an install, copy secrets, import a certificate, set machine
environment variables, or restart a process until the output identifies the
current machine and shows whether an installation already exists.

### Step 0 -- inventory the target machine before changing it

Run this in an elevated PowerShell 5.1+ window on the target Runner. It reads
metadata and file existence only; it never prints token or private-key
contents and never writes to disk.

```powershell
$candidateRunnerRoots = @('C:\actions-runner')
$candidateInstallRoots = @('C:\runner-observability-agent')
$candidateSecretRoots = @('C:\runner-observability-secrets')

Write-Output '===== HOST ====='
Get-CimInstance Win32_ComputerSystem |
    Select-Object Name, UserName
Write-Output "powershell=$($PSVersionTable.PSVersion)"

Write-Output ''
Write-Output '===== PYTHON ====='
$python = Get-Command python -ErrorAction SilentlyContinue
if ($python) {
    Write-Output "python.command=$($python.Source)"
    & $python.Source --version
} else {
    Write-Output 'python.command=<not found>'
}

Write-Output ''
Write-Output '===== MACHINE CONFIGURATION ====='
foreach ($name in @(
    'RUNNER_OBSERVABILITY_INSTALL_ROOT',
    'RUNNER_OBSERVABILITY_ENDPOINT',
    'RUNNER_OBSERVABILITY_TOKEN_PATH',
    'RUNNER_OBSERVABILITY_RUNNER_ID'
)) {
    $value = [Environment]::GetEnvironmentVariable($name, 'Machine')
    if ([string]::IsNullOrWhiteSpace($value)) { $value = '<empty>' }
    Write-Output "Machine.$name=$value"
}

Write-Output ''
Write-Output '===== CANDIDATE ROOTS ====='
foreach ($path in ($candidateRunnerRoots + $candidateInstallRoots + $candidateSecretRoots)) {
    $item = Get-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
    if ($item) {
        Write-Output "path.exists=$path type=$($item.GetType().Name)"
    } else {
        Write-Output "path.exists=$path value=False"
    }
}

Write-Output ''
Write-Output '===== ACTIVE RELEASES ====='
foreach ($root in $candidateInstallRoots) {
    $pointer = Join-Path $root 'current-release.txt'
    if (Test-Path -LiteralPath $pointer -PathType Leaf) {
        $revision = (Get-Content -LiteralPath $pointer -Raw).Trim()
        Write-Output "install_root=$root"
        Write-Output "current_release=$revision"
        Write-Output "release_src_exists=$(Test-Path -LiteralPath (Join-Path $root (Join-Path ('releases\' + $revision) 'src')) -PathType Container)"
        Write-Output "runner_id_exists=$(Test-Path -LiteralPath (Join-Path $root 'runner-id.txt') -PathType Leaf)"
    } elseif (Test-Path -LiteralPath $root) {
        Write-Output "install_root=$root pointer=<missing> state=inspect-before-use"
    }
}

Write-Output ''
Write-Output '===== SECRET FILE EXISTENCE ONLY ====='
foreach ($root in $candidateSecretRoots) {
    foreach ($name in @('monitor-token.txt', 'monitor.crt', 'monitor.key')) {
        $path = Join-Path $root $name
        $item = Get-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
        if ($item) {
            Write-Output "secret_file=$path exists=True length=$($item.Length)"
        } else {
            Write-Output "secret_file=$path exists=False"
        }
    }
}

Write-Output ''
Write-Output '===== SERVICES AND RUNNER PROCESS ====='
Get-CimInstance Win32_Service |
    Where-Object { $_.Name -match '(?i)action|runner|observability|promeo' -or $_.DisplayName -match '(?i)action|runner|observability|promeo' } |
    Select-Object Name, DisplayName, State, StartMode
Get-CimInstance Win32_Process |
    Where-Object { $_.Name -match '(?i)^Runner\.(Listener|Worker)\.exe$|runsvc|run\.cmd' } |
    Select-Object ProcessId, ParentProcessId, Name, ExecutablePath,
        @{Name='CommandLine'; Expression={
            ([string]$_.CommandLine) `
                -replace '(?i)(--token\s+)\S+', '$1<redacted>' `
                -replace '(?i)(Bearer\s+)\S+', '$1<redacted>'
        }}
```

Use the result to choose the next path:

| Inventory result | Next action |
| --- | --- |
| `current-release.txt` exists and names a valid `releases\<revision>\src` | Existing install: use the update procedure; preserve the active release. |
| Install root exists but pointer or release source is missing | Stop and inspect the root manually; do not overwrite it. |
| Install root does not exist, but the Runner root and launch mode are known | New install may proceed with the confirmed paths. |
| Endpoint is empty or contains `<monitor-host>` | Stop and obtain the real Monitor URL before configuring the Runner. |
| A matching service exists | Record its exact name and account; use that name for lifecycle commands. |
| No matching service and `Runner.Listener.exe` is direct | The Runner is interactive; restart it from its verified console/start command, not with `Restart-Service`. |

Record the inventory in [`CONTEXT.md`](CONTEXT.md) before proceeding. If the
machine does not match the known snapshot, keep its paths and account separate
from the other machines.

## New Runner onboarding (real deployment)

The following procedure creates the layout consumed by Promeo's
`Telemetry-Helpers.ps1`. Replace only values that were confirmed by Step 0 or
by the Monitor Host operator. The examples use the current convention
`C:\runner-observability-agent` and `C:\runner-observability-secrets`; they are
not automatic defaults.

### Step 1 -- prepare the Monitor certificate and token

On the Monitor Host, keep all three files in the protected secret directory:

```text
C:\runner-observability-secrets\monitor-token.txt
C:\runner-observability-secrets\monitor.crt
C:\runner-observability-secrets\monitor.key
```

`monitor.key` is the Monitor's private key and stays on the Monitor Host. Use
an approved secure transfer method for the token. Copy `monitor.crt` to a
Runner only when it is needed for the trust procedure below; never copy the
private key.

The Python agent creates its HTTPS context with the operating system's default
certificate trust. A certificate file sitting beside `monitor-token.txt` is
not automatically trusted. If the Monitor certificate is issued by a public
or already trusted internal CA, no Runner-side certificate copy is required.
If it is self-signed or issued by a private CA, copy the public certificate to
the confirmed secret directory and, after verifying its fingerprint through
an independent channel, import it into the Windows trust store:

```powershell
$certPath = 'C:\runner-observability-secrets\monitor.crt'
if (-not (Test-Path -LiteralPath $certPath -PathType Leaf)) {
    throw 'monitor.crt was not found at the inventory-confirmed path'
}

# Only for an approved self-signed/private-CA certificate.
Import-Certificate -FilePath $certPath -CertStoreLocation 'Cert:\LocalMachine\Root'
```

Do not import an unverified certificate and do not distribute `monitor.key`.
If the Runner job runs under a different account and the policy uses the
CurrentUser store instead, import into that account's approved store and
record the decision in `CONTEXT.md`.

### Step 1A -- resolve `monitor-test.local` on the Runner

If the endpoint uses `https://monitor-test.local:8765/v1/events` and the name
is not provided by the organization's DNS, add a hosts mapping on **each
Runner** that must send telemetry. On Windows the file is normally:

```text
C:\Windows\System32\drivers\etc\hosts
```

Use the actual value of `$env:SystemRoot` from Step 0 rather than assuming the
system drive. Inspect the existing mapping first, from an elevated PowerShell:

```powershell
$hostsPath = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
Select-String -LiteralPath $hostsPath -Pattern '(^|\s)monitor-test\.local(\s|$)' -ErrorAction SilentlyContinue
```

Ask the Monitor Host operator for the confirmed Monitor IP before editing. The
following is an example shape only; `168.1.1.1` is a placeholder and must not
be copied as the production address:

```text
# Runner observability Monitor -- example only; replace with the confirmed IP
168.1.1.1    monitor-test.local
```

After the real IP has been confirmed, run an idempotent update in an elevated
PowerShell. Replace the placeholder variable value; the guard intentionally
refuses to run while the placeholder remains:

```powershell
$hostsPath = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
$monitorIp = '<CONFIRMED_MONITOR_IP>'
$monitorHost = 'monitor-test.local'

if ($monitorIp -eq '<CONFIRMED_MONITOR_IP>') {
    throw 'Obtain the confirmed Monitor IP before editing the hosts file'
}
if ($monitorIp -notmatch '^\d{1,3}(\.\d{1,3}){3}$') {
    throw 'Monitor IP must be an IPv4 address'
}

$existing = Select-String -LiteralPath $hostsPath `
    -Pattern ('(^|\s)' + [regex]::Escape($monitorHost) + '(\s|$)') `
    -ErrorAction SilentlyContinue
if ($existing) {
    Write-Output 'hosts_mapping=already_present_review_existing_line'
} else {
    Add-Content -LiteralPath $hostsPath -Value ("{0}`t{1}" -f $monitorIp, $monitorHost)
    Write-Output 'hosts_mapping=added'
}

Resolve-DnsName -Name $monitorHost -ErrorAction SilentlyContinue
Test-NetConnection -ComputerName $monitorHost -Port 8765
```

If an existing line maps `monitor-test.local` to a different address, stop and
confirm whether it should be replaced; do not create a second conflicting
entry. Record the confirmed mapping in the machine's `CONTEXT.md` section
without recording credentials. If the hostname is already resolved correctly
through DNS, leave the hosts file unchanged.

Copy the token into the confirmed Runner path through the organization's
approved secret-transfer channel. Then verify existence without displaying it:

```powershell
$secretRoot = 'C:\runner-observability-secrets'
$tokenPath = Join-Path $secretRoot 'monitor-token.txt'
New-Item -ItemType Directory -Force -Path $secretRoot | Out-Null

# Replace <approved-secure-source> only after confirming the source.
Copy-Item -LiteralPath '<approved-secure-source>\monitor-token.txt' `
    -Destination $tokenPath -Force

$token = Get-Item -LiteralPath $tokenPath -Force
Write-Output "token.exists=$($token.Exists) length=$($token.Length)"
```

Apply the organization's least-privilege ACL. The account must be the account
that actually launches the GitHub Runner, not merely the administrator who
performed setup:

```powershell
$runnerAccount = 'MACHINE\confirmed-runner-account'
icacls $secretRoot /inheritance:r
icacls $secretRoot /grant:r ("{0}:(OI)(CI)(R)" -f $runnerAccount) `
    ("{0}:(OI)(CI)(F)" -f 'SYSTEM') `
    ("{0}:(OI)(CI)(F)" -f 'Administrators')
icacls $tokenPath /inheritance:r
icacls $tokenPath /grant:r ("{0}:(R)" -f $runnerAccount) `
    ("{0}:(F)" -f 'SYSTEM') `
    ("{0}:(F)" -f 'Administrators')
```

### Step 2 -- stage the agent release without overwriting an existing install

Promeo expects this exact release layout:

```text
C:\runner-observability-agent\
  current-release.txt
  runner-id.txt                 # initialized once; stable for this Runner
  releases\<revision>\
    src\runner_observability\
```

Use a separate, temporary source checkout. Do not clone the source into the
managed install root. The repository's `Install-RunnerObservability.ps1` and
`Update-RunnerObservability.ps1` are local deployment-contract simulations;
they do not register the Promeo CI agent as a Windows service. For a new CI
Runner, stage the release explicitly after Step 0 confirmed that the install
root is new:

```powershell
$sourceRoot = 'C:\runner-observability-bootstrap'
$installRoot = 'C:\runner-observability-agent'
$revision = 'd3d73b5' # approved runner-observability commit; use the chosen immutable revision

# Obtain the source through the approved repository/artifact channel. This
# example uses the public remote and a detached, immutable commit.
if (-not (Test-Path -LiteralPath $sourceRoot)) {
    git clone https://github.com/StolasIn-cl/runner-observability.git $sourceRoot
}
git -C $sourceRoot fetch --depth 1 origin codex/runner-observability
git -C $sourceRoot checkout --detach $revision

if (Test-Path -LiteralPath (Join-Path $installRoot 'current-release.txt') -PathType Leaf) {
    throw 'An active install already exists; use the update procedure instead'
}
if (Test-Path -LiteralPath $installRoot) {
    $existing = Get-ChildItem -LiteralPath $installRoot -Force -ErrorAction Stop
    if ($existing) {
        throw 'Install root exists and is not empty; inspect it before staging'
    }
} else {
    New-Item -ItemType Directory -Path $installRoot | Out-Null
}

$sourceSrc = Join-Path $sourceRoot 'src'
$releaseRoot = Join-Path $installRoot (Join-Path 'releases' $revision)
if (-not (Test-Path -LiteralPath (Join-Path $sourceSrc 'runner_observability') -PathType Container)) {
    throw 'Source checkout does not contain src\runner_observability'
}
if (Test-Path -LiteralPath $releaseRoot) {
    throw 'The requested revision is already staged; inspect it before continuing'
}

New-Item -ItemType Directory -Path (Join-Path $releaseRoot 'src') -Force | Out-Null
Copy-Item -Path (Join-Path $sourceSrc '*') `
    -Destination (Join-Path $releaseRoot 'src') -Recurse -Force

$python = (Get-Command python -ErrorAction Stop).Source
$env:PYTHONPATH = Join-Path $releaseRoot 'src'
& $python -m runner_observability --help
if ($LASTEXITCODE -ne 0) {
    throw 'The staged release failed its local import smoke test'
}

$pointerTemp = Join-Path $installRoot 'current-release.txt.tmp'
Set-Content -LiteralPath $pointerTemp -Value $revision -Encoding ASCII
Move-Item -LiteralPath $pointerTemp -Destination (Join-Path $installRoot 'current-release.txt') -Force

Write-Output "active_revision=$((Get-Content (Join-Path $installRoot 'current-release.txt') -Raw).Trim())"
Write-Output "release_exists=$(Test-Path -LiteralPath (Join-Path $releaseRoot 'src\runner_observability') -PathType Container)"
```

Use the actual approved source checkout and revision for your environment. A
new Runner does not need to install the Python package globally; the helper
sets `PYTHONPATH` to the active release's `src` directory for each bounded
agent invocation.

### Step 2A -- grant CI read access and persist the Runner identity

The heartbeat service and CI jobs use different Windows security contexts:

* `RunnerObservabilityHeartbeat` normally runs as `NT AUTHORITY\LocalService`.
* Promeo's CI telemetry runs as the account that launches `Runner.Listener.exe`
  and `Runner.Worker.exe`.

Grant the confirmed CI Runner account read/execute access to the managed agent
root and read access to the token file as described above. In addition, the CI
account must be able to persist the per-machine identity in
`C:\runner-observability-agent\runner-id.txt`. Without this write access,
`Telemetry-Helpers.ps1` refuses to send the affected event instead of using
an in-memory UUID. This prevents separate CI steps from appearing in the
dashboard as separate Runners; fix the ACL before treating telemetry as
operational.

Run the following once in an elevated PowerShell after replacing the account
with the account confirmed by `Runner.Listener.exe` ownership:

```powershell
$runnerAccount = 'MACHINE\confirmed-runner-account'
$installRoot = 'C:\runner-observability-agent'
$runnerIdPath = Join-Path $installRoot 'runner-id.txt'

if (-not (Test-Path -LiteralPath $installRoot -PathType Container)) {
    throw 'The inventory-confirmed install root does not exist'
}

if (-not (Test-Path -LiteralPath $runnerIdPath -PathType Leaf)) {
    $runnerId = ([guid]::NewGuid()).Guid
    Set-Content -LiteralPath $runnerIdPath -Value $runnerId -Encoding ASCII -NoNewline
} else {
    $runnerId = (Get-Content -LiteralPath $runnerIdPath -Raw -ErrorAction Stop).Trim()
}

$parsedRunnerId = [guid]::Empty
if (-not [guid]::TryParse($runnerId, [ref]$parsedRunnerId)) {
    throw 'runner-id.txt does not contain a valid UUID; inspect it before changing it'
}

# Read/execute the active release and its parent directories.
icacls.exe $installRoot /grant ("{0}:(RX)" -f $runnerAccount) /C
if ($LASTEXITCODE -ne 0) { throw 'Failed to grant agent-root read/execute access' }
icacls.exe $installRoot /grant ("{0}:(OI)(CI)(RX)" -f $runnerAccount) /T /C
if ($LASTEXITCODE -ne 0) { throw 'Failed to grant release read/execute access' }

# Only the stable identity file needs write access; do not grant Modify to the
# whole agent root or to the release source.
icacls.exe $runnerIdPath /grant ("{0}:(M)" -f $runnerAccount) /C
if ($LASTEXITCODE -ne 0) { throw 'Failed to grant runner-id persistence access' }

Write-Output 'runner_id_exists=True'
Write-Output 'runner_id_valid=True'
```

Do not delete or regenerate an existing `runner-id.txt` during ordinary
updates. If a machine image is cloned, generate one new UUID for each physical
Runner before its first CI job. As an alternative, a stable per-machine
`RUNNER_OBSERVABILITY_RUNNER_ID` machine environment variable may be used, but
never generate that value per job or per PowerShell process.

### Step 3 -- configure machine environment variables

Set these values only after Step 0 confirmed the paths and the Monitor Host
operator supplied the real endpoint. The endpoint must include `/v1/events`.

```powershell
$installRoot = 'C:\runner-observability-agent'
$endpoint = 'https://monitor.example.internal:8765/v1/events'
$tokenPath = 'C:\runner-observability-secrets\monitor-token.txt'

[Environment]::SetEnvironmentVariable('RUNNER_OBSERVABILITY_INSTALL_ROOT', $installRoot, 'Machine')
[Environment]::SetEnvironmentVariable('RUNNER_OBSERVABILITY_ENDPOINT', $endpoint, 'Machine')
[Environment]::SetEnvironmentVariable('RUNNER_OBSERVABILITY_TOKEN_PATH', $tokenPath, 'Machine')

foreach ($name in @(
    'RUNNER_OBSERVABILITY_INSTALL_ROOT',
    'RUNNER_OBSERVABILITY_ENDPOINT',
    'RUNNER_OBSERVABILITY_TOKEN_PATH'
)) {
    Write-Output "Machine.$name=$([Environment]::GetEnvironmentVariable($name, 'Machine'))"
}
```

Do not set `RUNNER_OBSERVABILITY_RUNNER_ID` during a normal new install when
`runner-id.txt` has been initialized and is writable by the CI Runner account.
The helper then reuses that UUID across jobs. If the install root came from a
cloned machine image and already contains another machine's `runner-id.txt`,
assign a new machine-specific UUID through the optional environment variable
instead:

```powershell
[Environment]::SetEnvironmentVariable(
    'RUNNER_OBSERVABILITY_RUNNER_ID',
    ([guid]::NewGuid()).Guid,
    'Machine'
)
```

### Step 4 -- restart the verified Runner launch process once

Machine environment variables are inherited when a process starts. A running
`Runner.Listener.exe` keeps its old process environment, so restart the Runner
after Step 3. This is a process restart, not a Windows reboot.

- If Step 0 found a Windows service, use its exact recorded service name:
  `Restart-Service -Name '<verified-service-name>'`.
- If Step 0 found no service and the Runner was started by `run.cmd`, stop it
  from its existing console with `Ctrl+C`, then start `run.cmd` again from the
  verified Runner root under the same account.

Do not use `Restart-Service` with an invented name and do not kill an unknown
process. Re-run the process-environment check from [`AGENTS.md`](AGENTS.md) in
a fresh shell after the Runner has restarted.

### Step 5 -- perform one real CI verification

Run one normal CI job that calls the Promeo telemetry helpers. After it starts,
verify the local identity without printing credentials:

```powershell
$installRoot = 'C:\runner-observability-agent'
$revision = (Get-Content (Join-Path $installRoot 'current-release.txt') -Raw).Trim()
Write-Output "active_revision=$revision"
Write-Output "runner_id_exists=$(Test-Path -LiteralPath (Join-Path $installRoot 'runner-id.txt') -PathType Leaf)"
Write-Output "token_exists=$(Test-Path -LiteralPath 'C:\runner-observability-secrets\monitor-token.txt' -PathType Leaf)"
```

`runner_id_exists=True` is required for a stable dashboard identity. If it is
`False`, or if separate jobs produce different IDs, stop and fix the
`runner-id.txt` ACL before treating the dashboard as showing multiple physical
Runners.

Then confirm in the dashboard that:

1. the new physical Runner appears once in the active Runners list;
2. rebuild and unsafe-merge progress is attached to the same `Dart shard N`
   job that started it; and
3. any remaining `progress_unreported` is a genuinely stale-progress hint,
   not a job-association mismatch.

If this verification fails, stop and follow the troubleshooting section in
[`AGENTS.md`](AGENTS.md) and the diagnostic table in [`docs/runbook.md`](docs/runbook.md).

## Runner Heartbeat Windows Service runtime boundary (issue #9)

The Runner Heartbeat Service runs as `NT AUTHORITY\LocalService` by default.
This is a separate Windows security context from the interactive Runner user.
Installing Python and `runner_observability` successfully for the interactive
user does not prove that `LocalService` can read and execute the same runtime.

Prefer a machine-scoped Python runtime or virtual environment under a managed
path such as `C:\runner-observability-agent\venv`. The runtime, its package
files, and every parent directory needed to reach them must be readable and
executable by `LocalService`. The heartbeat install script grants the service
account access to the config, token, and state paths; it does not grant access
to a per-user Python installation.

If a per-user Python runtime is used temporarily, verify the exact service
binary path and package location before changing ACLs. Grant only traverse
access on the confirmed parent directories and read/execute access on the
confirmed Python runtime; do not grant write or full-control access and never
print the token:

```powershell
$pythonPath = 'C:\Users\<runner-user>\AppData\Local\Programs\Python\Python311\python.exe'
$pythonRoot = Split-Path -Parent $pythonPath
$localService = '*S-1-5-19' # NT AUTHORITY\LocalService

& $pythonPath -c "import runner_observability.heartbeat_service as m; print(m.__file__)"
if ($LASTEXITCODE -ne 0) {
    throw 'The configured Python cannot import runner_observability.heartbeat_service'
}

# Replace these with the exact parents confirmed on the target Runner.
$traversePaths = @(
    'C:\Users\<runner-user>',
    'C:\Users\<runner-user>\AppData',
    'C:\Users\<runner-user>\AppData\Local',
    'C:\Users\<runner-user>\AppData\Local\Programs',
    'C:\Users\<runner-user>\AppData\Local\Programs\Python'
)
foreach ($path in $traversePaths) {
    icacls.exe $path /grant ("{0}:(X)" -f $localService) /C
    if ($LASTEXITCODE -ne 0) { throw "Failed to grant traverse access: $path" }
}

icacls.exe $pythonRoot /grant ("{0}:(OI)(CI)(RX)" -f $localService) /T /C
if ($LASTEXITCODE -ne 0) { throw "Failed to grant Python runtime access: $pythonRoot" }
```

The `Install` action registers the service but does not start it. Start and
verify it explicitly:

```powershell
./scripts/Install-RunnerHeartbeatService.ps1 -Action Start
sc.exe queryex RunnerObservabilityHeartbeat
```

The expected result is `STATE : 4 RUNNING` with a non-zero PID. If `sc start`
returns error 5 (`Access is denied`) while the service is configured for
`LocalService`, inspect the Python executable/package ACLs before changing the
service account. Do not delete the service, reset `runner-id.txt`, or expose
the token as a command-line argument.

On 2026-09-21, `PROMEORUNNER-DT` reproduced this boundary: registration and
config ACLs succeeded, but the per-user Python runtime could not be started by
`LocalService`. After the runtime traverse/read-execute ACLs were corrected,
the service reached `RUNNING`, the dashboard displayed the heartbeat, and a
real CI test completed successfully.

## Existing Runner update and component restart rules

The two recent fixes are deployed independently:

| Component | Change | Required action |
| --- | --- | --- |
| Promeo repository commit `d7076e2154` | Stable Runner identity and shard progress propagation | Merge/deploy to the branch used by CI. The next job checks out the updated workflow scripts; no agent reinstall is needed. |
| Monitor repository commit `d3d73b5` | Active Runner dashboard projection | Deploy to the Monitor Host and restart the actual Monitor process/service once. A browser refresh is sufficient after that. |
| Runner agent release | Python package under `C:\runner-observability-agent` | Only stage/update when the agent package itself changes. Preserve the old release for rollback. |

For an existing install, a `current-release.txt` is a hard boundary: do not
run the new-install block. First inventory it, then stage a new immutable
revision beside the old one and activate it only after the import smoke test.
The CI Runner itself does not need restarting for a dashboard-only deployment;
it does need one restart after machine environment variables are first added or
changed.

## Schema-v1 boundary

`runner_observability.contracts.validate_event(payload)` is the only allowed
input boundary for later HTTP and SQLite layers. It returns an immutable
`ValidatedEvent` only for complete `schema_version: 1` envelopes. The monitor,
not the sender, owns `received_at`.

Approved event types are `runner.heartbeat`, `runner.offline`, `job.started`,
`job.heartbeat`, `job.finished`, `job.progress`, and `job.fallback`. Generic
job events require the complete stable job key: repository, workflow run ID,
run attempt, and job ID. A supplied Actions run URL is validated and passed
through; this monitor does not query GitHub or construct run URLs.

The validator is closed-world: unknown fields and event types are rejected,
as are oversized inputs and credential-bearing, raw-log, environment, command,
absolute-path, PR-text, individual test/group, or raw fallback reason fields.
Rejections expose only stable reason codes, never input values.

Run the current contract suite with:

```powershell
$env:PYTHONPATH='src'
python -m unittest discover -s tests -v
```

## Running the monitor (`serve`)

```powershell
$env:PYTHONPATH='src'
python -m runner_observability serve --token <token> --database <path>
```

By default this serves plain HTTP, exactly as before issue #7. To serve
real HTTPS instead, pass a matching certificate and private key pair:

```powershell
python -m runner_observability serve --token <token> --database <path> `
    --tls-cert <path\to\tls-cert.pem> --tls-key <path\to\tls-key.pem>
```

For Windows Service startup, keep the bearer credential in an ACL-protected
file and use the service host's `--token-file` path boundary. The service
command line contains the config/token file paths, never the token value:

```powershell
python -m runner_observability serve --token-file <path\to\token.txt> --database <path>
```

Install and manage the SCM service with
`scripts/Install-RunnerObservabilityService.ps1`; it also applies the
service-file ACLs and the fixed Runner-address Firewall rule. Use
`-ServiceName` on `scripts/Update-RunnerObservability.ps1` to include service
stop/start in a pinned release update and rollback. The scripts' local
contract tests do not claim that a real host, reboot, effective Firewall, or
production-ready decision has been observed; those facts belong to issue #6.

`--tls-cert`/`--tls-key` are optional, stdlib-`ssl`-only (no third-party
TLS dependency), and must be provided as a pair -- supplying only one is a
controlled, redacted error and the monitor never starts serving. A
certificate/key that cannot be loaded (missing file, malformed content, a
mismatched key) is also a controlled, redacted error; the configured path,
file contents, and the underlying `ssl`/`OSError` exception text are never
included in any diagnostic. See "Native TLS/HTTPS support" below and
`docs/runbook.md` for the full contract.

### Native TLS/HTTPS support (issue #7)

Before this ticket, `create_server()` always built a plain
`ThreadingHTTPServer` -- the "TLS certificate" preflight check below only
ever confirmed a cert *file* existed on disk, never that the Monitor Host
would actually use it to encrypt traffic. `create_server()` (and the
`serve --tls-cert`/`--tls-key` flags above) now wrap the server's
listening socket with a real `ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)`
when both are supplied, using only the Python 3.11 standard library `ssl`
module -- no third-party TLS/certificate dependency. Omitting both
arguments keeps today's plain-HTTP behavior completely unchanged, which is
what the full test suite and the Local Verification Gate below continue to
exercise. This closes the gap between PERS-04's original plan ("Monitor
Host 採 HTTPS/TLS") and what the code actually did.

## Local Verification Gate (issue #5)

`scripts/Invoke-VerificationGate.ps1` is a thin PowerShell wrapper around
`runner_observability.gate`, which (1) runs the complete unittest suite
above, (2) runs a set of isolated fault drills -- monitor restart-and-
recover, runner/job offline-then-recovery, and injected SQLite/cleanup/
notification failures -- each against its own fresh, throwaway temp-file
SQLite database, never any shared or named database file, and (3) writes a
redacted Markdown evidence report (`gate-report.md` by default; regenerated
per run and git-ignored, since its timestamp changes every time).

```powershell
./scripts/Invoke-VerificationGate.ps1
```

**This gate is 100% runner-independent.** It never opens a socket to a real
host, never assumes a Monitor Host or Runner A/B exists, and its report is
always stamped `status: not-ready`. Local drills passing is necessary but not
sufficient for production; it is not real-hardware, TLS/auth/firewall, or
real-workflow-acceptance evidence.

### Local Gate results (most recent observed local run)

```
## Automated gate (full local suite)
- result: PASS
- tests_run: 105
- failures: 0
- errors: 0

## Isolated fault drills
- monitor_restart_recovery: PASS
- offline_recovery: PASS
- sqlite_integrity_failure_isolated: PASS (integrity_check_failed)
- cleanup_failure_isolated: PASS (cleanup_failed)
- notification_failure_isolated: PASS

## Fail-open contract
- fail_open_contract: PASS

Overall local gate result: PASS (status remains `not-ready`)
```

This is a snapshot of one real local run's own output, copied here as
observed evidence; the authoritative, freshly timestamped report is always
regenerated by running the script above, not by trusting this copy.

### Known limitations

- No Monitor Host, Runner A, or Runner B deployment evidence exists yet.
- No real, trusted-CA TLS certificate issuance, authentication against a
  real endpoint, or real firewall configuration has been exercised. The
  monitor itself can now serve genuine HTTPS locally (issue #7, see
  "Native TLS/HTTPS support" above) -- what remains issue #6's job is
  issuing/trusting a real certificate and exercising it against real
  hardware, not the encryption mechanism itself.
- No real GitHub Actions workflow acceptance has been observed.
- This gate cannot and does not produce a production-ready decision.

### Handoff to issue #6 (HITL)

Issue #6 is the only place real-hardware deployment, TLS/auth/firewall
configuration, real-workflow acceptance, and the production-ready decision
may be recorded, using `docs/canary-evidence-template.md` as the evidence
skeleton. This repository's automated tests may validate that template's
document shape only; they never assert that its deployment/acceptance facts
occurred.

**Next operator action:** open issue #6 and run its HITL deployment and
acceptance checklist against a real Monitor Host, Runner A, and Runner B,
recording results directly in `docs/canary-evidence-template.md`.

## Local Deployment Simulation (issue #4 gap closure)

`scripts/Install-RunnerObservability.ps1`,
`scripts/Update-RunnerObservability.ps1`, and
`scripts/Invoke-RunnerPreflight.ps1` implement and exercise the
install/upgrade/rollback **contract** required by issue #4 (PERS-04)'s own
verification table: a pinned revision, a preflight check battery
(Python version, TLS certificate file presence -- optionally strengthened
into a real, local `SSLContext` load when `-TlsKeyPath` is also supplied,
see issue #7 -- auth credential file presence, firewall, Monitor Host
reachability), an atomic activation
switch, a post-activation smoke test, and automatic rollback to the
previous version on any failure. The substantive logic lives in
`src/runner_observability/deploy.py` (unit-tested in
`tests/test_deployment_docs.py`), with the PowerShell scripts as thin
orchestration -- the same split already used for the Local Verification
Gate's `gate.py` / `Invoke-VerificationGate.ps1`.

```powershell
./scripts/Invoke-RunnerPreflight.ps1 -TlsCertPath <path> -TlsKeyPath <path> -AuthTokenPath <path>
./scripts/Install-RunnerObservability.ps1 -Revision <rev> -Source <dir> -InstallRoot <dir>
./scripts/Update-RunnerObservability.ps1 -Revision <rev> -Source <dir> -InstallRoot <dir>
```

**This is 100% runner-independent local simulation**, proven against local
fixture directories and injected/mocked checks -- it never installs a real
Windows Service, never issues or trusts a real TLS certificate, never
configures a real firewall rule, and never opens a real network socket on
its own. The `-FirewallResult`/`-HostReachableResult` parameters only let
an operator pass through a result already determined out of band; omitting
them leaves those two checks unconfigured (fail-closed, not a silent real
network call). Full install/upgrade/rollback/first-triage instructions for
a different operator, without this ticket, are in `docs/runbook.md`. Real
Monitor Host / Runner A / Runner B deployment, real TLS/auth/firewall
configuration, and the production-ready decision remain issue #6 (HITL)'s
responsibility, exactly as for the Local Verification Gate above.
