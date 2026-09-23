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

## Monitor Host onboarding (Monitor first)

Validate the Monitor Host before configuring any Runner. Run the shared Step 0
inventory on the actual Monitor Host, compare it with `CONTEXT.md`, and then
use `scripts/Install-RunnerObservabilityMonitor.ps1`. The script performs its
own inventory gate before every action; `Preflight` and `-WhatIf` are
read-only.

### Step 0A -- confirm the Monitor address and ingest listener (Monitor Host)

Run this read-only check on the actual Monitor Host after the shared Step 0
inventory. It lists usable IPv4 addresses with their interfaces and gateways,
then confirms whether the Monitor is listening on TCP `8765`:

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

Choose the IPv4 address that the Runner can route to; do not choose loopback
(`127.0.0.1`), APIPA (`169.254.x.x`), or a disconnected interface. If the
Monitor has multiple usable addresses, confirm the correct one from the
Runner network. On the Runner, verify the selected value before configuring:

```powershell
$monitorIp = '<CONFIRMED_MONITOR_IP>'
Test-NetConnection -ComputerName $monitorIp -Port 8765
```

Use this confirmed value consistently for `-MonitorIp`, the endpoint, and the
optional `monitor-test.local` hosts mapping. Keep the Monitor firewall scope
(`-RunnerAddress`) based on the separately confirmed Runner IPv4 address. Do
not copy any placeholder address from this document.

### Clean Monitor reset and first installation

Use this reset only when intentionally discarding the Monitor's local
telemetry history and generated credentials. It is not the update procedure.
Run Step 0 first, compare the result with `CONTEXT.md`, and confirm that the
paths below are the inventory-confirmed paths. `Uninstall` removes only the
named service and its owned firewall rule; it preserves persistent files until
the operator explicitly removes them.

```powershell
$serviceName = 'RunnerObservabilityMonitor'
$config = 'C:\runner-observability\service-config.json'
$database = 'C:\runner-observability-data\monitor.sqlite'
$secretRoot = 'C:\runner-observability-secrets'
$ownedFiles = @(
    (Join-Path $secretRoot 'monitor-token.txt'),
    (Join-Path $secretRoot 'monitor.crt'),
    (Join-Path $secretRoot 'monitor.key'),
    $config,
    $database
)

.\scripts\Install-RunnerObservabilityMonitor.ps1 `
    -Action Uninstall -ServiceName $serviceName `
    -ConfigPath $config -DatabasePath $database -SecretRoot $secretRoot
.\scripts\Install-RunnerObservabilityMonitor.ps1 `
    -Action Status -ServiceName $serviceName `
    -ConfigPath $config -DatabasePath $database -SecretRoot $secretRoot

$existing = @($ownedFiles | Where-Object {
    Test-Path -LiteralPath $_ -PathType Leaf
})
if ($existing.Count -gt 0) {
    Write-Output 'The following exact Monitor-owned files will be permanently removed:'
    $existing | ForEach-Object { Write-Output "  $_" }
    $confirmation = Read-Host 'Type RESET to remove them'
    if ($confirmation -cne 'RESET') {
        throw 'Clean reset cancelled'
    }
    Remove-Item -LiteralPath $existing -Force
}

$remaining = @($ownedFiles | Where-Object {
    Test-Path -LiteralPath $_ -PathType Leaf
})
if ($remaining.Count -gt 0) {
    throw ('Clean reset incomplete: ' + ($remaining -join ', '))
}
```

Do not delete these files during a normal update: the database contains the
Monitor history, and the token/certificate pair must remain stable for the
Runner configuration. The next `Install` creates missing parent directories,
generates the token and self-signed certificate, and registers the service.

Choose exactly one certificate path below. Do not run both the operator-supplied
certificate path and the self-signed path during the same clean installation.

Use paired operator-supplied files for `PublicCa`, `PrivateCa`, or `Existing`:

```powershell
$python = 'C:\Python311\python.exe'
$config = 'C:\runner-observability\service-config.json'
$database = 'C:\runner-observability-data\monitor.sqlite'
$secretRoot = 'C:\runner-observability-secrets'
$token = Join-Path $secretRoot 'monitor-token.txt'
$cert = Join-Path $secretRoot 'monitor.crt'
$key = Join-Path $secretRoot 'monitor.key'
$runnerIp = '192.0.2.10' # replace with the inventory-confirmed Runner address

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

For an explicitly approved development/test certificate, choose `SelfSigned`
and `-AllowDevSelfSigned`. The script creates missing parent directories, then
uses Windows/.NET `CertificateRequest` with a 2048-bit RSA key when the modern
export APIs are available. On Windows PowerShell 5.1, where
`ExportPkcs8PrivateKey` is absent, it uses the Windows PKI
`New-SelfSignedCertificate` capability or the available RSA provider and the
same in-script PKCS#8 encoder. It writes the certificate as PEM and the
private key as PKCS#8 PEM; it never calls OpenSSL. It fails closed with
`certificate_generation_unavailable` only when neither Windows certificate
generation path is available, and does not start the service. A `monitor.key`
is never copied to a Runner.

For a self-signed clean installation, define the paths and run `Preflight`
before `Install`:

```powershell
$python = 'C:\Python311\python.exe'
$config = 'C:\runner-observability\service-config.json'
$database = 'C:\runner-observability-data\monitor.sqlite'
$secretRoot = 'C:\runner-observability-secrets'
$token = Join-Path $secretRoot 'monitor-token.txt'
$cert = Join-Path $secretRoot 'monitor.crt'
$key = Join-Path $secretRoot 'monitor.key'
$runnerIp = '192.0.2.10' # replace with the inventory-confirmed Runner address

.\scripts\Install-RunnerObservabilityMonitor.ps1 `
    -Action Preflight -PythonPath $python -ConfigPath $config `
    -DatabasePath $database -SecretRoot $secretRoot -TokenPath $token `
    -TlsCertPath $cert -TlsKeyPath $key -CertificateMode SelfSigned `
    -AllowDevSelfSigned -TrustSelfSignedCertificate `
    -RunnerAddress $runnerIp

.\scripts\Install-RunnerObservabilityMonitor.ps1 `
    -Action Install -PythonPath $python -ConfigPath $config `
    -DatabasePath $database -SecretRoot $secretRoot -TokenPath $token `
    -TlsCertPath $cert -TlsKeyPath $key -CertificateMode SelfSigned `
    -AllowDevSelfSigned -TrustSelfSignedCertificate `
    -RunnerAddress $runnerIp
```

`-TrustSelfSignedCertificate` is an explicit clean-install development/test
option. It imports only the generated public `monitor.crt` into
`Cert:\CurrentUser\Root`, so a browser running as the installing user can
trust the Dashboard certificate. It never imports or copies `monitor.key`.
Without this switch, the self-signed certificate is still generated and used
for HTTPS, but browsers will show a trust warning by design. Open the
Dashboard at `https://monitor-test.local:8765/`; the hostname must resolve to
the Monitor Host before opening the page. The switch is intentionally limited
to `SelfSigned` installs and is not a repair action for an existing install.

The token is generated into an atomically activated, ACL-protected file when
it is absent. It is never accepted as a parameter or placed in the service
command line; the service configuration uses a token file and the runtime
expands it to `--token-file`. Installation registers the service and leaves it
stopped until `Start` is requested, and scopes the fixed inbound firewall rule
to the supplied Runner addresses.

Use the same entry point for bounded lifecycle actions. `Uninstall` removes
only the named Monitor service and its owned firewall rule; it preserves the
token, certificate, key, config, database, and Runner data.

```powershell
.\scripts\Install-RunnerObservabilityMonitor.ps1 -Action RepairPermissions `
    -PythonPath $python -ConfigPath $config -DatabasePath $database `
    -SecretRoot $secretRoot -TokenPath $token -TlsCertPath $cert `
    -TlsKeyPath $key -RunnerAddress $runnerIp
.\scripts\Install-RunnerObservabilityMonitor.ps1 -Action Status `
    -ServiceName 'RunnerObservabilityMonitor' -ConfigPath $config `
    -DatabasePath $database -SecretRoot $secretRoot
.\scripts\Install-RunnerObservabilityMonitor.ps1 -Action Start `
    -ServiceName 'RunnerObservabilityMonitor' -ConfigPath $config `
    -DatabasePath $database -SecretRoot $secretRoot
.\scripts\Install-RunnerObservabilityMonitor.ps1 -Action Stop `
    -ServiceName 'RunnerObservabilityMonitor' -ConfigPath $config `
    -DatabasePath $database -SecretRoot $secretRoot
.\scripts\Install-RunnerObservabilityMonitor.ps1 -Action Restart `
    -ServiceName 'RunnerObservabilityMonitor' -ConfigPath $config `
    -DatabasePath $database -SecretRoot $secretRoot
.\scripts\Install-RunnerObservabilityMonitor.ps1 -Action Uninstall `
    -ServiceName 'RunnerObservabilityMonitor' -ConfigPath $config `
    -DatabasePath $database -SecretRoot $secretRoot
```

After a fresh install, start and verify the service explicitly:

```powershell
.\scripts\Install-RunnerObservabilityMonitor.ps1 `
    -Action Start -ServiceName 'RunnerObservabilityMonitor' `
    -ConfigPath $config -DatabasePath $database -SecretRoot $secretRoot
.\scripts\Install-RunnerObservabilityMonitor.ps1 `
    -Action Status -ServiceName 'RunnerObservabilityMonitor' `
    -ConfigPath $config -DatabasePath $database -SecretRoot $secretRoot
Get-NetTCPConnection -LocalPort 8765 -State Listen
curl.exe -k -i https://127.0.0.1:8765/api/health
```

Open the browser Dashboard at `https://monitor-test.local:8765/`, not the
numeric loopback URL. The hostname must resolve to the Monitor Host. With
`-TrustSelfSignedCertificate`, the browser running as the installing user can
trust the generated certificate.

### Monitor update and restart

For a Monitor Python package or static Dashboard update, first complete the
inventory and deploy the verified package using the package-deployment
procedure below. Then restart only the verified Monitor service:

```powershell
.\scripts\Install-RunnerObservabilityMonitor.ps1 `
    -Action Restart -ServiceName 'RunnerObservabilityMonitor' `
    -ConfigPath $config -DatabasePath $database -SecretRoot $secretRoot
.\scripts\Install-RunnerObservabilityMonitor.ps1 `
    -Action Status -ServiceName 'RunnerObservabilityMonitor' `
    -ConfigPath $config -DatabasePath $database -SecretRoot $secretRoot
Get-NetTCPConnection -LocalPort 8765 -State Listen
curl.exe -k -i https://127.0.0.1:8765/api/health
```

Restarting the Monitor is required after deploying Monitor Python or static
Dashboard files. A Dashboard-only Monitor update does not require a Runner
restart; refresh the browser after the Monitor returns to `running`.

After Monitor `Preflight`/install and a real Monitor service check, continue
with the Runner onboarding below. A passing local test suite is not live
deployment evidence; finish with one real CI job and dashboard association.

## Runner Host onboarding (after Monitor passes)

Transfer only `monitor-token.txt` and, for a private-CA/self-signed trust
model, the public `monitor.crt` to the Runner. Never transfer `monitor.key`.
Because the Monitor regenerated both files, any copies and trust entry from a
previous Monitor generation are stale; the rebuilt Runner must receive the
current pair through the approved secure transfer channel.

### Recommended one-command clean rebuild

After the Runner Step 0 inventory, run the wizard from the updated repository
checkout on the Runner from an elevated **Windows PowerShell as Administrator**
window. The secrets directory and machine service settings are intentionally
not readable/writable by an ordinary interactive shell. If this checkout needs
the latest script, update it first with the repository's normal
`git pull --ff-only` procedure. The wizard uses the checkout's current immutable
`HEAD`; it does not contain a hard-coded old revision:

```powershell
.\scripts\Initialize-RunnerObservabilityRunner.ps1 `
    -CleanRebuild -MonitorIp '192.168.24.141' `
    -CertificateTrustModel SelfSigned -AllowHostsChange
```

The wizard prints the selected `python_path` and executes `python --version`
before the reset confirmation. If it reports `python_execute_access_denied`,
do not repeat the reset with the same runtime. Use `-PythonPath` with an
inventory-confirmed executable that the interactive user can run and that can
also be granted read/execute access for the configured Heartbeat service
account, for example:

```powershell
.\scripts\Initialize-RunnerObservabilityRunner.ps1 `
    -CleanRebuild -PythonPath 'C:\path\to\approved\python.exe' `
    -MonitorIp '192.168.24.141' `
    -CertificateTrustModel SelfSigned -AllowHostsChange
```

The wizard does not silently switch to a per-user Python installation because
the Heartbeat service runs as `NT AUTHORITY\LocalService`; a runtime that works
for the interactive user can still be inaccessible to the service account.

Omit `-MonitorIp` to have the wizard ask for the confirmed Monitor IPv4
address. Run `-WhatIf` first if you want to inspect the planned flow without
changing the Runner. The wizard performs the following sequence:

1. read-only inventory and state gate;
2. Monitor TCP/8765 reachability check;
3. explicit `RESET-RUNNER` confirmation;
4. removal of the named Heartbeat service, managed install root, old token and
   public certificate, and the four observability machine environment values;
5. optional removal/recreation of the exact `monitor-test.local` hosts mapping
   when `-AllowHostsChange` is supplied;
6. a pause with `status=WAITING_FOR_MONITOR_FILES` so the operator can use the
   approved remote-control channel to place `monitor-token.txt` and
   `monitor.crt` in the displayed secret directory;
7. current-HEAD release staging, import smoke test, Runner `Preflight`,
   `Configure`, and Heartbeat `Start`.

The wizard removes the confirmed managed install root with the Windows native
directory removal primitive because PowerShell `Remove-Item -Recurse -Force`
can report `Access is denied` for this tree even when Windows can remove it.
If the native delete is blocked by ACLs left by a previous service/runtime
attempt, the wizard repairs ownership and grants Administrators full control on
that exact install root only, then retries the native delete. It refuses
reparse-point install roots and never applies this repair to `C:\actions-runner`,
the source checkout, or the secrets directory.

The wizard never copies files between hosts, reads or prints the token,
accepts `monitor.key`, removes `C:\actions-runner`, unregisters the GitHub
Actions Runner, or deletes the source checkout. For a self-signed/private-CA
certificate it prints only the public SHA-256 fingerprint and requires the
operator to type `TRUST-CERTIFICATE` after verifying it against the Monitor.
If it reports `status=BLOCKED reason=administrator_required`, close that
window and rerun from an elevated PowerShell; do not weaken the secret-folder
ACL. `secret_inventory_access_denied` means the elevated shell still cannot
inspect the exact secret directory and requires ACL repair before continuing.
If an old matching LocalMachine trust entry is found, it requires the separate
`REMOVE-OLD-MONITOR-CERT` confirmation before removing that exact certificate.
The final `status=OK` means the observability agent and Heartbeat service are
ready; the existing direct `Runner.Listener.exe` launch is reported as
`runner_listener_restart=manual_required`. Restart that verified listener once,
then run one real CI job and confirm the Dashboard shows the physical Runner
as active.

The wizard clears stale PowerShell child-process exit state before each
delegated lifecycle action, so a successful `reason=uninstall_completed` or
`reason=configure_completed` result is not misreported because of an earlier
native command.

The detailed blocks below remain the low-level fallback for troubleshooting or
for machines whose paths differ from the standard conventions.

### Step 1 -- after the full-clean reset, transfer the current pair from the Monitor

For the explicit full-clean acceptance below, do not run this transfer block
until `Full-clean Runner reset` has completed. That reset removes the old
Runner token/certificate pair; transfer the newly generated current pair only
after the reset has finished. For a normal new install, Step 0 still remains
mandatory before this transfer.

The Monitor administrator can perform this transfer without displaying or
reading the token value. Run the following from an elevated PowerShell on the
Monitor, after Step 0 confirms the exact source and Runner paths. The `C$`
administrative share is only an example; replace it with the confirmed Runner
drive/share, and do not use a public or broadly shared directory:

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

This copies only the public certificate and token file. It does not put the
token in a command-line argument or output. If the transfer reports `Access
Denied` even in the elevated Monitor shell, inspect the ACLs of these two
exact source files only. When they belong to this deployment, the existing
Monitor permission repair can restore the intended `Administrators` and
service-account access without printing file contents:

```powershell
.\scripts\Install-RunnerObservabilityMonitor.ps1 `
    -Action RepairPermissions -PythonPath $python -ConfigPath $config `
    -DatabasePath $database -SecretRoot $monitorSecretRoot `
    -TokenPath (Join-Path $monitorSecretRoot 'monitor-token.txt') `
    -TlsCertPath (Join-Path $monitorSecretRoot 'monitor.crt') `
    -TlsKeyPath (Join-Path $monitorSecretRoot 'monitor.key')
```

Run this only with the inventory-confirmed Monitor paths. Do not grant
`Everyone`, do not recursively open the secrets directory, and do not copy
`monitor.key`. If the ACL is not deployment-owned, stop and use the
organization's exact-file ACL recovery process instead.

For the full-clean acceptance, the required order is Step 0 inventory, Monitor
IP/listener confirmation, full-clean Runner reset, current certificate/token
transfer and host resolution, release staging, identity/CI ACL setup, Runner
`Preflight`, Runner `Configure`, Heartbeat start, Runner listener restart, and
one real CI job. Do not run
`Preflight` or `Configure` before Step 2 has created a valid active release;
the entry point rejects that state and the service launcher uses that release's
`src` directory.

For this acceptance, use the explicit full-clean Runner reset below. First
stop the verified Runner listener using its actual launch method, then remove
the named Heartbeat service:

```powershell
$runnerScript = '.\scripts\Install-RunnerObservabilityRunner.ps1'
$installRoot = 'C:\runner-observability-agent'
$token = 'C:\runner-observability-secrets\monitor-token.txt'

& $runnerScript -Action Uninstall -InstallRoot $installRoot -TokenPath $token `
    -ServiceName 'RunnerObservabilityHeartbeat'
& $runnerScript -Action Status -InstallRoot $installRoot -TokenPath $token `
    -ServiceName 'RunnerObservabilityHeartbeat'
```

`Uninstall` stops and deletes only the verified SCM service. For this full-clean
test, continue with the reset below; do not treat `Uninstall` alone as a clean
environment.

### Full-clean Runner reset (destructive; Step 0 is mandatory)

Run this only after the actual Runner Step 0 output confirms the exact machine,
account, install root, secret root, service name, and current release. Pull the
updated repository checkout before using the scripts, but do not delete the
checkout itself. The reset removes only deployment-owned Runner files and
settings:

```powershell
$installRoot = 'C:\runner-observability-agent'       # Step 0 confirmed
$secretRoot = 'C:\runner-observability-secrets'     # Step 0 confirmed
$serviceName = 'RunnerObservabilityHeartbeat'       # Step 0 confirmed
$runnerScript = '.\scripts\Install-RunnerObservabilityRunner.ps1'

if (-not (Test-Path -LiteralPath $installRoot -PathType Container)) {
    throw 'The confirmed install root is absent; do not broaden the reset scope'
}
if (Test-Path -LiteralPath (Join-Path $secretRoot 'monitor.key') -PathType Leaf) {
    throw 'Unexpected monitor.key on a Runner; stop and investigate before reset'
}

& $runnerScript -Action Uninstall -InstallRoot $installRoot `
    -TokenPath (Join-Path $secretRoot 'monitor-token.txt') `
    -ServiceName $serviceName
& $runnerScript -Action Status -InstallRoot $installRoot `
    -TokenPath (Join-Path $secretRoot 'monitor-token.txt') `
    -ServiceName $serviceName
```

Before deleting the remaining files, inspect the exact owned paths and the
`monitor-test.local` hosts entry. If the hosts entry or a certificate trust
entry is shared with another purpose, stop and keep it. Remove a hosts entry
only when the inventory proves this deployment created it; remove a trusted
certificate only by its independently confirmed SHA-256 fingerprint.

If the old public certificate was imported into `Cert:\LocalMachine\Root`,
identify its thumbprint before deleting the old certificate file. The
fingerprint is public metadata; never print the token or private key:

```powershell
$python = 'C:\Python311\python.exe' # inventory-confirmed Python
$oldCert = Join-Path $secretRoot 'monitor.crt'
if (Test-Path -LiteralPath $oldCert -PathType Leaf) {
    $oldThumbprint = (& $python -c "import base64,hashlib,ssl,pathlib; der=base64.b64decode(ssl.PEM_cert_to_DER_cert(pathlib.Path(r'$oldCert').read_text())); print(hashlib.sha1(der).hexdigest().upper())").Trim()
    Get-ChildItem -Path 'Cert:\LocalMachine\Root' |
        Where-Object { $_.Thumbprint -eq $oldThumbprint } |
        Select-Object Subject, Thumbprint, NotAfter
    $removeTrust = Read-Host 'Type REMOVE-OLD-MONITOR-CERT only if this exact entry belongs to the old Monitor cert'
    if ($removeTrust -ceq 'REMOVE-OLD-MONITOR-CERT') {
        Get-ChildItem -Path 'Cert:\LocalMachine\Root' |
            Where-Object { $_.Thumbprint -eq $oldThumbprint } |
            Remove-Item -Force
    }
}
```

Also remove the old `monitor-test.local` hosts mapping only after reviewing
the matching line and confirming it was created for this deployment. Leave a
conflicting or shared mapping in place and resolve it with the Monitor Host
operator; Step 1A will add or validate the mapping for the new certificate.

After that review, use an explicit confirmation and remove only the exact
deployment paths. This does not remove `C:\actions-runner`, the Runner
registration, the source checkout, unrelated secrets, or a global Python
installation:

```powershell
$ownedFiles = @(
    (Join-Path $installRoot 'current-release.txt'),
    (Join-Path $installRoot 'runner-id.txt'),
    (Join-Path $installRoot 'heartbeat-config.json'),
    (Join-Path $installRoot 'state\heartbeat.json'),
    (Join-Path $secretRoot 'monitor-token.txt'),
    (Join-Path $secretRoot 'monitor.crt')
)
$confirmation = Read-Host 'Type RESET-RUNNER to remove the listed deployment files and install root'
if ($confirmation -cne 'RESET-RUNNER') {
    throw 'Runner reset cancelled'
}

Remove-Item -LiteralPath $installRoot -Recurse -Force
foreach ($path in @($ownedFiles | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf })) {
    Remove-Item -LiteralPath $path -Force
}

foreach ($name in @(
    'RUNNER_OBSERVABILITY_INSTALL_ROOT',
    'RUNNER_OBSERVABILITY_ENDPOINT',
    'RUNNER_OBSERVABILITY_TOKEN_PATH',
    'RUNNER_OBSERVABILITY_RUNNER_ID'
)) {
    [Environment]::SetEnvironmentVariable($name, $null, 'Machine')
}
```

The `Remove-Item $installRoot` operation is intentionally limited to the
inventory-confirmed managed root. The later per-file loop cleans the token and
public certificate without deleting other files in a shared secret directory;
if the secret directory contains unrelated files, leave the directory itself
in place. Verify the service is absent, the exact deployment files are absent,
the old trust entry is gone when it was deployment-owned, and the four machine
variables are empty before beginning Step 1 again. Step 1 must then copy the
new Monitor token and public certificate; do not reuse the old pair.

For `PrivateCa` or `SelfSigned`, pass only the public certificate and the
operator-confirmed SHA-256 fingerprint; `-ImportCertificate` verifies that
fingerprint before touching the Windows trust store. `-AllowHostsChange` is a
separate explicit gate and preserves unrelated hosts entries. If the token
file is absent, `Configure` prompts using `Read-Host -AsSecureString` and
creates an ACL-protected file. The token value is never a parameter or
service argument, and `monitor.key` is rejected on a Runner.

Use the Runner entry point for lifecycle and repair actions. `Uninstall`
removes only the named Heartbeat service and preserves persistent data:

```powershell
.\scripts\Install-RunnerObservabilityRunner.ps1 -Action RepairPermissions -InstallRoot $installRoot -TokenPath $token
.\scripts\Install-RunnerObservabilityRunner.ps1 -Action Status -ServiceName 'RunnerObservabilityHeartbeat'
.\scripts\Install-RunnerObservabilityRunner.ps1 -Action Start -ServiceName 'RunnerObservabilityHeartbeat'
.\scripts\Install-RunnerObservabilityRunner.ps1 -Action Stop -ServiceName 'RunnerObservabilityHeartbeat'
.\scripts\Install-RunnerObservabilityRunner.ps1 -Action Restart -ServiceName 'RunnerObservabilityHeartbeat'
.\scripts\Install-RunnerObservabilityRunner.ps1 -Action Uninstall -ServiceName 'RunnerObservabilityHeartbeat'
```

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

`monitor.key` is the Monitor's private key and stays on the Monitor Host. The
Monitor administrator must use the elevated transfer procedure in the Runner
Host onboarding section to copy `monitor-token.txt` and, when required,
`monitor.crt`; that operation does not display the token value. Never copy the
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

The Monitor administrator transfer above should already have placed the token
and, when required by the trust model, the public certificate in the confirmed
Runner path. Verify existence without displaying the token:

```powershell
$secretRoot = 'C:\runner-observability-secrets'
$tokenPath = Join-Path $secretRoot 'monitor-token.txt'
$token = Get-Item -LiteralPath $tokenPath -Force
Write-Output "token.exists=$($token.Exists) length=$($token.Length)"
if (Test-Path -LiteralPath (Join-Path $secretRoot 'monitor.key') -PathType Leaf) {
    throw 'Unexpected monitor.key on Runner; remove it only after investigation'
}
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
$revision = '4e4642900b188e0c9eacb4bc188401db0999b022' # approved Runner release; use the chosen immutable revision

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
if (-not (Test-Path -LiteralPath (Join-Path $sourceSrc 'runner_heartbeat_service.py') -PathType Leaf)) {
    throw 'Source checkout does not contain the Runner heartbeat launcher'
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

### Step 3 -- preflight, configure, and register the Heartbeat service

The endpoint must contain the real Monitor host and use `/v1/events` when it
is passed to this entry point. `Preflight` is read-only. `Configure` then
atomically writes the Heartbeat config, applies the service/token/state ACLs,
persists the machine environment values, and registers the service stopped;
it does not start the service.

```powershell
$python = 'C:\Python311\python.exe' # inventory-confirmed Python
$installRoot = 'C:\runner-observability-agent'
$endpoint = 'https://monitor-test.local:8765/v1/events'
$token = 'C:\runner-observability-secrets\monitor-token.txt'
$monitorIp = '192.0.2.20' # inventory-confirmed Monitor IPv4 address

& .\scripts\Install-RunnerObservabilityRunner.ps1 `
    -Action Preflight -PythonPath $python -InstallRoot $installRoot `
    -Endpoint $endpoint -TokenPath $token -MonitorHost 'monitor-test.local' `
    -MonitorIp $monitorIp -CertificateTrustModel PublicCa

& .\scripts\Install-RunnerObservabilityRunner.ps1 `
    -Action Configure -PythonPath $python -InstallRoot $installRoot `
    -Endpoint $endpoint -TokenPath $token -MonitorHost 'monitor-test.local' `
    -MonitorIp $monitorIp -CertificateTrustModel PublicCa
```

The selected Python must be able to import the managed release and the
Windows-service runtime (`pywin32`) without relying on the interactive user's
site-packages. If Preflight reports
`windows_service_runtime_unavailable`, install the optional Windows-service
dependency into the inventory-confirmed machine runtime, then rerun
Preflight; do not start a service that has not passed it.

For `PrivateCa` or `SelfSigned`, add `-MonitorCertificatePath`, the
independently confirmed `-ExpectedCertificateSha256`, and `-ImportCertificate`.
For a hosts-file mapping, add `-AllowHostsChange` only after inspecting the
existing `monitor-test.local` line.

Do not set `RUNNER_OBSERVABILITY_RUNNER_ID` manually during a normal install;
`Configure` persists the stable value created or verified in `runner-id.txt`.
If this is a cloned machine image, deliberately supply a new machine-specific
UUID through the supported override only after confirming the clone boundary.

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

The token directory receives only traverse (`X`) access for `LocalService`,
while `monitor-token.txt` receives read (`R`) access. The service account does
not receive write access to the secrets directory and never receives access to
`monitor.key`.

During `Configure`, the Runner installer also grants and verifies read/execute
access on the exact Python executable and the managed
`runner_heartbeat_service.py` launcher. This exact-file check is intentional:
`icacls /T /C` can continue after an individual protected file fails, which
would otherwise leave service registration looking successful until `sc.exe
start` returns `Access is denied`. A failure is reported as
`runtime_acl_failed`; stop and repair or replace the confirmed Python runtime
before retrying. Do not grant `LocalService` write or full-control access to
the Python installation.

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

The `Configure` action registers the service but does not start it. Start and
verify it explicitly with the Runner entry point:

```powershell
./scripts/Install-RunnerObservabilityRunner.ps1 -Action Start
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

### Monitor Host package deployment (Windows service model)

The currently verified Monitor Host runs `RunnerObservabilityMonitor` as
`NT AUTHORITY\LocalService`. Its service command imports the package from the
Python installation's global `site-packages` directory. This is a different
deployment model from the managed Runner release layout described in
"Existing Runner update and component restart rules" above.

Before changing anything, run the Step 0 inventory and confirm the actual
Python path, global `site-packages` path, service name, service account, and
service command on the target machine. Use the procedure below only when the
inventory confirms this same global-package service model. Do not print the
token, private key, or certificate contents.

The repository root is not necessarily a clean build input. An old
`build\lib` tree can contain older dashboard assets, and setuptools may reuse
those files when pip builds directly from the working tree. Never deploy with
`--user`: the service runs as `LocalService` and does not use the interactive
user's site-packages directory. Do not rerun the first-install service script
when the service already exists.

Run the following from an elevated PowerShell window. It creates a temporary
release copy that excludes generated build output, installs that copy into the
verified global package directory, restores the package read permission needed
by `LocalService`, verifies the deployed dashboard asset, and then restarts
only the verified service:

```powershell
$source = 'C:\Users\<user>\Desktop\runner-observability'
$python = 'C:\Users\<user>\AppData\Local\Programs\Python\Python311\python.exe'
$globalSite = 'C:\Users\<user>\AppData\Local\Programs\Python\Python311\Lib\site-packages'
$serviceName = 'RunnerObservabilityMonitor'

# Read-only target checks. Stop if any path or service differs from inventory.
if (-not (Test-Path -LiteralPath (Join-Path $source 'pyproject.toml'))) {
    throw 'Repository source or pyproject.toml was not found'
}
if (-not (Test-Path -LiteralPath $python)) {
    throw 'Verified Python executable was not found'
}
$service = Get-CimInstance Win32_Service -Filter "Name='$serviceName'"
if ($null -eq $service) {
    throw "Verified service '$serviceName' was not found"
}
if ($service.StartName -ne 'NT AUTHORITY\LocalService') {
    throw "Unexpected service account: $($service.StartName)"
}

$clean = Join-Path $env:TEMP ('runner-observability-release-' + [guid]::NewGuid().ToString('N'))
$exclude = @(
    (Join-Path $source '.git')
    (Join-Path $source 'build')
    (Join-Path $source 'src\runner_observability.egg-info')
)
New-Item -ItemType Directory -Path $clean -Force | Out-Null
& robocopy.exe $source $clean /E /XD $exclude /NFL /NDL /NJH /NJS /NP | Out-Null
if ($LASTEXITCODE -gt 7) {
    throw "Clean release copy failed with robocopy exit code $LASTEXITCODE"
}

$sourceAsset = Join-Path $source 'src\runner_observability\static\app.js'
$cleanAsset = Join-Path $clean 'src\runner_observability\static\app.js'
if (-not (Test-Path -LiteralPath $cleanAsset)) {
    throw 'Clean release copy is missing the dashboard asset'
}

& $python -m pip install --upgrade --force-reinstall --no-cache-dir --no-deps --target $globalSite $clean
if ($LASTEXITCODE -ne 0) {
    throw 'Monitor package deployment failed'
}

$packageRoot = Join-Path $globalSite 'runner_observability'
& icacls.exe $packageRoot /grant 'NT AUTHORITY\LOCAL SERVICE:(OI)(CI)(RX)' /T /C
if ($LASTEXITCODE -ne 0) {
    throw 'Monitor package ACL update failed'
}

$installedAsset = Join-Path $packageRoot 'static\app.js'
$sourceHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $sourceAsset).Hash
$cleanHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $cleanAsset).Hash
$installedHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $installedAsset).Hash
if (($sourceHash -ne $cleanHash) -or ($sourceHash -ne $installedHash)) {
    throw 'Installed monitor dashboard asset does not match the source asset'
}
& $python -s -c "import runner_observability; print(runner_observability.__file__)"
if ($LASTEXITCODE -ne 0) {
    throw 'Installed monitor package import failed'
}

Restart-Service -Name $serviceName
Start-Sleep -Seconds 5
$serviceStatus = Get-Service -Name $serviceName
if ($serviceStatus.Status -ne 'Running') {
    throw "Monitor service is not running: $($serviceStatus.Status)"
}
$listener = @(Get-NetTCPConnection -LocalPort 8765 -State Listen -ErrorAction SilentlyContinue)
if ($listener.Count -eq 0) {
    throw 'Monitor is not listening on port 8765'
}
$serviceStatus
$listener |
    Select-Object LocalAddress, LocalPort, State
```

The `pip` success message alone is not sufficient: it only proves that a
wheel was built and copied. The hash check proves that the deployed dashboard
asset came from the intended source, and the `icacls` step is required because
an installation into `site-packages` can replace the package directory's ACL.
If the service still fails to start, stop retrying and inspect the package ACL,
the installed asset hash, and the recent `RunnerObservabilityMonitor` and
Service Control Manager events. Do not change the token/key/configuration or
delete database rows as a first diagnostic step.

After the service is listening, open the dashboard and confirm that the
`Auto-refresh: on`, `Pause auto-refresh`, and `Last updated` controls are
visible and changing. A dashboard-only deployment does not require a Runner
restart. The temporary clean copy may be removed after verification with its
exact generated path, for example:

```powershell
Remove-Item -LiteralPath $clean -Recurse -Force
```

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
