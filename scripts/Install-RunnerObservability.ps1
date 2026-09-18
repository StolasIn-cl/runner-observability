<#
.SYNOPSIS
    First-time install of a pinned revision (issue #4 gap; not issue #6 HITL).

.DESCRIPTION
    Thin Windows orchestration only -- all substantive logic (revision
    validation, preflight, staging, atomic activation, smoke test,
    rollback) lives in the Python `runner_observability.deploy` module so
    it stays unit-testable (see tests/test_deployment_docs.py). This
    script:

      1. Runs the same preflight battery as Invoke-RunnerPreflight.ps1.
         If any check fails, nothing is written under -InstallRoot.
      2. Stages the given -Revision's files (copied from -Source) under
         `<InstallRoot>\releases\<Revision>\`.
      3. Atomically activates it (`current-release.txt` swapped in with a
         single same-directory rename -- never a partial write).
      4. Runs a local smoke test: invokes the newly staged release's own
         CLI entrypoint (`python -m runner_observability --help`) to
         confirm it imports and runs. This does not start a real Windows
         Service and does not open any socket.
      5. If the smoke test fails, this being a first install means there
         is no previous revision to restore, so the activation pointer is
         removed and the install ends in a clean "nothing active" state.

    This script never installs a real Windows Service, never issues or
    trusts a real TLS certificate, never configures a real firewall rule,
    and never deploys to a real Monitor Host, Runner A, or Runner B --
    those are issue #6 (HITL) responsibilities. See docs/runbook.md.

.PARAMETER Revision
    The pinned revision identifier to install (e.g. "1.0.0" or a commit
    hash). Never a floating reference like "latest".

.PARAMETER Source
    Local directory containing the built files for -Revision.

.PARAMETER InstallRoot
    Local directory this script owns and manages (releases + activation
    pointer). Should not contain unrelated content.

.PARAMETER TlsCertPath
    See Invoke-RunnerPreflight.ps1.

.PARAMETER AuthTokenPath
    See Invoke-RunnerPreflight.ps1.

.PARAMETER FirewallResult
    See Invoke-RunnerPreflight.ps1.

.PARAMETER HostReachableResult
    See Invoke-RunnerPreflight.ps1.

.EXAMPLE
    ./scripts/Install-RunnerObservability.ps1 -Revision "1.0.0" -Source "C:\path\to\built\1.0.0" -InstallRoot "C:\runner-observability"
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Revision,
    [Parameter(Mandatory = $true)]
    [string]$Source,
    [Parameter(Mandatory = $true)]
    [string]$InstallRoot,
    [string]$TlsCertPath = "",
    [string]$AuthTokenPath = "",
    [ValidateSet("Pass", "Fail")]
    [string]$FirewallResult = "",
    [ValidateSet("Pass", "Fail")]
    [string]$HostReachableResult = ""
)

$ErrorActionPreference = "Stop"

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")

$pythonCommand = Get-Command python -ErrorAction SilentlyContinue
if (-not $pythonCommand) {
    $pythonCommand = Get-Command py -ErrorAction SilentlyContinue
}
if (-not $pythonCommand) {
    Write-Host "No Python interpreter found on PATH. Install Python 3.11+ and re-run." -ForegroundColor Red
    exit 2
}

Write-Host "Install-RunnerObservability -- local install simulation contract."
Write-Host "This does not install a real Windows Service, TLS certificate, or firewall rule."
Write-Host "Real Monitor Host / Runner A / Runner B deployment is issue #6's responsibility."

$pythonArgs = @(
    "-m", "runner_observability.deploy", "install",
    "--revision", $Revision,
    "--source", $Source,
    "--install-root", $InstallRoot
)
if (-not [string]::IsNullOrWhiteSpace($TlsCertPath)) {
    $pythonArgs += @("--tls-cert-path", $TlsCertPath)
}
if (-not [string]::IsNullOrWhiteSpace($AuthTokenPath)) {
    $pythonArgs += @("--auth-token-path", $AuthTokenPath)
}
if ($FirewallResult) {
    $pythonArgs += @("--firewall-result", $FirewallResult.ToLowerInvariant())
}
if ($HostReachableResult) {
    $pythonArgs += @("--host-reachable-result", $HostReachableResult.ToLowerInvariant())
}

$hadPreviousPythonPath = Test-Path Env:PYTHONPATH
$previousPythonPath = $env:PYTHONPATH
try {
    $env:PYTHONPATH = Join-Path $repoRoot "src"
    & $pythonCommand.Source @pythonArgs
    $exitCode = $LASTEXITCODE
}
finally {
    if ($hadPreviousPythonPath) {
        $env:PYTHONPATH = $previousPythonPath
    }
    else {
        Remove-Item Env:PYTHONPATH -ErrorAction SilentlyContinue
    }
}

exit $exitCode
