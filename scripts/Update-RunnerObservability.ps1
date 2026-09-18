<#
.SYNOPSIS
    Upgrade an existing install to a new pinned revision, with automatic
    rollback on failure (issue #4 gap; not issue #6 HITL).

.DESCRIPTION
    Thin Windows orchestration only -- all substantive logic lives in the
    Python `runner_observability.deploy` module so it stays unit-testable
    (see tests/test_deployment_docs.py). Same sequence as
    Install-RunnerObservability.ps1 (preflight -> stage -> atomically
    activate -> smoke test), with one difference: because a previous
    revision is already active in -InstallRoot, any failure -- preflight
    or the post-activation smoke test -- automatically restores that
    previous revision as active. `current-release.txt` is left reading the
    old revision, unchanged, and the script prints only the stable failure
    reason. This is repeatable: re-running a still-failing update reaches
    the same safe "previous version still active" state every time.

    This script never installs a real Windows Service, never issues or
    trusts a real TLS certificate, never configures a real firewall rule,
    and never deploys to a real Monitor Host, Runner A, or Runner B --
    those are issue #6 (HITL) responsibilities. See docs/runbook.md.

.PARAMETER Revision
    The pinned revision identifier to upgrade to (e.g. "1.1.0" or a commit
    hash). Never a floating reference like "latest".

.PARAMETER Source
    Local directory containing the built files for -Revision.

.PARAMETER InstallRoot
    The same directory passed to Install-RunnerObservability.ps1 for this
    install.

.PARAMETER TlsCertPath
    See Invoke-RunnerPreflight.ps1.

.PARAMETER AuthTokenPath
    See Invoke-RunnerPreflight.ps1.

.PARAMETER FirewallResult
    See Invoke-RunnerPreflight.ps1.

.PARAMETER HostReachableResult
    See Invoke-RunnerPreflight.ps1.

.EXAMPLE
    ./scripts/Update-RunnerObservability.ps1 -Revision "1.1.0" -Source "C:\path\to\built\1.1.0" -InstallRoot "C:\runner-observability"

.EXAMPLE
    # Manual rollback to an earlier, still-staged revision:
    ./scripts/Update-RunnerObservability.ps1 -Revision "1.0.0" -Source "C:\path\to\built\1.0.0" -InstallRoot "C:\runner-observability"
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

Write-Host "Update-RunnerObservability -- local upgrade simulation contract."
Write-Host "A failed preflight or smoke test automatically retains the previous version."
Write-Host "Real Monitor Host / Runner A / Runner B deployment is issue #6's responsibility."

$pythonArgs = @(
    "-m", "runner_observability.deploy", "update",
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
