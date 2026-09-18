<#
.SYNOPSIS
    Local deployment preflight checks (issue #4 gap; not issue #6 HITL).

.DESCRIPTION
    Thin Windows orchestration only -- all substantive logic lives in the
    Python `runner_observability.deploy` module so it stays unit-testable
    (see tests/test_deployment_docs.py). This script runs a fixed battery
    of checks -- Python version, TLS certificate file presence, auth
    credential file presence, firewall, and Monitor Host reachability --
    and prints only stable, actionable diagnostic reason codes. It never
    prints a configured certificate/token file's path or contents.

    This script never performs a real firewall lookup or a real network
    reachability probe on its own. `-FirewallResult` and
    `-HostReachableResult` let an operator (or a future, separately
    reviewed real-check script written for issue #6) pass through a result
    they already determined out of band; omitting them leaves those two
    checks unconfigured, which fails closed with a stable
    "*_not_configured" reason rather than silently reaching for a real
    socket or firewall API. See docs/runbook.md for the full diagnostic
    table and first-triage guidance.

.PARAMETER TlsCertPath
    Path to a TLS certificate file to confirm is present and non-empty.
    Its contents are never read or printed by this check.

.PARAMETER AuthTokenPath
    Path to an auth credential/token file to confirm is present and
    non-empty. Its contents are never read or printed by this check.

.PARAMETER FirewallResult
    "Pass" or "Fail", if you already know the outcome of a real firewall
    check performed elsewhere. Omit to leave this check unconfigured.

.PARAMETER HostReachableResult
    "Pass" or "Fail", if you already know the outcome of a real Monitor
    Host reachability check performed elsewhere. Omit to leave this check
    unconfigured.

.EXAMPLE
    ./scripts/Invoke-RunnerPreflight.ps1 -TlsCertPath "C:\path\to\cert.pem" -AuthTokenPath "C:\path\to\token.txt"
#>
[CmdletBinding()]
param(
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

Write-Host "Runner Observability preflight -- local checks only."
Write-Host "This run never contacts a real Monitor Host, TLS store, or firewall API on its own."

$pythonArgs = @("-m", "runner_observability.deploy", "preflight")
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
