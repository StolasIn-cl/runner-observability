<#
.SYNOPSIS
    Local Verification Gate for issue #5 (runner-independent, local-only).

.DESCRIPTION
    Thin Windows orchestration only -- all substantive logic lives in the
    Python `runner_observability.gate` module so it stays unit-testable
    (see tests/test_gate.py). This script:

      1. Locates a Python interpreter on PATH (the child process itself
         re-invokes via `sys.executable`, so the interpreter this script
         finds only needs to be Python 3, not necessarily 3.11+).
      2. Points PYTHONPATH at this repository's `src` layout (the package is
         not installed; this matches the README's existing test instructions).
      3. Runs `python -m runner_observability.gate`, which in turn (a) runs
         the complete existing unittest suite, (b) runs every isolated fault
         drill against its own fresh throwaway SQLite database, and (c)
         writes a redacted Markdown evidence report.
      4. Displays that report and exits with the gate's own exit code.

    Crash safety: `runner_observability.gate` deletes any pre-existing
    report before it does anything else, and always writes a fresh report
    (a normal PASS/FAIL one, or -- if the run could not complete -- a
    report explicitly marked CRASHED) before it returns. This script adds a
    second, independent check on top of that: it records the time just
    before invoking Python and refuses to display any report whose
    last-write time is not at or after that moment, so a bug in the Python
    side (or an even harder failure, such as the interpreter itself being
    killed) can never make this script show a stale prior run's report as
    if it were this run's evidence.

    This script never contacts a real runner, Monitor Host, or GitHub API,
    never installs a Windows service, and never claims production readiness.
    The evidence it produces is always stamped `not-ready`; only issue #6's
    HITL acceptance evidence (docs/canary-evidence-template.md) can change
    that decision.

.PARAMETER ReportPath
    Where to write the redacted Markdown evidence report. Defaults to
    `gate-report.md` at the repository root.

.EXAMPLE
    ./scripts/Invoke-VerificationGate.ps1
#>
[CmdletBinding()]
param(
    [string]$ReportPath = ""
)

$ErrorActionPreference = "Stop"

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
if ([string]::IsNullOrWhiteSpace($ReportPath)) {
    $ReportPath = Join-Path $repoRoot "gate-report.md"
}

$pythonCommand = Get-Command python -ErrorAction SilentlyContinue
if (-not $pythonCommand) {
    $pythonCommand = Get-Command py -ErrorAction SilentlyContinue
}
if (-not $pythonCommand) {
    # Write-Host, not Write-Error: with $ErrorActionPreference = "Stop",
    # Write-Error is itself terminating and would skip the explicit `exit 2`
    # below, silently falling back to PowerShell's default error exit code.
    Write-Host "No Python interpreter found on PATH. Install Python 3.11+ and re-run." -ForegroundColor Red
    exit 2
}

Write-Host "Local Verification Gate (issue #5) -- runner-independent, local-only."
Write-Host "This run never contacts a real runner, Monitor Host, or GitHub API."

$invocationStart = Get-Date

# The package is not installed (see README); point the child Python process
# at the src/ layout the same way the documented test command does. Only
# restore PYTHONPATH afterward if it was actually set beforehand -- setting
# it to an empty string when it was previously unset would put the current
# directory on sys.path for later commands in this shell session.
$hadPreviousPythonPath = Test-Path Env:PYTHONPATH
$previousPythonPath = $env:PYTHONPATH
try {
    $env:PYTHONPATH = Join-Path $repoRoot "src"
    & $pythonCommand.Source -m runner_observability.gate --repo-root "$repoRoot" --report-path "$ReportPath"
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

if (Test-Path -LiteralPath $ReportPath) {
    $reportInfo = Get-Item -LiteralPath $ReportPath
    if ($reportInfo.LastWriteTime -lt $invocationStart) {
        # Belt-and-suspenders: runner_observability.gate already deletes any
        # pre-existing report before doing anything else, so this should be
        # unreachable in practice -- but if it ever is reached, never show a
        # stale prior run's report as if it were this run's evidence.
        Write-Warning "gate-report.md predates this run; not displaying it as this run's evidence."
        if ($exitCode -eq 0) {
            $exitCode = 1
        }
    }
    else {
        Write-Host ""
        Write-Host "----- Evidence report -----"
        Get-Content -LiteralPath $ReportPath | Write-Host
        Write-Host "----------------------------"
    }
}
else {
    Write-Warning "No evidence report was produced at the expected path."
    if ($exitCode -eq 0) {
        $exitCode = 1
    }
}

exit $exitCode
