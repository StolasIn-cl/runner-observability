$script:RunnerObservabilityFirewallRuleName = "Runner Observability Monitor TCP 8765"

function Invoke-RunnerObservabilityNativeCommand {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $false)][string[]]$ArgumentList = @()
    )

    try {
        $output = & $FilePath @ArgumentList 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw [System.InvalidOperationException]::new("service_command_failed")
        }
        return @($output)
    }
    catch {
        throw [System.InvalidOperationException]::new("service_command_failed")
    }
}

function Write-RunnerObservabilityConfigAtomic {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][hashtable]$Configuration
    )

    $parent = Split-Path -Parent $Path
    if (-not $parent) {
        $parent = (Get-Location).Path
    }
    New-Item -ItemType Directory -Path $parent -Force | Out-Null
    $temporaryPath = Join-Path $parent ("." + (Split-Path -Leaf $Path) + "." + $PID + ".tmp")
    try {
        $json = $Configuration | ConvertTo-Json -Depth 5
        [System.IO.File]::WriteAllText($temporaryPath, $json, [System.Text.UTF8Encoding]::new($false))
        if (Test-Path -LiteralPath $Path -PathType Leaf) {
            [System.IO.File]::Replace($temporaryPath, $Path, $null)
        }
        else {
            [System.IO.File]::Move($temporaryPath, $Path)
        }
    }
    catch {
        throw [System.InvalidOperationException]::new("service_config_write_failed")
    }
    finally {
        if (Test-Path -LiteralPath $temporaryPath -PathType Leaf) {
            Remove-Item -LiteralPath $temporaryPath -Force -ErrorAction SilentlyContinue
        }
    }
}

function Set-RunnerObservabilityFileAcl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$ServiceAccount,
        [ValidateSet("R", "M")][string]$Access = "R"
    )

    $serviceGrant = "{0}:({1})" -f $ServiceAccount, $Access
    $arguments = @(
        $Path,
        "/inheritance:r",
        "/grant:r",
        "SYSTEM:(F)",
        "Administrators:(F)",
        $serviceGrant,
        "/c"
    )
    Invoke-RunnerObservabilityNativeCommand -FilePath "icacls.exe" -ArgumentList $arguments | Out-Null
}

function Set-RunnerObservabilityDirectoryAcl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$ServiceAccount
    )

    New-Item -ItemType Directory -Path $Path -Force | Out-Null
    $serviceGrant = "{0}:(OI)(CI)(M)" -f $ServiceAccount
    $arguments = @(
        $Path,
        "/inheritance:r",
        "/grant:r",
        "SYSTEM:(OI)(CI)(F)",
        "Administrators:(OI)(CI)(F)",
        $serviceGrant,
        "/c"
    )
    Invoke-RunnerObservabilityNativeCommand -FilePath "icacls.exe" -ArgumentList $arguments | Out-Null
}

function Ensure-RunnerObservabilityFirewallRule {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string[]]$RunnerAddress,
        [Parameter(Mandatory = $true)][int]$Port
    )

    try {
        $existing = @(Get-NetFirewallRule -DisplayName $script:RunnerObservabilityFirewallRuleName -ErrorAction SilentlyContinue)
        if ($existing.Count -gt 0) {
            $existing | Remove-NetFirewallRule -Confirm:$false -ErrorAction Stop
        }
        New-NetFirewallRule `
            -DisplayName $script:RunnerObservabilityFirewallRuleName `
            -Direction Inbound `
            -Action Allow `
            -Protocol TCP `
            -LocalPort $Port `
            -RemoteAddress $RunnerAddress `
            -Profile Domain,Private `
            -Enabled True `
            -ErrorAction Stop | Out-Null
    }
    catch {
        throw [System.InvalidOperationException]::new("firewall_rule_failed")
    }
}

function Remove-RunnerObservabilityFirewallRule {
    [CmdletBinding()]
    param()

    try {
        Get-NetFirewallRule -DisplayName $script:RunnerObservabilityFirewallRuleName -ErrorAction SilentlyContinue |
            Remove-NetFirewallRule -Confirm:$false -ErrorAction SilentlyContinue
    }
    catch {
        throw [System.InvalidOperationException]::new("firewall_rule_remove_failed")
    }
}

function Register-RunnerObservabilityService {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$ServiceName,
        [Parameter(Mandatory = $true)][string]$PythonPath,
        [Parameter(Mandatory = $true)][string]$ConfigPath,
        [Parameter(Mandatory = $true)][string]$ServiceAccount
    )

    $binPath = '"{0}" -m runner_observability.service run --config "{1}"' -f $PythonPath, $ConfigPath
    Invoke-RunnerObservabilityNativeCommand -FilePath "sc.exe" -ArgumentList @(
        "create", $ServiceName, "binPath=", $binPath, "start=", "auto", "DisplayName=", "Runner Observability Monitor"
    ) | Out-Null
    Invoke-RunnerObservabilityNativeCommand -FilePath "sc.exe" -ArgumentList @(
        "config", $ServiceName, "obj=", $ServiceAccount, "start=", "auto"
    ) | Out-Null
    Invoke-RunnerObservabilityNativeCommand -FilePath "sc.exe" -ArgumentList @(
        "failure", $ServiceName, "reset=", "86400", "actions=", "restart/5000/restart/30000/restart/60000"
    ) | Out-Null
}

function Start-RunnerObservabilityService {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$ServiceName)

    Invoke-RunnerObservabilityNativeCommand -FilePath "sc.exe" -ArgumentList @("start", $ServiceName) | Out-Null
}

function Stop-RunnerObservabilityService {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$ServiceName)

    Invoke-RunnerObservabilityNativeCommand -FilePath "sc.exe" -ArgumentList @("stop", $ServiceName) | Out-Null
}

function Get-RunnerObservabilityServiceState {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$ServiceName)

    try {
        $output = Invoke-RunnerObservabilityNativeCommand -FilePath "sc.exe" -ArgumentList @("query", $ServiceName)
    }
    catch {
        return "unknown"
    }
    $joined = ($output -join "`n")
    if ($joined -match "RUNNING") { return "running" }
    if ($joined -match "STOPPED") { return "stopped" }
    return "unknown"
}

function Remove-RunnerObservabilityService {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$ServiceName)

    Invoke-RunnerObservabilityNativeCommand -FilePath "sc.exe" -ArgumentList @("delete", $ServiceName) | Out-Null
}

Export-ModuleMember -Function @(
    "Write-RunnerObservabilityConfigAtomic",
    "Set-RunnerObservabilityFileAcl",
    "Set-RunnerObservabilityDirectoryAcl",
    "Ensure-RunnerObservabilityFirewallRule",
    "Remove-RunnerObservabilityFirewallRule",
    "Register-RunnerObservabilityService",
    "Start-RunnerObservabilityService",
    "Stop-RunnerObservabilityService",
    "Get-RunnerObservabilityServiceState",
    "Remove-RunnerObservabilityService"
)
