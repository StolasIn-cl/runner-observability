function Invoke-RunnerHeartbeatNativeCommand {
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

function Write-RunnerHeartbeatConfigAtomic {
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

function Set-RunnerHeartbeatFileAcl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$ServiceAccount,
        [ValidateSet("R", "M")][string]$Access = "R"
    )

    $serviceGrant = "{0}:({1})" -f $ServiceAccount, $Access
    Invoke-RunnerHeartbeatNativeCommand -FilePath "icacls.exe" -ArgumentList @(
        $Path,
        "/inheritance:r",
        "/grant:r",
        "SYSTEM:(F)",
        "Administrators:(F)",
        $serviceGrant,
        "/c"
    ) | Out-Null
}

function Set-RunnerHeartbeatDirectoryAcl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$ServiceAccount
    )

    New-Item -ItemType Directory -Path $Path -Force | Out-Null
    $serviceGrant = "{0}:(OI)(CI)(M)" -f $ServiceAccount
    Invoke-RunnerHeartbeatNativeCommand -FilePath "icacls.exe" -ArgumentList @(
        $Path,
        "/inheritance:r",
        "/grant:r",
        "SYSTEM:(OI)(CI)(F)",
        "Administrators:(OI)(CI)(F)",
        $serviceGrant,
        "/c"
    ) | Out-Null
}

function Register-RunnerHeartbeatService {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$ServiceName,
        [Parameter(Mandatory = $true)][string]$PythonPath,
        [Parameter(Mandatory = $true)][string]$ConfigPath,
        [Parameter(Mandatory = $true)][string]$ServiceAccount
    )

    $binPath = '"{0}" -m runner_observability.heartbeat_service run --config "{1}"' -f $PythonPath, $ConfigPath
    Invoke-RunnerHeartbeatNativeCommand -FilePath "sc.exe" -ArgumentList @(
        "create", $ServiceName, "binPath= $binPath", "start= auto", "DisplayName= Runner Observability Heartbeat"
    ) | Out-Null
    Invoke-RunnerHeartbeatNativeCommand -FilePath "sc.exe" -ArgumentList @(
        "config", $ServiceName, "obj= $ServiceAccount", "start= auto"
    ) | Out-Null
    Invoke-RunnerHeartbeatNativeCommand -FilePath "sc.exe" -ArgumentList @(
        "failure", $ServiceName, "reset= 86400", "actions= restart/5000/restart/30000/restart/60000"
    ) | Out-Null
}

function Start-RunnerHeartbeatService {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$ServiceName)

    Invoke-RunnerHeartbeatNativeCommand -FilePath "sc.exe" -ArgumentList @("start", $ServiceName) | Out-Null
}

function Stop-RunnerHeartbeatService {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$ServiceName)

    Invoke-RunnerHeartbeatNativeCommand -FilePath "sc.exe" -ArgumentList @("stop", $ServiceName) | Out-Null
}

function Get-RunnerHeartbeatServiceState {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$ServiceName)

    try {
        $output = Invoke-RunnerHeartbeatNativeCommand -FilePath "sc.exe" -ArgumentList @("query", $ServiceName)
    }
    catch {
        return "unknown"
    }
    $joined = ($output -join "`n")
    if ($joined -match "RUNNING") { return "running" }
    if ($joined -match "STOPPED") { return "stopped" }
    return "unknown"
}

function Remove-RunnerHeartbeatService {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$ServiceName)

    Invoke-RunnerHeartbeatNativeCommand -FilePath "sc.exe" -ArgumentList @("delete", $ServiceName) | Out-Null
}

Export-ModuleMember -Function @(
    "Write-RunnerHeartbeatConfigAtomic",
    "Set-RunnerHeartbeatFileAcl",
    "Set-RunnerHeartbeatDirectoryAcl",
    "Register-RunnerHeartbeatService",
    "Start-RunnerHeartbeatService",
    "Stop-RunnerHeartbeatService",
    "Get-RunnerHeartbeatServiceState",
    "Remove-RunnerHeartbeatService"
)
