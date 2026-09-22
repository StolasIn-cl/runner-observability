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
    $backupPath = Join-Path $parent ("." + (Split-Path -Leaf $Path) + "." + [guid]::NewGuid().ToString("N") + ".bak")
    try {
        $json = $Configuration | ConvertTo-Json -Depth 5
        [System.IO.File]::WriteAllText($temporaryPath, $json, [System.Text.UTF8Encoding]::new($false))
        if (Test-Path -LiteralPath $Path -PathType Leaf) {
            [System.IO.File]::Replace($temporaryPath, $Path, $backupPath)
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
        if (Test-Path -LiteralPath $backupPath -PathType Leaf) {
            Remove-Item -LiteralPath $backupPath -Force -ErrorAction SilentlyContinue
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

function Get-RunnerHeartbeatServiceRecord {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$ServiceName)

    try {
        $escapedServiceName = $ServiceName.Replace("'", "''")
        return Get-CimInstance `
            -ClassName Win32_Service `
            -Filter ("Name = '{0}'" -f $escapedServiceName) `
            -ErrorAction Stop
    }
    catch {
        throw [System.InvalidOperationException]::new("service_state_read_failed")
    }
}

function Get-RunnerHeartbeatServiceState {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$ServiceName)

    $service = Get-RunnerHeartbeatServiceRecord -ServiceName $ServiceName
    if ($null -eq $service) {
        return "Absent"
    }
    $state = [string]$service.State
    if ([string]::IsNullOrWhiteSpace($state)) {
        return "Unknown"
    }
    return $state
}

function Assert-RunnerHeartbeatServiceAbsent {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$ServiceName)

    if ((Get-RunnerHeartbeatServiceState -ServiceName $ServiceName) -ne "Absent") {
        throw [System.InvalidOperationException]::new("service_already_exists")
    }
}

function Wait-RunnerHeartbeatServiceState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$ServiceName,
        [Parameter(Mandatory = $true)][ValidateSet("Running", "Stopped", "Absent")][string]$DesiredState,
        [ValidateRange(1, 600)][int]$TimeoutSeconds = 30,
        [ValidateRange(25, 5000)][int]$PollMilliseconds = 250
    )

    $stopwatch = [Diagnostics.Stopwatch]::StartNew()
    while ($true) {
        $state = Get-RunnerHeartbeatServiceState -ServiceName $ServiceName
        if ($state -eq $DesiredState) {
            return $state
        }
        if ($stopwatch.Elapsed.TotalSeconds -ge $TimeoutSeconds) {
            break
        }
        Start-Sleep -Milliseconds $PollMilliseconds
    }
    throw [System.InvalidOperationException]::new("service_state_timeout")
}

function Register-RunnerHeartbeatService {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$ServiceName,
        [Parameter(Mandatory = $true)][string]$PythonPath,
        [Parameter(Mandatory = $true)][string]$ConfigPath,
        [Parameter(Mandatory = $true)][string]$ServiceAccount
    )

    Assert-RunnerHeartbeatServiceAbsent -ServiceName $ServiceName
    $binPath = '"{0}" -m runner_observability.heartbeat_service run --config "{1}"' -f $PythonPath, $ConfigPath
    Invoke-RunnerHeartbeatNativeCommand -FilePath "sc.exe" -ArgumentList @(
        "create", $ServiceName, "binPath=", $binPath, "start=", "auto", "DisplayName=", "Runner Observability Heartbeat"
    ) | Out-Null
    Wait-RunnerHeartbeatServiceState -ServiceName $ServiceName -DesiredState "Stopped" | Out-Null
    Invoke-RunnerHeartbeatNativeCommand -FilePath "sc.exe" -ArgumentList @(
        "config", $ServiceName, "obj=", $ServiceAccount, "start=", "auto"
    ) | Out-Null
    Wait-RunnerHeartbeatServiceState -ServiceName $ServiceName -DesiredState "Stopped" | Out-Null
    Invoke-RunnerHeartbeatNativeCommand -FilePath "sc.exe" -ArgumentList @(
        "failure", $ServiceName, "reset=", "86400", "actions=", "restart/5000/restart/30000/restart/60000"
    ) | Out-Null
    Wait-RunnerHeartbeatServiceState -ServiceName $ServiceName -DesiredState "Stopped" | Out-Null
}

function Start-RunnerHeartbeatService {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$ServiceName)

    $state = Get-RunnerHeartbeatServiceState -ServiceName $ServiceName
    if ($state -eq "Running") {
        return $state
    }
    Invoke-RunnerHeartbeatNativeCommand -FilePath "sc.exe" -ArgumentList @("start", $ServiceName) | Out-Null
    return Wait-RunnerHeartbeatServiceState -ServiceName $ServiceName -DesiredState "Running"
}

function Stop-RunnerHeartbeatService {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$ServiceName)

    $state = Get-RunnerHeartbeatServiceState -ServiceName $ServiceName
    if (($state -eq "Stopped") -or ($state -eq "Absent")) {
        return $state
    }
    Invoke-RunnerHeartbeatNativeCommand -FilePath "sc.exe" -ArgumentList @("stop", $ServiceName) | Out-Null
    return Wait-RunnerHeartbeatServiceState -ServiceName $ServiceName -DesiredState "Stopped"
}

function Remove-RunnerHeartbeatService {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$ServiceName)

    $state = Get-RunnerHeartbeatServiceState -ServiceName $ServiceName
    if ($state -eq "Absent") {
        return $state
    }
    if ($state -ne "Stopped") {
        Stop-RunnerHeartbeatService -ServiceName $ServiceName | Out-Null
    }
    Invoke-RunnerHeartbeatNativeCommand -FilePath "sc.exe" -ArgumentList @("delete", $ServiceName) | Out-Null
    return Wait-RunnerHeartbeatServiceState -ServiceName $ServiceName -DesiredState "Absent"
}

Export-ModuleMember -Function @(
    "Write-RunnerHeartbeatConfigAtomic",
    "Set-RunnerHeartbeatFileAcl",
    "Set-RunnerHeartbeatDirectoryAcl",
    "Assert-RunnerHeartbeatServiceAbsent",
    "Wait-RunnerHeartbeatServiceState",
    "Register-RunnerHeartbeatService",
    "Start-RunnerHeartbeatService",
    "Stop-RunnerHeartbeatService",
    "Get-RunnerHeartbeatServiceState",
    "Remove-RunnerHeartbeatService"
)
