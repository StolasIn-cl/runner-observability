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

function Set-RunnerHeartbeatDirectoryTraverseAcl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$ServiceAccount
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Container -ErrorAction Stop)) {
        throw [System.InvalidOperationException]::new("directory_acl_failed")
    }
    $serviceGrant = "{0}:(X)" -f $ServiceAccount
    Invoke-RunnerHeartbeatNativeCommand -FilePath "icacls.exe" -ArgumentList @(
        $Path,
        "/grant:r",
        "SYSTEM:(F)",
        "Administrators:(F)",
        $serviceGrant
    ) | Out-Null
}

function Get-RunnerHeartbeatServiceRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$ServiceName,
        [ValidateRange(1, 600)][int]$OperationTimeoutSeconds = 5
    )

    try {
        $escapedServiceName = $ServiceName.Replace("'", "''")
        return Get-CimInstance `
            -ClassName Win32_Service `
            -Filter ("Name = '{0}'" -f $escapedServiceName) `
            -OperationTimeoutSec $OperationTimeoutSeconds `
            -ErrorAction Stop
    }
    catch {
        throw [System.InvalidOperationException]::new("service_state_read_failed")
    }
}

function Convert-RunnerHeartbeatServiceRecordToControlState {
    [CmdletBinding()]
    param([Parameter(Mandatory = $false)][object]$Service)

    if ($null -eq $Service) {
        return "absent"
    }
    switch (([string]$Service.State).Trim().ToLowerInvariant()) {
        "running" { return "running" }
        "stopped" { return "stopped" }
        "start pending" { return "start_pending" }
        "stop pending" { return "stop_pending" }
        default { return "unknown" }
    }
}

function Get-RunnerHeartbeatServiceControlState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$ServiceName,
        [ValidateRange(1, 600)][int]$OperationTimeoutSeconds = 5
    )

    $service = Get-RunnerHeartbeatServiceRecord `
        -ServiceName $ServiceName `
        -OperationTimeoutSeconds $OperationTimeoutSeconds
    return Convert-RunnerHeartbeatServiceRecordToControlState -Service $service
}

function Get-RunnerHeartbeatServiceState {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$ServiceName)

    switch (Get-RunnerHeartbeatServiceControlState -ServiceName $ServiceName) {
        "running" { return "running" }
        "stopped" { return "stopped" }
        "absent" { return "absent" }
        default { return "unknown" }
    }
}

function Assert-RunnerHeartbeatServiceAbsent {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$ServiceName)

    if ((Get-RunnerHeartbeatServiceState -ServiceName $ServiceName) -ne "absent") {
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
    $deadline = $TimeoutSeconds
    $desiredState = $DesiredState.ToLowerInvariant()
    while ($true) {
        if ($stopwatch.Elapsed.TotalSeconds -ge $deadline) {
            break
        }
        $remainingSeconds = $deadline - $stopwatch.Elapsed.TotalSeconds
        $readTimeoutSeconds = [Math]::Max(1, [Math]::Min(5, [int][Math]::Ceiling($remainingSeconds)))
        try {
            $state = Get-RunnerHeartbeatServiceControlState `
                -ServiceName $ServiceName `
                -OperationTimeoutSeconds $readTimeoutSeconds
        }
        catch {
            if ($stopwatch.Elapsed.TotalSeconds -ge $deadline) {
                break
            }
            throw
        }
        if ($stopwatch.Elapsed.TotalSeconds -ge $deadline) {
            break
        }
        if ($state -eq $desiredState) {
            return $state
        }
        $remainingMilliseconds = [int][Math]::Floor(($deadline - $stopwatch.Elapsed.TotalSeconds) * 1000)
        if ($remainingMilliseconds -le 0) {
            break
        }
        Start-Sleep -Milliseconds ([Math]::Min($PollMilliseconds, $remainingMilliseconds))
    }
    throw [System.InvalidOperationException]::new("service_state_timeout")
}

function Register-RunnerHeartbeatService {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$ServiceName,
        [Parameter(Mandatory = $true)][string]$PythonPath,
        [Parameter(Mandatory = $true)][string]$ConfigPath,
        [Parameter(Mandatory = $true)][string]$ModulePath,
        [Parameter(Mandatory = $true)][string]$ServiceAccount
    )

    Assert-RunnerHeartbeatServiceAbsent -ServiceName $ServiceName
    $launcherPath = Join-Path $ModulePath "runner_heartbeat_service.py"
    if (-not (Test-Path -LiteralPath $launcherPath -PathType Leaf)) {
        throw [System.InvalidOperationException]::new("runtime_path_missing")
    }
    $binPath = '"{0}" "{1}" run --config "{2}"' -f $PythonPath, $launcherPath, $ConfigPath
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

    $state = Get-RunnerHeartbeatServiceControlState -ServiceName $ServiceName
    if ($state -eq "running") {
        return $state
    }
    if ($state -eq "start_pending") {
        return Wait-RunnerHeartbeatServiceState -ServiceName $ServiceName -DesiredState "Running"
    }
    if ($state -eq "stop_pending") {
        Wait-RunnerHeartbeatServiceState -ServiceName $ServiceName -DesiredState "Stopped" | Out-Null
    }
    Invoke-RunnerHeartbeatNativeCommand -FilePath "sc.exe" -ArgumentList @("start", $ServiceName) | Out-Null
    return Wait-RunnerHeartbeatServiceState -ServiceName $ServiceName -DesiredState "Running"
}

function Stop-RunnerHeartbeatService {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$ServiceName)

    $state = Get-RunnerHeartbeatServiceControlState -ServiceName $ServiceName
    if (($state -eq "stopped") -or ($state -eq "absent")) {
        return $state
    }
    if ($state -eq "start_pending") {
        Wait-RunnerHeartbeatServiceState -ServiceName $ServiceName -DesiredState "Running" | Out-Null
    }
    if ($state -eq "stop_pending") {
        return Wait-RunnerHeartbeatServiceState -ServiceName $ServiceName -DesiredState "Stopped"
    }
    Invoke-RunnerHeartbeatNativeCommand -FilePath "sc.exe" -ArgumentList @("stop", $ServiceName) | Out-Null
    return Wait-RunnerHeartbeatServiceState -ServiceName $ServiceName -DesiredState "Stopped"
}

function Remove-RunnerHeartbeatService {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$ServiceName)

    $state = Get-RunnerHeartbeatServiceControlState -ServiceName $ServiceName
    if ($state -eq "absent") {
        return $state
    }
    if ($state -ne "stopped") {
        Stop-RunnerHeartbeatService -ServiceName $ServiceName | Out-Null
    }
    Invoke-RunnerHeartbeatNativeCommand -FilePath "sc.exe" -ArgumentList @("delete", $ServiceName) | Out-Null
    return Wait-RunnerHeartbeatServiceState -ServiceName $ServiceName -DesiredState "Absent"
}

Export-ModuleMember -Function @(
    "Write-RunnerHeartbeatConfigAtomic",
    "Set-RunnerHeartbeatFileAcl",
    "Set-RunnerHeartbeatDirectoryAcl",
    "Set-RunnerHeartbeatDirectoryTraverseAcl",
    "Assert-RunnerHeartbeatServiceAbsent",
    "Wait-RunnerHeartbeatServiceState",
    "Register-RunnerHeartbeatService",
    "Start-RunnerHeartbeatService",
    "Stop-RunnerHeartbeatService",
    "Get-RunnerHeartbeatServiceState",
    "Remove-RunnerHeartbeatService"
)
