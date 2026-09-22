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

function Get-RunnerObservabilityServiceRecord {
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

function Convert-RunnerObservabilityServiceRecordToControlState {
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

function Get-RunnerObservabilityServiceControlState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$ServiceName,
        [ValidateRange(1, 600)][int]$OperationTimeoutSeconds = 5
    )

    $service = Get-RunnerObservabilityServiceRecord `
        -ServiceName $ServiceName `
        -OperationTimeoutSeconds $OperationTimeoutSeconds
    return Convert-RunnerObservabilityServiceRecordToControlState -Service $service
}

function Get-RunnerObservabilityServiceState {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$ServiceName)

    switch (Get-RunnerObservabilityServiceControlState -ServiceName $ServiceName) {
        "running" { return "running" }
        "stopped" { return "stopped" }
        "absent" { return "absent" }
        default { return "unknown" }
    }
}

function Assert-RunnerObservabilityServiceAbsent {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$ServiceName)

    if ((Get-RunnerObservabilityServiceState -ServiceName $ServiceName) -ne "absent") {
        throw [System.InvalidOperationException]::new("service_already_exists")
    }
}

function Wait-RunnerObservabilityServiceState {
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
            $state = Get-RunnerObservabilityServiceControlState `
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

function Register-RunnerObservabilityService {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$ServiceName,
        [Parameter(Mandatory = $true)][string]$PythonPath,
        [Parameter(Mandatory = $true)][string]$ConfigPath,
        [Parameter(Mandatory = $true)][string]$ServiceAccount
    )

    Assert-RunnerObservabilityServiceAbsent -ServiceName $ServiceName
    $binPath = '"{0}" -m runner_observability.service run --config "{1}"' -f $PythonPath, $ConfigPath
    Invoke-RunnerObservabilityNativeCommand -FilePath "sc.exe" -ArgumentList @(
        "create", $ServiceName, "binPath=", $binPath, "start=", "auto", "DisplayName=", "Runner Observability Monitor"
    ) | Out-Null
    Wait-RunnerObservabilityServiceState -ServiceName $ServiceName -DesiredState "Stopped" | Out-Null
    Invoke-RunnerObservabilityNativeCommand -FilePath "sc.exe" -ArgumentList @(
        "config", $ServiceName, "obj=", $ServiceAccount, "start=", "auto"
    ) | Out-Null
    Wait-RunnerObservabilityServiceState -ServiceName $ServiceName -DesiredState "Stopped" | Out-Null
    Invoke-RunnerObservabilityNativeCommand -FilePath "sc.exe" -ArgumentList @(
        "failure", $ServiceName, "reset=", "86400", "actions=", "restart/5000/restart/30000/restart/60000"
    ) | Out-Null
    Wait-RunnerObservabilityServiceState -ServiceName $ServiceName -DesiredState "Stopped" | Out-Null
}

function Start-RunnerObservabilityService {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$ServiceName)

    $state = Get-RunnerObservabilityServiceControlState -ServiceName $ServiceName
    if ($state -eq "running") {
        return $state
    }
    if ($state -eq "start_pending") {
        return Wait-RunnerObservabilityServiceState -ServiceName $ServiceName -DesiredState "Running"
    }
    if ($state -eq "stop_pending") {
        Wait-RunnerObservabilityServiceState -ServiceName $ServiceName -DesiredState "Stopped" | Out-Null
    }
    Invoke-RunnerObservabilityNativeCommand -FilePath "sc.exe" -ArgumentList @("start", $ServiceName) | Out-Null
    return Wait-RunnerObservabilityServiceState -ServiceName $ServiceName -DesiredState "Running"
}

function Stop-RunnerObservabilityService {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$ServiceName)

    $state = Get-RunnerObservabilityServiceControlState -ServiceName $ServiceName
    if (($state -eq "stopped") -or ($state -eq "absent")) {
        return $state
    }
    if ($state -eq "start_pending") {
        Wait-RunnerObservabilityServiceState -ServiceName $ServiceName -DesiredState "Running" | Out-Null
    }
    if ($state -eq "stop_pending") {
        return Wait-RunnerObservabilityServiceState -ServiceName $ServiceName -DesiredState "Stopped"
    }
    Invoke-RunnerObservabilityNativeCommand -FilePath "sc.exe" -ArgumentList @("stop", $ServiceName) | Out-Null
    return Wait-RunnerObservabilityServiceState -ServiceName $ServiceName -DesiredState "Stopped"
}

function Remove-RunnerObservabilityService {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$ServiceName)

    $state = Get-RunnerObservabilityServiceControlState -ServiceName $ServiceName
    if ($state -eq "absent") {
        return $state
    }
    if ($state -ne "stopped") {
        Stop-RunnerObservabilityService -ServiceName $ServiceName | Out-Null
    }
    Invoke-RunnerObservabilityNativeCommand -FilePath "sc.exe" -ArgumentList @("delete", $ServiceName) | Out-Null
    return Wait-RunnerObservabilityServiceState -ServiceName $ServiceName -DesiredState "Absent"
}

Export-ModuleMember -Function @(
    "Write-RunnerObservabilityConfigAtomic",
    "Set-RunnerObservabilityFileAcl",
    "Set-RunnerObservabilityDirectoryAcl",
    "Ensure-RunnerObservabilityFirewallRule",
    "Remove-RunnerObservabilityFirewallRule",
    "Assert-RunnerObservabilityServiceAbsent",
    "Wait-RunnerObservabilityServiceState",
    "Register-RunnerObservabilityService",
    "Start-RunnerObservabilityService",
    "Stop-RunnerObservabilityService",
    "Get-RunnerObservabilityServiceState",
    "Remove-RunnerObservabilityService"
)
