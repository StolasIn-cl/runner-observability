$script:RunnerObservabilityEnvironmentNames = @(
    "RUNNER_OBSERVABILITY_INSTALL_ROOT",
    "RUNNER_OBSERVABILITY_ENDPOINT",
    "RUNNER_OBSERVABILITY_TOKEN_PATH",
    "RUNNER_OBSERVABILITY_RUNNER_ID"
)

function New-RunnerObservabilityStableError {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Reason)

    return [System.InvalidOperationException]::new($Reason)
}

function ConvertTo-RunnerObservabilityRedactedCommandLine {
    [CmdletBinding()]
    param([AllowNull()][string]$CommandLine)

    if ($null -eq $CommandLine) {
        return $null
    }
    return ($CommandLine -replace '(?i)(--token\s+)\S+', '$1<redacted>') -replace '(?i)(Bearer\s+)\S+', '$1<redacted>'
}

function Invoke-RunnerObservabilityBootstrapNativeCommand {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $false)][string[]]$ArgumentList = @(),
        [Parameter(Mandatory = $true)][string]$FailureReason
    )

    try {
        & $FilePath @ArgumentList 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw (New-RunnerObservabilityStableError -Reason $FailureReason)
        }
    }
    catch {
        throw (New-RunnerObservabilityStableError -Reason $FailureReason)
    }
}

function Get-RunnerObservabilityInstallInspection {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Path)

    $pointer = Join-Path $Path "current-release.txt"
    if (Test-Path -LiteralPath $pointer -PathType Leaf) {
        try {
            $revision = (Get-Content -LiteralPath $pointer -Raw -ErrorAction Stop).Trim()
        }
        catch {
            throw (New-RunnerObservabilityStableError -Reason "release_pointer_read_failed")
        }
        if ([string]::IsNullOrWhiteSpace($revision)) {
            return [pscustomobject]@{
                Path = $Path
                ReleaseState = "inspect-before-use"
                Revision = $null
                ReleaseSourceExists = $false
                RunnerIdExists = (Test-Path -LiteralPath (Join-Path $Path "runner-id.txt") -PathType Leaf)
            }
        }
        $releaseSource = Join-Path (Join-Path (Join-Path $Path "releases") $revision) "src"
        return [pscustomobject]@{
            Path = $Path
            ReleaseState = "existing"
            Revision = $revision
            ReleaseSourceExists = (Test-Path -LiteralPath $releaseSource -PathType Container)
            RunnerIdExists = (Test-Path -LiteralPath (Join-Path $Path "runner-id.txt") -PathType Leaf)
        }
    }

    if (-not (Test-Path -LiteralPath $Path)) {
        $state = "new"
    }
    else {
        try {
            $children = @(Get-ChildItem -LiteralPath $Path -Force -ErrorAction Stop)
        }
        catch {
            throw (New-RunnerObservabilityStableError -Reason "install_root_inspection_failed")
        }
        if ($children.Count -eq 0) {
            $state = "new"
        }
        else {
            $state = "inspect-before-use"
        }
    }

    return [pscustomobject]@{
        Path = $Path
        ReleaseState = $state
        Revision = $null
        ReleaseSourceExists = $false
        RunnerIdExists = (Test-Path -LiteralPath (Join-Path $Path "runner-id.txt") -PathType Leaf)
    }
}

function Get-RunnerObservabilityInventory {
    [CmdletBinding()]
    param(
        [string[]]$CandidateRunnerRoots = @("C:\actions-runner"),
        [string[]]$CandidateInstallRoots = @("C:\runner-observability-agent"),
        [string[]]$CandidateSecretRoots = @("C:\runner-observability-secrets"),
        [string[]]$ServiceNamePatterns = @("*RunnerObservability*")
    )

    $pythonCommand = Get-Command python -ErrorAction SilentlyContinue
    $pythonPath = $null
    $pythonVersion = $null
    if ($null -ne $pythonCommand) {
        $pythonPath = $pythonCommand.Source
        try {
            $pythonVersion = ((& $pythonPath --version 2>&1) -join " ").Trim()
            if ($LASTEXITCODE -ne 0) {
                $pythonVersion = $null
            }
        }
        catch {
            $pythonVersion = $null
        }
    }

    $machineConfiguration = foreach ($name in $script:RunnerObservabilityEnvironmentNames) {
        $value = [Environment]::GetEnvironmentVariable($name, "Machine")
        [pscustomobject]@{
            Name = $name
            Present = (-not [string]::IsNullOrWhiteSpace($value))
        }
    }

    $candidateRoots = @()
    foreach ($path in $CandidateRunnerRoots) {
        $candidateRoots += [pscustomobject]@{ Kind = "runner"; Path = $path; Exists = (Test-Path -LiteralPath $path) }
    }
    foreach ($path in $CandidateInstallRoots) {
        $candidateRoots += [pscustomobject]@{ Kind = "install"; Path = $path; Exists = (Test-Path -LiteralPath $path) }
    }
    foreach ($path in $CandidateSecretRoots) {
        $candidateRoots += [pscustomobject]@{ Kind = "secret"; Path = $path; Exists = (Test-Path -LiteralPath $path) }
    }

    $installRoots = foreach ($path in $CandidateInstallRoots) {
        Get-RunnerObservabilityInstallInspection -Path $path
    }

    $secretFiles = foreach ($root in $CandidateSecretRoots) {
        foreach ($name in @("monitor-token.txt", "monitor.crt", "monitor.key")) {
            [pscustomobject]@{
                Root = $root
                Name = $name
                Exists = (Test-Path -LiteralPath (Join-Path $root $name) -PathType Leaf)
            }
        }
    }

    $matchingServices = @()
    if (@($ServiceNamePatterns).Count -gt 0) {
        try {
            $services = @(Get-CimInstance Win32_Service -ErrorAction Stop)
            foreach ($service in $services) {
                $matches = $false
                foreach ($pattern in $ServiceNamePatterns) {
                    if (($service.Name -like $pattern) -or ($service.DisplayName -like $pattern)) {
                        $matches = $true
                        break
                    }
                }
                if ($matches) {
                    $matchingServices += [pscustomobject]@{
                        Name = $service.Name
                        DisplayName = $service.DisplayName
                        State = $service.State
                        StartName = $service.StartName
                        PathName = ConvertTo-RunnerObservabilityRedactedCommandLine -CommandLine $service.PathName
                    }
                }
            }
        }
        catch {
            throw (New-RunnerObservabilityStableError -Reason "service_inventory_failed")
        }
    }

    try {
        $runnerProcesses = @(
            Get-CimInstance Win32_Process -Filter "Name = 'Runner.Listener.exe'" -ErrorAction Stop |
                ForEach-Object {
                    [pscustomobject]@{
                        ProcessId = $_.ProcessId
                        ParentProcessId = $_.ParentProcessId
                        ExecutablePath = $_.ExecutablePath
                        Present = $true
                    }
                }
        )
    }
    catch {
        throw (New-RunnerObservabilityStableError -Reason "runner_process_inventory_failed")
    }

    return [pscustomobject]@{
        ComputerName = $env:COMPUTERNAME
        UserName = [Environment]::UserName
        PowerShellVersion = $PSVersionTable.PSVersion.ToString()
        PythonCommand = $pythonPath
        PythonVersion = $pythonVersion
        MachineConfiguration = @($machineConfiguration)
        CandidateRoots = @($candidateRoots)
        InstallRoots = @($installRoots)
        SecretFiles = @($secretFiles)
        MatchingServices = @($matchingServices)
        RunnerProcesses = @($runnerProcesses)
    }
}

function Assert-RunnerObservabilityInventoryGate {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Inventory,
        [Parameter(Mandatory = $true)][string]$InstallRoot,
        [ValidateSet("NewInstall", "ExistingUpdate", "Troubleshooting")][string]$Operation,
        [ValidateSet("Monitor", "Runner")][string]$Role
    )

    $inspection = @($Inventory.InstallRoots | Where-Object { $_.Path -eq $InstallRoot })
    if ($inspection.Count -ne 1) {
        throw (New-RunnerObservabilityStableError -Reason "inventory_install_root_missing")
    }
    if (($Operation -eq "NewInstall") -and ($inspection[0].ReleaseState -ne "new")) {
        throw (New-RunnerObservabilityStableError -Reason "new_install_not_allowed")
    }
    if (($Operation -eq "ExistingUpdate") -and ($inspection[0].ReleaseState -ne "existing")) {
        throw (New-RunnerObservabilityStableError -Reason "managed_install_required")
    }
    if ($Role -eq "Runner") {
        $privateKeys = @($Inventory.SecretFiles | Where-Object { $_.Name -ieq "monitor.key" -and $_.Exists })
        if ($privateKeys.Count -gt 0) {
            throw (New-RunnerObservabilityStableError -Reason "monitor_key_not_allowed")
        }
    }
    return $inspection[0]
}

function Read-RunnerObservabilitySecureValue {
    [CmdletBinding()]
    param([string]$Prompt = "Enter the monitor token")

    $secureValue = Read-Host -AsSecureString -Prompt $Prompt
    $pointer = [IntPtr]::Zero
    try {
        $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureValue)
        return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
    }
    finally {
        if ($pointer -ne [IntPtr]::Zero) {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer)
        }
    }
}

function Set-RunnerObservabilityFileAcl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$ServiceAccount
    )

    $serviceGrant = "{0}:(R)" -f $ServiceAccount
    Invoke-RunnerObservabilityBootstrapNativeCommand -FilePath "icacls.exe" -FailureReason "file_acl_failed" -ArgumentList @(
        $Path,
        "/inheritance:r",
        "/grant:r",
        "SYSTEM:(F)",
        "Administrators:(F)",
        $serviceGrant,
        "/c"
    )
}

function Set-RunnerObservabilityDirectoryAcl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$ServiceAccount,
        [Parameter(Mandatory = $true)][ValidateSet("State", "Database")][string]$Purpose
    )

    try {
        New-Item -ItemType Directory -Path $Path -Force -ErrorAction Stop | Out-Null
    }
    catch {
        throw (New-RunnerObservabilityStableError -Reason "state_directory_create_failed")
    }
    $serviceGrant = "{0}:(OI)(CI)(M)" -f $ServiceAccount
    Invoke-RunnerObservabilityBootstrapNativeCommand -FilePath "icacls.exe" -FailureReason "directory_acl_failed" -ArgumentList @(
        $Path,
        "/inheritance:r",
        "/grant:r",
        "SYSTEM:(OI)(CI)(F)",
        "Administrators:(OI)(CI)(F)",
        $serviceGrant,
        "/c"
    )
}

function Set-RunnerObservabilityRuntimeAcl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$ServiceAccount
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        throw (New-RunnerObservabilityStableError -Reason "runtime_path_missing")
    }
    $serviceGrant = "{0}:(OI)(CI)(RX)" -f $ServiceAccount
    Invoke-RunnerObservabilityBootstrapNativeCommand -FilePath "icacls.exe" -FailureReason "runtime_acl_failed" -ArgumentList @(
        $Path,
        "/grant:r",
        $serviceGrant,
        "/t",
        "/c"
    )
}

function New-RunnerObservabilityTokenFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$ServiceAccount,
        [switch]$PromptForToken
    )

    if ((Split-Path -Leaf $Path) -ieq "monitor.key") {
        throw (New-RunnerObservabilityStableError -Reason "monitor_key_not_allowed")
    }
    if (Test-Path -LiteralPath $Path) {
        throw (New-RunnerObservabilityStableError -Reason "token_file_exists")
    }

    if ($PromptForToken) {
        $tokenValue = Read-RunnerObservabilitySecureValue
        if ([string]::IsNullOrWhiteSpace($tokenValue)) {
            throw (New-RunnerObservabilityStableError -Reason "token_value_empty")
        }
    }
    else {
        $bytes = New-Object byte[] 32
        $generator = [Security.Cryptography.RandomNumberGenerator]::Create()
        try {
            $generator.GetBytes($bytes)
        }
        finally {
            $generator.Dispose()
        }
        $tokenValue = [Convert]::ToBase64String($bytes).TrimEnd("=").Replace("+", "-").Replace("/", "_")
    }

    $parent = Split-Path -Parent $Path
    if ([string]::IsNullOrWhiteSpace($parent)) {
        $parent = (Get-Location).Path
    }
    try {
        New-Item -ItemType Directory -Path $parent -Force -ErrorAction Stop | Out-Null
        $temporaryPath = Join-Path $parent ("." + (Split-Path -Leaf $Path) + "." + [guid]::NewGuid().ToString("N") + ".tmp")
        [IO.File]::WriteAllText($temporaryPath, $tokenValue, [Text.UTF8Encoding]::new($false))
    }
    catch {
        throw (New-RunnerObservabilityStableError -Reason "token_file_write_failed")
    }
    finally {
        $tokenValue = $null
    }

    try {
        Set-RunnerObservabilityFileAcl -Path $temporaryPath -ServiceAccount $ServiceAccount
        [IO.File]::Move($temporaryPath, $Path)
    }
    catch {
        if (Test-Path -LiteralPath $temporaryPath -PathType Leaf) {
            Remove-Item -LiteralPath $temporaryPath -Force -ErrorAction SilentlyContinue
        }
        if ($_.Exception.Message -eq "file_acl_failed") {
            throw
        }
        throw (New-RunnerObservabilityStableError -Reason "token_file_activate_failed")
    }

    return [pscustomobject]@{ Path = $Path; Created = $true }
}

function Test-RunnerObservabilityMonitorIp {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$MonitorIp)

    $address = $null
    if (-not [Net.IPAddress]::TryParse($MonitorIp, [ref]$address)) {
        return $false
    }
    if ($address.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork) {
        return $false
    }
    $bytes = $address.GetAddressBytes()
    if (($bytes[0] -eq 0) -or ($bytes[0] -eq 127) -or ($bytes[0] -ge 224)) {
        return $false
    }
    if (($bytes[0] -eq 255) -and ($bytes[1] -eq 255) -and ($bytes[2] -eq 255) -and ($bytes[3] -eq 255)) {
        return $false
    }
    return $true
}

function Set-RunnerObservabilityHostsMapping {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$MonitorIp,
        [string]$Hostname = "monitor-test.local",
        [string]$HostsPath = (Join-Path $env:SystemRoot "System32\drivers\etc\hosts"),
        [switch]$AllowHostsChange,
        [switch]$ReplaceConflicting
    )

    if (-not $AllowHostsChange) {
        throw (New-RunnerObservabilityStableError -Reason "hosts_change_not_allowed")
    }
    if ($Hostname -cne "monitor-test.local") {
        throw (New-RunnerObservabilityStableError -Reason "hosts_hostname_invalid")
    }
    if (-not (Test-RunnerObservabilityMonitorIp -MonitorIp $MonitorIp)) {
        throw (New-RunnerObservabilityStableError -Reason "monitor_ip_invalid")
    }

    try {
        $contents = [IO.File]::ReadAllText($HostsPath)
    }
    catch {
        throw (New-RunnerObservabilityStableError -Reason "hosts_read_failed")
    }
    if ($contents.Contains("`r`n")) {
        $newline = "`r`n"
    }
    else {
        $newline = "`n"
    }
    $lines = @($contents -split "`r?`n")
    if (($lines.Count -gt 0) -and ($lines[$lines.Count - 1] -eq "")) {
        $lines = @($lines[0..($lines.Count - 2)])
    }

    $matchingIndexes = @()
    for ($index = 0; $index -lt $lines.Count; $index += 1) {
        $body = ($lines[$index] -split "#", 2)[0].Trim()
        if ([string]::IsNullOrWhiteSpace($body)) {
            continue
        }
        $parts = @($body -split "\s+")
        if ($parts.Count -lt 2) {
            continue
        }
        foreach ($alias in $parts[1..($parts.Count - 1)]) {
            if ($alias -ieq $Hostname) {
                $matchingIndexes += $index
                break
            }
        }
    }

    if ($matchingIndexes.Count -gt 0) {
        $allMatch = $true
        foreach ($index in $matchingIndexes) {
            $mappedIp = (($lines[$index] -split "#", 2)[0].Trim() -split "\s+")[0]
            if ($mappedIp -ne $MonitorIp) {
                $allMatch = $false
            }
        }
        if ($allMatch -and ($matchingIndexes.Count -eq 1)) {
            return [pscustomobject]@{ Changed = $false; Path = $HostsPath }
        }
        if (-not $ReplaceConflicting) {
            throw (New-RunnerObservabilityStableError -Reason "hosts_mapping_conflict")
        }
        $kept = @()
        for ($index = 0; $index -lt $lines.Count; $index += 1) {
            if ($matchingIndexes -notcontains $index) {
                $kept += $lines[$index]
            }
        }
        $lines = $kept
    }

    $lines += ("{0}`t{1}" -f $MonitorIp, $Hostname)
    $updated = ($lines -join $newline) + $newline
    $parent = Split-Path -Parent $HostsPath
    $temporaryPath = Join-Path $parent (".hosts." + [guid]::NewGuid().ToString("N") + ".tmp")
    $backupPath = Join-Path $parent (".hosts." + [guid]::NewGuid().ToString("N") + ".bak")
    try {
        [IO.File]::WriteAllText($temporaryPath, $updated, [Text.Encoding]::ASCII)
        [IO.File]::Replace($temporaryPath, $HostsPath, $backupPath)
    }
    catch {
        if (Test-Path -LiteralPath $temporaryPath -PathType Leaf) {
            Remove-Item -LiteralPath $temporaryPath -Force -ErrorAction SilentlyContinue
        }
        throw (New-RunnerObservabilityStableError -Reason "hosts_write_failed")
    }
    finally {
        if (Test-Path -LiteralPath $backupPath -PathType Leaf) {
            Remove-Item -LiteralPath $backupPath -Force -ErrorAction SilentlyContinue
        }
    }
    return [pscustomobject]@{ Changed = $true; Path = $HostsPath }
}

function Set-RunnerObservabilityMachineEnvironment {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][hashtable]$Values,
        [switch]$AllowMachineEnvironmentChange
    )

    if (-not $AllowMachineEnvironmentChange) {
        throw (New-RunnerObservabilityStableError -Reason "machine_environment_change_not_allowed")
    }
    foreach ($name in $Values.Keys) {
        if ($script:RunnerObservabilityEnvironmentNames -notcontains $name) {
            throw (New-RunnerObservabilityStableError -Reason "machine_environment_name_invalid")
        }
        $value = [string]$Values[$name]
        if ([string]::IsNullOrWhiteSpace($value)) {
            throw (New-RunnerObservabilityStableError -Reason "machine_environment_value_invalid")
        }
        try {
            [Environment]::SetEnvironmentVariable($name, $value, "Machine")
            $readBack = [Environment]::GetEnvironmentVariable($name, "Machine")
        }
        catch {
            throw (New-RunnerObservabilityStableError -Reason "machine_environment_write_failed")
        }
        if ($readBack -ne $value) {
            throw (New-RunnerObservabilityStableError -Reason "machine_environment_readback_failed")
        }
    }
    return [pscustomobject]@{ Changed = $true; Names = @($Values.Keys) }
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
    while ($stopwatch.Elapsed.TotalSeconds -lt $TimeoutSeconds) {
        $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if (($DesiredState -eq "Absent") -and ($null -eq $service)) {
            return "Absent"
        }
        if (($null -ne $service) -and ($service.Status.ToString() -eq $DesiredState)) {
            return $DesiredState
        }
        Start-Sleep -Milliseconds $PollMilliseconds
    }
    throw (New-RunnerObservabilityStableError -Reason "service_state_timeout")
}

function Assert-RunnerObservabilityServiceAbsent {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$ServiceName)

    if ($null -ne (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue)) {
        throw (New-RunnerObservabilityStableError -Reason "service_already_exists")
    }
    return $true
}

function Invoke-RunnerObservabilityServiceAction {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$ServiceName,
        [Parameter(Mandatory = $true)][ValidateSet("Start", "Stop", "Restart", "Delete")][string]$Action,
        [ValidateRange(1, 600)][int]$TimeoutSeconds = 30
    )

    if ($Action -eq "Start") {
        Invoke-RunnerObservabilityBootstrapNativeCommand -FilePath "sc.exe" -FailureReason "service_start_failed" -ArgumentList @("start", $ServiceName)
        return Wait-RunnerObservabilityServiceState -ServiceName $ServiceName -DesiredState Running -TimeoutSeconds $TimeoutSeconds
    }
    if ($Action -eq "Stop") {
        Invoke-RunnerObservabilityBootstrapNativeCommand -FilePath "sc.exe" -FailureReason "service_stop_failed" -ArgumentList @("stop", $ServiceName)
        return Wait-RunnerObservabilityServiceState -ServiceName $ServiceName -DesiredState Stopped -TimeoutSeconds $TimeoutSeconds
    }
    if ($Action -eq "Restart") {
        Invoke-RunnerObservabilityBootstrapNativeCommand -FilePath "sc.exe" -FailureReason "service_stop_failed" -ArgumentList @("stop", $ServiceName)
        Wait-RunnerObservabilityServiceState -ServiceName $ServiceName -DesiredState Stopped -TimeoutSeconds $TimeoutSeconds | Out-Null
        Invoke-RunnerObservabilityBootstrapNativeCommand -FilePath "sc.exe" -FailureReason "service_start_failed" -ArgumentList @("start", $ServiceName)
        return Wait-RunnerObservabilityServiceState -ServiceName $ServiceName -DesiredState Running -TimeoutSeconds $TimeoutSeconds
    }

    Invoke-RunnerObservabilityBootstrapNativeCommand -FilePath "sc.exe" -FailureReason "service_delete_failed" -ArgumentList @("delete", $ServiceName)
    return Wait-RunnerObservabilityServiceState -ServiceName $ServiceName -DesiredState Absent -TimeoutSeconds $TimeoutSeconds
}

Export-ModuleMember -Function @(
    "Get-RunnerObservabilityInventory",
    "Assert-RunnerObservabilityInventoryGate",
    "New-RunnerObservabilityTokenFile",
    "Set-RunnerObservabilityFileAcl",
    "Set-RunnerObservabilityDirectoryAcl",
    "Set-RunnerObservabilityRuntimeAcl",
    "Set-RunnerObservabilityHostsMapping",
    "Set-RunnerObservabilityMachineEnvironment",
    "Wait-RunnerObservabilityServiceState",
    "Assert-RunnerObservabilityServiceAbsent",
    "Invoke-RunnerObservabilityServiceAction"
)
