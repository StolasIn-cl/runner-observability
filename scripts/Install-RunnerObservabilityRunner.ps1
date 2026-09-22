<#
.SYNOPSIS
    Safe Runner Host onboarding and Heartbeat service lifecycle entry point.

.DESCRIPTION
    This script owns only the Runner role. It starts with the shared
    read-only inventory, keeps token material out of command lines and output,
    and never accepts or copies a Monitor private key.
#>
[CmdletBinding()]
param(
    [ValidateSet("Preflight", "Configure", "RepairPermissions", "Start", "Stop", "Restart", "Status", "Uninstall")]
    [string]$Action = "Preflight",
    [string]$PythonPath = "",
    [string]$InstallRoot = "C:\runner-observability-agent",
    [string]$Endpoint = "",
    [string]$TokenPath = "",
    [string]$RunnerId = "",
    [string]$StatePath = "",
    [string]$MonitorHost = "monitor-test.local",
    [string]$MonitorIp = "",
    [ValidateSet("PublicCa", "PrivateCa", "SelfSigned", "Existing", "None")]
    [string]$CertificateTrustModel = "PublicCa",
    [string]$MonitorCertificatePath = "",
    [string]$ExpectedCertificateSha256 = "",
    [switch]$ImportCertificate,
    [switch]$AllowHostsChange,
    [string]$RunnerAccount = "",
    [string]$ServiceAccount = "NT AUTHORITY\LocalService",
    [string]$ServiceName = "RunnerObservabilityHeartbeat",
    [switch]$AllowInsecureHttp
)

$ErrorActionPreference = "Stop"

$bootstrapPath = Join-Path $PSScriptRoot "RunnerObservability.Bootstrap.psm1"
$heartbeatModulePath = Join-Path $PSScriptRoot "RunnerHeartbeat.Service.psm1"
Import-Module $bootstrapPath -Force
Import-Module $heartbeatModulePath -Force

if ([string]::IsNullOrWhiteSpace($TokenPath)) {
    $TokenPath = "C:\runner-observability-secrets\monitor-token.txt"
}
if ([string]::IsNullOrWhiteSpace($RunnerId)) {
    $RunnerId = Join-Path $InstallRoot "runner-id.txt"
}
if ([string]::IsNullOrWhiteSpace($StatePath)) {
    $StatePath = Join-Path $InstallRoot "state\heartbeat.json"
}
$configPath = Join-Path $InstallRoot "heartbeat-config.json"

function New-RunnerRoleError {
    param([Parameter(Mandatory = $true)][string]$Reason)

    return [System.InvalidOperationException]::new($Reason)
}

function Get-RunnerInstallInspection {
    $inventory = Get-RunnerObservabilityInventory -CandidateRunnerRoots @("C:\actions-runner") -CandidateInstallRoots @($InstallRoot) -CandidateSecretRoots @(Split-Path -Parent $TokenPath) -ServiceNamePatterns @("*action*", "*runner*", "*observability*", "*promeo*", $ServiceName)
    $inspection = Assert-RunnerObservabilityInventoryGate -Inventory $inventory -InstallRoot $InstallRoot -Operation "Troubleshooting" -Role "Runner"
    return [pscustomobject]@{
        Inventory = $inventory
        Inspection = $inspection
    }
}

function Assert-RunnerInstallStateForConfigure {
    $result = Get-RunnerInstallInspection
    $state = [string]$result.Inspection.ReleaseState
    if ($state -eq "inspect-before-use") {
        throw (New-RunnerRoleError -Reason "install_root_inspect_before_use")
    }
    return $result
}

function Assert-RunnerPython {
    if ([string]::IsNullOrWhiteSpace($PythonPath)) {
        $pythonCommand = Get-Command python -ErrorAction SilentlyContinue
        if ($null -eq $pythonCommand) {
            throw (New-RunnerRoleError -Reason "python_not_found")
        }
        $script:PythonPath = $pythonCommand.Source
    }
    if (-not (Test-Path -LiteralPath $PythonPath -PathType Leaf)) {
        throw (New-RunnerRoleError -Reason "python_not_found")
    }
}

function Assert-RunnerEndpoint {
    if ([string]::IsNullOrWhiteSpace($Endpoint)) {
        throw (New-RunnerRoleError -Reason "endpoint_required")
    }
    try {
        $uri = [System.Uri]$Endpoint
    }
    catch {
        throw (New-RunnerRoleError -Reason "invalid_endpoint")
    }
    if ($uri.Scheme -notin @("http", "https") -or [string]::IsNullOrWhiteSpace($uri.Host) -or -not [string]::IsNullOrWhiteSpace($uri.UserInfo)) {
        throw (New-RunnerRoleError -Reason "invalid_endpoint")
    }
    if (($uri.Scheme -eq "http") -and (-not $AllowInsecureHttp)) {
        throw (New-RunnerRoleError -Reason "insecure_endpoint")
    }
    if (-not [string]::IsNullOrWhiteSpace($MonitorHost) -and ($uri.Host -ine $MonitorHost)) {
        throw (New-RunnerRoleError -Reason "endpoint_host_mismatch")
    }
}

function Assert-RunnerMonitorAddress {
    if ([string]::IsNullOrWhiteSpace($MonitorHost) -or $MonitorHost -match "[<>]") {
        throw (New-RunnerRoleError -Reason "monitor_host_invalid")
    }
    if ([string]::IsNullOrWhiteSpace($MonitorIp) -or -not (Test-RunnerObservabilityMonitorIp -MonitorIp $MonitorIp)) {
        throw (New-RunnerRoleError -Reason "monitor_ip_invalid")
    }
}

function Get-RunnerIdValue {
    if (-not (Test-Path -LiteralPath $RunnerId -PathType Leaf)) {
        return $null
    }
    try {
        $value = (Get-Content -LiteralPath $RunnerId -Raw -ErrorAction Stop).Trim()
        [guid]::Parse($value) | Out-Null
        return $value
    }
    catch {
        throw (New-RunnerRoleError -Reason "runner_id_invalid")
    }
}

function Ensure-RunnerId {
    $parent = Split-Path -Parent $RunnerId
    if ([string]::IsNullOrWhiteSpace($parent)) {
        throw (New-RunnerRoleError -Reason "runner_id_path_invalid")
    }
    New-Item -ItemType Directory -Path $parent -Force | Out-Null
    $existing = Get-RunnerIdValue
    if ($null -ne $existing) {
        Set-RunnerObservabilityFileAcl -Path $RunnerId -ServiceAccount $ServiceAccount
        return $existing
    }
    $value = [guid]::NewGuid().ToString()
    $temporaryPath = Join-Path $parent ("." + (Split-Path -Leaf $RunnerId) + "." + [guid]::NewGuid().ToString("N") + ".tmp")
    try {
        [IO.File]::WriteAllBytes($temporaryPath, [byte[]]@())
        Set-RunnerObservabilityFileAcl -Path $temporaryPath -ServiceAccount $ServiceAccount
        [IO.File]::WriteAllText($temporaryPath, $value, [Text.UTF8Encoding]::new($false))
        [IO.File]::Move($temporaryPath, $RunnerId)
    }
    catch {
        if ($_.Exception.Message -eq "file_acl_failed") {
            throw
        }
        throw (New-RunnerRoleError -Reason "runner_id_write_failed")
    }
    finally {
        if (Test-Path -LiteralPath $temporaryPath -PathType Leaf) {
            Remove-Item -LiteralPath $temporaryPath -Force -ErrorAction SilentlyContinue
        }
    }
    return $value
}

function Ensure-RunnerToken {
    if ((Split-Path -Leaf $TokenPath) -ieq "monitor.key") {
        throw (New-RunnerRoleError -Reason "monitor_key_not_allowed")
    }
    if (Test-Path -LiteralPath $TokenPath -PathType Leaf) {
        Set-RunnerObservabilityFileAcl -Path $TokenPath -ServiceAccount $ServiceAccount
        return
    }
    New-RunnerObservabilityTokenFile -Path $TokenPath -ServiceAccount $ServiceAccount -PromptForToken | Out-Null
}

function Get-NormalizedSha256 {
    param([Parameter(Mandatory = $true)][string]$Value)

    $normalized = ($Value -replace "[^0-9A-Fa-f]", "").ToUpperInvariant()
    if ($normalized.Length -ne 64) {
        throw (New-RunnerRoleError -Reason "certificate_fingerprint_invalid")
    }
    return $normalized
}

function Assert-RunnerCertificate {
    if ($CertificateTrustModel -in @("None", "PublicCa")) {
        if ($ImportCertificate) {
            throw (New-RunnerRoleError -Reason "certificate_import_not_allowed")
        }
        return
    }
    if ([string]::IsNullOrWhiteSpace($MonitorCertificatePath) -or -not (Test-Path -LiteralPath $MonitorCertificatePath -PathType Leaf)) {
        throw (New-RunnerRoleError -Reason "monitor_certificate_missing")
    }
    if ((Split-Path -Leaf $MonitorCertificatePath) -ieq "monitor.key") {
        throw (New-RunnerRoleError -Reason "monitor_key_not_allowed")
    }
    $certificate = $null
    try {
        $certificate = [Security.Cryptography.X509Certificates.X509Certificate2]::new($MonitorCertificatePath)
        $actual = $certificate.GetCertHashString("SHA256").ToUpperInvariant()
    }
    catch {
        throw (New-RunnerRoleError -Reason "monitor_certificate_invalid")
    }
    finally {
        if ($null -ne $certificate) {
            $certificate.Dispose()
        }
    }
    if ([string]::IsNullOrWhiteSpace($ExpectedCertificateSha256)) {
        if ($ImportCertificate) {
            throw (New-RunnerRoleError -Reason "certificate_fingerprint_required")
        }
        return
    }
    if ($actual -ne (Get-NormalizedSha256 -Value $ExpectedCertificateSha256)) {
        throw (New-RunnerRoleError -Reason "certificate_fingerprint_mismatch")
    }
}

function Import-RunnerMonitorCertificate {
    if (-not $ImportCertificate) {
        return
    }
    Assert-RunnerCertificate
    try {
        Import-Certificate -FilePath $MonitorCertificatePath -CertStoreLocation "Cert:\LocalMachine\Root" -ErrorAction Stop | Out-Null
    }
    catch {
        throw (New-RunnerRoleError -Reason "certificate_import_failed")
    }
}

function Assert-RunnerPythonImport {
    $previousPythonPath = $env:PYTHONPATH
    try {
        $env:PYTHONPATH = Join-Path (Split-Path -Parent $PSScriptRoot) "src"
        & $PythonPath -s -c "import runner_observability, runner_observability.heartbeat_service" 2>$null | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw (New-RunnerRoleError -Reason "python_import_failed")
        }
    }
    catch {
        if ($_.Exception.Message -eq "python_import_failed") {
            throw
        }
        throw (New-RunnerRoleError -Reason "python_import_failed")
    }
    finally {
        if ($null -eq $previousPythonPath) {
            Remove-Item Env:PYTHONPATH -ErrorAction SilentlyContinue
        }
        else {
            $env:PYTHONPATH = $previousPythonPath
        }
    }
}

function Invoke-RunnerPreflight {
    $result = Get-RunnerInstallInspection
    Assert-RunnerPython
    Assert-RunnerEndpoint
    Assert-RunnerMonitorAddress
    Assert-RunnerCertificate
    Assert-RunnerPythonImport
    if ((Test-Path -LiteralPath $TokenPath -PathType Leaf) -and ((Split-Path -Leaf $TokenPath) -ieq "monitor.key")) {
        throw (New-RunnerRoleError -Reason "monitor_key_not_allowed")
    }
    [pscustomobject]@{
        InstallState = $result.Inspection.ReleaseState
        PythonPath = $PythonPath
        Endpoint = $Endpoint
        MonitorHost = $MonitorHost
        CertificateTrustModel = $CertificateTrustModel
        TokenPresent = (Test-Path -LiteralPath $TokenPath -PathType Leaf)
        Reason = "preflight_passed"
    }
}

function New-RunnerHeartbeatConfiguration {
    param([Parameter(Mandatory = $true)][string]$RunnerIdValue)

    return @{
        endpoint = $Endpoint
        token_file = $TokenPath
        runner_id = $RunnerIdValue
        state_file = $StatePath
        producer_id = "runner-heartbeat"
        service_name = $ServiceName
        python_executable = $PythonPath
        interval_seconds = 60
        network_poll_seconds = 5
        allow_insecure_http = [bool]$AllowInsecureHttp
    }
}

function Invoke-RunnerConfigure {
    $result = Assert-RunnerInstallStateForConfigure
    $null = Invoke-RunnerPreflight
    if ((Get-RunnerHeartbeatServiceState -ServiceName $ServiceName) -ne "absent") {
        throw (New-RunnerRoleError -Reason "service_already_exists")
    }
    New-Item -ItemType Directory -Path $InstallRoot -Force | Out-Null
    New-Item -ItemType Directory -Path (Split-Path -Parent $StatePath) -Force | Out-Null
    $runnerIdValue = Ensure-RunnerId
    Ensure-RunnerToken
    Import-RunnerMonitorCertificate
    if ($AllowHostsChange) {
        Set-RunnerObservabilityHostsMapping -MonitorIp $MonitorIp -AllowHostsChange | Out-Null
    }
    $configuration = New-RunnerHeartbeatConfiguration -RunnerIdValue $runnerIdValue
    Write-RunnerHeartbeatConfigAtomic -Path $configPath -Configuration $configuration
    Set-RunnerHeartbeatFileAcl -Path $configPath -ServiceAccount $ServiceAccount -Access "R"
    Set-RunnerHeartbeatFileAcl -Path $TokenPath -ServiceAccount $ServiceAccount -Access "R"
    Set-RunnerHeartbeatFileAcl -Path $RunnerId -ServiceAccount $ServiceAccount -Access "R"
    Set-RunnerHeartbeatDirectoryAcl -Path (Split-Path -Parent $StatePath) -ServiceAccount $ServiceAccount
    $pythonDirectory = Split-Path -Parent $PythonPath
    Set-RunnerObservabilityRuntimeAcl -Path $pythonDirectory -ServiceAccount $ServiceAccount
    if ($null -ne $result.Inspection.Revision) {
        $releaseSource = Join-Path (Join-Path (Join-Path $InstallRoot "releases") $result.Inspection.Revision) "src"
        if (Test-Path -LiteralPath $releaseSource -PathType Container) {
            Set-RunnerObservabilityRuntimeAcl -Path $releaseSource -ServiceAccount $ServiceAccount
        }
    }
    Set-RunnerObservabilityMachineEnvironment -Values @{
        RUNNER_OBSERVABILITY_INSTALL_ROOT = $InstallRoot
        RUNNER_OBSERVABILITY_ENDPOINT = $Endpoint
        RUNNER_OBSERVABILITY_TOKEN_PATH = $TokenPath
        RUNNER_OBSERVABILITY_RUNNER_ID = $runnerIdValue
    } -AllowMachineEnvironmentChange | Out-Null
    Register-RunnerHeartbeatService -ServiceName $ServiceName -PythonPath $PythonPath -ConfigPath $configPath -ServiceAccount $ServiceAccount
    Write-Output ("runner_id_path={0}" -f $RunnerId)
    Write-Output ("heartbeat_config_path={0}" -f $configPath)
    Write-Output "service_state=stopped"
    Write-Output "reason=configure_completed"
}

function Invoke-RunnerRepairPermissions {
    $null = Get-RunnerInstallInspection
    if (-not (Test-Path -LiteralPath $configPath -PathType Leaf)) {
        throw (New-RunnerRoleError -Reason "runner_installation_missing")
    }
    if (-not (Test-Path -LiteralPath $TokenPath -PathType Leaf)) {
        throw (New-RunnerRoleError -Reason "token_file_missing")
    }
    Set-RunnerHeartbeatFileAcl -Path $configPath -ServiceAccount $ServiceAccount -Access "R"
    Set-RunnerHeartbeatFileAcl -Path $TokenPath -ServiceAccount $ServiceAccount -Access "R"
    if (Test-Path -LiteralPath $RunnerId -PathType Leaf) {
        Set-RunnerHeartbeatFileAcl -Path $RunnerId -ServiceAccount $ServiceAccount -Access "R"
    }
    Set-RunnerHeartbeatDirectoryAcl -Path (Split-Path -Parent $StatePath) -ServiceAccount $ServiceAccount
    Write-Output "reason=permissions_repaired"
}

function Invoke-RunnerLifecycle {
    $null = Get-RunnerInstallInspection
    switch ($Action) {
        "Start" { Write-Output ("service_state={0}" -f (Start-RunnerHeartbeatService -ServiceName $ServiceName)) }
        "Stop" { Write-Output ("service_state={0}" -f (Stop-RunnerHeartbeatService -ServiceName $ServiceName)) }
        "Restart" {
            Stop-RunnerHeartbeatService -ServiceName $ServiceName | Out-Null
            Write-Output ("service_state={0}" -f (Start-RunnerHeartbeatService -ServiceName $ServiceName))
        }
        "Status" { Write-Output ("service_state={0}" -f (Get-RunnerHeartbeatServiceState -ServiceName $ServiceName)) }
        "Uninstall" {
            Remove-RunnerHeartbeatService -ServiceName $ServiceName | Out-Null
            Write-Output "service_state=absent"
            Write-Output "persistent_data_preserved=true"
            Write-Output "reason=uninstall_completed"
        }
    }
}

try {
    switch ($Action) {
        "Preflight" {
            $result = Invoke-RunnerPreflight
            $result | ConvertTo-Json -Compress
        }
        "Configure" { Invoke-RunnerConfigure }
        "RepairPermissions" { Invoke-RunnerRepairPermissions }
        "Start" { Invoke-RunnerLifecycle }
        "Stop" { Invoke-RunnerLifecycle }
        "Restart" { Invoke-RunnerLifecycle }
        "Status" { Invoke-RunnerLifecycle }
        "Uninstall" { Invoke-RunnerLifecycle }
    }
}
catch {
    $reason = [string]$_.Exception.Message
    $knownReasons = @(
        "endpoint_required",
        "invalid_endpoint",
        "insecure_endpoint",
        "endpoint_host_mismatch",
        "monitor_host_invalid",
        "monitor_ip_invalid",
        "monitor_key_not_allowed",
        "monitor_certificate_missing",
        "monitor_certificate_invalid",
        "certificate_fingerprint_required",
        "certificate_fingerprint_invalid",
        "certificate_fingerprint_mismatch",
        "certificate_import_not_allowed",
        "certificate_import_failed",
        "python_not_found",
        "python_import_failed",
        "install_root_inspect_before_use",
        "runner_id_invalid",
        "runner_id_path_invalid",
        "runner_id_write_failed",
        "token_file_missing",
        "token_file_write_failed",
        "token_file_activate_failed",
        "token_file_exists",
        "service_already_exists",
        "service_state_timeout",
        "service_state_read_failed",
        "service_command_failed",
        "runner_installation_missing",
        "file_acl_failed",
        "directory_acl_failed",
        "runtime_path_missing",
        "hosts_change_not_allowed",
        "hosts_mapping_conflict",
        "hosts_write_failed",
        "machine_environment_change_not_allowed",
        "machine_environment_write_failed",
        "machine_environment_readback_failed"
    )
    if ($knownReasons -notcontains $reason) {
        $reason = "runner_onboarding_failed"
    }
    [System.Console]::Error.WriteLine("reason=" + $reason)
    exit 2
}
