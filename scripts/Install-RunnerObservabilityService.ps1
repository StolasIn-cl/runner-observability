[CmdletBinding()]
param(
    [ValidateSet("Install", "Start", "Stop", "Status", "Restart", "Uninstall")]
    [string]$Action = "Install",
    [string]$ConfigPath = "",
    [string]$PythonPath = "",
    [string]$TokenPath = "",
    [string]$DatabasePath = "",
    [string]$TlsCertPath = "",
    [string]$TlsKeyPath = "",
    [string[]]$RunnerAddress = @(),
    [string]$ServiceName = "RunnerObservabilityMonitor",
    [string]$ServiceAccount = "NT AUTHORITY\LocalService",
    [ValidateRange(1, 65535)]
    [int]$Port = 8765
)

$ErrorActionPreference = "Stop"
$modulePath = Join-Path $PSScriptRoot "RunnerObservability.Service.psm1"
Import-Module $modulePath -Force

function Assert-InstallInput {
    if ($Port -ne 8765) {
        throw [System.InvalidOperationException]::new("unsupported_service_port")
    }
    if ([string]::IsNullOrWhiteSpace($ConfigPath) -or [string]::IsNullOrWhiteSpace($PythonPath) -or [string]::IsNullOrWhiteSpace($TokenPath) -or [string]::IsNullOrWhiteSpace($DatabasePath)) {
        throw [System.InvalidOperationException]::new("service_configuration_missing")
    }
    if (-not (Test-Path -LiteralPath $PythonPath -PathType Leaf)) {
        throw [System.InvalidOperationException]::new("python_executable_missing")
    }
    if (-not (Test-Path -LiteralPath $TokenPath -PathType Leaf)) {
        throw [System.InvalidOperationException]::new("auth_credential_file_missing")
    }
    if ([string]::IsNullOrWhiteSpace($RunnerAddress)) {
        throw [System.InvalidOperationException]::new("runner_address_missing")
    }
    if (([string]::IsNullOrWhiteSpace($TlsCertPath)) -xor ([string]::IsNullOrWhiteSpace($TlsKeyPath))) {
        throw [System.InvalidOperationException]::new("tls_partial_configuration")
    }
}

function Invoke-Install {
    Assert-InstallInput
    Assert-RunnerObservabilityServiceAbsent -ServiceName $ServiceName
    $databaseDirectory = Split-Path -Parent $DatabasePath
    $configuration = @{
        service_name = $ServiceName
        python_executable = $PythonPath
        database = $DatabasePath
        token_file = $TokenPath
        host = "0.0.0.0"
        port = $Port
        tls_cert = if ([string]::IsNullOrWhiteSpace($TlsCertPath)) { $null } else { $TlsCertPath }
        tls_key = if ([string]::IsNullOrWhiteSpace($TlsKeyPath)) { $null } else { $TlsKeyPath }
        release_root = (Split-Path -Parent $ConfigPath)
    }

    Write-RunnerObservabilityConfigAtomic -Path $ConfigPath -Configuration $configuration
    Set-RunnerObservabilityFileAcl -Path $ConfigPath -ServiceAccount $ServiceAccount -Access "R"
    Set-RunnerObservabilityFileAcl -Path $TokenPath -ServiceAccount $ServiceAccount -Access "R"
    Set-RunnerObservabilityDirectoryAcl -Path $databaseDirectory -ServiceAccount $ServiceAccount
    if (-not [string]::IsNullOrWhiteSpace($TlsCertPath)) {
        Set-RunnerObservabilityFileAcl -Path $TlsCertPath -ServiceAccount $ServiceAccount -Access "R"
        Set-RunnerObservabilityFileAcl -Path $TlsKeyPath -ServiceAccount $ServiceAccount -Access "R"
    }
    Register-RunnerObservabilityService -ServiceName $ServiceName -PythonPath $PythonPath -ConfigPath $ConfigPath -ServiceAccount $ServiceAccount
    Ensure-RunnerObservabilityFirewallRule -RunnerAddress $RunnerAddress -Port $Port
    Write-Output "service operation=install result=pass"
}

try {
    switch ($Action) {
        "Install" { Invoke-Install }
        "Start" { Start-RunnerObservabilityService -ServiceName $ServiceName | Out-Null; Write-Output "service operation=start result=pass" }
        "Stop" { Stop-RunnerObservabilityService -ServiceName $ServiceName | Out-Null; Write-Output "service operation=stop result=pass" }
        "Status" {
            $state = Get-RunnerObservabilityServiceState -ServiceName $ServiceName
            Write-Output ("service operation=status state=" + $state.ToLowerInvariant())
        }
        "Restart" {
            Stop-RunnerObservabilityService -ServiceName $ServiceName | Out-Null
            Start-RunnerObservabilityService -ServiceName $ServiceName | Out-Null
            Write-Output "service operation=restart result=pass"
        }
        "Uninstall" {
            Stop-RunnerObservabilityService -ServiceName $ServiceName | Out-Null
            Remove-RunnerObservabilityService -ServiceName $ServiceName | Out-Null
            Remove-RunnerObservabilityFirewallRule
            Write-Output "service operation=uninstall result=pass"
        }
    }
    exit 0
}
catch {
    $reason = $_.Exception.Message
    if ($reason -notin @("service_already_exists", "service_state_timeout")) {
        $reason = "service_operation_failed"
    }
    Write-Error ("service operation failed reason=" + $reason)
    exit 2
}
