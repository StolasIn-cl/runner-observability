[CmdletBinding()]
param(
    [ValidateSet("Install", "Start", "Stop", "Status", "Restart", "Uninstall")]
    [string]$Action = "Install",
    [string]$ConfigPath = "",
    [string]$PythonPath = "",
    [string]$Endpoint = "",
    [string]$TokenPath = "",
    [string]$RunnerId = "",
    [string]$StatePath = "",
    [string]$ProducerId = "runner-heartbeat",
    [string]$ServiceName = "RunnerObservabilityHeartbeat",
    [string]$ServiceAccount = "NT AUTHORITY\LocalService",
    [ValidateRange(1, 86400)]
    [int]$IntervalSeconds = 60,
    [switch]$AllowInsecureHttp
)

$ErrorActionPreference = "Stop"
$modulePath = Join-Path $PSScriptRoot "RunnerHeartbeat.Service.psm1"
Import-Module $modulePath -Force

function Assert-InstallInput {
    if ([string]::IsNullOrWhiteSpace($ConfigPath) -or [string]::IsNullOrWhiteSpace($PythonPath) -or [string]::IsNullOrWhiteSpace($Endpoint) -or [string]::IsNullOrWhiteSpace($TokenPath) -or [string]::IsNullOrWhiteSpace($RunnerId) -or [string]::IsNullOrWhiteSpace($StatePath)) {
        throw [System.InvalidOperationException]::new("service_configuration_missing")
    }
    if (-not (Test-Path -LiteralPath $PythonPath -PathType Leaf)) {
        throw [System.InvalidOperationException]::new("python_executable_missing")
    }
    if (-not (Test-Path -LiteralPath $TokenPath -PathType Leaf)) {
        throw [System.InvalidOperationException]::new("auth_credential_file_missing")
    }
    try {
        [guid]::Parse($RunnerId) | Out-Null
        $uri = [System.Uri]$Endpoint
        if ($uri.Scheme -notin @("https", "http") -or [string]::IsNullOrWhiteSpace($uri.Host)) {
            throw [System.InvalidOperationException]::new("invalid_endpoint")
        }
        if ($uri.Scheme -eq "http" -and -not $AllowInsecureHttp) {
            throw [System.InvalidOperationException]::new("insecure_endpoint")
        }
    }
    catch [System.InvalidOperationException] {
        throw
    }
    catch {
        throw [System.InvalidOperationException]::new("invalid_heartbeat_configuration")
    }
}

function Invoke-Install {
    Assert-InstallInput
    $stateDirectory = Split-Path -Parent $StatePath
    $configuration = @{
        endpoint = $Endpoint
        token_file = $TokenPath
        runner_id = $RunnerId
        state_file = $StatePath
        producer_id = $ProducerId
        service_name = $ServiceName
        python_executable = $PythonPath
        interval_seconds = $IntervalSeconds
        network_poll_seconds = 5
        allow_insecure_http = [bool]$AllowInsecureHttp
    }

    Write-RunnerHeartbeatConfigAtomic -Path $ConfigPath -Configuration $configuration
    Set-RunnerHeartbeatFileAcl -Path $ConfigPath -ServiceAccount $ServiceAccount -Access "R"
    Set-RunnerHeartbeatFileAcl -Path $TokenPath -ServiceAccount $ServiceAccount -Access "R"
    Set-RunnerHeartbeatDirectoryAcl -Path $stateDirectory -ServiceAccount $ServiceAccount
    Register-RunnerHeartbeatService -ServiceName $ServiceName -PythonPath $PythonPath -ConfigPath $ConfigPath -ServiceAccount $ServiceAccount
    Write-Output "service operation=install result=pass"
}

try {
    switch ($Action) {
        "Install" { Invoke-Install }
        "Start" { Start-RunnerHeartbeatService -ServiceName $ServiceName; Write-Output "service operation=start result=pass" }
        "Stop" { Stop-RunnerHeartbeatService -ServiceName $ServiceName; Write-Output "service operation=stop result=pass" }
        "Status" { Write-Output ("service operation=status state=" + (Get-RunnerHeartbeatServiceState -ServiceName $ServiceName)) }
        "Restart" {
            Stop-RunnerHeartbeatService -ServiceName $ServiceName
            Start-RunnerHeartbeatService -ServiceName $ServiceName
            Write-Output "service operation=restart result=pass"
        }
        "Uninstall" {
            Stop-RunnerHeartbeatService -ServiceName $ServiceName
            Remove-RunnerHeartbeatService -ServiceName $ServiceName
            Write-Output "service operation=uninstall result=pass"
        }
    }
    exit 0
}
catch {
    Write-Error "service operation failed reason=service_operation_failed"
    exit 2
}
