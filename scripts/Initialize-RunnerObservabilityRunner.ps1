<#
.SYNOPSIS
    Interactive, guarded clean rebuild of the Runner observability agent.

.DESCRIPTION
    This is the single-command Runner onboarding entry point. It inventories
    the target first, checks the Monitor endpoint, requires an explicit reset
    confirmation, waits for the operator to place the new token and public
    certificate, stages the current checkout HEAD, and delegates service
    lifecycle work to Install-RunnerObservabilityRunner.ps1.

    The script never copies secrets between hosts, prints token contents, or
    deletes the GitHub Actions Runner registration.
#>
[CmdletBinding()]
param(
    [switch]$CleanRebuild,
    [string]$MonitorIp = "",
    [string]$MonitorHost = "monitor-test.local",
    [string]$Endpoint = "",
    [string]$PythonPath = "",
    [string]$SourceRoot = "",
    [string]$InstallRoot = "C:\runner-observability-agent",
    [string]$SecretRoot = "C:\runner-observability-secrets",
    [string]$RunnerAccount = "",
    [string]$ServiceName = "RunnerObservabilityHeartbeat",
    [string]$ServiceAccount = "NT AUTHORITY\LocalService",
    [ValidateSet("PublicCa", "PrivateCa", "SelfSigned", "Existing", "None")]
    [string]$CertificateTrustModel = "SelfSigned",
    [string]$ExpectedCertificateSha256 = "",
    [switch]$AllowHostsChange,
    [switch]$NoWaitForSecrets,
    [switch]$SkipCertificateImport,
    [switch]$AllowInsecureHttp,
    [switch]$WhatIf
)

$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($SourceRoot)) {
    $SourceRoot = Split-Path -Parent $PSScriptRoot
}

$bootstrapPath = Join-Path $PSScriptRoot "RunnerObservability.Bootstrap.psm1"
$runnerScript = Join-Path $PSScriptRoot "Install-RunnerObservabilityRunner.ps1"
Import-Module $bootstrapPath -Force

$tokenPath = Join-Path $SecretRoot "monitor-token.txt"
$certificatePath = Join-Path $SecretRoot "monitor.crt"
$privateKeyPath = Join-Path $SecretRoot "monitor.key"
$hostsPath = Join-Path $env:SystemRoot "System32\drivers\etc\hosts"
$script:ImportCertificate = $false

function New-RunnerWizardError {
    param([Parameter(Mandatory = $true)][string]$Reason)

    return [System.InvalidOperationException]::new($Reason)
}

function Assert-RunnerWizardAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw (New-RunnerWizardError -Reason "administrator_required")
    }
}

function Get-FullPath {
    param([Parameter(Mandatory = $true)][string]$Path)

    try {
        return ([IO.Path]::GetFullPath($Path)).TrimEnd("\")
    }
    catch {
        throw (New-RunnerWizardError -Reason "path_invalid")
    }
}

function Assert-RunnerWizardOwnedPaths {
    $managedInstall = Get-FullPath -Path $InstallRoot
    $managedSecrets = Get-FullPath -Path $SecretRoot
    $source = Get-FullPath -Path $SourceRoot
    $runnerRoot = Get-FullPath -Path "C:\actions-runner"
    $systemDrive = Get-FullPath -Path ([IO.Path]::GetPathRoot($managedInstall))

    if (($managedInstall -eq $systemDrive) -or ($managedSecrets -eq $systemDrive)) {
        throw (New-RunnerWizardError -Reason "owned_path_too_broad")
    }
    if ($managedInstall -ieq $managedSecrets) {
        throw (New-RunnerWizardError -Reason "install_and_secret_roots_must_differ")
    }
    if (($managedInstall -ieq $runnerRoot) -or
        $managedInstall.StartsWith($runnerRoot + "\", [StringComparison]::OrdinalIgnoreCase) -or
        ($managedSecrets -ieq $runnerRoot) -or
        $managedSecrets.StartsWith($runnerRoot + "\", [StringComparison]::OrdinalIgnoreCase)) {
        throw (New-RunnerWizardError -Reason "runner_root_not_owned")
    }
    if (($managedInstall.StartsWith($managedSecrets + "\", [StringComparison]::OrdinalIgnoreCase)) -or
        ($managedSecrets.StartsWith($managedInstall + "\", [StringComparison]::OrdinalIgnoreCase))) {
        throw (New-RunnerWizardError -Reason "install_and_secret_roots_must_be_siblings")
    }
    if (($managedInstall -ieq $source) -or ($managedSecrets -ieq $source)) {
        throw (New-RunnerWizardError -Reason "source_root_not_owned")
    }
    if ($managedInstall.StartsWith($source + "\", [StringComparison]::OrdinalIgnoreCase)) {
        throw (New-RunnerWizardError -Reason "install_root_inside_source")
    }
    if ($managedSecrets.StartsWith($source + "\", [StringComparison]::OrdinalIgnoreCase)) {
        throw (New-RunnerWizardError -Reason "secret_root_inside_source")
    }
}

function Get-RunnerWizardPythonCandidates {
    $candidates = [System.Collections.Generic.List[string]]::new()
    $addCandidate = {
        param([AllowNull()][string]$Candidate)

        if ([string]::IsNullOrWhiteSpace($Candidate)) {
            return
        }
        $normalized = $Candidate.Trim().Trim('"')
        if (-not [string]::IsNullOrWhiteSpace($normalized) -and
            -not @($candidates | Where-Object { $_ -ieq $normalized })) {
            [void]$candidates.Add($normalized)
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($PythonPath)) {
        & $addCandidate $PythonPath
        return @($candidates)
    }

    foreach ($commandName in @("python.exe", "python")) {
        foreach ($command in @(Get-Command $commandName -All -ErrorAction SilentlyContinue | Where-Object { $_.CommandType -eq "Application" })) {
            & $addCandidate ([string]$command.Source)
        }
    }

    $launcher = Get-Command "py.exe" -ErrorAction SilentlyContinue |
        Where-Object { $_.CommandType -eq "Application" } |
        Select-Object -First 1
    if ($null -ne $launcher) {
        $launcherOutput = @(& $launcher.Source -0p 2>$null)
        foreach ($line in $launcherOutput) {
            $lineText = [string]$line
            if ($lineText -match '(?<path>[A-Za-z]:\\.*\\python(?:\.exe)?)\s*$') {
                & $addCandidate $Matches.path
            }
        }
    }

    return @($candidates)
}

function Test-RunnerWizardPythonCandidate {
    param([Parameter(Mandatory = $true)][string]$CandidatePath)

    $result = [ordered]@{
        Path = $CandidatePath
        Version = ""
        VersionSupported = $false
        ServiceRuntimeAvailable = $false
        Status = "unknown"
        ExitCode = $null
    }
    if (-not (Test-Path -LiteralPath $CandidatePath -PathType Leaf)) {
        $result.Status = "not_found"
        return [pscustomobject]$result
    }

    try {
        $versionOutput = @(& $CandidatePath -s --version 2>&1)
        $versionExitCode = $LASTEXITCODE
        $versionText = [string]($versionOutput -join [Environment]::NewLine)
    }
    catch {
        $versionExitCode = -1
        $versionText = [string]$_.Exception.Message
    }
    $result.ExitCode = $versionExitCode
    if (($versionExitCode -eq -1073741790) -or ($versionText -match "(?i)Access is denied")) {
        $result.Status = "access_denied"
        return [pscustomobject]$result
    }
    if ($versionExitCode -ne 0) {
        $result.Status = "execute_failed"
        return [pscustomobject]$result
    }
    if ($versionText -notmatch '(?i)Python\s+(?<version>\d+\.\d+\.\d+)') {
        $result.Status = "version_invalid"
        return [pscustomobject]$result
    }
    $result.Version = $Matches.version
    $version = [version]$Matches.version
    $result.VersionSupported = (($version.Major -gt 3) -or (($version.Major -eq 3) -and ($version.Minor -ge 11)))
    if (-not $result.VersionSupported) {
        $result.Status = "version_unsupported"
        return [pscustomobject]$result
    }

    try {
        $serviceRuntimeOutput = @(& $CandidatePath -s -c "import servicemanager, win32event, win32service, win32serviceutil" 2>&1)
        $serviceRuntimeExitCode = $LASTEXITCODE
        $serviceRuntimeText = [string]($serviceRuntimeOutput -join [Environment]::NewLine)
    }
    catch {
        $serviceRuntimeExitCode = -1
        $serviceRuntimeText = [string]$_.Exception.Message
    }
    if (($serviceRuntimeExitCode -eq -1073741790) -or ($serviceRuntimeText -match "(?i)Access is denied")) {
        $result.Status = "access_denied"
        return [pscustomobject]$result
    }
    if ($serviceRuntimeExitCode -ne 0) {
        $result.Status = "service_runtime_unavailable"
        return [pscustomobject]$result
    }
    $result.ServiceRuntimeAvailable = $true
    $result.Status = "usable"
    return [pscustomobject]$result
}

function Resolve-RunnerWizardPython {
    $candidatePaths = @(Get-RunnerWizardPythonCandidates)
    if ($candidatePaths.Count -eq 0) {
        Write-Output "python_install_hint=Install Python 3.11 or newer from the approved software channel, then rerun this wizard"
        throw (New-RunnerWizardError -Reason "python_not_found")
    }

    $supportedVersionFound = $false
    $serviceRuntimeMissing = $false
    $serviceRuntimeCandidatePaths = [System.Collections.Generic.List[string]]::new()
    $accessDeniedCount = 0
    $executeFailureCount = 0
    foreach ($candidatePath in $candidatePaths) {
        $candidate = Test-RunnerWizardPythonCandidate -CandidatePath $candidatePath
        if ($candidate.VersionSupported) {
            $supportedVersionFound = $true
        }
        if ($candidate.ServiceRuntimeAvailable -and $candidate.VersionSupported) {
            $script:PythonPath = $candidate.Path
            Write-Output ("python_path={0}" -f $candidate.Path)
            Write-Output ("python_version={0}" -f $candidate.Version)
            return
        }
        switch ($candidate.Status) {
            "access_denied" {
                $accessDeniedCount += 1
                Write-Output ("python_candidate_access_denied={0}" -f $candidate.Path)
            }
            "execute_failed" {
                $executeFailureCount += 1
                Write-Output ("python_execute_exit_code={0}" -f $candidate.ExitCode)
            }
            "service_runtime_unavailable" {
                $serviceRuntimeMissing = $true
                if ($candidate.VersionSupported) {
                    [void]$serviceRuntimeCandidatePaths.Add($candidate.Path)
                }
            }
        }
    }

    if ($serviceRuntimeMissing -and $supportedVersionFound) {
        $runtimePath = $serviceRuntimeCandidatePaths[0]
        Write-Output ("python_service_runtime_path={0}" -f $runtimePath)
        Write-Output ("python_service_runtime_hint=Run `"{0}`" -m pip install --upgrade --no-user 'pywin32>=306', then rerun this wizard" -f $runtimePath)
        throw (New-RunnerWizardError -Reason "windows_service_runtime_unavailable")
    }
    if (($accessDeniedCount -eq $candidatePaths.Count) -and ($accessDeniedCount -gt 0)) {
        throw (New-RunnerWizardError -Reason "python_execute_access_denied")
    }
    if (-not $supportedVersionFound) {
        Write-Output "python_install_hint=Install Python 3.11 or newer from the approved software channel, then rerun this wizard"
        throw (New-RunnerWizardError -Reason "python_version_unsupported")
    }
    if ($executeFailureCount -gt 0) {
        throw (New-RunnerWizardError -Reason "python_execute_failed")
    }
    throw (New-RunnerWizardError -Reason "windows_service_runtime_unavailable")
}

function Get-RunnerWizardCertificateSha256 {
    param([Parameter(Mandatory = $true)][string]$Path)

    $certificate = $null
    try {
        $certificate = [Security.Cryptography.X509Certificates.X509Certificate2]::new($Path)
        return $certificate.GetCertHashString("SHA256").ToUpperInvariant()
    }
    catch {
        throw (New-RunnerWizardError -Reason "monitor_certificate_invalid")
    }
    finally {
        if ($null -ne $certificate) {
            $certificate.Dispose()
        }
    }
}

function Get-RunnerWizardHostMappings {
    if (-not (Test-Path -LiteralPath $hostsPath -PathType Leaf)) {
        return @()
    }
    $contents = [IO.File]::ReadAllText($hostsPath)
    $lines = @($contents -split "`r?`n")
    $entries = @()
    for ($index = 0; $index -lt $lines.Count; $index += 1) {
        $commentIndex = $lines[$index].IndexOf("#")
        if ($commentIndex -ge 0) {
            $body = $lines[$index].Substring(0, $commentIndex).Trim()
        }
        else {
            $body = $lines[$index].Trim()
        }
        if ([string]::IsNullOrWhiteSpace($body)) {
            continue
        }
        $parts = @($body -split "\s+")
        if (($parts.Count -ge 2) -and (@($parts[1..($parts.Count - 1)] | Where-Object { $_ -ieq $MonitorHost }).Count -gt 0)) {
            $entries += [pscustomobject]@{
                Index = $index
                IpAddress = $parts[0]
                Line = $lines[$index]
            }
        }
    }
    return @($entries)
}

function Remove-RunnerWizardHostMappings {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$Mappings
    )

    if (($null -eq $Mappings) -or ($Mappings.Count -eq 0)) {
        return "unchanged"
    }
    $contents = [IO.File]::ReadAllText($hostsPath)
    $newline = if ($contents.Contains("`r`n")) { "`r`n" } else { "`n" }
    $lines = @($contents -split "`r?`n")
    $kept = @()
    for ($index = 0; $index -lt $lines.Count; $index += 1) {
        if (@($Mappings | Where-Object { $_.Index -eq $index }).Count -eq 0) {
            $kept += $lines[$index]
            continue
        }
        $commentIndex = $lines[$index].IndexOf("#")
        $comment = if ($commentIndex -ge 0) { $lines[$index].Substring($commentIndex).Trim() } else { "" }
        $body = if ($commentIndex -ge 0) { $lines[$index].Substring(0, $commentIndex).Trim() } else { $lines[$index].Trim() }
        $parts = @($body -split "\s+")
        $remainingAliases = @($parts[1..($parts.Count - 1)] | Where-Object { $_ -ine $MonitorHost })
        if ($remainingAliases.Count -gt 0) {
            $replacement = $parts[0] + "`t" + ($remainingAliases -join "`t")
            if (-not [string]::IsNullOrWhiteSpace($comment)) {
                $replacement += " " + $comment
            }
            $kept += $replacement
        }
        elseif (-not [string]::IsNullOrWhiteSpace($comment)) {
            $kept += $comment
        }
    }
    $temporaryPath = Join-Path (Split-Path -Parent $hostsPath) (".hosts.runner-wizard." + [guid]::NewGuid().ToString("N") + ".tmp")
    $backupPath = Join-Path (Split-Path -Parent $hostsPath) (".hosts.runner-wizard." + [guid]::NewGuid().ToString("N") + ".bak")
    try {
        [IO.File]::WriteAllText($temporaryPath, (($kept -join $newline) + $newline), [Text.UTF8Encoding]::new($false))
        [IO.File]::Replace($temporaryPath, $hostsPath, $backupPath)
    }
    finally {
        if (Test-Path -LiteralPath $temporaryPath -PathType Leaf) {
            Remove-Item -LiteralPath $temporaryPath -Force -ErrorAction SilentlyContinue
        }
        if (Test-Path -LiteralPath $backupPath -PathType Leaf) {
            Remove-Item -LiteralPath $backupPath -Force -ErrorAction SilentlyContinue
        }
    }
    return "removed"
}

function Clear-RunnerWizardMachineEnvironment {
    foreach ($name in @(
        "RUNNER_OBSERVABILITY_INSTALL_ROOT",
        "RUNNER_OBSERVABILITY_ENDPOINT",
        "RUNNER_OBSERVABILITY_TOKEN_PATH",
        "RUNNER_OBSERVABILITY_RUNNER_ID"
    )) {
        [Environment]::SetEnvironmentVariable($name, $null, "Machine")
        if ($null -ne [Environment]::GetEnvironmentVariable($name, "Machine")) {
            throw (New-RunnerWizardError -Reason "machine_environment_clear_failed")
        }
    }
}

function Remove-RunnerWizardInstallRoot {
    if (-not (Test-Path -LiteralPath $InstallRoot -PathType Container)) {
        return
    }
    try {
        $item = Get-Item -LiteralPath $InstallRoot -Force -ErrorAction Stop
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw (New-RunnerWizardError -Reason "install_root_reparse_point")
        }
        # PowerShell Remove-Item can report Access Denied for this managed
        # tree even when the exact same tree is removable by the Windows
        # directory-delete primitive. Keep the target exact and let cmd.exe
        # invoke rd without interpolating any operator-controlled command.
        $nativeDeleteOutput = @(& cmd.exe /d /c rd /s /q "$InstallRoot" 2>&1)
        $nativeDeleteExitCode = $LASTEXITCODE
        if (($nativeDeleteExitCode -ne 0) -or (Test-Path -LiteralPath $InstallRoot)) {
            throw (New-RunnerWizardError -Reason "reset_install_root_cleanup_failed")
        }
    }
    catch {
        if ($_.Exception.Message -eq "install_root_reparse_point") {
            throw
        }
        Write-Output "reset_acl_repair=install_root"
        try {
            & takeown.exe /f $InstallRoot /r /d Y 2>&1 | Out-Null
            if ($LASTEXITCODE -ne 0) {
                throw (New-RunnerWizardError -Reason "reset_install_root_cleanup_failed")
            }
            & icacls.exe $InstallRoot /grant:r "Administrators:(OI)(CI)(F)" /t /c 2>&1 | Out-Null
            if ($LASTEXITCODE -ne 0) {
                throw (New-RunnerWizardError -Reason "reset_install_root_cleanup_failed")
            }
            $nativeDeleteOutput = @(& cmd.exe /d /c rd /s /q "$InstallRoot" 2>&1)
            $nativeDeleteExitCode = $LASTEXITCODE
            if (($nativeDeleteExitCode -ne 0) -or (Test-Path -LiteralPath $InstallRoot)) {
                throw (New-RunnerWizardError -Reason "reset_install_root_cleanup_failed")
            }
        }
        catch {
            if ($_.Exception.Message -eq "reset_install_root_cleanup_failed") {
                throw
            }
            throw (New-RunnerWizardError -Reason "reset_install_root_cleanup_failed")
        }
    }
    if (Test-Path -LiteralPath $InstallRoot) {
        throw (New-RunnerWizardError -Reason "reset_install_root_cleanup_failed")
    }
}

function Invoke-RunnerScript {
    param([Parameter(Mandatory = $true)][ValidateSet("Uninstall", "Preflight", "Configure", "Start")][string]$Action)

    $arguments = @{
        Action = $Action
        PythonPath = $PythonPath
        InstallRoot = $InstallRoot
        Endpoint = $Endpoint
        TokenPath = $tokenPath
        MonitorHost = $MonitorHost
        MonitorIp = $MonitorIp
        CertificateTrustModel = $CertificateTrustModel
        MonitorCertificatePath = $certificatePath
        ExpectedCertificateSha256 = $ExpectedCertificateSha256
        RunnerAccount = $RunnerAccount
        ServiceName = $ServiceName
        ServiceAccount = $ServiceAccount
    }
    if ($script:ImportCertificate) {
        $arguments["ImportCertificate"] = $true
    }
    if ($AllowHostsChange) {
        $arguments["AllowHostsChange"] = $true
    }
    if ($AllowInsecureHttp) {
        $arguments["AllowInsecureHttp"] = $true
    }
    # A successful child script does not necessarily overwrite PowerShell's
    # automatic LASTEXITCODE. Clear a stale value before invoking it so a
    # completed uninstall/configure action cannot be reported as failed.
    $global:LASTEXITCODE = 0
    & $runnerScript @arguments
    if ($LASTEXITCODE -ne 0) {
        throw (New-RunnerWizardError -Reason ("runner_action_failed_" + $Action.ToLowerInvariant()))
    }
}

function Invoke-RunnerWizardSmokeTest {
    param([Parameter(Mandatory = $true)][string]$ReleaseSource)

    $previousPythonPath = $env:PYTHONPATH
    try {
        $env:PYTHONPATH = $ReleaseSource
        & $PythonPath -s -m runner_observability --help 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw (New-RunnerWizardError -Reason "release_import_smoke_failed")
        }
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

function Invoke-RunnerWizard {
    if (-not $CleanRebuild) {
        throw (New-RunnerWizardError -Reason "clean_rebuild_required")
    }
    Assert-RunnerWizardAdministrator
    Assert-RunnerWizardOwnedPaths

    # Step 0: this is deliberately the first target-host operation.
    try {
        $inventory = Get-RunnerObservabilityInventory `
            -CandidateRunnerRoots @("C:\actions-runner") `
            -CandidateInstallRoots @($InstallRoot) `
            -CandidateSecretRoots @($SecretRoot) `
            -ServiceNamePatterns @("*action*", "*runner*", "*observability*", "*promeo*", $ServiceName)
    }
    catch {
        $errorRecord = $_
        $accessDenied = ($errorRecord.Exception -is [System.UnauthorizedAccessException]) -or
            ($errorRecord.FullyQualifiedErrorId -match "(?i)UnauthorizedAccess|PermissionDenied")
        if (-not $accessDenied -and ($null -ne $errorRecord.Exception.InnerException)) {
            $accessDenied = $errorRecord.Exception.InnerException -is [System.UnauthorizedAccessException]
        }
        if ($accessDenied) {
            throw (New-RunnerWizardError -Reason "secret_inventory_access_denied")
        }
        throw
    }
    $secretAccessDenied = @($inventory.SecretFiles | Where-Object { $_.AccessDenied })
    if ($secretAccessDenied.Count -gt 0) {
        throw (New-RunnerWizardError -Reason "secret_inventory_access_denied")
    }
    $initialInspection = Assert-RunnerObservabilityInventoryGate `
        -Inventory $inventory -InstallRoot $InstallRoot -Operation "Troubleshooting" -Role "Runner"
    Write-Output "inventory.computer=$env:COMPUTERNAME"
    Write-Output ("inventory.install_root_state={0}" -f $initialInspection.ReleaseState)
    Write-Output ("inventory.install_revision={0}" -f $(if ($null -eq $initialInspection.Revision) { "none" } else { $initialInspection.Revision }))
    Write-Output ("inventory.secret_root_exists={0}" -f (Test-Path -LiteralPath $SecretRoot -PathType Container))

    if (-not (Test-RunnerObservabilityMonitorIp -MonitorIp $MonitorIp)) {
        if ([string]::IsNullOrWhiteSpace($MonitorIp)) {
            $script:MonitorIp = (Read-Host "Enter the confirmed Monitor IPv4 address")
        }
    }
    if (-not (Test-RunnerObservabilityMonitorIp -MonitorIp $MonitorIp)) {
        throw (New-RunnerWizardError -Reason "monitor_ip_invalid")
    }
    if ([string]::IsNullOrWhiteSpace($Endpoint)) {
        $script:Endpoint = "https://${MonitorHost}:8765/v1/events"
    }
    Resolve-RunnerWizardPython

    if ($WhatIf) {
        Write-Output "whatif=true"
        Write-Output "status=OK"
        Write-Output "plan=inventory,monitor_port_check,reset,secret_gate,stage_current_head,configure,start"
        return
    }

    $portReachable = $false
    try {
        $portReachable = [bool](Test-NetConnection -ComputerName $MonitorIp -Port 8765 -InformationLevel Quiet -WarningAction SilentlyContinue)
    }
    catch {
        $portReachable = $false
    }
    if (-not $portReachable) {
        throw (New-RunnerWizardError -Reason "monitor_port_unreachable")
    }
    Write-Output "monitor_port=reachable"

    $oldCertificateThumbprint = $null
    $oldCertificateStoreEntries = @()
    if (Test-Path -LiteralPath $certificatePath -PathType Leaf) {
        $oldCertificateThumbprint = Get-RunnerWizardCertificateSha256 -Path $certificatePath
        try {
            $oldCertificateStoreEntries = @(Get-ChildItem -Path "Cert:\LocalMachine\Root" -ErrorAction Stop | Where-Object { $_.Thumbprint -ieq $oldCertificateThumbprint })
        }
        catch {
            throw (New-RunnerWizardError -Reason "certificate_store_inventory_failed")
        }
    }
    $oldHostMappings = @(Get-RunnerWizardHostMappings)

    Write-Output "reset_scope.install_root=$InstallRoot"
    Write-Output "reset_scope.secret_files=monitor-token.txt,monitor.crt"
    Write-Output "reset_scope.machine_environment=RUNNER_OBSERVABILITY_*"
    Write-Output "reset_scope.runner_registration=preserved"
    Write-Output "reset_scope.private_key=preserved_and_rejected"
    $confirmation = Read-Host "Type RESET-RUNNER to continue"
    if ($confirmation -cne "RESET-RUNNER") {
        throw (New-RunnerWizardError -Reason "reset_cancelled")
    }
    if ($oldCertificateStoreEntries.Count -gt 0) {
        Write-Output ("old_certificate_sha256={0}" -f $oldCertificateThumbprint)
        $trustConfirmation = Read-Host "Type REMOVE-OLD-MONITOR-CERT to remove the exact matching LocalMachine Root entry"
        if ($trustConfirmation -cne "REMOVE-OLD-MONITOR-CERT") {
            throw (New-RunnerWizardError -Reason "certificate_cleanup_confirmation_required")
        }
    }
    if ($AllowHostsChange -and ($oldHostMappings.Count -gt 0)) {
        Write-Output ("old_hosts_mapping_count={0}" -f $oldHostMappings.Count)
        $hostsConfirmation = Read-Host "Type REMOVE-OLD-MONITOR-HOSTS to remove the exact $MonitorHost entries"
        if ($hostsConfirmation -cne "REMOVE-OLD-MONITOR-HOSTS") {
            throw (New-RunnerWizardError -Reason "hosts_cleanup_confirmation_required")
        }
    }

    Invoke-RunnerScript -Action "Uninstall"
    Remove-RunnerWizardInstallRoot
    foreach ($path in @($tokenPath, $certificatePath)) {
        if (Test-Path -LiteralPath $path -PathType Leaf) {
            Remove-Item -LiteralPath $path -Force
        }
    }
    if (Test-Path -LiteralPath $privateKeyPath -PathType Leaf) {
        throw (New-RunnerWizardError -Reason "monitor_key_not_allowed")
    }
    if ($oldCertificateStoreEntries.Count -gt 0) {
        foreach ($entry in $oldCertificateStoreEntries) {
            Remove-Item -LiteralPath $entry.PSPath -Force
        }
        Write-Output "certificate_trust_cleanup=removed"
    }
    if ($AllowHostsChange) {
        Write-Output ("hosts_cleanup={0}" -f (Remove-RunnerWizardHostMappings -Mappings $oldHostMappings))
    }
    Clear-RunnerWizardMachineEnvironment
    Write-Output "reset=complete"

    New-Item -ItemType Directory -Path $SecretRoot -Force | Out-Null
    if (Test-Path -LiteralPath $privateKeyPath -PathType Leaf) {
        throw (New-RunnerWizardError -Reason "monitor_key_not_allowed")
    }
    $tokenExists = Test-Path -LiteralPath $tokenPath -PathType Leaf
    $certificateExists = Test-Path -LiteralPath $certificatePath -PathType Leaf
    if (-not ($tokenExists -and $certificateExists)) {
        Write-Output "status=WAITING_FOR_MONITOR_FILES"
        Write-Output ("copy_to={0}" -f $SecretRoot)
        Write-Output "required_files=monitor-token.txt,monitor.crt"
        Write-Output "forbidden_file=monitor.key"
        if ($NoWaitForSecrets) {
            return
        }
        Read-Host "Copy the two files through the approved secure channel, then press Enter" | Out-Null
        $tokenExists = Test-Path -LiteralPath $tokenPath -PathType Leaf
        $certificateExists = Test-Path -LiteralPath $certificatePath -PathType Leaf
    }
    if (Test-Path -LiteralPath $privateKeyPath -PathType Leaf) {
        throw (New-RunnerWizardError -Reason "monitor_key_not_allowed")
    }
    if (-not $tokenExists) {
        throw (New-RunnerWizardError -Reason "monitor_token_missing")
    }
    if (-not $certificateExists) {
        throw (New-RunnerWizardError -Reason "monitor_certificate_missing")
    }
    Write-Output ("token_file_exists={0}" -f $tokenExists)
    Write-Output ("token_file_length={0}" -f (Get-Item -LiteralPath $tokenPath).Length)
    Write-Output ("certificate_file_exists={0}" -f $certificateExists)

    $certificateSha256 = Get-RunnerWizardCertificateSha256 -Path $certificatePath
    if ($CertificateTrustModel -in @("SelfSigned", "PrivateCa") -and -not $SkipCertificateImport) {
        if ([string]::IsNullOrWhiteSpace($ExpectedCertificateSha256)) {
            Write-Output ("certificate_sha256={0}" -f $certificateSha256)
            $trustConfirmation = Read-Host "Verify this public fingerprint against the Monitor, then type TRUST-CERTIFICATE"
            if ($trustConfirmation -cne "TRUST-CERTIFICATE") {
                throw (New-RunnerWizardError -Reason "certificate_trust_confirmation_required")
            }
            $script:ExpectedCertificateSha256 = $certificateSha256
        }
        $script:ImportCertificate = $true
    }

    if (-not (Test-Path -LiteralPath (Join-Path $SourceRoot ".git") -PathType Container)) {
        throw (New-RunnerWizardError -Reason "source_checkout_missing")
    }
    $sourceSrc = Join-Path $SourceRoot "src"
    if (-not (Test-Path -LiteralPath (Join-Path $sourceSrc "runner_observability") -PathType Container)) {
        throw (New-RunnerWizardError -Reason "source_package_missing")
    }
    if (-not (Test-Path -LiteralPath (Join-Path $sourceSrc "runner_heartbeat_service.py") -PathType Leaf)) {
        throw (New-RunnerWizardError -Reason "heartbeat_launcher_missing")
    }
    $revision = ((& git -C $SourceRoot rev-parse --verify HEAD 2>$null) -join "").Trim()
    if (($LASTEXITCODE -ne 0) -or [string]::IsNullOrWhiteSpace($revision) -or $revision -notmatch "^[0-9a-fA-F]{40}$") {
        throw (New-RunnerWizardError -Reason "source_revision_unavailable")
    }
    $releaseRoot = Join-Path (Join-Path $InstallRoot "releases") $revision
    $releaseSource = Join-Path $releaseRoot "src"
    New-Item -ItemType Directory -Path $releaseSource -Force | Out-Null
    Copy-Item -Path (Join-Path $sourceSrc "*") -Destination $releaseSource -Recurse -Force
    Invoke-RunnerWizardSmokeTest -ReleaseSource $releaseSource
    $pointerTemp = Join-Path $InstallRoot "current-release.txt.tmp"
    Set-Content -LiteralPath $pointerTemp -Value $revision -Encoding ASCII
    Move-Item -LiteralPath $pointerTemp -Destination (Join-Path $InstallRoot "current-release.txt") -Force
    Write-Output ("staged_revision={0}" -f $revision)

    Invoke-RunnerScript -Action "Preflight" | Out-Null
    Invoke-RunnerScript -Action "Configure"
    Invoke-RunnerScript -Action "Start"
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if (($null -eq $service) -or ($service.Status.ToString() -ne "Running")) {
        throw (New-RunnerWizardError -Reason "heartbeat_service_not_running")
    }
    Write-Output ("heartbeat_service={0}" -f $service.Status)
    Write-Output "runner_listener_restart=manual_required"
    Write-Output "status=OK"
    Write-Output "ready_for_real_ci=false"
}

try {
    Invoke-RunnerWizard
}
catch {
    $reason = [string]$_.Exception.Message
    [System.Console]::Error.WriteLine("status=BLOCKED reason=" + $reason)
    exit 2
}
