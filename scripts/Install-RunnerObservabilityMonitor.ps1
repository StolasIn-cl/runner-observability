<#
.SYNOPSIS
    Safe Monitor Host onboarding and Windows Service lifecycle entry point.

.DESCRIPTION
    This script owns only the Monitor role. It starts with the shared
    read-only inventory, keeps token/private-key material out of command
    lines and output, and delegates ACL and SCM operations to the existing
    bootstrap and service adapters.

    SelfSigned is an explicit development/test mode. It uses the Windows
    .NET CertificateRequest API when available and falls back to the Windows
    PKI New-SelfSignedCertificate cmdlet when the host runtime lacks modern
    PKCS#8 export methods. Private-key encoding remains in-script and requires
    no external certificate tool.
#>
[CmdletBinding()]
param(
    [ValidateSet("Preflight", "Install", "RepairPermissions", "Start", "Stop", "Restart", "Status", "Uninstall")]
    [string]$Action = "Preflight",
    [string]$PythonPath = "",
    [string]$ConfigPath = "C:\runner-observability\service-config.json",
    [string]$DatabasePath = "C:\runner-observability-data\monitor.sqlite",
    [string]$SecretRoot = "C:\runner-observability-secrets",
    [string]$TokenPath = "",
    [string]$TlsCertPath = "",
    [string]$TlsKeyPath = "",
    [ValidateSet("PublicCa", "PrivateCa", "SelfSigned", "Existing")]
    [string]$CertificateMode = "Existing",
    [string[]]$RunnerAddress = @(),
    [string]$ServiceName = "RunnerObservabilityMonitor",
    [string]$ServiceAccount = "NT AUTHORITY\LocalService",
    [switch]$AllowDevSelfSigned,
    [switch]$WhatIf
)

$ErrorActionPreference = "Stop"

$bootstrapPath = Join-Path $PSScriptRoot "RunnerObservability.Bootstrap.psm1"
$serviceModulePath = Join-Path $PSScriptRoot "RunnerObservability.Service.psm1"
Import-Module $bootstrapPath -Force
Import-Module $serviceModulePath -Force

if ([string]::IsNullOrWhiteSpace($TokenPath)) {
    $TokenPath = Join-Path $SecretRoot "monitor-token.txt"
}
if ([string]::IsNullOrWhiteSpace($TlsCertPath)) {
    $TlsCertPath = Join-Path $SecretRoot "monitor.crt"
}
if ([string]::IsNullOrWhiteSpace($TlsKeyPath)) {
    $TlsKeyPath = Join-Path $SecretRoot "monitor.key"
}

function New-MonitorStableError {
    param([Parameter(Mandatory = $true)][string]$Reason)

    return [System.InvalidOperationException]::new($Reason)
}

function ConvertTo-MonitorPem {
    param(
        [Parameter(Mandatory = $true)][byte[]]$Bytes,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $base64 = [Convert]::ToBase64String($Bytes)
    $builder = [Text.StringBuilder]::new()
    [void]$builder.AppendLine("-----BEGIN $Label-----")
    for ($offset = 0; $offset -lt $base64.Length; $offset += 64) {
        $length = [Math]::Min(64, $base64.Length - $offset)
        [void]$builder.AppendLine($base64.Substring($offset, $length))
    }
    [void]$builder.AppendLine("-----END $Label-----")
    return $builder.ToString()
}

function ConvertTo-MonitorDerLength {
    param([Parameter(Mandatory = $true)][int]$Length)

    if ($Length -lt 128) {
        return ,([byte[]]@([byte]$Length))
    }

    $octets = New-Object 'System.Collections.Generic.List[byte]'
    $remaining = $Length
    while ($remaining -gt 0) {
        $octets.Insert(0, [byte]($remaining -band 0xff))
        $remaining = [int][Math]::Floor($remaining / 256)
    }
    $encoded = New-Object 'System.Collections.Generic.List[byte]'
    $encoded.Add([byte](0x80 -bor $octets.Count))
    $encoded.AddRange($octets.ToArray())
    return ,([byte[]]$encoded.ToArray())
}

function ConvertTo-MonitorDerTlv {
    param(
        [Parameter(Mandatory = $true)][byte]$Tag,
        [byte[]]$Content
    )

    $encoded = New-Object 'System.Collections.Generic.List[byte]'
    $encoded.Add($Tag)
    $encoded.AddRange((ConvertTo-MonitorDerLength -Length $Content.Length))
    $encoded.AddRange($Content)
    return ,([byte[]]$encoded.ToArray())
}

function ConvertTo-MonitorDerInteger {
    param([Parameter(Mandatory = $true)][byte[]]$Value)

    $first = 0
    while (($first -lt ($Value.Length - 1)) -and ($Value[$first] -eq 0)) {
        $first++
    }

    $content = New-Object 'System.Collections.Generic.List[byte]'
    if (($Value[$first] -band 0x80) -ne 0) {
        $content.Add([byte]0)
    }
    for ($index = $first; $index -lt $Value.Length; $index++) {
        $content.Add($Value[$index])
    }
    return ,(ConvertTo-MonitorDerTlv -Tag 0x02 -Content ([byte[]]$content.ToArray()))
}

function ConvertTo-MonitorPkcs8Pem {
    param([Parameter(Mandatory = $true)][Security.Cryptography.RSAParameters]$Parameters)

    $rsaPrivateKey = New-Object 'System.Collections.Generic.List[byte]'
    foreach ($component in @(
            [byte[]]@([byte]0),
            $Parameters.Modulus,
            $Parameters.Exponent,
            $Parameters.D,
            $Parameters.P,
            $Parameters.Q,
            $Parameters.DP,
            $Parameters.DQ,
            $Parameters.InverseQ
        )) {
        $rsaPrivateKey.AddRange((ConvertTo-MonitorDerInteger -Value $component))
    }
    $rsaPrivateKeyDer = ConvertTo-MonitorDerTlv -Tag 0x30 -Content ([byte[]]$rsaPrivateKey.ToArray())

    $algorithmIdentifier = New-Object 'System.Collections.Generic.List[byte]'
    $algorithmIdentifier.AddRange((ConvertTo-MonitorDerTlv -Tag 0x06 -Content ([byte[]]@(
                0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01
            ))))
    $algorithmIdentifier.AddRange((ConvertTo-MonitorDerTlv -Tag 0x05 -Content ([byte[]]@())))
    $algorithmIdentifierDer = ConvertTo-MonitorDerTlv -Tag 0x30 -Content ([byte[]]$algorithmIdentifier.ToArray())

    $privateKeyInfo = New-Object 'System.Collections.Generic.List[byte]'
    $privateKeyInfo.AddRange((ConvertTo-MonitorDerInteger -Value ([byte[]]@([byte]0))))
    $privateKeyInfo.AddRange($algorithmIdentifierDer)
    $privateKeyInfo.AddRange((ConvertTo-MonitorDerTlv -Tag 0x04 -Content $rsaPrivateKeyDer))
    $privateKeyInfoDer = ConvertTo-MonitorDerTlv -Tag 0x30 -Content ([byte[]]$privateKeyInfo.ToArray())
    return ConvertTo-MonitorPem -Bytes $privateKeyInfoDer -Label "PRIVATE KEY"
}

function Write-MonitorProtectedTextAtomically {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Contents,
        [Parameter(Mandatory = $true)][string]$ServiceAccount
    )

    $parent = Split-Path -Parent $Path
    New-Item -ItemType Directory -Path $parent -Force | Out-Null
    $temporaryPath = Join-Path $parent ("." + (Split-Path -Leaf $Path) + "." + [guid]::NewGuid().ToString("N") + ".tmp")
    try {
        # Create an empty file first, remove inherited access, then write the
        # PEM bytes. The private key must never exist as plaintext in an
        # inherited-permission temporary file.
        [IO.File]::WriteAllBytes($temporaryPath, [byte[]]@())
        Set-RunnerObservabilityFileAcl -Path $temporaryPath -ServiceAccount $ServiceAccount
        [IO.File]::WriteAllText($temporaryPath, $Contents, [Text.UTF8Encoding]::new($false))
        [IO.File]::Move($temporaryPath, $Path)
    }
    catch {
        if ($_.Exception.Message -eq "file_acl_failed") {
            throw
        }
        throw (New-MonitorStableError -Reason "certificate_file_write_failed")
    }
    finally {
        if (Test-Path -LiteralPath $temporaryPath -PathType Leaf) {
            Remove-Item -LiteralPath $temporaryPath -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-MonitorCertificateGenerationAvailable {
    $rsa = $null
    try {
        $requestType = "System.Security.Cryptography.X509Certificates.CertificateRequest" -as [Type]
        $rsa = [Security.Cryptography.RSA]::Create(2048)
        if ($rsa.KeySize -ne 2048) {
            throw "rsa_key_size_invalid"
        }
        try {
            $parameters = $rsa.ExportParameters($true)
            $hasExportableParameters = ($null -ne $parameters.Modulus) -and ($null -ne $parameters.D)
        }
        catch {
            $hasExportableParameters = $false
        }
        if (($null -ne $requestType) -and $hasExportableParameters) {
            return $true
        }
        return ($null -ne (Get-Command New-SelfSignedCertificate -ErrorAction SilentlyContinue))
    }
    catch {
        return $false
    }
    finally {
        if ($null -ne $rsa) {
            $rsa.Dispose()
        }
    }
}

function New-MonitorSelfSignedCertificate {
    param(
        [Parameter(Mandatory = $true)][string]$CertificatePath,
        [Parameter(Mandatory = $true)][string]$PrivateKeyPath
    )

    if (-not (Test-MonitorCertificateGenerationAvailable)) {
        throw (New-MonitorStableError -Reason "certificate_generation_unavailable")
    }
    if ((Test-Path -LiteralPath $CertificatePath -PathType Leaf) -or
        (Test-Path -LiteralPath $PrivateKeyPath -PathType Leaf)) {
        throw (New-MonitorStableError -Reason "certificate_files_exist")
    }

    $certParent = Split-Path -Parent $CertificatePath
    $keyParent = Split-Path -Parent $PrivateKeyPath
    New-Item -ItemType Directory -Path $certParent -Force | Out-Null
    New-Item -ItemType Directory -Path $keyParent -Force | Out-Null

    $rsa = $null
    $privateKeyProvider = $null
    $certificateStore = $null
    $certificate = $null
    $temporaryCertificate = Join-Path $certParent ("." + (Split-Path -Leaf $CertificatePath) + "." + [guid]::NewGuid().ToString("N") + ".tmp")
    $temporaryKey = Join-Path $keyParent ("." + (Split-Path -Leaf $PrivateKeyPath) + "." + [guid]::NewGuid().ToString("N") + ".tmp")
    try {
        $requestType = "System.Security.Cryptography.X509Certificates.CertificateRequest" -as [Type]
        $parameters = $null
        if ($null -ne $requestType) {
            try {
                $rsa = [Security.Cryptography.RSA]::Create(2048)
                $parameters = $rsa.ExportParameters($true)
            }
            catch {
                if ($null -ne $rsa) {
                    $rsa.Dispose()
                    $rsa = $null
                }
            }
        }

        if ($null -ne $rsa) {
            $request = [Security.Cryptography.X509Certificates.CertificateRequest]::new(
                "CN=monitor-test.local",
                $rsa,
                [Security.Cryptography.HashAlgorithmName]::SHA256,
                [Security.Cryptography.RSASignaturePadding]::Pkcs1
            )
            $request.CertificateExtensions.Add(
                [Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($false, $false, 0, $false)
            )
            $request.CertificateExtensions.Add(
                [Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new(
                    [Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature,
                    $false
                )
            )
            $san = [Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder]::new()
            $san.AddDnsName("monitor-test.local")
            $request.CertificateExtensions.Add($san.Build())

            $notBefore = [DateTimeOffset]::UtcNow.AddMinutes(-5)
            $notAfter = [DateTimeOffset]::UtcNow.AddYears(1)
            $certificate = $request.CreateSelfSigned($notBefore, $notAfter)
        }
        else {
            $nativeGenerator = Get-Command New-SelfSignedCertificate -ErrorAction SilentlyContinue
            if ($null -eq $nativeGenerator) {
                throw (New-MonitorStableError -Reason "certificate_generation_unavailable")
            }
            $certificateStore = New-Object System.Security.Cryptography.X509Certificates.X509Store("My", "CurrentUser")
            $certificateStore.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
            $certificate = New-SelfSignedCertificate `
                -Subject "CN=monitor-test.local" `
                -DnsName "monitor-test.local" `
                -CertStoreLocation "Cert:\CurrentUser\My" `
                -KeyAlgorithm RSA `
                -KeyLength 2048 `
                -HashAlgorithm SHA256 `
                -KeyExportPolicy Exportable `
                -NotAfter ([DateTime]::UtcNow.AddYears(1))
            $privateKeyProvider = $certificate.PrivateKey
            if ($null -eq $privateKeyProvider) {
                $rsaExtensionsType = "System.Security.Cryptography.X509Certificates.RSACertificateExtensions" -as [Type]
                if ($null -ne $rsaExtensionsType) {
                    $getPrivateKeyMethod = $rsaExtensionsType.GetMethod(
                        "GetRSAPrivateKey",
                        [Type[]]@([Security.Cryptography.X509Certificates.X509Certificate2])
                    )
                    if ($null -ne $getPrivateKeyMethod) {
                        $privateKeyProvider = $getPrivateKeyMethod.Invoke($null, @($certificate))
                    }
                }
            }
            if ($null -eq $privateKeyProvider) {
                throw (New-MonitorStableError -Reason "certificate_generation_unavailable")
            }
            $parameters = $privateKeyProvider.ExportParameters($true)
        }
        $certificatePem = ConvertTo-MonitorPem -Bytes $certificate.Export([Security.Cryptography.X509Certificates.X509ContentType]::Cert) -Label "CERTIFICATE"
        $privateKeyPem = ConvertTo-MonitorPkcs8Pem -Parameters $parameters

        Write-MonitorProtectedTextAtomically -Path $temporaryCertificate -Contents $certificatePem -ServiceAccount $ServiceAccount
        Write-MonitorProtectedTextAtomically -Path $temporaryKey -Contents $privateKeyPem -ServiceAccount $ServiceAccount
        [IO.File]::Move($temporaryCertificate, $CertificatePath)
        [IO.File]::Move($temporaryKey, $PrivateKeyPath)

        $hash = [Security.Cryptography.SHA256]::Create()
        try {
            $fingerprint = ([BitConverter]::ToString($hash.ComputeHash($certificate.RawData))).Replace("-", "")
        }
        finally {
            $hash.Dispose()
        }
        return [pscustomobject]@{
            Fingerprint = $fingerprint
            NotAfter = $certificate.NotAfter.ToUniversalTime().ToString("o")
        }
    }
    catch {
        if ($_.Exception.Message -in @(
                "certificate_generation_unavailable",
                "certificate_files_exist",
                "file_acl_failed"
            )) {
            throw
        }
        throw (New-MonitorStableError -Reason "certificate_generation_failed")
    }
    finally {
        if ($null -ne $certificate) {
            if ($null -ne $certificateStore) {
                try { $certificateStore.Remove($certificate) } catch { }
            }
            $certificate.Dispose()
        }
        if ($null -ne $certificateStore) {
            $certificateStore.Close()
        }
        if ($null -ne $privateKeyProvider) {
            $privateKeyProvider.Dispose()
        }
        if ($null -ne $rsa) {
            $rsa.Dispose()
        }
        foreach ($temporaryPath in @($temporaryCertificate, $temporaryKey)) {
            if (Test-Path -LiteralPath $temporaryPath -PathType Leaf) {
                Remove-Item -LiteralPath $temporaryPath -Force -ErrorAction SilentlyContinue
            }
        }
    }
}

function Test-MonitorPathPair {
    if ([string]::IsNullOrWhiteSpace($TlsCertPath) -or [string]::IsNullOrWhiteSpace($TlsKeyPath)) {
        throw (New-MonitorStableError -Reason "certificate_key_pair_missing")
    }
    if (-not (Test-Path -LiteralPath $TlsCertPath -PathType Leaf) -or
        -not (Test-Path -LiteralPath $TlsKeyPath -PathType Leaf)) {
        throw (New-MonitorStableError -Reason "certificate_key_pair_missing")
    }
}

function Assert-MonitorCertificateConfiguration {
    switch ($CertificateMode) {
        "SelfSigned" {
            if (-not $AllowDevSelfSigned) {
                throw (New-MonitorStableError -Reason "self_signed_not_allowed")
            }
            if (-not (Test-MonitorCertificateGenerationAvailable)) {
                throw (New-MonitorStableError -Reason "certificate_generation_unavailable")
            }
        }
        "PublicCa" { Test-MonitorPathPair }
        "PrivateCa" { Test-MonitorPathPair }
        "Existing" { Test-MonitorPathPair }
        default { throw (New-MonitorStableError -Reason "unsupported_certificate_mode") }
    }
}

function Invoke-MonitorInventory {
    $configRoot = Split-Path -Parent $ConfigPath
    # The Monitor config directory is not a managed Runner release root;
    # an existing service-config.json is safe to inspect and atomically
    # replace only after the exact Monitor service absence check.
    $inventory = Get-RunnerObservabilityInventory `
        -CandidateRunnerRoots @() `
        -CandidateInstallRoots @($configRoot) `
        -CandidateSecretRoots @($SecretRoot) `
        -ServiceNamePatterns @("*action*", "*runner*", "*observability*", "*promeo*", $ServiceName)
    Assert-RunnerObservabilityInventoryGate `
        -Inventory $inventory `
        -InstallRoot $configRoot `
        -Operation "Troubleshooting" `
        -Role "Monitor" | Out-Null
    return $inventory
}

function Assert-MonitorRunnerAddresses {
    if ($RunnerAddress.Count -eq 0) {
        throw (New-MonitorStableError -Reason "runner_address_required")
    }
    foreach ($address in $RunnerAddress) {
        if (-not (Test-RunnerObservabilityMonitorIp -MonitorIp $address)) {
            throw (New-MonitorStableError -Reason "runner_address_invalid")
        }
    }
}

function Assert-MonitorPython {
    if ([string]::IsNullOrWhiteSpace($PythonPath)) {
        $pythonCommand = Get-Command python -ErrorAction SilentlyContinue
        if ($null -eq $pythonCommand) {
            throw (New-MonitorStableError -Reason "python_not_found")
        }
        $script:PythonPath = $pythonCommand.Source
    }
    if (-not (Test-Path -LiteralPath $PythonPath -PathType Leaf)) {
        throw (New-MonitorStableError -Reason "python_not_found")
    }
}

function Assert-MonitorPythonImport {
    $previousPythonPath = $env:PYTHONPATH
    try {
        $env:PYTHONPATH = Join-Path (Split-Path -Parent $PSScriptRoot) "src"
        & $PythonPath -s -c "import runner_observability, runner_observability.service" 2>$null | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw (New-MonitorStableError -Reason "python_import_failed")
        }
    }
    catch {
        if ($_.Exception.Message -eq "python_import_failed") {
            throw
        }
        throw (New-MonitorStableError -Reason "python_import_failed")
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

function Invoke-MonitorPreflight {
    $null = Invoke-MonitorInventory
    Assert-MonitorPython
    Assert-MonitorPythonImport
    Assert-MonitorCertificateConfiguration
    Assert-MonitorRunnerAddresses
    $serviceState = Get-RunnerObservabilityServiceState -ServiceName $ServiceName
    [pscustomobject]@{
        PythonPath = $PythonPath
        CertificateMode = $CertificateMode
        ServiceState = $serviceState
        RunnerAddressCount = $RunnerAddress.Count
        Reason = "preflight_passed"
    }
}

function New-MonitorConfiguration {
    # RunnerObservability.Service expands token_file to the runtime --token-file argument.
    return @{
        service_name = $ServiceName
        python_executable = $PythonPath
        database = $DatabasePath
        token_file = $TokenPath
        host = "0.0.0.0"
        port = 8765
        tls_cert = $TlsCertPath
        tls_key = $TlsKeyPath
    }
}

function Invoke-MonitorInstall {
    $null = Invoke-MonitorInventory
    if ($WhatIf) {
        Write-Output "whatif=true"
        return
    }
    $preflight = Invoke-MonitorPreflight
    Assert-RunnerObservabilityServiceAbsent -ServiceName $ServiceName

    New-Item -ItemType Directory -Path $SecretRoot -Force | Out-Null
    New-Item -ItemType Directory -Path (Split-Path -Parent $ConfigPath) -Force | Out-Null
    New-Item -ItemType Directory -Path (Split-Path -Parent $DatabasePath) -Force | Out-Null

    if (-not (Test-Path -LiteralPath $TokenPath -PathType Leaf)) {
        New-RunnerObservabilityTokenFile -Path $TokenPath -ServiceAccount $ServiceAccount | Out-Null
    }
    else {
        Set-RunnerObservabilityFileAcl -Path $TokenPath -ServiceAccount $ServiceAccount
    }

    $certificateMetadata = $null
    if ($CertificateMode -eq "SelfSigned") {
        $certificateMetadata = New-MonitorSelfSignedCertificate -CertificatePath $TlsCertPath -PrivateKeyPath $TlsKeyPath
    }
    else {
        Test-MonitorPathPair
        Set-RunnerObservabilityFileAcl -Path $TlsCertPath -ServiceAccount $ServiceAccount
        Set-RunnerObservabilityFileAcl -Path $TlsKeyPath -ServiceAccount $ServiceAccount
    }

    Write-RunnerObservabilityConfigAtomic -Path $ConfigPath -Configuration (New-MonitorConfiguration)
    Set-RunnerObservabilityFileAcl -Path $ConfigPath -ServiceAccount $ServiceAccount
    Set-RunnerObservabilityDirectoryAcl -Path (Split-Path -Parent $DatabasePath) -ServiceAccount $ServiceAccount
    Ensure-RunnerObservabilityFirewallRule -RunnerAddress $RunnerAddress -Port 8765
    Register-RunnerObservabilityService `
        -ServiceName $ServiceName `
        -PythonPath $PythonPath `
        -ConfigPath $ConfigPath `
        -ServiceAccount $ServiceAccount

    if ($null -ne $certificateMetadata) {
        Write-Output ("certificate_fingerprint={0}" -f $certificateMetadata.Fingerprint)
        Write-Output ("certificate_expiry_utc={0}" -f $certificateMetadata.NotAfter)
    }
    Write-Output "service_state=Stopped"
    Write-Output "reason=install_completed"
}

function Invoke-MonitorRepairPermissions {
    $null = Invoke-MonitorInventory
    if ($WhatIf) {
        Write-Output "whatif=true"
        return
    }
    if (-not (Test-Path -LiteralPath $ConfigPath -PathType Leaf) -or
        -not (Test-Path -LiteralPath $TokenPath -PathType Leaf)) {
        throw (New-MonitorStableError -Reason "monitor_installation_missing")
    }
    Set-RunnerObservabilityFileAcl -Path $ConfigPath -ServiceAccount $ServiceAccount
    Set-RunnerObservabilityFileAcl -Path $TokenPath -ServiceAccount $ServiceAccount
    if (Test-Path -LiteralPath $TlsCertPath -PathType Leaf) {
        Set-RunnerObservabilityFileAcl -Path $TlsCertPath -ServiceAccount $ServiceAccount
    }
    if (Test-Path -LiteralPath $TlsKeyPath -PathType Leaf) {
        Set-RunnerObservabilityFileAcl -Path $TlsKeyPath -ServiceAccount $ServiceAccount
    }
    Set-RunnerObservabilityDirectoryAcl -Path (Split-Path -Parent $DatabasePath) -ServiceAccount $ServiceAccount
    Write-Output "reason=permissions_repaired"
}

function Invoke-MonitorLifecycle {
    $null = Invoke-MonitorInventory
    if ($WhatIf) {
        Write-Output "whatif=true"
        return
    }
    switch ($Action) {
        "Start" {
            Write-Output ("service_state={0}" -f (Start-RunnerObservabilityService -ServiceName $ServiceName))
        }
        "Stop" {
            Write-Output ("service_state={0}" -f (Stop-RunnerObservabilityService -ServiceName $ServiceName))
        }
        "Restart" {
            Stop-RunnerObservabilityService -ServiceName $ServiceName | Out-Null
            Write-Output ("service_state={0}" -f (Start-RunnerObservabilityService -ServiceName $ServiceName))
        }
        "Status" {
            Write-Output ("service_state={0}" -f (Get-RunnerObservabilityServiceState -ServiceName $ServiceName))
        }
        "Uninstall" {
            Remove-RunnerObservabilityService -ServiceName $ServiceName | Out-Null
            Remove-RunnerObservabilityFirewallRule
            Write-Output "service_state=Absent"
            Write-Output "persistent_data_preserved=true"
            Write-Output "reason=uninstall_completed"
        }
    }
}

try {
    switch ($Action) {
        "Preflight" {
            $result = Invoke-MonitorPreflight
            $result | ConvertTo-Json -Compress
        }
        "Install" { Invoke-MonitorInstall }
        "RepairPermissions" { Invoke-MonitorRepairPermissions }
        "Start" { Invoke-MonitorLifecycle }
        "Stop" { Invoke-MonitorLifecycle }
        "Restart" { Invoke-MonitorLifecycle }
        "Status" { Invoke-MonitorLifecycle }
        "Uninstall" { Invoke-MonitorLifecycle }
    }
}
catch {
    $reason = [string]$_.Exception.Message
    $knownReasons = @(
        "certificate_generation_unavailable",
        "certificate_generation_failed",
        "certificate_files_exist",
        "certificate_file_write_failed",
        "certificate_key_pair_missing",
        "self_signed_not_allowed",
        "unsupported_certificate_mode",
        "runner_address_required",
        "runner_address_invalid",
        "python_not_found",
        "python_import_failed",
        "service_already_exists",
        "service_state_timeout",
        "service_state_read_failed",
        "service_command_failed",
        "monitor_installation_missing",
        "file_acl_failed",
        "directory_acl_failed",
        "state_directory_create_failed",
        "runtime_path_missing",
        "firewall_rule_failed",
        "firewall_rule_remove_failed",
        "token_file_exists",
        "token_file_write_failed",
        "token_file_activate_failed",
        "monitor_key_not_allowed",
        "inventory_install_root_missing",
        "install_root_inspection_failed"
    )
    if ($knownReasons -notcontains $reason) {
        $reason = "monitor_onboarding_failed"
    }
    Write-Output ("reason={0}" -f $reason)
    exit 2
}
