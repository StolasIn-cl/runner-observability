function Test-MonitorPythonMachinePath {
    param([Parameter(Mandatory = $true)][string]$Path)

    return ($Path -notmatch '(?i)\\WindowsApps\\|\\Users\\[^\\]+\\')
}

function Select-MonitorPythonCandidate {
    [CmdletBinding()]
    param([object[]]$Candidates = @())

    $eligible = @(
        foreach ($candidate in $Candidates) {
            $path = [string]$candidate.Path
            if ([string]::IsNullOrWhiteSpace($path) -or -not (Test-MonitorPythonMachinePath -Path $path)) {
                continue
            }

            $version = $null
            if (-not [version]::TryParse([string]$candidate.Version, [ref]$version) -or
                $version -lt [version]"3.11") {
                continue
            }

            [pscustomobject]@{
                Path = $path
                Version = $version
                Is64Bit = ([string]$candidate.RegistryView -eq "Registry64")
            }
        }
    )

    if ($eligible.Count -eq 0) {
        throw [System.InvalidOperationException]::new("python_not_found")
    }

    $selected = $eligible |
        Sort-Object -Property @{ Expression = "Version"; Descending = $true }, @{ Expression = "Is64Bit"; Descending = $true } |
        Select-Object -First 1
    return [string]$selected.Path
}

function Get-MonitorPythonVersion {
    param([Parameter(Mandatory = $true)][string]$PythonPath)

    try {
        $output = & $PythonPath -I -s -c "import sys; print('%d.%d' % sys.version_info[:2])" 2>$null
        if ($LASTEXITCODE -ne 0) {
            return $null
        }
        $versionText = [string]($output | Select-Object -Last 1)
        if ($versionText -notmatch '^\d+\.\d+$') {
            return $null
        }
        return [version]::Parse($versionText)
    }
    catch {
        return $null
    }
}

function Get-MonitorMachinePythonCandidates {
    $candidates = New-Object 'System.Collections.Generic.List[object]'
    $views = @([Microsoft.Win32.RegistryView]::Registry32)
    if ([Environment]::Is64BitOperatingSystem) {
        $views = @([Microsoft.Win32.RegistryView]::Registry64, [Microsoft.Win32.RegistryView]::Registry32)
    }

    foreach ($view in $views) {
        $baseKey = $null
        $pythonCore = $null
        try {
            $baseKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
                [Microsoft.Win32.RegistryHive]::LocalMachine,
                $view
            )
            $pythonCore = $baseKey.OpenSubKey("SOFTWARE\Python\PythonCore")
            if ($null -eq $pythonCore) {
                continue
            }

            foreach ($versionName in $pythonCore.GetSubKeyNames()) {
                $installKey = $null
                try {
                    $installKey = $pythonCore.OpenSubKey("$versionName\InstallPath")
                    if ($null -eq $installKey) {
                        continue
                    }

                    $pythonPath = [string]$installKey.GetValue("ExecutablePath")
                    if ([string]::IsNullOrWhiteSpace($pythonPath)) {
                        $installPath = [string]$installKey.GetValue("")
                        if ([string]::IsNullOrWhiteSpace($installPath)) {
                            continue
                        }
                        if ([IO.Path]::GetExtension($installPath) -ieq ".exe") {
                            $pythonPath = $installPath
                        }
                        else {
                            $pythonPath = Join-Path $installPath "python.exe"
                        }
                    }

                    if (-not (Test-MonitorPythonMachinePath -Path $pythonPath) -or
                        -not (Test-Path -LiteralPath $pythonPath -PathType Leaf)) {
                        continue
                    }

                    $version = Get-MonitorPythonVersion -PythonPath $pythonPath
                    if ($null -ne $version) {
                        $candidates.Add([pscustomobject]@{
                            Path = $pythonPath
                            Version = $version.ToString()
                            RegistryView = $view.ToString()
                        })
                    }
                }
                catch {
                    continue
                }
                finally {
                    if ($null -ne $installKey) {
                        $installKey.Dispose()
                    }
                }
            }
        }
        catch {
            continue
        }
        finally {
            if ($null -ne $pythonCore) {
                $pythonCore.Dispose()
            }
            if ($null -ne $baseKey) {
                $baseKey.Dispose()
            }
        }
    }

    $baseKey = $null
    $environmentKey = $null
    try {
        $baseKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
            [Microsoft.Win32.RegistryHive]::LocalMachine,
            [Microsoft.Win32.RegistryView]::Default
        )
        $environmentKey = $baseKey.OpenSubKey("SYSTEM\CurrentControlSet\Control\Session Manager\Environment")
        if ($null -ne $environmentKey) {
            $machinePath = [string]$environmentKey.GetValue(
                "Path",
                "",
                [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames
            )
            foreach ($entry in ($machinePath -split ";")) {
                $directory = [Environment]::ExpandEnvironmentVariables($entry.Trim().Trim('"'))
                if ([string]::IsNullOrWhiteSpace($directory)) {
                    continue
                }

                $pythonPath = if ([IO.Path]::GetExtension($directory) -ieq ".exe") {
                    $directory
                }
                else {
                    Join-Path $directory "python.exe"
                }
                if (-not (Test-MonitorPythonMachinePath -Path $pythonPath) -or
                    -not (Test-Path -LiteralPath $pythonPath -PathType Leaf)) {
                    continue
                }

                $version = Get-MonitorPythonVersion -PythonPath $pythonPath
                if ($null -ne $version) {
                    $candidates.Add([pscustomobject]@{
                        Path = $pythonPath
                        Version = $version.ToString()
                        RegistryView = "MachinePath"
                    })
                }
            }
        }
    }
    catch {
        # A missing system PATH registry value is equivalent to no candidates.
    }
    finally {
        if ($null -ne $environmentKey) {
            $environmentKey.Dispose()
        }
        if ($null -ne $baseKey) {
            $baseKey.Dispose()
        }
    }

    return $candidates.ToArray()
}

function Resolve-MonitorPython {
    [CmdletBinding()]
    param(
        [string]$PreferredPath = "",
        [string]$ServiceAccount = "NT AUTHORITY\LocalService"
    )

    if ([string]::IsNullOrWhiteSpace($PreferredPath)) {
        $candidates = @(Get-MonitorMachinePythonCandidates)
        $resolvedPath = Select-MonitorPythonCandidate -Candidates $candidates
        $global:LASTEXITCODE = 0
        return $resolvedPath
    }

    if (-not (Test-Path -LiteralPath $PreferredPath -PathType Leaf)) {
        throw [System.InvalidOperationException]::new("python_not_found")
    }

    $serviceAccountUsesBuiltinIdentity = $ServiceAccount -in @(
        "NT AUTHORITY\LocalService",
        "NT AUTHORITY\NetworkService",
        "NT AUTHORITY\SYSTEM",
        "LocalSystem"
    )
    if ($serviceAccountUsesBuiltinIdentity -and -not (Test-MonitorPythonMachinePath -Path $PreferredPath)) {
        throw [System.InvalidOperationException]::new("python_runtime_not_service_accessible")
    }

    $version = Get-MonitorPythonVersion -PythonPath $PreferredPath
    if ($null -eq $version) {
        throw [System.InvalidOperationException]::new("python_not_found")
    }
    if ($version -lt [version]"3.11") {
        throw [System.InvalidOperationException]::new("python_version_unsupported")
    }

    $global:LASTEXITCODE = 0
    return (Resolve-Path -LiteralPath $PreferredPath).Path
}

Export-ModuleMember -Function Get-MonitorMachinePythonCandidates, Select-MonitorPythonCandidate, Resolve-MonitorPython
