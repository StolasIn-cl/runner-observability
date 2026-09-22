[CmdletBinding()]
param(
    [string]$RunnerRoot = 'C:\actions-runner'
)

# Read-only Runner-side diagnostic. It never sends telemetry, changes machine
# environment variables, changes ACLs, restarts services, or prints secrets.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'
$Prefix = '[RUNNER-DIAG]'
$ConfigFailures = New-Object System.Collections.Generic.List[string]

function Write-Diag {
    param(
        [Parameter(Mandatory = $true)][string]$Key,
        [Parameter(Mandatory = $true)][string]$Status,
        [AllowEmptyString()][string]$Detail = ''
    )
    $safe = if ($null -eq $Detail) { '' } else { $Detail -replace '[\r\n]+', ' ' }
    Write-Output ("{0} key={1} status={2} detail={3}" -f $Prefix, $Key, $Status, $safe)
}

function Add-ConfigFailure {
    param([Parameter(Mandatory = $true)][string]$Stage)
    [void]$ConfigFailures.Add($Stage)
}

function Get-EnvValue {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][System.EnvironmentVariableTarget]$Target
    )
    $value = [Environment]::GetEnvironmentVariable($Name, $Target)
    if ([string]::IsNullOrWhiteSpace($value)) { return '<empty>' }
    return $value
}

function Write-PathCheck {
    param(
        [Parameter(Mandatory = $true)][string]$Key,
        [AllowEmptyString()][string]$Path
    )
    if ([string]::IsNullOrWhiteSpace($Path) -or $Path -eq '<empty>') {
        Write-Diag $Key 'FAIL' 'path_empty'
        return
    }
    try {
        $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        $length = if ($item.PSIsContainer) { '<directory>' } else { [string]$item.Length }
        Write-Diag $Key 'PASS' ("exists=True;type={0};length={1}" -f $item.GetType().Name, $length)
        return
    } catch {
        $kind = $_.Exception.GetType().Name
        Write-Diag $Key 'FAIL' ("exists=False_or_unreadable;error_type={0}" -f $kind)
        return
    }
}

function Write-AclCheck {
    param(
        [Parameter(Mandatory = $true)][string]$Key,
        [AllowEmptyString()][string]$Path
    )
    if ([string]::IsNullOrWhiteSpace($Path) -or $Path -eq '<empty>' -or -not (Test-Path -LiteralPath $Path)) {
        Write-Diag ($Key + '.acl') 'SKIP' 'target_missing'
        return
    }
    try {
        $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
        $entries = @($acl.Access | ForEach-Object {
            "{0}:{1}:{2}" -f $_.IdentityReference, $_.FileSystemRights, $_.AccessControlType
        })
        $summary = ($entries -join ',')
        if ($summary.Length -gt 1800) { $summary = $summary.Substring(0, 1800) + '...' }
        Write-Diag ($Key + '.acl') 'PASS' ("owner={0};entries={1}" -f $acl.Owner, $summary)
    } catch {
        Write-Diag ($Key + '.acl') 'FAIL' ("error_type={0}" -f $_.Exception.GetType().Name)
    }
}

Write-Output "$Prefix read_only=true; no telemetry event will be sent"

try {
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
} catch {
    $identity = '<unavailable>'
}
Write-Diag 'host' 'INFO' ("computer={0};account={1};powershell={2}" -f $env:COMPUTERNAME, $identity, $PSVersionTable.PSVersion)

$names = @(
    'RUNNER_OBSERVABILITY_INSTALL_ROOT',
    'RUNNER_OBSERVABILITY_ENDPOINT',
    'RUNNER_OBSERVABILITY_TOKEN_PATH',
    'RUNNER_OBSERVABILITY_RUNNER_ID'
)
$processValues = @{}
foreach ($name in $names) {
    $process = Get-EnvValue $name ([EnvironmentVariableTarget]::Process)
    $machine = Get-EnvValue $name ([EnvironmentVariableTarget]::Machine)
    $processValues[$name] = $process
    $status = if ($process -eq $machine) { 'MATCH' } elseif ($process -eq '<empty>' -and $machine -ne '<empty>') { 'PROCESS_MISSING' } else { 'MISMATCH' }
    Write-Diag ("env.{0}" -f $name) $status ("process={0};machine={1}" -f $process, $machine)
}

$pythonCommand = Get-Command python -ErrorAction SilentlyContinue
$pythonPath = $null
if ($null -eq $pythonCommand) {
    Write-Diag 'python.command' 'FAIL' 'python_not_found_on_current_PATH'
} else {
    $pythonPath = [string]$pythonCommand.Source
    if ([string]::IsNullOrWhiteSpace($pythonPath)) { $pythonPath = [string]$pythonCommand.Path }
    Write-Diag 'python.command' 'PASS' $pythonPath
    try {
        $version = (& $pythonPath --version 2>&1 | Select-Object -First 1)
        Write-Diag 'python.version' 'PASS' ([string]$version)
    } catch {
        Write-Diag 'python.version' 'FAIL' ("error_type={0}" -f $_.Exception.GetType().Name)
    }
}

$runnerFound = $false
try {
    $runnerProcesses = @(Get-CimInstance Win32_Process -Filter "Name = 'Runner.Listener.exe'" -ErrorAction Stop)
    foreach ($process in $runnerProcesses) {
        $runnerFound = $true
        $owner = '<unavailable>'
        try {
            $ownerInfo = Invoke-CimMethod -InputObject $process -MethodName GetOwner -ErrorAction Stop
            if ($ownerInfo.ReturnValue -eq 0) { $owner = "$($ownerInfo.Domain)\$($ownerInfo.User)" }
        } catch {}
        Write-Diag ("runner.listener.{0}" -f $process.ProcessId) 'PASS' ("owner={0};executable={1}" -f $owner, $process.ExecutablePath)
    }
} catch {
    Write-Diag 'runner.listener' 'FAIL' ("inventory_error_type={0}" -f $_.Exception.GetType().Name)
}
if (-not $runnerFound) { Write-Diag 'runner.listener' 'WARN' 'Runner.Listener.exe_not_found_on_this_host' }

try {
    $services = @(Get-CimInstance Win32_Service -ErrorAction Stop | Where-Object {
        $_.Name -match '(?i)RunnerObservabilityHeartbeat|RunnerObservabilityMonitor'
    })
    if ($services.Count -eq 0) {
        Write-Diag 'services' 'WARN' 'no_runner_observability_service_found'
    } else {
        foreach ($service in $services) {
            Write-Diag ("service.{0}" -f $service.Name) 'INFO' ("state={0};start_mode={1};account={2}" -f $service.State, $service.StartMode, $service.StartName)
        }
    }
} catch {
    Write-Diag 'services' 'FAIL' ("inventory_error_type={0}" -f $_.Exception.GetType().Name)
}

$installRoot = [string]$processValues['RUNNER_OBSERVABILITY_INSTALL_ROOT']
$endpoint = [string]$processValues['RUNNER_OBSERVABILITY_ENDPOINT']
$tokenPath = [string]$processValues['RUNNER_OBSERVABILITY_TOKEN_PATH']
$releaseFile = $null
$revision = $null
$releaseRoot = $null
$srcPath = $null
$resolvedReleaseRoot = $null
$resolvedSrcPath = $null

if ($installRoot -eq '<empty>') {
    Add-ConfigFailure 'install_root'
    Write-Diag 'helper.install_root' 'FAIL' 'agent_not_installed_process_value_empty'
} else {
    Write-Diag 'helper.install_root' 'PASS' $installRoot
    try {
        $releaseFile = Join-Path $installRoot 'current-release.txt'
        if (-not (Test-Path -LiteralPath $releaseFile -PathType Leaf)) {
            Add-ConfigFailure 'current_release_missing'
            Write-Diag 'helper.current_release' 'FAIL' 'current-release.txt_missing_or_not_a_file'
        } else {
            try {
                $revision = (Get-Content -LiteralPath $releaseFile -ErrorAction Stop | Select-Object -First 1)
                if ($null -ne $revision) { $revision = $revision.Trim() }
            } catch {
                Add-ConfigFailure 'current_release_read'
                Write-Diag 'helper.current_release' 'FAIL' ("read_error_type={0}" -f $_.Exception.GetType().Name)
            }
            if ([string]::IsNullOrWhiteSpace($revision)) {
                Add-ConfigFailure 'current_release_empty'
                Write-Diag 'helper.current_release' 'FAIL' 'revision_empty'
            } else {
                Write-Diag 'helper.current_release' 'PASS' ("revision={0}" -f $revision)
                try {
                    $releaseRoot = Join-Path $installRoot (Join-Path 'releases' $revision)
                    $srcPath = Join-Path $releaseRoot 'src'
                    if (-not (Test-Path -LiteralPath $srcPath -PathType Container)) {
                        Add-ConfigFailure 'release_src_missing'
                        Write-Diag 'helper.release_src' 'FAIL' 'active_release_src_missing_or_not_a_directory'
                    } else {
                        Write-Diag 'helper.release_src' 'PASS' 'active_release_src_exists'
                        try {
                            $resolvedReleaseRoot = (Resolve-Path -LiteralPath $releaseRoot -ErrorAction Stop).Path
                            $resolvedSrcPath = (Resolve-Path -LiteralPath $srcPath -ErrorAction Stop).Path
                            Write-Diag 'helper.resolve_path' 'PASS' 'release_root_and_src_resolved'
                        } catch {
                            Add-ConfigFailure 'resolve_path'
                            Write-Diag 'helper.resolve_path' 'FAIL' ("error_type={0}" -f $_.Exception.GetType().Name)
                        }
                    }
                } catch {
                    Add-ConfigFailure 'release_path_build'
                    Write-Diag 'helper.release_path_build' 'FAIL' ("error_type={0}" -f $_.Exception.GetType().Name)
                }
            }
        }
    } catch {
        Add-ConfigFailure 'release_pointer_path'
        Write-Diag 'helper.current_release' 'FAIL' ("path_error_type={0}" -f $_.Exception.GetType().Name)
    }
}

if ($endpoint -eq '<empty>') {
    Add-ConfigFailure 'endpoint'
    Write-Diag 'helper.endpoint' 'FAIL' 'endpoint_not_configured'
} else {
    try {
        $uri = New-Object System.Uri($endpoint)
        $endpointSummary = "scheme=$($uri.Scheme);host=$($uri.DnsSafeHost);port=$($uri.Port);path=$($uri.AbsolutePath);userinfo_present=$([string]::IsNullOrEmpty($uri.UserInfo) -eq $false)"
        Write-Diag 'helper.endpoint' 'PASS' $endpointSummary
    } catch {
        Write-Diag 'helper.endpoint' 'WARN' 'endpoint_is_nonempty_but_uri_parse_failed'
    }
}

if ($tokenPath -eq '<empty>') {
    Add-ConfigFailure 'token_path'
    Write-Diag 'helper.token' 'FAIL' 'token_not_configured_path_empty'
} elseif (-not (Test-Path -LiteralPath $tokenPath -PathType Leaf)) {
    Add-ConfigFailure 'token_file_missing'
    Write-Diag 'helper.token' 'FAIL' 'token_file_missing_or_not_a_file'
} else {
    try {
        $tokenItem = Get-Item -LiteralPath $tokenPath -Force -ErrorAction Stop
        $stream = [System.IO.File]::Open($tokenPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        $tokenLength = $stream.Length
        $stream.Dispose()
        if ($tokenLength -le 0) {
            Add-ConfigFailure 'token_file_empty'
            Write-Diag 'helper.token' 'FAIL' 'token_file_empty'
        } else {
            Write-Diag 'helper.token' 'PASS' ("exists=True;length={0};content_not_printed=True" -f $tokenLength)
        }
    } catch {
        Add-ConfigFailure 'token_file_read'
        Write-Diag 'helper.token' 'FAIL' ("read_error_type={0};content_not_printed=True" -f $_.Exception.GetType().Name)
    }
}

if ($null -eq $pythonPath) {
    Add-ConfigFailure 'python'
} else {
    Write-Diag 'helper.python' 'PASS' 'python_command_resolved'
}

foreach ($pathPair in @(
    @('path.runner_root', $RunnerRoot),
    @('path.install_root', $installRoot),
    @('path.current_release', $releaseFile),
    @('path.release_src', $srcPath),
    @('path.token', $tokenPath)
)) {
    Write-PathCheck -Key $pathPair[0] -Path ([string]$pathPair[1])
    Write-AclCheck -Key $pathPair[0] -Path ([string]$pathPair[1])
}

if ($null -ne $pythonPath -and $null -ne $resolvedSrcPath) {
    $oldPythonPath = [Environment]::GetEnvironmentVariable('PYTHONPATH', 'Process')
    $importOutput = @()
    $importFingerprints = @()
    try {
        [Environment]::SetEnvironmentVariable('PYTHONPATH', $resolvedSrcPath, 'Process')
        foreach ($relativePath in @(
            'runner_observability\__init__.py',
            'runner_observability\heartbeat.py',
            'runner_observability\heartbeat_service.py',
            'runner_observability\__main__.py',
            'runner_observability\agent.py',
            'runner_observability\contracts.py',
            'runner_observability\credentials.py',
            'runner_observability\service.py'
        )) {
            $releaseFilePath = Join-Path $resolvedSrcPath $relativePath
            $releaseFileKey = 'release.file.' + ($relativePath -replace '\\', '.')
            if (Test-Path -LiteralPath $releaseFilePath -PathType Leaf) {
                Write-Diag $releaseFileKey 'PASS' 'exists=True'
            } else {
                Write-Diag $releaseFileKey 'FAIL' 'exists=False'
            }
        }

        $packageOriginOutput = @(& $pythonPath -c 'import runner_observability; print(runner_observability.__file__)' 2>$null)
        $packageOrigin = [string]($packageOriginOutput | Select-Object -Last 1)
        if ([string]::IsNullOrWhiteSpace($packageOrigin)) {
            Write-Diag 'helper.module_origin' 'FAIL' 'runner_observability_origin_unavailable'
        } else {
            try {
                $resolvedPackageOrigin = (Resolve-Path -LiteralPath $packageOrigin -ErrorAction Stop).Path
                $expectedPrefix = $resolvedSrcPath.TrimEnd('\') + '\'
                if ($resolvedPackageOrigin.StartsWith($expectedPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
                    Write-Diag 'helper.module_origin' 'PASS' 'runner_observability=under_expected_src'
                } else {
                    Write-Diag 'helper.module_origin' 'FAIL' 'runner_observability=outside_expected_src'
                }
            } catch {
                Write-Diag 'helper.module_origin' 'FAIL' 'runner_observability_origin_unreadable'
            }
        }

        $importOutput = @(& $pythonPath -c 'import runner_observability; import runner_observability.heartbeat_service; print(1)' 2>&1)
        $importExitCode = $LASTEXITCODE
        if ($importExitCode -eq 0) {
            Write-Diag 'helper.python_import' 'PASS' 'runner_observability_and_heartbeat_service_imported'
        } else {
            foreach ($lineObject in $importOutput) {
                $line = [string]$lineObject
                if ($line -match 'No module named [''\"](?<module>[^''\"]+)') {
                    $importFingerprints += ('missing_module={0}' -f $matches['module'])
                } elseif ($line -match 'name [''\"](?<name>[A-Za-z_][A-Za-z0-9_]*)[''\"] is not defined') {
                    $importFingerprints += ('missing_name={0}' -f $matches['name'])
                } elseif ($line -match 'ModuleNotFoundError') {
                    $importFingerprints += 'error_type=ModuleNotFoundError'
                } elseif ($line -match 'ImportError') {
                    $importFingerprints += 'error_type=ImportError'
                } elseif ($line -match 'SyntaxError') {
                    $importFingerprints += 'error_type=SyntaxError'
                } elseif ($line -match 'PermissionError') {
                    $importFingerprints += 'error_type=PermissionError'
                } elseif ($line -match '(?<errorType>AttributeError|FileNotFoundError|KeyError|NameError|OSError|RuntimeError|SyntaxError|TypeError|ValueError|UnboundLocalError):') {
                    $importFingerprints += ('error_type={0}' -f $matches['errorType'])
                }
            }
            $importFingerprints = @($importFingerprints | Select-Object -Unique)
            if ($importFingerprints.Count -eq 0) {
                $importFingerprints = @('error_fingerprint=unclassified')
            }
            Write-Diag 'helper.python_import' 'FAIL' ("exit_code={0};{1};stderr_not_printed=True" -f $importExitCode, ($importFingerprints -join ','))
        }

        & $pythonPath -m runner_observability emit --help 1>$null 2>$null
        $cliExitCode = $LASTEXITCODE
        if ($cliExitCode -eq 0) {
            Write-Diag 'helper.cli_smoke' 'PASS' 'command=emit_help;telemetry_sent=False'
        } else {
            Write-Diag 'helper.cli_smoke' 'FAIL' ("exit_code={0};command=emit_help;telemetry_sent=False" -f $cliExitCode)
        }
    } catch {
        Write-Diag 'helper.python_import' 'FAIL' ("error_type={0};stderr_not_printed=True" -f $_.Exception.GetType().Name)
    } finally {
        [Environment]::SetEnvironmentVariable('PYTHONPATH', $oldPythonPath, 'Process')
    }
} else {
    Write-Diag 'helper.python_import' 'SKIP' 'requires_python_and_resolved_release_src'
}

if ($ConfigFailures.Count -eq 0) {
    Write-Diag 'helper.config_resolution' 'PASS' 'all_config_read_boundaries_passed;actual_CI_helper_should_not_emit_config_read_failed_for_these_checks'
} else {
    Write-Diag 'helper.config_resolution' 'FAIL' ("blocking_stages={0}" -f ($ConfigFailures -join ','))
}

Write-Output "$Prefix done=true; token/private_key_contents_printed=false; telemetry_sent=false; machine_state_changed=false"
