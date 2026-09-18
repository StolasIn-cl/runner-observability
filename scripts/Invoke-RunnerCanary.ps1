[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("Smoke", "OfflineRecovery", "Auth", "NetworkFailure")]
    [string]$Mode,

    [Parameter(Mandatory = $true)]
    [string]$Endpoint,

    [Parameter(Mandatory = $true)]
    [string]$RunnerId,

    [Parameter(Mandatory = $true)]
    [string]$TokenPath,

    [string]$ProducerId = "runner-canary",

    [string]$StatePath = $null,

    [ValidateRange(1, 86400)]
    [int]$OfflineWaitSeconds = 601,

    [ValidateRange(1, 600)]
    [int]$PollSeconds = 10,

    [switch]$AllowInsecureHttp,

    [string]$FailureEndpoint = $null
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = "Stop"

function Stop-Canary {
    param([Parameter(Mandatory = $true)][string]$Reason)

    throw "canary:$Reason"
}

function Write-Pass {
    param([Parameter(Mandatory = $true)][string]$Message)

    Write-Host ("[PASS] " + $Message)
}

function Write-Info {
    param([Parameter(Mandatory = $true)][string]$Message)

    Write-Host ("[INFO] " + $Message)
}

function Get-TokenValue {
    try {
        $value = (Get-Content -LiteralPath $TokenPath -Raw).Trim()
    }
    catch {
        Stop-Canary "token_file_unreadable"
    }
    if ([string]::IsNullOrWhiteSpace($value)) {
        Stop-Canary "token_file_empty"
    }
    return $value
}

function Get-ResponseStatusCode {
    param([Parameter(Mandatory = $true)]$ErrorRecord)

    try {
        if ($null -ne $ErrorRecord.Exception.Response) {
            return [int]$ErrorRecord.Exception.Response.StatusCode
        }
    }
    catch {
        return 0
    }
    return 0
}

function Invoke-CanaryRequest {
    param(
        [Parameter(Mandatory = $true)][ValidateSet("GET", "POST")][string]$Method,
        [Parameter(Mandatory = $true)][string]$Uri,
        [hashtable]$Headers,
        [string]$Body
    )

    try {
        if ($Method -eq "POST") {
            $response = Invoke-WebRequest -Uri $Uri -Method Post -Headers $Headers `
                -ContentType "application/json" -Body $Body -UseBasicParsing -ErrorAction Stop
        }
        else {
            $response = Invoke-WebRequest -Uri $Uri -Method Get -Headers $Headers `
                -UseBasicParsing -ErrorAction Stop
        }
        return [pscustomobject]@{
            StatusCode = [int]$response.StatusCode
            Body = [string]$response.Content
        }
    }
    catch {
        # A status code is enough for the auth canary. A zero status means the
        # endpoint could not be reached (DNS, TCP, TLS, timeout, or shutdown).
        return [pscustomobject]@{
            StatusCode = Get-ResponseStatusCode $_
            Body = ""
        }
    }
}

function Get-EventEndpoint {
    return ($Endpoint.TrimEnd("/") + "/v1/events")
}

function Get-DashboardEndpoint {
    return ($Endpoint.TrimEnd("/") + "/api/dashboard")
}

function Read-CanaryState {
    $state = $null
    if (Test-Path -LiteralPath $StatePath -PathType Leaf) {
        try {
            $state = Get-Content -LiteralPath $StatePath -Raw | ConvertFrom-Json
        }
        catch {
            $state = $null
        }
    }

    $hasUsableState = $null -ne $state -and
        [string]$state.runner_id -eq $RunnerId -and
        [string]$state.producer_id -eq $ProducerId -and
        [string]$state.producer_epoch -match "^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$" -and
        [long]$state.next_sequence -ge 1

    if ($hasUsableState) {
        return [pscustomobject]@{
            runner_id = $RunnerId
            producer_id = $ProducerId
            producer_epoch = [string]$state.producer_epoch
            next_sequence = [long]$state.next_sequence
        }
    }

    # A new epoch makes a deleted/corrupt state file safe to recover without
    # reusing a sequence from an older producer incarnation.
    return [pscustomobject]@{
        runner_id = $RunnerId
        producer_id = $ProducerId
        producer_epoch = ([guid]::NewGuid().ToString())
        next_sequence = [long]1
    }
}

function Save-CanaryState {
    param([Parameter(Mandatory = $true)]$State)

    try {
        $parent = Split-Path -Parent $StatePath
        if (-not [string]::IsNullOrWhiteSpace($parent)) {
            New-Item -ItemType Directory -Path $parent -Force | Out-Null
        }
        $json = $State | ConvertTo-Json -Depth 3
        [System.IO.File]::WriteAllText($StatePath, $json, (New-Object System.Text.UTF8Encoding($false)))
    }
    catch {
        Stop-Canary "state_file_unwritable"
    }
}

function New-HeartbeatEvent {
    param(
        [Parameter(Mandatory = $true)]$State,
        [Parameter(Mandatory = $true)][long]$Sequence
    )

    return [ordered]@{
        schema_version = 1
        event_type = "runner.heartbeat"
        event_id = ([guid]::NewGuid().ToString())
        runner_id = $RunnerId
        producer_id = $ProducerId
        producer_epoch = [string]$State.producer_epoch
        producer_sequence = $Sequence
        occurred_at = [DateTime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
    }
}

function Send-Heartbeat {
    param(
        [Parameter(Mandatory = $true)]$State,
        [Parameter(Mandatory = $true)][string]$Token,
        [Parameter(Mandatory = $true)][bool]$AdvanceState
    )

    $sequence = [long]$State.next_sequence
    $event = New-HeartbeatEvent -State $State -Sequence $sequence
    try {
        $body = $event | ConvertTo-Json -Depth 4 -Compress
    }
    catch {
        Stop-Canary "event_serialization_failed"
    }
    $headers = @{ Authorization = ("Bearer " + $Token) }
    $response = Invoke-CanaryRequest -Method "POST" -Uri (Get-EventEndpoint) -Headers $headers -Body $body
    if ($response.StatusCode -ne 202) {
        Stop-Canary "heartbeat_rejected"
    }

    try {
        $ack = $response.Body | ConvertFrom-Json
        if ($false -eq [bool]$ack.accepted) {
            Stop-Canary "heartbeat_not_accepted"
        }
    }
    catch {
        Stop-Canary "heartbeat_ack_invalid"
    }

    if ($AdvanceState) {
        $State.next_sequence = $sequence + 1
        Save-CanaryState -State $State
    }
    return $State
}

function Get-RunnerSnapshot {
    $headers = @{ "Cache-Control" = "no-cache" }
    $response = Invoke-CanaryRequest -Method "GET" -Uri (Get-DashboardEndpoint) -Headers $headers
    if ($response.StatusCode -ne 200) {
        Stop-Canary "dashboard_unavailable"
    }
    try {
        $dashboard = $response.Body | ConvertFrom-Json
        $runner = @($dashboard.runners | Where-Object { [string]$_.runner_id -eq $RunnerId })
    }
    catch {
        Stop-Canary "dashboard_response_invalid"
    }
    if ($runner.Count -ne 1) {
        Stop-Canary "runner_not_found"
    }
    return $runner[0]
}

function Assert-Liveness {
    param(
        [Parameter(Mandatory = $true)][string]$Expected,
        [Parameter(Mandatory = $true)][string]$Reason
    )

    $snapshot = Get-RunnerSnapshot
    if ([string]$snapshot.liveness -ne $Expected) {
        Stop-Canary $Reason
    }
    return $snapshot
}

function Invoke-Smoke {
    param([Parameter(Mandatory = $true)][string]$Token)

    $state = Read-CanaryState
    $null = Send-Heartbeat -State $state -Token $Token -AdvanceState $true
    $null = Assert-Liveness -Expected "online" -Reason "heartbeat_not_online"
    Write-Pass ($script:TransportLabel + " heartbeat accepted and runner is online")
}

function Invoke-OfflineRecovery {
    param([Parameter(Mandatory = $true)][string]$Token)

    $state = Read-CanaryState
    $null = Send-Heartbeat -State $state -Token $Token -AdvanceState $true
    $null = Assert-Liveness -Expected "online" -Reason "heartbeat_not_online"
    Write-Pass "baseline heartbeat accepted and runner is online"

    Write-Info ("Do not send another heartbeat from any producer for " + $OfflineWaitSeconds + " seconds")
    $remaining = $OfflineWaitSeconds
    while ($remaining -gt 0) {
        $sleepFor = [Math]::Min($PollSeconds, $remaining)
        Start-Sleep -Seconds $sleepFor
        $remaining -= $sleepFor
        Write-Info ("offline wait remaining: " + $remaining + " seconds")
    }

    $snapshot = Assert-Liveness -Expected "offline" -Reason "offline_timeout_not_observed"
    if ([string]$snapshot.offline_reason -ne "heartbeat_timeout") {
        Stop-Canary "offline_reason_unexpected"
    }
    Write-Pass "runner entered offline with heartbeat_timeout"

    $null = Send-Heartbeat -State $state -Token $Token -AdvanceState $true
    $null = Assert-Liveness -Expected "online" -Reason "heartbeat_recovery_not_observed"
    Write-Pass "newer heartbeat recovered runner to online"
}

function Invoke-Auth {
    param([Parameter(Mandatory = $true)][string]$Token)

    $state = Read-CanaryState
    $sequence = [long]$state.next_sequence
    $event = New-HeartbeatEvent -State $state -Sequence $sequence
    $body = $event | ConvertTo-Json -Depth 4 -Compress
    $invalidHeaders = @{ Authorization = ("Bearer " + $Token + ".invalid") }
    $rejected = Invoke-CanaryRequest -Method "POST" -Uri (Get-EventEndpoint) -Headers $invalidHeaders -Body $body
    if ($rejected.StatusCode -ne 401) {
        Stop-Canary "invalid_token_not_rejected"
    }
    Write-Pass "invalid token rejected with HTTP 401"

    $null = Send-Heartbeat -State $state -Token $Token -AdvanceState $true
    $null = Assert-Liveness -Expected "online" -Reason "valid_token_recovery_failed"
    Write-Pass "valid token accepted after the rejection"
}

function Invoke-NetworkFailure {
    param([Parameter(Mandatory = $true)][string]$Token)

    $state = Read-CanaryState
    $sequence = [long]$state.next_sequence
    $event = New-HeartbeatEvent -State $state -Sequence $sequence
    $body = $event | ConvertTo-Json -Depth 4 -Compress
    $headers = @{ Authorization = ("Bearer " + $Token) }
    $target = if ([string]::IsNullOrWhiteSpace($FailureEndpoint)) { $Endpoint } else { $FailureEndpoint }
    $response = Invoke-CanaryRequest -Method "POST" -Uri ($target.TrimEnd("/") + "/v1/events") -Headers $headers -Body $body
    if ($response.StatusCode -ne 0) {
        Stop-Canary "network_failure_not_observed"
    }
    Write-Pass "heartbeat endpoint failure was observed without exposing the token"
}

try {
    if ([string]::IsNullOrWhiteSpace($StatePath)) {
        $stateRoot = $env:LOCALAPPDATA
        if ([string]::IsNullOrWhiteSpace($stateRoot)) {
            $stateRoot = [Environment]::GetFolderPath("LocalApplicationData")
        }
        $StatePath = Join-Path $stateRoot "RunnerObservability\canary-state.json"
    }
    if ([string]::IsNullOrWhiteSpace($FailureEndpoint)) {
        $FailureEndpoint = $Endpoint
    }

    try {
        $parsedEndpoint = [Uri]$Endpoint
    }
    catch {
        Stop-Canary "invalid_endpoint"
    }
    if ($parsedEndpoint.Scheme -notin @("http", "https") -or [string]::IsNullOrWhiteSpace($parsedEndpoint.Host)) {
        Stop-Canary "invalid_endpoint"
    }
    if ($parsedEndpoint.Scheme -ne "https" -and -not $AllowInsecureHttp) {
        Stop-Canary "https_required"
    }
    try {
        $parsedFailureEndpoint = [Uri]$FailureEndpoint
    }
    catch {
        Stop-Canary "invalid_failure_endpoint"
    }
    if ($parsedFailureEndpoint.Scheme -notin @("http", "https") -or [string]::IsNullOrWhiteSpace($parsedFailureEndpoint.Host)) {
        Stop-Canary "invalid_failure_endpoint"
    }
    if ($parsedFailureEndpoint.Scheme -ne "https" -and -not $AllowInsecureHttp) {
        Stop-Canary "https_required"
    }
    $script:TransportLabel = if ($parsedEndpoint.Scheme -eq "https") { "HTTPS" } else { "HTTP" }
    if ($ProducerId -notmatch "^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$") {
        Stop-Canary "invalid_producer_id"
    }
    try {
        [void][guid]::Parse($RunnerId)
    }
    catch {
        Stop-Canary "invalid_runner_id"
    }
    $token = Get-TokenValue

    switch ($Mode) {
        "Smoke" { Invoke-Smoke -Token $token }
        "OfflineRecovery" { Invoke-OfflineRecovery -Token $token }
        "Auth" { Invoke-Auth -Token $token }
        "NetworkFailure" { Invoke-NetworkFailure -Token $token }
    }
    exit 0
}
catch {
    $message = [string]$_.Exception.Message
    if ($message.StartsWith("canary:")) {
        Write-Host ("[FAIL] " + $message.Substring(7))
    }
    else {
        Write-Host "[FAIL] unexpected_error"
    }
    exit 1
}
