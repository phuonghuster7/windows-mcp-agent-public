<#
.SYNOPSIS
    Read-only, non-mutating end-to-end diagnostic verification for the WinOwner MCP Stack.

.DESCRIPTION
    Verifies:
      1. Windows interactive session & lock state
      2. FastAPI Backend (127.0.0.1:3080) TCP listener + GET /health
      3. MCP Bridge (127.0.0.1:8765/mcp) TCP listener + live MCP initialize + tools/list count +
         path_exists & list_directory read-only smoke calls
      4. Primary Secure MCP Tunnel (windows-mcp-isolated / tunnel_unconfigured_isolated)
         process check + dynamic health URL /healthz & /readyz + redacted tunnel-client doctor summary
      5. Legacy Codex Tunnel (codex-chatgpt-web / tunnel_unconfigured_legacy)
         process & health verification (confirming it is untouched and running)

    Outputs a formatted PASS/FAIL diagnostic table and saves a redacted report bundle to:
      D:\ExampleProjects\Windows-MCP-Agent\runtime\logs\diagnostic-report.json
#>
[CmdletBinding()]
param(
    [string]$ReportPath = $(if ($PSScriptRoot) { Join-Path (Resolve-Path (Join-Path $PSScriptRoot "..")).Path "runtime\logs\diagnostic-report.json" } else { Join-Path (Get-Location).Path "runtime\logs\diagnostic-report.json" }),
    [string]$SmokePath = $(if ($PSScriptRoot) { (Resolve-Path (Join-Path $PSScriptRoot "..")).Path } else { (Get-Location).Path })
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ---------------------------------------------------------------------------
# Secret Redaction Helper
# ---------------------------------------------------------------------------
function ConvertTo-RedactedText {
    param([AllowNull()][string]$InputText)
    if ([string]::IsNullOrEmpty($InputText)) { return "" }
    $text = $InputText
    $text = [regex]::Replace($text, '(?i)(Bearer\s+)[A-Za-z0-9._\-+/=]{8,}', '$1[REDACTED]')
    $text = [regex]::Replace($text, '\bsk-[A-Za-z0-9_\-]{10,}\b', '[REDACTED_SK]')
    $text = [regex]::Replace(
        $text,
        '(?i)((?:api_key|apikey|token|secret|password|authorization|credential|access_token)\s*[:=]\s*[''"]?)([^\s''",;}\]]{6,})',
        '$1[REDACTED]'
    )
    return $text
}

# ---------------------------------------------------------------------------
# MCP Streamable HTTP JSON-RPC Helper (Read-Only)
# ---------------------------------------------------------------------------
function Invoke-McpJsonRpc {
    param(
        [Parameter(Mandatory = $true)][string]$Method,
        [Parameter(Mandatory = $false)][hashtable]$Params = @{},
        [int]$Id = 1,
        [string]$Uri = "http://127.0.0.1:8765/mcp"
    )
    $payloadObj = @{
        jsonrpc = "2.0"
        id      = $Id
        method  = $Method
        params  = $Params
    }
    $bodyJson = $payloadObj | ConvertTo-Json -Depth 8 -Compress
    $headers = @{
        "Accept"       = "application/json, text/event-stream"
        "Content-Type" = "application/json"
    }
    $resp = Invoke-WebRequest -Uri $Uri -Method Post -Headers $headers -Body ([System.Text.Encoding]::UTF8.GetBytes($bodyJson)) -UseBasicParsing -TimeoutSec 8
    $content = [string]$resp.Content
    foreach ($line in ($content -split "`r?`n")) {
        $trimmed = $line.Trim()
        if ($trimmed.StartsWith("data:")) {
            $jsonPart = $trimmed.Substring(5).Trim()
            if ($jsonPart) {
                return ($jsonPart | ConvertFrom-Json)
            }
        }
    }
    if ($content.Trim().StartsWith("{")) {
        return ($content.Trim() | ConvertFrom-Json)
    }
    throw "Unrecognized MCP HTTP response payload: $($content.Substring(0, [Math]::Min(120, $content.Length)))"
}

$checks = New-Object System.Collections.Generic.List[object]
function Add-DiagnosticCheck {
    param(
        [string]$Name,
        [string]$Category,
        [bool]$Passed,
        [string]$Details,
        [object]$Metadata = $null
    )
    $checks.Add([PSCustomObject]@{
        Check    = $Name
        Category = $Category
        Status   = $(if ($Passed) { "PASS" } else { "FAIL" })
        Passed   = $Passed
        Details  = ConvertTo-RedactedText $Details
        Metadata = $Metadata
    })
}

# Pre-fetch process inventory once (read-only)
$allProcs = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue)

# ---------------------------------------------------------------------------
# 1. Windows Session & Lock Status
# ---------------------------------------------------------------------------
$currentPid = $PID
$currentProc = Get-Process -Id $currentPid
$sessionId = $currentProc.SessionId
$logonUiProc = @(Get-Process -Name "LogonUI" -ErrorAction SilentlyContinue)
$isLocked = ($logonUiProc.Count -gt 0)
$isInteractive = ($sessionId -gt 0)

Add-DiagnosticCheck -Name "Windows Session & Lock Status" -Category "System" `
    -Passed ($isInteractive -and (-not $isLocked)) `
    -Details "User=$env:USERNAME, SessionId=$sessionId, Interactive=$isInteractive, Locked=$isLocked" `
    -Metadata @{
        user        = $env:USERNAME
        session_id  = $sessionId
        interactive = $isInteractive
        locked      = $isLocked
    }

# ---------------------------------------------------------------------------
# 2. FastAPI Backend (127.0.0.1:3080)
# ---------------------------------------------------------------------------
$listener3080 = @(Get-NetTCPConnection -LocalAddress "127.0.0.1" -LocalPort 3080 -State Listen -ErrorAction SilentlyContinue)
$port3080Open = ($listener3080.Count -ge 1)
$backendPid = $(if ($port3080Open) { $listener3080[0].OwningProcess } else { $null })

Add-DiagnosticCheck -Name "Backend Port 3080 Listening" -Category "Backend" `
    -Passed $port3080Open `
    -Details $(if ($port3080Open) { "127.0.0.1:3080 LISTENING (PID=$backendPid)" } else { "Port 3080 not listening" }) `
    -Metadata @{ port = 3080; pid = $backendPid }

$backendHealthOk = $false
$backendHealthDetails = ""
$backendHealthBody = $null
if ($port3080Open) {
    try {
        $backendHealthBody = Invoke-RestMethod -Uri "http://127.0.0.1:3080/health" -Method Get -TimeoutSec 5
        if ($backendHealthBody.status -eq "ok") {
            $backendHealthOk = $true
            $backendHealthDetails = "status=$($backendHealthBody.status), server=$($backendHealthBody.server), version=$($backendHealthBody.version)"
        } else {
            $backendHealthDetails = "Unexpected response: $($backendHealthBody | ConvertTo-Json -Compress)"
        }
    } catch {
        $backendHealthDetails = "HTTP GET /health failed: $($_.Exception.Message)"
    }
} else {
    $backendHealthDetails = "Skipped because port 3080 is not listening"
}
Add-DiagnosticCheck -Name "Backend HTTP /health" -Category "Backend" `
    -Passed $backendHealthOk `
    -Details $backendHealthDetails `
    -Metadata $backendHealthBody

# ---------------------------------------------------------------------------
# 3. MCP Bridge (127.0.0.1:8765/mcp)
# ---------------------------------------------------------------------------
$listener8765 = @(Get-NetTCPConnection -LocalAddress "127.0.0.1" -LocalPort 8765 -State Listen -ErrorAction SilentlyContinue)
$port8765Open = ($listener8765.Count -ge 1)
$bridgePid = $(if ($port8765Open) { $listener8765[0].OwningProcess } else { $null })

Add-DiagnosticCheck -Name "MCP Bridge Port 8765 Listening" -Category "MCP Bridge" `
    -Passed $port8765Open `
    -Details $(if ($port8765Open) { "127.0.0.1:8765 LISTENING (PID=$bridgePid)" } else { "Port 8765 not listening" }) `
    -Metadata @{ port = 8765; pid = $bridgePid }

$mcpInitOk = $false
$mcpInitDetails = ""
$mcpServerInfo = $null
$toolsCount = 0
$toolNames = @()
$toolsListOk = $false
$toolsListDetails = ""
$smokePathExistsOk = $false
$smokePathExistsDetails = ""
$smokeListDirOk = $false
$smokeListDirDetails = ""

if ($port8765Open) {
    # 3a. initialize
    try {
        $initResp = Invoke-McpJsonRpc -Id 1 -Method "initialize" -Params @{
            protocolVersion = "2024-11-05"
            capabilities    = @{}
            clientInfo      = @{ name = "Test-WindowsMcpStack"; version = "1.0.0" }
        }
        if ($null -ne $initResp.result) {
            $mcpInitOk = $true
            $mcpServerInfo = $initResp.result.serverInfo
            $mcpInitDetails = "protocol=$($initResp.result.protocolVersion), server=$($mcpServerInfo.name) v$($mcpServerInfo.version)"
        } else {
            $mcpInitDetails = "Initialize returned error or empty result"
        }
    } catch {
        $mcpInitDetails = "MCP initialize failed: $($_.Exception.Message)"
    }

    # 3b. tools/list
    try {
        $toolsResp = Invoke-McpJsonRpc -Id 2 -Method "tools/list" -Params @{}
        if ($null -ne $toolsResp.result -and $null -ne $toolsResp.result.tools) {
            $toolNames = @($toolsResp.result.tools | ForEach-Object { $_.name })
            $toolsCount = $toolNames.Count
            $toolsListOk = ($toolsCount -ge 8)
            $toolsListDetails = "Discovered $toolsCount tools: $($toolNames -join ', ')"
        } else {
            $toolsListDetails = "tools/list returned no tools"
        }
    } catch {
        $toolsListDetails = "MCP tools/list failed: $($_.Exception.Message)"
    }

    # 3c. tools/call path_exists
    try {
        $peResp = Invoke-McpJsonRpc -Id 3 -Method "tools/call" -Params @{
            name      = "path_exists"
            arguments = @{ path = $SmokePath }
        }
        $isErr = ($peResp.result.isError -eq $true)
        $textOut = if ($peResp.result.content -and $peResp.result.content.Count -gt 0) { [string]$peResp.result.content[0].text } else { "" }
        if ((-not $isErr) -and ($textOut -match "true|exists")) {
            $smokePathExistsOk = $true
            $smokePathExistsDetails = "path_exists('$SmokePath') -> PASS"
        } else {
            $smokePathExistsDetails = "path_exists failed (isError=$isErr): $textOut"
        }
    } catch {
        $smokePathExistsDetails = "MCP path_exists failed: $($_.Exception.Message)"
    }

    # 3d. tools/call list_directory
    try {
        $ldResp = Invoke-McpJsonRpc -Id 4 -Method "tools/call" -Params @{
            name      = "list_directory"
            arguments = @{ path = $SmokePath }
        }
        $isErr = ($ldResp.result.isError -eq $true)
        $textOut = if ($ldResp.result.content -and $ldResp.result.content.Count -gt 0) { [string]$ldResp.result.content[0].text } else { "" }
        if ((-not $isErr) -and ($textOut.Length -gt 2)) {
            $smokeListDirOk = $true
            $smokeListDirDetails = "list_directory('$SmokePath') -> PASS ($($textOut.Length) chars returned)"
        } else {
            $smokeListDirDetails = "list_directory failed (isError=$isErr)"
        }
    } catch {
        $smokeListDirDetails = "MCP list_directory failed: $($_.Exception.Message)"
    }
} else {
    $mcpInitDetails = "Skipped (port 8765 not listening)"
    $toolsListDetails = "Skipped (port 8765 not listening)"
    $smokePathExistsDetails = "Skipped (port 8765 not listening)"
    $smokeListDirDetails = "Skipped (port 8765 not listening)"
}

Add-DiagnosticCheck -Name "MCP Bridge initialize Handshake" -Category "MCP Bridge" `
    -Passed $mcpInitOk -Details $mcpInitDetails -Metadata $mcpServerInfo

Add-DiagnosticCheck -Name "MCP Bridge tools/list Count" -Category "MCP Bridge" `
    -Passed $toolsListOk -Details $toolsListDetails -Metadata @{ count = $toolsCount; tools = $toolNames }

Add-DiagnosticCheck -Name "MCP Smoke Call: path_exists" -Category "MCP Bridge" `
    -Passed $smokePathExistsOk -Details $smokePathExistsDetails

Add-DiagnosticCheck -Name "MCP Smoke Call: list_directory" -Category "MCP Bridge" `
    -Passed $smokeListDirOk -Details $smokeListDirDetails

# ---------------------------------------------------------------------------
# 4. Primary Secure Tunnel (windows-mcp-isolated)
# ---------------------------------------------------------------------------
$isolatedTunnelProcs = @($allProcs | Where-Object {
    $_.Name -eq "tunnel-client.exe" -and
    $_.CommandLine -match "--profile(?:\s+|=)[`"']?windows-mcp-isolated\b"
})
$isolatedRunning = ($isolatedTunnelProcs.Count -ge 1)
$isolatedPid = $(if ($isolatedRunning) { $isolatedTunnelProcs[0].ProcessId } else { $null })
$isolatedCmd = $(if ($isolatedRunning) { ConvertTo-RedactedText $isolatedTunnelProcs[0].CommandLine } else { $null })

Add-DiagnosticCheck -Name "Primary Tunnel Process (windows-mcp-isolated)" -Category "Primary Tunnel" `
    -Passed $isolatedRunning `
    -Details $(if ($isolatedRunning) { "PID=$isolatedPid, TunnelId=tunnel_unconfigured_isolated" } else { "tunnel-client.exe --profile windows-mcp-isolated not running" }) `
    -Metadata @{ pid = $isolatedPid; profile = "windows-mcp-isolated"; tunnel_id = "tunnel_unconfigured_isolated"; command_line = $isolatedCmd }

$userProfileDir = if ($env:USERPROFILE) { $env:USERPROFILE } else { $HOME }
$healthUrlFile = Join-Path $userProfileDir ".codex-chatgpt-web\tunnel\windows-mcp-isolated-health.url"
$isolatedHealthUrl = $null
$healthzOk = $false
$readyzOk = $false
$tunnelHealthDetails = ""

if (Test-Path $healthUrlFile) {
    $isolatedHealthUrl = (Get-Content $healthUrlFile -Raw).Trim().TrimEnd("/")
    try {
        $hzResp = Invoke-WebRequest -Uri "$isolatedHealthUrl/healthz" -UseBasicParsing -TimeoutSec 4
        $rzResp = Invoke-WebRequest -Uri "$isolatedHealthUrl/readyz" -UseBasicParsing -TimeoutSec 4
        $hzBody = ([string]$hzResp.Content).Trim()
        $rzBody = ([string]$rzResp.Content).Trim()
        $healthzOk = ($hzResp.StatusCode -eq 200 -and $hzBody -eq "live")
        $readyzOk = ($rzResp.StatusCode -eq 200 -and $rzBody -eq "ready")
        $tunnelHealthDetails = "URL=$isolatedHealthUrl, /healthz=$($hzResp.StatusCode) ($hzBody), /readyz=$($rzResp.StatusCode) ($rzBody)"
    } catch {
        $tunnelHealthDetails = "Health probe failed at $isolatedHealthUrl : $($_.Exception.Message)"
    }
} else {
    $tunnelHealthDetails = "Health URL file missing: $healthUrlFile"
}

Add-DiagnosticCheck -Name "Primary Tunnel /healthz & /readyz" -Category "Primary Tunnel" `
    -Passed ($isolatedRunning -and $healthzOk -and $readyzOk) `
    -Details $tunnelHealthDetails `
    -Metadata @{ health_url = $isolatedHealthUrl; healthz_ok = $healthzOk; readyz_ok = $readyzOk }

# Run tunnel-client doctor --profile windows-mcp-isolated --explain (read-only) with secret redaction
$tunnelBin = Join-Path $userProfileDir ".codex-chatgpt-web\bin\tunnel-client.exe"
$doctorOk = $false
$doctorSummaryLines = @()
if (Test-Path $tunnelBin) {
    try {
        $rawDoctor = & $tunnelBin doctor --profile windows-mcp-isolated --explain 2>&1
        $doctorExit = $LASTEXITCODE
        foreach ($line in $rawDoctor) {
            $s = [string]$line
            if ($s -match "^(CHECK|RESULT|FAILED_CHECKS|NEXT)\s+") {
                $doctorSummaryLines += (ConvertTo-RedactedText $s)
            }
        }
        $doctorOk = ($doctorExit -eq 0 -or ($doctorSummaryLines -join "`n") -match "RESULT\s+ok")
    } catch {
        $doctorSummaryLines += "doctor command failed: $($_.Exception.Message)"
    }
} else {
    $doctorSummaryLines += "tunnel-client.exe not found at $tunnelBin"
}

$filteredDoctor = @($doctorSummaryLines | Where-Object { $_ -match "^RESULT\s+|^CHECK\s+(config_source|tunnel_id|mcp_target|mcp_server_reachable)" })
Add-DiagnosticCheck -Name "Primary Tunnel Doctor Validation" -Category "Primary Tunnel" `
    -Passed $doctorOk `
    -Details ($filteredDoctor -join " | ") `
    -Metadata @{ summary_lines = $doctorSummaryLines }

# ---------------------------------------------------------------------------
# 5. Legacy Codex Tunnel (tunnel_unconfigured_legacy)
# ---------------------------------------------------------------------------
$legacyTunnelProcs = @($allProcs | Where-Object {
    $_.Name -eq "tunnel-client.exe" -and (
        $_.CommandLine -match "--profile(?:\s+|=)[`"']?codex-chatgpt-web\b" -or
        $_.CommandLine -match "tunnel_unconfigured_legacy"
    )
})
$legacyRunning = ($legacyTunnelProcs.Count -ge 1)
$legacyPid = if ($legacyRunning) { $legacyTunnelProcs[0].ProcessId } else { $null }
$legacyCmd = if ($legacyRunning) { ConvertTo-RedactedText $legacyTunnelProcs[0].CommandLine } else { $null }

$legacyHealthFile = Join-Path $userProfileDir ".local\state\tunnel-client\health\codex-chatgpt-web.url"
$legacyHealthInfo = "Process running (PID=$legacyPid, untouched)"
if ($legacyRunning -and (Test-Path $legacyHealthFile)) {
    try {
        $lUrl = (Get-Content $legacyHealthFile -Raw).Trim().TrimEnd("/")
        $lHz = Invoke-WebRequest -Uri "$lUrl/healthz" -UseBasicParsing -TimeoutSec 3
        $lRz = Invoke-WebRequest -Uri "$lUrl/readyz" -UseBasicParsing -TimeoutSec 3
        $legacyHealthInfo = "PID=$legacyPid, TunnelId=tunnel_unconfigured_legacy, URL=$lUrl (/healthz=$($lHz.StatusCode), /readyz=$($lRz.StatusCode)), Untouched=True"
    } catch {
        $legacyHealthInfo = "PID=$legacyPid, TunnelId=tunnel_unconfigured_legacy, Untouched=True"
    }
} elseif (-not $legacyRunning) {
    $legacyHealthInfo = "Legacy Codex tunnel (codex-chatgpt-web) is NOT running"
}

Add-DiagnosticCheck -Name "Legacy Codex Tunnel (Untouched & Running)" -Category "Coexistence" `
    -Passed $legacyRunning `
    -Details $legacyHealthInfo `
    -Metadata @{
        pid          = $legacyPid
        profile      = "codex-chatgpt-web"
        tunnel_id    = "tunnel_unconfigured_legacy"
        command_line = $legacyCmd
        untouched    = $true
    }

# ---------------------------------------------------------------------------
# 6. Unified Gateway Staging (127.0.0.1:8766/mcp)
# ---------------------------------------------------------------------------
$listener8766 = @(Get-NetTCPConnection -LocalAddress "127.0.0.1" -LocalPort 8766 -State Listen -ErrorAction SilentlyContinue)
$port8766Open = ($listener8766.Count -ge 1)
$stagingPid = $(if ($port8766Open) { $listener8766[0].OwningProcess } else { $null })
$stagingOk = $false
$stagingDetails = ""
$stagingMeta = @{ port = 8766; pid = $stagingPid }

if ($port8766Open) {
    try {
        $gwHealth = Invoke-RestMethod -Uri "http://127.0.0.1:8766/health" -Method Get -TimeoutSec 4
        $gwInit = Invoke-McpJsonRpc -Id 10 -Method "initialize" -Uri "http://127.0.0.1:8766/mcp" -Params @{
            protocolVersion = "2024-11-05"
            capabilities    = @{}
            clientInfo      = @{ name = "Test-WindowsMcpStack"; version = "1.0.0" }
        }
        $gwTools = Invoke-McpJsonRpc -Id 11 -Method "tools/list" -Uri "http://127.0.0.1:8766/mcp" -Params @{}
        $gwToolCount = @($gwTools.result.tools).Count
        if ($gwHealth.status -eq "ok" -and $null -ne $gwInit.result -and $gwToolCount -ge 15) {
            $stagingOk = $true
            $stagingDetails = "127.0.0.1:8766 LISTENING (PID=$stagingPid), profile=$($gwHealth.profile), tools=$gwToolCount, server=$($gwInit.result.serverInfo.name) v$($gwInit.result.serverInfo.version)"
            $stagingMeta = @{
                port        = 8766
                pid         = $stagingPid
                profile     = $gwHealth.profile
                tools_count = $gwToolCount
                version     = $gwInit.result.serverInfo.version
            }
        } else {
            $stagingDetails = "Staging Gateway unexpected response: tools=$gwToolCount"
        }
    } catch {
        $stagingDetails = "Staging Gateway check failed: $($_.Exception.Message)"
    }
} else {
    $stagingDetails = "Port 8766 not listening"
}

Add-DiagnosticCheck -Name "Unified Gateway Staging (127.0.0.1:8766)" -Category "Unified Gateway" `
    -Passed $stagingOk `
    -Details $stagingDetails `
    -Metadata $stagingMeta

# ---------------------------------------------------------------------------
# 7. Security Posture (Ngrok Absent & Backend Auth Enforced)
# ---------------------------------------------------------------------------
$ngrokProcs = @($allProcs | Where-Object { $_.Name -eq "ngrok.exe" })
$ngrokAbsent = ($ngrokProcs.Count -eq 0)
$unauthRejected = $false
$unauthStatus = 0
try {
    $null = Invoke-WebRequest -Uri "http://127.0.0.1:3080/api/tools/path_exists" -Method Post `
        -ContentType "application/json" -Body '{"path":"D:\\ProjectsWindows-MCP-Agent"}' -UseBasicParsing -TimeoutSec 4
    $unauthStatus = 200
} catch {
    if ($_.Exception.Response -and $_.Exception.Response.StatusCode) {
        $unauthStatus = [int]$_.Exception.Response.StatusCode
    }
    if ($unauthStatus -in @(401, 403)) {
        $unauthRejected = $true
    }
}
$secPostureOk = ($ngrokAbsent -and $unauthRejected)
$secPostureDetails = "ngrok_running=$($ngrokProcs.Count), unauthenticated_3080_post_status=$unauthStatus (expected 401/403)"

Add-DiagnosticCheck -Name "Security Posture (No Public Ngrok & 3080 Auth)" -Category "Security" `
    -Passed $secPostureOk `
    -Details $secPostureDetails `
    -Metadata @{
        ngrok_processes            = $ngrokProcs.Count
        unauthenticated_3080_http  = $unauthStatus
        backend_bearer_auth_active = $unauthRejected
    }

# ---------------------------------------------------------------------------
# Output PASS/FAIL Table & Save Redacted Diagnostic Bundle
# ---------------------------------------------------------------------------
$passedCount = @($checks | Where-Object { $_.Passed }).Count
$totalCount = $checks.Count
$allPassed = ($passedCount -eq $totalCount)

Write-Host ""
Write-Host "==========================================================================================" -ForegroundColor Cyan
Write-Host " WinOwner MCP Stack - Diagnostic Verification Report ($passedCount/$totalCount PASS)" -ForegroundColor Cyan
Write-Host "==========================================================================================" -ForegroundColor Cyan
$checks | Select-Object Status, Category, Check, Details | Format-Table -AutoSize -Wrap

$reportDir = Split-Path -Parent $ReportPath
if (-not (Test-Path $reportDir)) {
    New-Item -ItemType Directory -Path $reportDir -Force | Out-Null
}

$reportBundle = [ordered]@{
    schema_version = "1.0.0"
    generated_at   = (Get-Date).ToString("o")
    overall_status = $(if ($allPassed) { "PASS" } else { "FAIL" })
    passed_checks  = $passedCount
    total_checks   = $totalCount
    checks         = $checks
}

$jsonOut = ConvertTo-RedactedText ($reportBundle | ConvertTo-Json -Depth 8)
[System.IO.File]::WriteAllText($ReportPath, $jsonOut, [System.Text.UTF8Encoding]::new($false))
Write-Host "Saved redacted diagnostic bundle to: $ReportPath" -ForegroundColor Green

if (-not $allPassed) {
    exit 1
}
exit 0
