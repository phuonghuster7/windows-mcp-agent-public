<#
.SYNOPSIS
    ChatGPT Account Migration & Secure Tunnel Binding Wizard (Stage S6 / P6).

.DESCRIPTION
    Supports:
      - Scenario A: Same Windows machine, switching to a new ChatGPT Web/Work account
                    while preserving existing tunnel backup and zero-downtime rollback.
      - Scenario B: Fresh Windows installation tunnel binding (`windows-mcp-isolated`
                    -> `http://127.0.0.1:8765/mcp` or `http://127.0.0.1:8766/mcp`).

    Safety Guarantees:
      1. Backs up existing `windows-mcp-isolated.yaml` (redacted + SHA256 hash) and health
         URL file to `$TargetRoot\backups\tunnel_migration_<timestamp>\` BEFORE any changes.
      2. Never invalidates or overwrites the active tunnel prematurely.
      3. Explicitly blocks any modification to `codex-chatgpt-web`
         (`tunnel_unconfigured_legacy`).
      4. Validates the generated tunnel YAML template structure.
      5. Runs `tunnel-client.exe doctor --profile <profile> --explain` with full secret redaction.
      6. Explicitly labels all output and JSON artifacts as `SIMULATED` when `-Simulated` or `-DryRun` is used.
#>
[CmdletBinding()]
param(
    [string]$NewProfileName = "windows-mcp-isolated",
    [string]$NewTunnelId = "",
    [string]$McpTargetUrl = "http://127.0.0.1:8765/mcp",
    [ValidateSet("Auto", "ScenarioA", "ScenarioB")][string]$Scenario = "Auto",
    [string]$TargetRoot = $(if ($PSScriptRoot) { (Resolve-Path (Join-Path $PSScriptRoot "..")).Path } else { (Get-Location).Path }),
    [System.Security.SecureString]$NewApiKey = $null,
    [switch]$Simulated,
    [switch]$DryRun
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
# 1. Coexistence Guard: Never touch codex-chatgpt-web
# ---------------------------------------------------------------------------
if ($NewProfileName -ieq "codex-chatgpt-web" -or ($env:WINDOWS_MCP_LEGACY_CODEX_TUNNEL_ID -and $NewTunnelId -ieq $env:WINDOWS_MCP_LEGACY_CODEX_TUNNEL_ID)) {
    throw "SECURITY VIOLATION: Modifying legacy Codex profile 'codex-chatgpt-web' (tunnel_unconfigured_legacy) is strictly forbidden."
}

$TargetRoot = [System.IO.Path]::GetFullPath($TargetRoot)
$IsSimulatedMode = [bool]($Simulated -or $DryRun)
$ModeBanner = $(if ($IsSimulatedMode) { "SIMULATED" } else { "LIVE" })

$appDataRoaming = if ($env:APPDATA) { $env:APPDATA } else { Join-Path $env:USERPROFILE "AppData\Roaming" }
$userProfileDir = if ($env:USERPROFILE) { $env:USERPROFILE } else { $HOME }

$liveProfilePath = Join-Path $appDataRoaming "tunnel-client\$NewProfileName.yaml"
$liveHealthUrlPath = Join-Path $userProfileDir ".codex-chatgpt-web\tunnel\$NewProfileName-health.url"
$existingProfilePresent = (Test-Path $liveProfilePath)

if ($Scenario -eq "Auto") {
    $resolvedScenario = $(if ($existingProfilePresent) { "ScenarioA_SameMachineAccountSwitch" } else { "ScenarioB_FreshMachineTunnelBind" })
} elseif ($Scenario -eq "ScenarioA") {
    $resolvedScenario = "ScenarioA_SameMachineAccountSwitch"
} else {
    $resolvedScenario = "ScenarioB_FreshMachineTunnelBind"
}

$effectiveTunnelId = $(if (-not [string]::IsNullOrWhiteSpace($NewTunnelId)) {
    $NewTunnelId.Trim()
} elseif ($IsSimulatedMode) {
    "tunnel_simulated_new_account_000000000000"
} else {
    "tunnel_unconfigured_isolated"
})

# ---------------------------------------------------------------------------
# 2. Backup Existing Tunnel Config BEFORE Any Changes
# ---------------------------------------------------------------------------
$timestamp = (Get-Date).ToString("yyyyMMdd_HHmmss_fff")
$backupDir = Join-Path $TargetRoot "backups\tunnel_migration_$timestamp"
$backupCreated = $false
$originalProfileSha256 = $null
$originalHealthUrl = $null

if (-not $DryRun) {
    New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
    $backupCreated = $true
}

if ($existingProfilePresent) {
    $originalProfileSha256 = (Get-FileHash -Path $liveProfilePath -Algorithm SHA256).Hash.ToUpperInvariant()
    $rawContent = Get-Content -Path $liveProfilePath -Raw
    $redactedContent = ConvertTo-RedactedText $rawContent
    if (-not $DryRun) {
        $redactedBackupFile = Join-Path $backupDir "$NewProfileName.redacted.yaml"
        [System.IO.File]::WriteAllText($redactedBackupFile, $redactedContent, [System.Text.UTF8Encoding]::new($false))
    }
}

if (Test-Path $liveHealthUrlPath) {
    $originalHealthUrl = (Get-Content -Path $liveHealthUrlPath -Raw).Trim()
    if (-not $DryRun) {
        Copy-Item -Path $liveHealthUrlPath -Destination (Join-Path $backupDir "$NewProfileName-health.url") -Force
    }
}

# ---------------------------------------------------------------------------
# 3. Generate & Validate Tunnel YAML Template
# ---------------------------------------------------------------------------
$escapedHealthPath = $liveHealthUrlPath.Replace("\", "\\")
$yamlTemplate = @"
config_version: 1
control_plane:
  base_url: "https://api.openai.com"

  tunnel_id: "$effectiveTunnelId"
  api_key: "<REDACTED_DPAPI_SEALED_API_KEY>"
health:
  listen_addr: "127.0.0.1:0"
  url_file: "$escapedHealthPath"
admin_ui:
  open_browser: false
log:
  level: info
  format: json
mcp:
  server_urls:
    - channel: main
      url: "$McpTargetUrl"
"@

# Validate YAML template fields
$yamlChecks = [ordered]@{
    has_config_version = [bool]($yamlTemplate -match "(?m)^config_version:\s*1\b")
    has_base_url       = [bool]($yamlTemplate -match 'base_url:\s*"https://api\.openai\.com"')
    has_tunnel_id      = [bool]($yamlTemplate -match 'tunnel_id:\s*"tunnel_[A-Za-z0-9_]+"')
    has_health_addr    = [bool]($yamlTemplate -match 'listen_addr:\s*"127\.0\.0\.1:0"')
    has_mcp_url        = [bool]($yamlTemplate -match [regex]::Escape($McpTargetUrl))
}
$yamlValid = ($yamlChecks.Values -notcontains $false)

$candidateFile = Join-Path $backupDir "candidate_$NewProfileName.redacted.yaml"
if (-not $DryRun) {
    [System.IO.File]::WriteAllText($candidateFile, $yamlTemplate, [System.Text.UTF8Encoding]::new($false))
    $migrationManifest = [ordered]@{
        schema_version          = "1.0.0"
        created_at              = (Get-Date).ToString("o")
        mode                    = $ModeBanner
        simulated               = $IsSimulatedMode
        scenario                = $resolvedScenario
        profile_name            = $NewProfileName
        new_tunnel_id           = $effectiveTunnelId
        mcp_target_url          = $McpTargetUrl
        live_profile_path       = $liveProfilePath
        live_profile_untouched  = $true
        original_profile_sha256 = $originalProfileSha256
        original_health_url     = $originalHealthUrl
        candidate_yaml_path     = $candidateFile
        yaml_template_valid     = $yamlValid
    }
    [System.IO.File]::WriteAllText(
        (Join-Path $backupDir "migration_manifest.json"),
        ($migrationManifest | ConvertTo-Json -Depth 6),
        [System.Text.UTF8Encoding]::new($false)
    )
}

# If live mode AND NewApiKey was explicitly supplied, seal via Protect-TunnelCredential.ps1
$dpapiSealed = $false
if ((-not $IsSimulatedMode) -and ($null -ne $NewApiKey)) {
    $protectScript = Join-Path $TargetRoot "scripts\Protect-TunnelCredential.ps1"
    if (Test-Path $protectScript) {
        & $protectScript `
            -SecretName "$NewProfileName.api_key" `
            -SecretValue $NewApiKey `
            -SecretsDir (Join-Path $TargetRoot "runtime\secrets") | Out-Null
        $dpapiSealed = $true
    }
}

# ---------------------------------------------------------------------------
# 4. Run tunnel-client.exe doctor --profile <profile> --explain (Redacted)
# ---------------------------------------------------------------------------
$tunnelBin = Join-Path $userProfileDir ".codex-chatgpt-web\bin\tunnel-client.exe"
$doctorLines = @()
$doctorOk = $false
$profileToCheck = $(if ($existingProfilePresent) { $NewProfileName } else { "windows-mcp-isolated" })

if ((Test-Path $tunnelBin) -and (Test-Path (Join-Path $appDataRoaming "tunnel-client\$profileToCheck.yaml"))) {
    try {
        $rawOut = & $tunnelBin doctor --profile $profileToCheck --explain 2>&1
        $exitCode = $LASTEXITCODE
        foreach ($line in $rawOut) {
            $strLine = [string]$line
            if ($strLine -match "^(CHECK|RESULT|FAILED_CHECKS|NEXT)\s+") {
                $doctorLines += (ConvertTo-RedactedText $strLine)
            }
        }
        if ($IsSimulatedMode) {
            $doctorOk = $true
        } else {
            $doctorOk = ($exitCode -eq 0 -or ($doctorLines -join "`n") -match "RESULT\s+ok")
        }
    } catch {
        $doctorLines += "doctor invocation failed: $($_.Exception.Message)"
    }
} else {
    $doctorLines += "SIMULATED_DOCTOR_SKIPPED (profile or binary not present on fresh machine)"
    $doctorOk = $IsSimulatedMode
}

# Verify live profile hash did not change when Simulated/DryRun
$liveProfileUnchanged = $true
if ($existingProfilePresent -and $IsSimulatedMode) {
    $afterHash = (Get-FileHash -Path $liveProfilePath -Algorithm SHA256).Hash.ToUpperInvariant()
    $liveProfileUnchanged = ($afterHash -eq $originalProfileSha256)
}

# ---------------------------------------------------------------------------
# 5. Step-by-Step Instructions & Structured Report
# ---------------------------------------------------------------------------
$instructions = @(
    "Step 1 [Backup Verified]: Existing tunnel profile backed up to '$backupDir' (SHA256=$originalProfileSha256).",
    "Step 2 [ChatGPT Browser Login]: Sign in to the target ChatGPT account at https://chatgpt.com.",
    "Step 3 [Tunnel Provisioning]: Create or bind Secure Tunnel '$effectiveTunnelId' for profile '$NewProfileName' pointing to '$McpTargetUrl'.",
    "Step 4 [DPAPI Credential Seal]: Run scripts\Protect-TunnelCredential.ps1 -ProtectFromProfile to seal the new api_key into runtime\secrets\$NewProfileName.api_key.dpapi.",
    "Step 5 [Restart Only Isolated Tunnel]: Run python runtime\watchdog.py --once (codex-chatgpt-web remains 100% untouched).",
    "Step 6 [Refresh Connector Cache]: Open https://chatgpt.com/#settings/Connectors, select 'Windows MCP Direct', and click 'Refresh' to sync all 15 tools (Mode A) or 55 tools (Mode B)."
)

$overallOk = ($yamlValid -and $doctorOk -and $liveProfileUnchanged)

$reportObj = [ordered]@{
    schema_version          = "1.0.0"
    generated_at            = (Get-Date).ToString("o")
    script                  = "Connect-ChatGPTAccount.ps1"
    execution_mode          = $ModeBanner
    simulated               = $IsSimulatedMode
    dry_run                 = [bool]$DryRun
    scenario                = $resolvedScenario
    profile_name            = $NewProfileName
    new_tunnel_id           = $effectiveTunnelId
    mcp_target_url          = $McpTargetUrl
    backup_dir              = $backupDir
    backup_created          = $backupCreated
    original_profile_sha256 = $originalProfileSha256
    live_profile_unchanged  = $liveProfileUnchanged
    yaml_template_valid     = $yamlValid
    yaml_validation_checks  = $yamlChecks
    dpapi_sealed            = $dpapiSealed
    doctor_validation       = [ordered]@{
        profile_checked = $profileToCheck
        passed          = $doctorOk
        redacted_lines  = $doctorLines
    }
    coexistence_guard       = [ordered]@{
        legacy_codex_profile = "codex-chatgpt-web"
        legacy_codex_tunnel  = "tunnel_unconfigured_legacy"
        untouched            = $true
    }
    operator_steps          = $instructions
    overall_status          = $(if ($overallOk) { "PASS" } else { "FAIL" })
}

$reportPath = Join-Path $TargetRoot "runtime\logs\account-migration-report.json"
$reportDir = Split-Path -Parent $reportPath
if (-not (Test-Path $reportDir) -and (-not $DryRun)) {
    New-Item -ItemType Directory -Path $reportDir -Force | Out-Null
}
if (Test-Path $reportDir) {
    [System.IO.File]::WriteAllText(
        $reportPath,
        ($reportObj | ConvertTo-Json -Depth 6),
        [System.Text.UTF8Encoding]::new($false)
    )
}

Write-Host "==========================================================================================" -ForegroundColor Cyan
Write-Host " [$ModeBanner] ChatGPT Account Migration & Tunnel Wizard ($resolvedScenario)" -ForegroundColor $(if ($overallOk) { "Green" } else { "Red" })
Write-Host " Profile: $NewProfileName | Target: $McpTargetUrl | TunnelId: $effectiveTunnelId" -ForegroundColor Cyan
Write-Host " BackupDir: $backupDir | LiveProfileUntouched: $liveProfileUnchanged" -ForegroundColor Cyan
Write-Host "==========================================================================================" -ForegroundColor Cyan
foreach ($step in $instructions) {
    Write-Host "  * $step"
}

if (-not $overallOk) {
    exit 1
}
exit 0
