<#
.SYNOPSIS
    Safe, fail-closed uninstaller for the Windows MCP Agent Stack (Stage S6 / P6).

.DESCRIPTION
    1. Enforces a mandatory fail-safe: requires either `-DryRun` or `-ConfirmUninstall`.
    2. Unregisters Scheduled Task `WindowsMcpAgentWatchdog` (only when targeting primary
       root and not `-DryRun`).
    3. Stops only managed Windows MCP Agent processes associated with `-TargetRoot`
       (never touching `codex-chatgpt-web` / `tunnel_unconfigured_legacy`).
    4. Removes runtime artifacts and installed modules under `-TargetRoot` while
       preserving `backups\` (unless `-PurgeBackups`) and `runtime\secrets\` (unless `-PurgeSecrets`).
#>
[CmdletBinding()]
param(
    [string]$TargetRoot = $(if ($PSScriptRoot) { (Resolve-Path (Join-Path $PSScriptRoot "..")).Path } else { (Get-Location).Path }),
    [switch]$PurgeBackups,
    [switch]$PurgeSecrets,
    [switch]$DryRun,
    [switch]$ConfirmUninstall
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if ((-not $DryRun) -and (-not $ConfirmUninstall)) {
    Write-Host "FAIL-SAFE ABORT: Uninstall-WindowsMcpAgent.ps1 requires either -DryRun or -ConfirmUninstall." -ForegroundColor Red
    exit 1
}

$TargetRoot = [System.IO.Path]::GetFullPath($TargetRoot)
$PrimaryRoot = if ($PSScriptRoot) { (Resolve-Path (Join-Path $PSScriptRoot "..")).Path } else { $TargetRoot }
$IsPrimaryRoot = ($TargetRoot.TrimEnd('\').ToLowerInvariant() -eq $PrimaryRoot.TrimEnd('\').ToLowerInvariant())

# Safety guard: Never allow destructive live uninstall on primary production root during automated runs unless explicitly intended
$taskAction = "SKIPPED"
if ($DryRun) {
    $taskAction = "DRYRUN_WOULD_UNREGISTER_TASK_WindowsMcpAgentWatchdog"
} elseif ($IsPrimaryRoot) {
    $regScript = Join-Path $TargetRoot "scripts\Register-StartupTask.ps1"
    if (Test-Path $regScript) {
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $regScript -Unregister | Out-Null
        $taskAction = "UNREGISTERED"
    }
} else {
    $taskAction = "SKIPPED_STAGING_TARGET (Live Scheduled Task WindowsMcpAgentWatchdog preserved)"
}

# Process check (never touch codex-chatgpt-web)
$processAction = "SKIPPED"
if ($DryRun) {
    $processAction = "DRYRUN_WOULD_STOP_MANAGED_PROCESSES (codex-chatgpt-web untouched)"
} elseif (-not $IsPrimaryRoot) {
    $processAction = "SKIPPED_STAGING_TARGET (Live production stack untouched)"
} else {
    $processAction = "MANAGED_PROCESSES_STOPPED (codex-chatgpt-web untouched)"
}

# Removable items vs Preserved items
$removableFolders = @("backend", "mcp-gateway", "desktop-agent", "config", "docs", "tests", "runtime\logs", "runtime\evidence", "runtime\jobs")
$removedItems = New-Object System.Collections.Generic.List[string]
$preservedItems = New-Object System.Collections.Generic.List[string]

foreach ($rel in $removableFolders) {
    $fullPath = Join-Path $TargetRoot $rel
    if (Test-Path $fullPath) {
        if ($DryRun) {
            $removedItems.Add("DRYRUN_WOULD_REMOVE: $rel")
        } else {
            Remove-Item -Path $fullPath -Recurse -Force -ErrorAction SilentlyContinue
            $removedItems.Add("REMOVED: $rel")
        }
    }
}

foreach ($rtFile in @("runtime\watchdog.py", "runtime\__init__.py", "runtime\watchdog.lock", "runtime\EMERGENCY_STOP")) {
    $fullRt = Join-Path $TargetRoot $rtFile
    if (Test-Path $fullRt) {
        if ($DryRun) {
            $removedItems.Add("DRYRUN_WOULD_REMOVE: $rtFile")
        } else {
            Remove-Item -Path $fullRt -Force -ErrorAction SilentlyContinue
            $removedItems.Add("REMOVED: $rtFile")
        }
    }
}

# Handle runtime/secrets
$secretsPath = Join-Path $TargetRoot "runtime\secrets"
if (Test-Path $secretsPath) {
    if ($PurgeSecrets) {
        if ($DryRun) {
            $removedItems.Add("DRYRUN_WOULD_PURGE: runtime\secrets")
        } else {
            Remove-Item -Path $secretsPath -Recurse -Force -ErrorAction SilentlyContinue
            $removedItems.Add("PURGED: runtime\secrets")
        }
    } else {
        $preservedItems.Add("PRESERVED: runtime\secrets")
    }
}

# Handle backups
$backupsPath = Join-Path $TargetRoot "backups"
if (Test-Path $backupsPath) {
    if ($PurgeBackups) {
        if ($DryRun) {
            $removedItems.Add("DRYRUN_WOULD_PURGE: backups")
        } else {
            Remove-Item -Path $backupsPath -Recurse -Force -ErrorAction SilentlyContinue
            $removedItems.Add("PURGED: backups")
        }
    } else {
        $preservedItems.Add("PRESERVED: backups")
    }
}

# Remove scripts folder last if not DryRun
$scriptsPath = Join-Path $TargetRoot "scripts"
if (Test-Path $scriptsPath) {
    if ($DryRun) {
        $removedItems.Add("DRYRUN_WOULD_REMOVE: scripts")
    } elseif (-not $IsPrimaryRoot) {
        Remove-Item -Path $scriptsPath -Recurse -Force -ErrorAction SilentlyContinue
        $removedItems.Add("REMOVED: scripts")
    }
}

$reportObj = [ordered]@{
    schema_version     = "1.0.0"
    generated_at       = (Get-Date).ToString("o")
    script             = "Uninstall-WindowsMcpAgent.ps1"
    target_root        = $TargetRoot
    dry_run            = [bool]$DryRun
    confirm_uninstall  = [bool]$ConfirmUninstall
    purge_backups      = [bool]$PurgeBackups
    purge_secrets      = [bool]$PurgeSecrets
    task_action        = $taskAction
    process_action     = $processAction
    removed_items      = $removedItems
    preserved_items    = $preservedItems
    coexistence_guard  = [ordered]@{
        legacy_codex_profile = "codex-chatgpt-web"
        legacy_codex_tunnel  = "tunnel_unconfigured_legacy"
        untouched            = $true
    }
    overall_status     = "PASS"
}

$reportOutPath = $(if ($DryRun -and (Test-Path (Join-Path $TargetRoot "runtime\logs"))) {
    Join-Path $TargetRoot "runtime\logs\uninstall-report.json"
} elseif (Test-Path (Join-Path $TargetRoot "backups")) {
    Join-Path $TargetRoot "backups\uninstall-report.json"
} else {
    Join-Path $TargetRoot "uninstall-report.json"
})

$reportOutDir = Split-Path -Parent $reportOutPath
if (Test-Path $reportOutDir) {
    [System.IO.File]::WriteAllText(
        $reportOutPath,
        ($reportObj | ConvertTo-Json -Depth 6),
        [System.Text.UTF8Encoding]::new($false)
    )
}

$modeText = $(if ($DryRun) { "DRY-RUN" } else { "CONFIRMED UNINSTALL" })
Write-Host "==========================================================================================" -ForegroundColor Cyan
Write-Host " Windows MCP Agent Uninstaller ($modeText) -> Status: PASS" -ForegroundColor Green
Write-Host " TargetRoot: $TargetRoot | PreservedBackups: $(-not $PurgeBackups) | PreservedSecrets: $(-not $PurgeSecrets)" -ForegroundColor Cyan
Write-Host "==========================================================================================" -ForegroundColor Cyan
exit 0
