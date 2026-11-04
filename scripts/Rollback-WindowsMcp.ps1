<#
.SYNOPSIS
    Verifiable rollback script for the WinOwner MCP Stack (P0 Baseline).

.DESCRIPTION
    1. Reads `D:\ExampleProjects\Windows-MCP-Agent\backups\baseline_p0\baseline_hashes.json`.
    2. Verifies SHA256 hashes of all backed-up files in `backups\baseline_p0`.
    3. Compares live files against baseline SHA256 hashes.
    4. In `-DryRun` mode, reports verification status without modifying any files or processes.
    5. When `-DryRun` is omitted, restores files from `backups\baseline_p0` to their
       original paths, re-verifies SHA256 hashes post-restore, and optionally restarts
       the MCP Bridge / Secure Tunnel via `-RestartServices` (never touching the legacy Codex tunnel).
#>
[CmdletBinding()]
param(
    [string]$BackupDir = $(if ($PSScriptRoot) { Join-Path (Resolve-Path (Join-Path $PSScriptRoot "..")).Path "backups\baseline_p0" } else { Join-Path (Get-Location).Path "backups\baseline_p0" }),
    [switch]$DryRun,
    [switch]$RestartServices
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ManifestPath = Join-Path $BackupDir "baseline_hashes.json"
if (-not (Test-Path $ManifestPath)) {
    throw "Baseline hash manifest not found at: $ManifestPath"
}

$manifest = Get-Content -Path $ManifestPath -Raw | ConvertFrom-Json
$results = New-Object System.Collections.Generic.List[object]
$failures = 0
$restoredCount = 0
$driftCount = 0

foreach ($entry in $manifest.files) {
    $relPath = [string]$entry.relative_path
    $origPath = [string]$entry.original_path
    $expectedHash = ([string]$entry.sha256).ToUpperInvariant()

    # Special handling for redacted tunnel config: verify live file hash against baseline without overwriting live key with [REDACTED]
    if ($relPath -match "windows-mcp-isolated\.redacted\.yaml") {
        $redactedFile = Join-Path $BackupDir "windows-mcp-isolated.redacted.yaml"
        $redactedExists = Test-Path $redactedFile
        $liveExists = Test-Path $origPath
        $liveHash = $(if ($liveExists) { (Get-FileHash -Path $origPath -Algorithm SHA256).Hash.ToUpperInvariant() } else { "MISSING" })
        $hashMatch = ($liveHash -eq $expectedHash)

        if (-not $redactedExists -or -not $liveExists) {
            $failures++
        }

        $results.Add([PSCustomObject]@{
            File         = "windows-mcp-isolated.yaml (redacted backup)"
            BackupHashOk = $redactedExists
            LiveMatches  = $hashMatch
            Action       = $(if ($DryRun) { "DRYRUN_VERIFY_ONLY (secret preserved)" } else { "VERIFIED_SECRET_PRESERVED" })
            Status       = $(if ($redactedExists -and $liveExists) { "PASS" } else { "FAIL" })
        })
        continue
    }

    $backupFile = Join-Path $BackupDir $relPath
    if (-not (Test-Path $backupFile)) {
        $failures++
        $results.Add([PSCustomObject]@{
            File         = $relPath
            BackupHashOk = $false
            LiveMatches  = $false
            Action       = "BACKUP_FILE_MISSING"
            Status       = "FAIL"
        })
        continue
    }

    $backupHash = (Get-FileHash -Path $backupFile -Algorithm SHA256).Hash.ToUpperInvariant()
    $backupHashOk = ($backupHash -eq $expectedHash)
    if (-not $backupHashOk) {
        $failures++
        $results.Add([PSCustomObject]@{
            File         = $relPath
            BackupHashOk = $false
            LiveMatches  = $false
            Action       = "BACKUP_HASH_MISMATCH"
            Status       = "FAIL"
        })
        continue
    }

    $liveExists = Test-Path $origPath
    $liveHash = $(if ($liveExists) { (Get-FileHash -Path $origPath -Algorithm SHA256).Hash.ToUpperInvariant() } else { "MISSING" })
    $liveMatches = ($liveHash -eq $expectedHash)
    if (-not $liveMatches) {
        $driftCount++
    }

    if ($DryRun) {
        $actionText = $(if ($liveMatches) { "DRYRUN_IN_SYNC" } else { "DRYRUN_WOULD_RESTORE" })
        $results.Add([PSCustomObject]@{
            File         = $relPath
            BackupHashOk = $true
            LiveMatches  = $liveMatches
            Action       = $actionText
            Status       = "PASS"
        })
    } else {
        $parentDir = Split-Path -Parent $origPath
        if (-not (Test-Path $parentDir)) {
            New-Item -ItemType Directory -Path $parentDir -Force | Out-Null
        }
        Copy-Item -Path $backupFile -Destination $origPath -Force
        $postHash = (Get-FileHash -Path $origPath -Algorithm SHA256).Hash.ToUpperInvariant()
        $verifyOk = ($postHash -eq $expectedHash)
        if ($verifyOk) {
            $restoredCount++
        } else {
            $failures++
        }
        $results.Add([PSCustomObject]@{
            File         = $relPath
            BackupHashOk = $true
            LiveMatches  = $verifyOk
            Action       = $(if ($verifyOk) { "RESTORED_AND_VERIFIED" } else { "POST_RESTORE_HASH_FAIL" })
            Status       = $(if ($verifyOk) { "PASS" } else { "FAIL" })
        })
    }
}

$modeLabel = $(if ($DryRun) { "DRY-RUN VERIFICATION" } else { "LIVE ROLLBACK" })
Write-Host ""
Write-Host "==========================================================================================" -ForegroundColor Cyan
Write-Host " WinOwner MCP Stack - Baseline P0 Rollback ($modeLabel)" -ForegroundColor Cyan
Write-Host "==========================================================================================" -ForegroundColor Cyan
$results | Format-Table -AutoSize

Write-Host "Summary: TotalFiles=$($results.Count), DriftDetected=$driftCount, Restored=$restoredCount, Failures=$failures" -ForegroundColor $(if ($failures -eq 0) { "Green" } else { "Red" })

if ((-not $DryRun) -and $RestartServices -and ($failures -eq 0)) {
    Write-Host "Restarting/verifying MCP Bridge & Secure Tunnel via watchdog.py --once..." -ForegroundColor Cyan
    $targetRoot = if ($PSScriptRoot) { (Resolve-Path (Join-Path $PSScriptRoot "..")).Path } else { (Get-Location).Path }
    $cmdPy = Get-Command python.exe -ErrorAction SilentlyContinue
    if ($null -ne $cmdPy -and (Test-Path $cmdPy.Source)) {
        $pythonExe = $cmdPy.Source
    } else {
        $localAppData = if ($env:LOCALAPPDATA) { $env:LOCALAPPDATA } else { Join-Path $env:USERPROFILE "AppData\Local" }
        $pythonExe = Join-Path $localAppData "Programs\Python\Python312\python.exe"
    }
    & $pythonExe (Join-Path $targetRoot "runtime\watchdog.py") --once
}

if ($failures -gt 0) {
    exit 1
}
exit 0
