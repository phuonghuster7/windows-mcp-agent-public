<#
.SYNOPSIS
    Safe, transactional update script for the WinOwner MCP Stack (Stage S6 / P6).

.DESCRIPTION
    1. Creates a timestamped backup snapshot of current code and configuration
       in `$TargetRoot\backups\pre_update_<timestamp>` with a SHA256 manifest.
    2. Preserves machine-specific secrets, DPAPI blobs (`runtime/secrets/*.dpapi`),
       and active tunnel profiles (`windows-mcp-isolated.yaml`, `codex-chatgpt-web.yaml`).
    3. Applies updated code files from `-SourcePath` into `-TargetRoot`.
    4. Validates Python syntax (`py_compile`) across all core Python modules.
    5. Performs automatic rollback from the pre-update snapshot if any update step
       or validation check fails (or when `-SimulateFailure` is passed for testing).
    6. Writes a structured JSON report to `$TargetRoot\runtime\logs\update-report.json`.
#>
[CmdletBinding()]
param(
    [string]$TargetRoot = $(if ($PSScriptRoot) { (Resolve-Path (Join-Path $PSScriptRoot "..")).Path } else { (Get-Location).Path }),
    [string]$SourcePath = "",
    [switch]$DryRun,
    [switch]$SimulateFailure
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($SourcePath)) {
    $SourcePath = Split-Path -Parent $PSScriptRoot
}
$SourcePath = [System.IO.Path]::GetFullPath($SourcePath)
$TargetRoot = [System.IO.Path]::GetFullPath($TargetRoot)

if (-not (Test-Path $TargetRoot)) {
    throw "TargetRoot does not exist: $TargetRoot"
}
if (-not (Test-Path $SourcePath)) {
    throw "SourcePath does not exist: $SourcePath"
}

$timestamp = (Get-Date).ToString("yyyyMMdd_HHmmss_fff")
$backupDir = Join-Path $TargetRoot "backups\pre_update_$timestamp"
$manifestPath = Join-Path $backupDir "update_backup_manifest.json"

$trackedRelativeFiles = @(
    "backend\__init__.py",
    "backend\file_code_ops.py",
    "backend\exec_jobs.py",
    "mcp-gateway\__init__.py",
    "mcp-gateway\policy.py",
    "mcp-gateway\gateway_server.py",
    "mcp-gateway\http_server.py",
    "mcp-gateway\tools_catalog.json",
    "desktop-agent\__init__.py",
    "desktop-agent\agent.py",
    "runtime\__init__.py",
    "runtime\watchdog.py",
    "config\policy.json"
)

# Discover existing DPAPI secret blobs to guarantee preservation
$secretsDir = Join-Path $TargetRoot "runtime\secrets"
$secretBlobsBefore = @()
if (Test-Path $secretsDir) {
    $secretBlobsBefore = @(Get-ChildItem -Path $secretsDir -Filter "*.dpapi" -File -ErrorAction SilentlyContinue | ForEach-Object {
        [PSCustomObject]@{
            Name   = $_.Name
            Sha256 = (Get-FileHash -Path $_.FullName -Algorithm SHA256).Hash.ToUpperInvariant()
        }
    })
}

# 1. Build pre-update snapshot & SHA256 manifest
$manifestEntries = New-Object System.Collections.Generic.List[object]
if (-not $DryRun) {
    New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
}

foreach ($rel in $trackedRelativeFiles) {
    $targetFile = Join-Path $TargetRoot $rel
    if (Test-Path $targetFile) {
        $hash = (Get-FileHash -Path $targetFile -Algorithm SHA256).Hash.ToUpperInvariant()
        if (-not $DryRun) {
            $bkpFile = Join-Path $backupDir $rel
            $bkpParent = Split-Path -Parent $bkpFile
            if (-not (Test-Path $bkpParent)) {
                New-Item -ItemType Directory -Path $bkpParent -Force | Out-Null
            }
            Copy-Item -Path $targetFile -Destination $bkpFile -Force
        }
        $manifestEntries.Add([PSCustomObject]@{
            relative_path = $rel
            original_path = $targetFile
            sha256        = $hash
        })
    }
}

$manifestObj = [ordered]@{
    schema_version = "1.0.0"
    created_at     = (Get-Date).ToString("o")
    target_root    = $TargetRoot
    source_path    = $SourcePath
    backup_dir     = $backupDir
    files          = $manifestEntries
}

if (-not $DryRun) {
    [System.IO.File]::WriteAllText(
        $manifestPath,
        ($manifestObj | ConvertTo-Json -Depth 6),
        [System.Text.UTF8Encoding]::new($false)
    )
}

# 2. Apply updates & validate syntax with automatic rollback on failure
$updatedCount = 0
$rolledBack = $false
$rollbackVerified = $false
$updateError = $null
$syntaxValidationPassed = $true

$cmdPy = Get-Command python.exe -ErrorAction SilentlyContinue
if ($null -ne $cmdPy -and (Test-Path $cmdPy.Source)) {
    $pythonExe = $cmdPy.Source
} else {
    $localAppData = if ($env:LOCALAPPDATA) { $env:LOCALAPPDATA } else { Join-Path $env:USERPROFILE "AppData\Local" }
    $pythonExe = Join-Path $localAppData "Programs\Python\Python312\python.exe"
}

try {
    if (-not $DryRun) {
        $sameRoot = ($SourcePath.TrimEnd('\').ToLowerInvariant() -eq $TargetRoot.TrimEnd('\').ToLowerInvariant())
        foreach ($rel in $trackedRelativeFiles) {
            # Never overwrite existing config\policy.json if it already exists in TargetRoot
            if ($rel -eq "config\policy.json" -and (Test-Path (Join-Path $TargetRoot $rel))) {
                continue
            }
            $srcFile = Join-Path $SourcePath $rel
            $dstFile = Join-Path $TargetRoot $rel
            if ((Test-Path $srcFile) -and (-not $sameRoot)) {
                $dstParent = Split-Path -Parent $dstFile
                if (-not (Test-Path $dstParent)) {
                    New-Item -ItemType Directory -Path $dstParent -Force | Out-Null
                }
                Copy-Item -Path $srcFile -Destination $dstFile -Force
                $updatedCount++
            } elseif (Test-Path $srcFile) {
                $updatedCount++
            }
        }
    } else {
        $updatedCount = $trackedRelativeFiles.Count
    }

    # Syntax validation across Python files
    $pyFiles = @($trackedRelativeFiles | Where-Object { $_ -like "*.py" })
    foreach ($pyRel in $pyFiles) {
        $pyFull = Join-Path $TargetRoot $pyRel
        if (Test-Path $pyFull) {
            & $pythonExe -m py_compile $pyFull 2>$null
            if ($LASTEXITCODE -ne 0) {
                $syntaxValidationPassed = $false
                throw "Python syntax validation failed for $pyFull"
            }
        }
    }

    if ($SimulateFailure) {
        throw "Simulated post-update verification failure triggered via -SimulateFailure."
    }
} catch {
    $updateError = $_.Exception.Message
    if (-not $DryRun) {
        $rolledBack = $true
        $allRestoredOk = $true
        foreach ($entry in $manifestEntries) {
            $bkpFile = Join-Path $backupDir $entry.relative_path
            $origFile = $entry.original_path
            if (Test-Path $bkpFile) {
                Copy-Item -Path $bkpFile -Destination $origFile -Force
                $restoredHash = (Get-FileHash -Path $origFile -Algorithm SHA256).Hash.ToUpperInvariant()
                if ($restoredHash -ne $entry.sha256) {
                    $allRestoredOk = $false
                }
            } else {
                $allRestoredOk = $false
            }
        }
        $rollbackVerified = $allRestoredOk
    }
}

# Verify secrets remained untouched
$secretsPreserved = $true
foreach ($blob in $secretBlobsBefore) {
    $blobPath = Join-Path $secretsDir $blob.Name
    if (-not (Test-Path $blobPath)) {
        $secretsPreserved = $false
    } else {
        $afterHash = (Get-FileHash -Path $blobPath -Algorithm SHA256).Hash.ToUpperInvariant()
        if ($afterHash -ne $blob.Sha256) {
            $secretsPreserved = $false
        }
    }
}

$overallOk = (($null -eq $updateError -and $syntaxValidationPassed -and $secretsPreserved) -or ($SimulateFailure -and $rolledBack -and $rollbackVerified -and $secretsPreserved))

$reportObj = [ordered]@{
    schema_version           = "1.0.0"
    generated_at             = (Get-Date).ToString("o")
    script                   = "Update-WindowsMcpAgent.ps1"
    target_root              = $TargetRoot
    source_path              = $SourcePath
    dry_run                  = [bool]$DryRun
    simulate_failure         = [bool]$SimulateFailure
    backup_dir               = $backupDir
    manifest_path            = $manifestPath
    backed_up_files_count    = $manifestEntries.Count
    updated_files_count      = $updatedCount
    syntax_validation_passed = $syntaxValidationPassed
    secrets_preserved        = $secretsPreserved
    rolled_back              = $rolledBack
    rollback_verified        = $rollbackVerified
    error_message            = $updateError
    overall_status           = $(if ($overallOk) { "PASS" } else { "FAIL" })
}

$reportPath = Join-Path $TargetRoot "runtime\logs\update-report.json"
$reportDir = Split-Path -Parent $reportPath
if (Test-Path $reportDir) {
    [System.IO.File]::WriteAllText(
        $reportPath,
        ($reportObj | ConvertTo-Json -Depth 6),
        [System.Text.UTF8Encoding]::new($false)
    )
}

$modeText = $(if ($DryRun) { "DRY-RUN" } elseif ($SimulateFailure) { "ROLLBACK-DRILL" } else { "LIVE UPDATE" })
Write-Host "==========================================================================================" -ForegroundColor Cyan
Write-Host " WinOwner MCP Updater ($modeText) -> Status: $($reportObj.overall_status)" -ForegroundColor $(if ($overallOk) { "Green" } else { "Red" })
Write-Host " BackedUp: $($manifestEntries.Count) | SecretsPreserved: $secretsPreserved | RolledBack: $rolledBack" -ForegroundColor Cyan
Write-Host "==========================================================================================" -ForegroundColor Cyan

if (-not $overallOk) {
    exit 1
}
exit 0
