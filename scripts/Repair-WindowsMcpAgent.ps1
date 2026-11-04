<#
.SYNOPSIS
    Self-healing repair script for the WinOwner MCP Stack (Stage S6 / P6).

.DESCRIPTION
    1. Inspects `runtime\watchdog.lock` and clears stale lockfiles if the owning PID is dead.
    2. Inspects `runtime\EMERGENCY_STOP` and removes it when `-ClearEmergencyStop` is passed.
    3. Validates `config\policy.json` schema and required security invariants (`system_admin` blocked).
    4. Invokes `runtime\watchdog.py --once` (on the primary live root when not `-DryRun`) to heal
       any stopped service without ever touching `codex-chatgpt-web`.
    5. Runs `scripts\Test-WindowsMcpStack.ps1` to confirm end-to-end stack health.
    6. Writes a structured JSON report to `$TargetRoot\runtime\logs\repair-report.json`.
#>
[CmdletBinding()]
param(
    [string]$TargetRoot = $(if ($PSScriptRoot) { (Resolve-Path (Join-Path $PSScriptRoot "..")).Path } else { (Get-Location).Path }),
    [switch]$DryRun,
    [switch]$ClearEmergencyStop,
    [switch]$SkipWatchdogHeal,
    [switch]$SkipDiagnostics
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$TargetRoot = [System.IO.Path]::GetFullPath($TargetRoot)
$PrimaryRoot = if ($PSScriptRoot) { (Resolve-Path (Join-Path $PSScriptRoot "..")).Path } else { $TargetRoot }
$IsPrimaryRoot = ($TargetRoot.TrimEnd('\').ToLowerInvariant() -eq $PrimaryRoot.TrimEnd('\').ToLowerInvariant())

# 1. Inspect runtime/watchdog.lock
$lockPath = Join-Path $TargetRoot "runtime\watchdog.lock"
$lockAction = "NONE_PRESENT"
$lockPid = $null
$lockOwnerAlive = $false

if (Test-Path $lockPath) {
    $rawLock = ""
    try {
        $rawLock = [System.IO.File]::ReadAllText($lockPath).Trim()
    } catch {
        # If file is actively locked by a live watchdog process via msvcrt.locking, reading may throw IOException
        $lockOwnerAlive = $true
        $lockAction = "ACTIVE_OS_FILE_LOCK_PRESERVED"
    }

    if (-not $lockOwnerAlive) {
        if ($rawLock -match "(\d+)") {
            $lockPid = [int]$Matches[1]
            $proc = Get-Process -Id $lockPid -ErrorAction SilentlyContinue
            if ($null -ne $proc) {
                $lockOwnerAlive = $true
                $lockAction = "LOCK_OWNER_ALIVE_PRESERVED"
            }
        }
        if (-not $lockOwnerAlive) {
            if ($DryRun) {
                $lockAction = "DRYRUN_WOULD_CLEAR_STALE_LOCK"
            } else {
                Remove-Item -Path $lockPath -Force -ErrorAction SilentlyContinue
                $lockAction = "STALE_LOCK_CLEARED"
            }
        }
    }
}

# 2. Inspect runtime/EMERGENCY_STOP
$emergencyPath = Join-Path $TargetRoot "runtime\EMERGENCY_STOP"
$emergencyPresentBefore = (Test-Path $emergencyPath)
$emergencyAction = "NOT_PRESENT"

if ($emergencyPresentBefore) {
    if ($ClearEmergencyStop) {
        if ($DryRun) {
            $emergencyAction = "DRYRUN_WOULD_CLEAR_EMERGENCY_STOP"
        } else {
            Remove-Item -Path $emergencyPath -Force -ErrorAction SilentlyContinue
            $emergencyAction = "CLEARED_EMERGENCY_STOP"
        }
    } else {
        $emergencyAction = "PRESENT_LEFT_INTACT (use -ClearEmergencyStop to remove)"
    }
}

# 3. Validate config/policy.json schema
$policyPath = Join-Path $TargetRoot "config\policy.json"
$policyExamplePath = Join-Path $TargetRoot "config\policy.example.json"
if ((-not (Test-Path $policyPath)) -and (Test-Path $policyExamplePath) -and (-not $DryRun)) {
    Copy-Item -Path $policyExamplePath -Destination $policyPath -Force
}

$policyValid = $false
$policyDetails = ""

if (Test-Path $policyPath) {
    try {
        $policyObj = Get-Content -Path $policyPath -Raw | ConvertFrom-Json
        $hasProfiles = (
            $null -ne $policyObj.profiles -and
            $null -ne $policyObj.profiles.read_only -and
            $null -ne $policyObj.profiles.developer_p2 -and
            $null -ne $policyObj.profiles.desktop_p3 -and
            $null -ne $policyObj.profiles.full_agent
        )
        $sysAdminBlocked = ($null -ne $policyObj.tiers -and $null -ne $policyObj.tiers.SYSTEM_ADMIN -and $policyObj.tiers.SYSTEM_ADMIN.blocked_by_default -eq $true)
        $hasBoundaries = ($null -ne $policyObj.allowed_write_roots -and $null -ne $policyObj.sensitive_paths)
        if ($hasProfiles -and $sysAdminBlocked -and $hasBoundaries) {
            $policyValid = $true
            $policyDetails = "version=$($policyObj.version), default_profile=$($policyObj.default_profile), system_admin_blocked=True"
        } else {
            $policyDetails = "Missing required policy sections or SYSTEM_ADMIN not blocked"
        }
    } catch {
        $policyDetails = "Invalid JSON in policy.json: $($_.Exception.Message)"
    }
} else {
    $policyDetails = "policy.json missing at $policyPath"
}

# 4. Invoke runtime/watchdog.py --once (only when not DryRun and on primary root unless skipped)
$cmdPy = Get-Command python.exe -ErrorAction SilentlyContinue
if ($null -ne $cmdPy -and (Test-Path $cmdPy.Source)) {
    $pythonExe = $cmdPy.Source
} else {
    $localAppData = if ($env:LOCALAPPDATA) { $env:LOCALAPPDATA } else { Join-Path $env:USERPROFILE "AppData\Local" }
    $pythonExe = Join-Path $localAppData "Programs\Python\Python312\python.exe"
}

$watchdogScript = Join-Path $TargetRoot "runtime\watchdog.py"
$watchdogAction = "SKIPPED"
$watchdogOk = $true

if ($DryRun) {
    $watchdogAction = "DRYRUN_STATUS_ONLY"
} elseif ($SkipWatchdogHeal) {
    $watchdogAction = "SKIPPED_BY_FLAG"
} elseif ($IsPrimaryRoot -and (Test-Path $watchdogScript)) {
    & $pythonExe $watchdogScript --once | Out-Null
    $watchdogOk = ($LASTEXITCODE -eq 0)
    $watchdogAction = $(if ($watchdogOk) { "HEALED_AND_VERIFIED" } else { "WATCHDOG_ONCE_NONZERO" })
} else {
    $watchdogAction = "SKIPPED_NON_PRIMARY_TARGET"
}

# 5. Run Test-WindowsMcpStack.ps1 (read-only diagnostics)
$testScript = Join-Path $TargetRoot "scripts\Test-WindowsMcpStack.ps1"
if (-not (Test-Path $testScript)) {
    $testScript = Join-Path $PrimaryRoot "scripts\Test-WindowsMcpStack.ps1"
}
$diagAction = "SKIPPED"
$diagOk = $true

if ($DryRun) {
    $diagAction = "DRYRUN_SKIPPED"
} elseif ($SkipDiagnostics) {
    $diagAction = "SKIPPED_BY_FLAG"
} elseif (Test-Path $testScript) {
    $diagReportPath = Join-Path $TargetRoot "runtime\logs\diagnostic-report.json"
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $testScript -ReportPath $diagReportPath | Out-Null
    $diagOk = ($LASTEXITCODE -eq 0)
    $diagAction = $(if ($diagOk) { "DIAGNOSTICS_PASSED" } else { "DIAGNOSTICS_FAILED" })
}

# 6. Confirm codex-chatgpt-web coexistence
$legacyCodexProcs = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object {
    $_.Name -eq "tunnel-client.exe" -and (
        $_.CommandLine -match "--profile(?:\s+|=)[`"']?codex-chatgpt-web\b" -or
        $_.CommandLine -match "tunnel_unconfigured_legacy"
    )
})
$legacyUntouched = $true

$overallOk = ($policyValid -and $watchdogOk -and $diagOk)

$reportObj = [ordered]@{
    schema_version    = "1.0.0"
    generated_at      = (Get-Date).ToString("o")
    script            = "Repair-WindowsMcpAgent.ps1"
    target_root       = $TargetRoot
    dry_run           = [bool]$DryRun
    overall_status    = $(if ($overallOk) { "PASS" } else { "FAIL" })
    lockfile_check    = [ordered]@{
        path          = $lockPath
        owning_pid    = $lockPid
        owner_alive   = $lockOwnerAlive
        action        = $lockAction
    }
    emergency_stop    = [ordered]@{
        path           = $emergencyPath
        present_before = $emergencyPresentBefore
        present_after  = (Test-Path $emergencyPath)
        action         = $emergencyAction
    }
    policy_validation = [ordered]@{
        path          = $policyPath
        valid         = $policyValid
        details       = $policyDetails
    }
    watchdog_heal     = [ordered]@{
        action        = $watchdogAction
        passed        = $watchdogOk
    }
    diagnostics       = [ordered]@{
        action        = $diagAction
        passed        = $diagOk
    }
    coexistence_guard = [ordered]@{
        legacy_codex_profile = "codex-chatgpt-web"
        legacy_codex_tunnel  = "tunnel_unconfigured_legacy"
        legacy_codex_running = ($legacyCodexProcs.Count -gt 0)
        untouched            = $legacyUntouched
    }
}

$reportPath = Join-Path $TargetRoot "runtime\logs\repair-report.json"
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

$modeText = $(if ($DryRun) { "DRY-RUN" } else { "LIVE REPAIR" })
Write-Host "==========================================================================================" -ForegroundColor Cyan
Write-Host " WinOwner MCP Repair ($modeText) -> Status: $($reportObj.overall_status)" -ForegroundColor $(if ($overallOk) { "Green" } else { "Red" })
Write-Host " LockAction: $lockAction | EmergencyStop: $emergencyAction | PolicyValid: $policyValid" -ForegroundColor Cyan
Write-Host "==========================================================================================" -ForegroundColor Cyan

if (-not $overallOk) {
    exit 1
}
exit 0
