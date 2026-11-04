<#
.SYNOPSIS
    Cleanly starts and supervises the WinOwner MCP Stack (Backend -> Bridge -> Tunnel)
    without requiring a visible terminal window to stay open.

.DESCRIPTION
    1. Invokes `runtime/watchdog.py --once` to verify and heal the dependency chain in order:
         FastAPI Backend (127.0.0.1:3080) -> MCP Bridge (127.0.0.1:8765/mcp) ->
         Secure MCP Tunnel (windows-mcp-isolated) -> Optional Desktop Agent (127.0.0.1:8766)
    2. Reuses existing healthy processes and never touches the legacy Codex tunnel.
    3. If -Daemon is specified (or by default unless -Once / -NoDaemon is passed),
       ensures the background `watchdog.py --daemon` process is running hidden.
#>
[CmdletBinding()]
param(
    [switch]$Once,
    [switch]$Daemon,
    [switch]$NoDaemon,
    [int]$IntervalSeconds = 15
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ProjectRoot = if ($PSScriptRoot) { (Resolve-Path (Join-Path $PSScriptRoot "..")).Path } else { (Get-Location).Path }
$WatchdogScript = Join-Path $ProjectRoot "runtime\watchdog.py"
$LogDir = Join-Path $ProjectRoot "runtime\logs"
$LockFile = Join-Path $ProjectRoot "runtime\watchdog.lock"

$cmdPy = Get-Command python.exe -ErrorAction SilentlyContinue
if ($null -ne $cmdPy -and (Test-Path $cmdPy.Source)) {
    $PythonExe = $cmdPy.Source
} else {
    $localAppData = if ($env:LOCALAPPDATA) { $env:LOCALAPPDATA } else { Join-Path $env:USERPROFILE "AppData\Local" }
    $PythonExe = Join-Path $localAppData "Programs\Python\Python312\python.exe"
}

if (-not (Test-Path $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
}

# Check if a background watchdog daemon is already running
$existingWatchdog = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object {
    $_.Name -in @("python.exe", "pythonw.exe") -and
    $_.CommandLine -match "watchdog\.py" -and
    $_.CommandLine -match "--daemon"
})

if ($existingWatchdog.Count -gt 0 -and (-not $Once)) {
    $wPid = $existingWatchdog[0].ProcessId
    Write-Host "Watchdog daemon is already running in background (PID=$wPid). Running non-mutating status check..." -ForegroundColor Cyan
    & $PythonExe $WatchdogScript --status
    exit $LASTEXITCODE
}

# Step 1: Run a single synchronous check & heal pass (--once)
Write-Host "Running Windows MCP Stack dependency check & heal pass (--once)..." -ForegroundColor Cyan
& $PythonExe $WatchdogScript --once
$onceExit = $LASTEXITCODE

if ($Once -or $NoDaemon) {
    exit $onceExit
}

# Step 2: Launch background watchdog daemon hidden if requested or default
if ($Daemon -or (-not $Once -and -not $NoDaemon)) {
    $existingAfterOnce = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object {
        $_.Name -in @("python.exe", "pythonw.exe") -and
        $_.CommandLine -match "watchdog\.py" -and
        $_.CommandLine -match "--daemon"
    })
    if ($existingAfterOnce.Count -eq 0) {
        $stdoutLog = Join-Path $LogDir "watchdog_daemon.stdout.log"
        $stderrLog = Join-Path $LogDir "watchdog_daemon.stderr.log"
        $spawnCode = @"
import sys
from pathlib import Path
sys.path.insert(0, r'$ProjectRoot')
from runtime.watchdog import _spawn_detached_background
pid = _spawn_detached_background(
    [r'$PythonExe', r'$WatchdogScript', '--daemon', '--interval', '$IntervalSeconds'],
    cwd=r'$ProjectRoot',
    stdout_path=Path(r'$stdoutLog'),
    stderr_path=Path(r'$stderrLog'),
)
print(pid)
"@
        $daemonPid = (& $PythonExe -c $spawnCode).Trim()
        Start-Sleep -Seconds 1
        Write-Host "Started hidden background Watchdog Daemon (PID=$daemonPid)." -ForegroundColor Green
    } else {
        Write-Host "Background Watchdog Daemon already active (PID=$($existingAfterOnce[0].ProcessId))." -ForegroundColor Green
    }
}

exit $onceExit
