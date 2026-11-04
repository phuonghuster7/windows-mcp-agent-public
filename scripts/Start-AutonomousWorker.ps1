<#
.SYNOPSIS
    Start the Unattended Autonomous Worker Daemon for Windows MCP Agent.
.DESCRIPTION
    Runs the persistent autonomous task worker background daemon, which claims
    QUEUED tasks under valid TaskGrants and executes them with durable checkpoints.
#>
[CmdletBinding()]
param(
    [string]$WorkspaceRoot = "$PSScriptRoot\..",
    [int]$PollIntervalSeconds = 2,
    [string]$DbPath = "",
    [string]$KeyPath = "",
    [int]$MaxTasks = 0,
    [switch]$Once,
    [switch]$RunInBackground
)

$ErrorActionPreference = "Stop"
$ResolvedRoot = (Resolve-Path $WorkspaceRoot).Path

$PythonExe = (Get-Command python -ErrorAction SilentlyContinue).Source
if (-not $PythonExe) {
    $PythonCandidates = @(
        "$env:LOCALAPPDATA\Programs\Python\Python312\python.exe",
        "$env:LOCALAPPDATA\Programs\Python\Python311\python.exe",
        "$env:ProgramFiles\Python312\python.exe",
        "$env:ProgramFiles\Python311\python.exe"
    )
    foreach ($cand in $PythonCandidates) {
        if (Test-Path $cand) { $PythonExe = $cand; break }
    }
}

if (-not $PythonExe) {
    Write-Error "Python executable not found. Please install Python 3.11 or 3.12."
    exit 1
}

$LogDir = "$ResolvedRoot\runtime\logs"
if (-not (Test-Path $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
}

$LogFile = "$LogDir\autonomous_worker.log"
$ErrFile = "$LogDir\autonomous_worker.err"
$PidFile = "$LogDir\autonomous_worker.pid"

# Build argument list
$ArgList = @("-m", "runtime.autonomous_agent", "--poll-interval", "$PollIntervalSeconds")
if ($DbPath) {
    $ArgList += @("--db-path", $DbPath)
}
if ($KeyPath) {
    $ArgList += @("--key-path", $KeyPath)
}
if ($MaxTasks -gt 0) {
    $ArgList += @("--max-tasks", "$MaxTasks")
}
if ($Once) {
    $ArgList += @("--once")
}

if ($RunInBackground) {
    # Check if a worker is already running
    if (Test-Path $PidFile) {
        $ExistingPid = (Get-Content $PidFile -Raw -ErrorAction SilentlyContinue).Trim()
        if ($ExistingPid -match '^\d+$') {
            $ExistingProc = Get-Process -Id [int]$ExistingPid -ErrorAction SilentlyContinue
            if ($ExistingProc) {
                Write-Host "Autonomous Worker is already running with PID $ExistingPid."
                exit 0
            }
        }
    }

    $ArgString = $ArgList -join " "
    $Process = Start-Process -FilePath $PythonExe `
        -ArgumentList $ArgString `
        -WorkingDirectory $ResolvedRoot `
        -PassThru `
        -NoNewWindow `
        -RedirectStandardOutput $LogFile `
        -RedirectStandardError $ErrFile

    $Process.Id | Out-File -FilePath $PidFile -Encoding utf8
    Write-Host "Started Autonomous Worker Daemon in background with PID: $($Process.Id)"
} else {
    Push-Location $ResolvedRoot
    try {
        & $PythonExe $ArgList
    } finally {
        Pop-Location
    }
}
