<#
.SYNOPSIS
    Stop the Autonomous Worker Daemon gracefully.
#>
[CmdletBinding()]
param(
    [string]$WorkspaceRoot = "$PSScriptRoot\..",
    [int]$TimeoutSeconds = 5
)

$ErrorActionPreference = "Continue"
$ResolvedRoot = (Resolve-Path $WorkspaceRoot).Path
$PidFile = "$ResolvedRoot\runtime\logs\autonomous_worker.pid"
$NormRoot = $ResolvedRoot -replace '\\', '/'

if (Test-Path $PidFile) {
    $TargetPid = (Get-Content $PidFile -Raw -ErrorAction SilentlyContinue).Trim()
    if ($TargetPid -match '^\d+$') {
        $PidInt = [int]$TargetPid
        $Proc = Get-Process -Id $PidInt -ErrorAction SilentlyContinue
        if ($Proc) {
            Write-Host "Stopping Autonomous Worker Process PID $PidInt..."

            # Signal pause on running tasks in database first
            $DbFile = "$ResolvedRoot\runtime\tasks.db"
            if (Test-Path $DbFile) {
                try {
                    $PythonExe = "python"
                    $StopCmd = @"
import sys
sys.path.insert(0, '$NormRoot')
from runtime.task_store import TaskStore
s = TaskStore()
for t in s.list_tasks():
    if t.state in ('PLANNING', 'RUNNING', 'VERIFYING', 'REPAIRING') and t.worker_pid == ${PidInt}:
        s.set_control_signal(t.task_id, 'PAUSE')
"@
                    $StopCmd | & $PythonExe - | Out-Null
                } catch {
                    # Ignore db update errors
                }
            }

            # Terminate process and cleanup PID file
            Stop-Process -Id $PidInt -Force -ErrorAction SilentlyContinue
            Remove-Item $PidFile -Force -ErrorAction SilentlyContinue
            Write-Host "Autonomous Worker PID $PidInt stopped successfully."
            exit 0
        }
    }
    Remove-Item $PidFile -Force -ErrorAction SilentlyContinue
}

Write-Host "No active Autonomous Worker PID found."
