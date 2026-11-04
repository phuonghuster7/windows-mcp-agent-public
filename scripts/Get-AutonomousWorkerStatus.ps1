<#
.SYNOPSIS
    Check status of the Autonomous Worker Daemon and queued/running tasks.
#>
[CmdletBinding()]
param(
    [string]$WorkspaceRoot = "$PSScriptRoot\..",
    [string]$DbPath = ""
)

$ResolvedRoot = (Resolve-Path $WorkspaceRoot).Path
$PidFile = "$ResolvedRoot\runtime\logs\autonomous_worker.pid"

$WorkerRunning = $false
$WorkerPid = $null

if (Test-Path $PidFile) {
    $TargetPid = (Get-Content $PidFile -Raw -ErrorAction SilentlyContinue).Trim()
    if ($TargetPid -match '^\d+$') {
        $PidInt = [int]$TargetPid
        $Proc = Get-Process -Id $PidInt -ErrorAction SilentlyContinue
        if ($Proc) {
            $WorkerRunning = $true
            $WorkerPid = $PidInt
        } else {
            # Stale PID file
            Remove-Item $PidFile -Force -ErrorAction SilentlyContinue
        }
    }
}

$PythonExe = "python"
$NormRoot = $ResolvedRoot -replace '\\', '/'
$NormDb = $DbPath -replace '\\', '/'

$StatusScript = @"
import sys, json, time
sys.path.insert(0, '$NormRoot')
from runtime.task_store import TaskStore, is_pid_alive
db_arg = '$NormDb' if '$NormDb' else None
store = TaskStore(db_path=db_arg)

reconciled = store.reconcile_orphaned_tasks()
all_tasks = store.list_tasks(limit=20)
active = [t for t in all_tasks if t.state in ('PLANNING', 'RUNNING', 'VERIFYING', 'REPAIRING')]
queued = [t for t in all_tasks if t.state == 'QUEUED']
completed = [t for t in all_tasks if t.state == 'COMPLETED']
failed = [t for t in all_tasks if t.state == 'FAILED']

out = {
    'worker_running': $(if ($WorkerRunning) { 'True' } else { 'False' }),
    'worker_pid': $(if ($WorkerPid) { $WorkerPid } else { 'None' }),
    'reconciled_orphans': reconciled,
    'counts': {
        'active': len(active),
        'queued': len(queued),
        'completed': len(completed),
        'failed': len(failed),
        'total_recent': len(all_tasks)
    },
    'active_tasks': [
        {
            'id': t.task_id,
            'state': t.state,
            'worker_pid': t.worker_pid,
            'heartbeat_age_sec': round(time.time() - t.worker_heartbeat_at, 1) if t.worker_heartbeat_at else None,
            'tool_calls': t.tool_call_count,
            'files_modified': len(t.files_modified),
            'obj': t.objective[:60]
        }
        for t in active
    ],
    'recent_tasks': [
        {
            'id': t.task_id,
            'state': t.state,
            'control_signal': t.control_signal,
            'obj': t.objective[:60]
        }
        for t in all_tasks[:10]
    ]
}
print(json.dumps(out, indent=2))
"@

try {
    $res = $StatusScript | & $PythonExe -
    Write-Output $res
} catch {
    Write-Host "Worker Running: $WorkerRunning (PID: $WorkerPid)"
}
