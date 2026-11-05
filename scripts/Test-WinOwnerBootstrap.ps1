#requires -Version 5.1
<#
Integration test for read-only local WinOwner bootstrap.
Run on an isolated Windows checkout; must not run on an active owner production root.
The test creates an owner-scoped scheduled task and removes it in finally.
#>
[CmdletBinding()]
param([ValidateRange(1024,65535)][int]$Port = 18769)
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$bootstrap = Join-Path $PSScriptRoot "Bootstrap-WindowsMcp.ps1"
$taskName = "WinOwnerMCP-$Port"
if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
    throw "Refusing integration test: task $taskName already exists."
}
if (Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue) {
    throw "Refusing integration test: port $Port is already in use."
}
function Invoke-Bootstrap([string]$suffix) {
    $args = ('-NoProfile -ExecutionPolicy Bypass -File "{0}" -Port {1} -NoPythonInstall {2}' -f $bootstrap,$Port,$suffix)
    $proc = Start-Process -FilePath "powershell.exe" -ArgumentList $args -WorkingDirectory $root -NoNewWindow -PassThru -Wait
    if ($proc.ExitCode -ne 0) { throw "Bootstrap $suffix failed with exit $($proc.ExitCode)" }
}
function Test-Boundary {
    $t = Get-ScheduledTask -TaskName $taskName -ErrorAction Stop
    if ($t.State -ne "Running") { throw "Task not running: $($t.State)" }
    $h = Invoke-RestMethod -Uri "http://127.0.0.1:$Port/health" -TimeoutSec 3
    if ($h.status -ne "ok" -or $h.require_autonomous_auth -ne $true -or
        $h.allow_loopback_tunnel_identity -ne $false) { throw "Unsafe health/auth state" }
    try {
        $body = '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'
        $null = Invoke-WebRequest -Uri "http://127.0.0.1:$Port/mcp" -Method POST -Body $body -ContentType "application/json" -UseBasicParsing -TimeoutSec 3
        throw "Unauthenticated request was accepted"
    } catch {
        if (-not $_.Exception.Response -or [int]$_.Exception.Response.StatusCode -ne 401) { throw }
    }
}
try {
    Invoke-Bootstrap "-DryRun"
    if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
        throw "DryRun unexpectedly registered a task."
    }
    Invoke-Bootstrap ""
    Test-Boundary
    $tokenFile = Join-Path $root "runtime\secrets\gateway_caller.token"
    $before = (Get-FileHash -LiteralPath $tokenFile -Algorithm SHA256).Hash
    Invoke-Bootstrap ""
    Test-Boundary
    $after = (Get-FileHash -LiteralPath $tokenFile -Algorithm SHA256).Hash
    if ($before -ne $after) { throw "Idempotent rerun rotated the owner bearer token." }
    Write-Host "BOOTSTRAP_INTEGRATION_PASS: Task still running after child installer exits; read_only, HTTP 401, idempotent token."
} finally {
    try {
        Invoke-Bootstrap "-Remove"
        Start-Sleep -Milliseconds 650
        if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
            throw "Task removal failed"
        }
        if (Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue) {
            throw "Local port remained in use after cleanup"
        }
        Write-Host "BOOTSTRAP_CLEANUP_PASS: Task removed, local port released."
    } catch {
        Write-Warning ("Bootstrap cleanup requires manual review: " + $_.Exception.Message)
        throw
    }
}
