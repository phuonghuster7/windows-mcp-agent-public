#requires -Version 5.1
<#
WinOwner MCP safe local bootstrap.
Installs read-only local adapter; registers restartable current-user Task Scheduler task.
Remote OAuth pairing and owner-global filesystem are never enabled automatically.
#>
[CmdletBinding()]
param(
    [switch]$DryRun,
    [switch]$NoStart,
    [switch]$NoPythonInstall,
    [switch]$Remove,
    [ValidateRange(1024,65535)][int]$Port = 8768
)
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$venv = Join-Path $root ".venv\Scripts\python.exe"
$runner = Join-Path $root "scripts\Run-WinOwnerMcp.py"
$adapter = Join-Path $root "mcp-gateway\cloud_autonomous_adapter.py"
$policyExample = Join-Path $root "config\policy.example.json"
$policyPath = Join-Path $root "config\policy.json"
$secretDir = Join-Path $root "runtime\secrets"
$tokenPath = Join-Path $secretDir "gateway_caller.token"
$logDir = Join-Path $root "runtime\logs"
$taskName = "WinOwnerMCP-$Port"
$identity = [Security.Principal.WindowsIdentity]::GetCurrent().Name
function Step([string]$s) { Write-Host "[WinOwner] $s" }
function Check-Exit([string]$s) { if ($LASTEXITCODE -ne 0) { throw "$s failed: $LASTEXITCODE" } }
function Port-IsFree {
    $l = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, $Port)
    try { $l.Start(); return $true } catch { return $false } finally { try { $l.Stop() } catch {} }
}
function Find-Python {
    $candidates = @()
    $py = Get-Command py.exe -ErrorAction SilentlyContinue
    if ($py) { $candidates += ,@($py.Source, "-3.12") }
    if ($env:LOCALAPPDATA) { $candidates += ,@((Join-Path $env:LOCALAPPDATA "Programs\Python\Python312\python.exe")) }
    $exe = Get-Command python.exe -ErrorAction SilentlyContinue
    if ($exe) { $candidates += ,@($exe.Source) }
    foreach ($c in $candidates) {
        if (-not (Test-Path -LiteralPath $c[0])) { continue }
        $p = @()
        if ($c.Count -gt 1) { $p = @($c[1]) }
        try {
            $null = & $c[0] @p -c "import sys; assert sys.version_info[:2] == (3,12)" 2>$null
            if ($LASTEXITCODE -eq 0) { return @{Path=$c[0]; Args=$p} }
        } catch {}
    }
    return $null
}
function Managed-Task {
    $t = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    if ($t) {
        $a = @($t.Actions)
        if ($a.Count -ne 1 -or -not $a[0].Arguments -or
            $a[0].Arguments.IndexOf($runner, [StringComparison]::OrdinalIgnoreCase) -lt 0 -or
            $a[0].Execute.IndexOf($venv, [StringComparison]::OrdinalIgnoreCase) -lt 0 -or
            @($identity, $env:USERNAME, ("$env:USERDOMAIN\$env:USERNAME")) -notcontains $t.Principal.UserId) {
            throw "Task name collision for $taskName; refusing to modify another task."
        }
    }
    return $t
}
function Healthy-And-Authenticated {
    try {
        $h = Invoke-RestMethod "http://127.0.0.1:$Port/health" -TimeoutSec 2
        if ($h.status -ne "ok" -or $h.require_autonomous_auth -ne $true -or
            $h.allow_loopback_tunnel_identity -ne $false) { return $false }
        try {
            $body = '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'
            $null = Invoke-WebRequest "http://127.0.0.1:$Port/mcp" -Method Post -Body $body -ContentType "application/json" -UseBasicParsing -TimeoutSec 3
            return $false
        } catch {
            return [bool]($_.Exception.Response -and [int]$_.Exception.Response.StatusCode -eq 401)
        }
    } catch { return $false }
}
if ([Environment]::OSVersion.Platform.ToString() -ne "Win32NT") { throw "Windows required" }
function Stop-VerifiedLocalListener {
    $listeners = Get-NetTCPConnection -LocalAddress "127.0.0.1" -LocalPort $Port -State Listen -ErrorAction SilentlyContinue
    foreach ($listener in $listeners) {
        $proc = Get-CimInstance Win32_Process -Filter ("ProcessId=" + $listener.OwningProcess)
        if (-not $proc -or -not $proc.CommandLine -or
            ($proc.CommandLine.IndexOf($runner, [StringComparison]::OrdinalIgnoreCase) -lt 0 -and
             $proc.CommandLine.IndexOf($adapter, [StringComparison]::OrdinalIgnoreCase) -lt 0) -or
            $proc.CommandLine -notmatch ("(?<!\S)--port\s+" + $Port + "(?=\s|$)")) {
            throw "Refusing to stop unverified listener on port $Port."
        }
        Stop-Process -Id $listener.OwningProcess -Force -ErrorAction Stop
    }
}
if ($Remove) {
    $task = Managed-Task
    if ($task) {
        Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction Stop
    }
    Start-Sleep -Milliseconds 400
    Stop-VerifiedLocalListener
    if (-not (Port-IsFree)) { throw "Removal incomplete: port $Port remains occupied." }
    Step "TASK_REMOVED: $taskName, verified local listener stopped. Credentials/config kept for owner review."
    exit 0
}
foreach ($p in @($runner, $adapter, $policyExample, (Join-Path $root "requirements.txt"))) {
    if (-not (Test-Path -LiteralPath $p -PathType Leaf)) { throw "Missing release file: $p" }
}
$task = Managed-Task
$free = Port-IsFree
if ($DryRun) {
    $py = Find-Python
    Step "DRY_RUN Python312=$([bool]$py) port_free=$free task_exists=$([bool]$task)"
    if (-not $py -and $NoPythonInstall) { throw "Python 3.12 unavailable" }
    exit 0
}
if ($task -and (Healthy-And-Authenticated)) {
    Step "LOCAL_INSTALL_PASS: existing managed task is healthy; no changes made."
    exit 0
}
if (-not $free) { throw "Port $Port occupied by an unverified process; no changes made." }
$py = Find-Python
if (-not $py) {
    if ($NoPythonInstall) { throw "Python 3.12 missing" }
    $winget = Get-Command winget.exe -ErrorAction SilentlyContinue
    if (-not $winget) { throw "Python 3.12 missing and winget unavailable" }
    & $winget.Source install --id Python.Python.3.12 --exact --scope user --silent --accept-source-agreements --accept-package-agreements
    Check-Exit "Python install"
    $py = Find-Python
    if (-not $py) { throw "Open a new PowerShell after installing Python 3.12 and rerun" }
}
if (-not (Test-Path -LiteralPath $venv)) {
    & $py.Path @($py.Args) -m venv (Join-Path $root ".venv")
    Check-Exit "venv"
}
Step "Installing/verifying pinned dependencies."
& $venv -m pip install --disable-pip-version-check --quiet -r (Join-Path $root "requirements.txt")
Check-Exit "Python dependencies"
New-Item -ItemType Directory -Path $secretDir, $logDir -Force | Out-Null
if (-not (Test-Path -LiteralPath $policyPath)) {
    Copy-Item -LiteralPath $policyExample -Destination $policyPath
}
$policy = Get-Content $policyPath -Raw -Encoding UTF8 | ConvertFrom-Json
if ($policy.default_profile -ne "read_only") { throw "Refusing non-read_only policy" }
& icacls.exe $secretDir /inheritance:r /grant:r "$($identity):(OI)(CI)F" "SYSTEM:(OI)(CI)F" | Out-Null
Check-Exit "private directory ACL"
if (-not (Test-Path -LiteralPath $tokenPath)) {
    $bytes = New-Object byte[] 48
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    [IO.File]::WriteAllText($tokenPath, [Convert]::ToBase64String($bytes), [Text.UTF8Encoding]::new($false))
    [Array]::Clear($bytes,0,$bytes.Length)
}
& icacls.exe $tokenPath /inheritance:r /grant:r "$($identity):(F)" "SYSTEM:(F)" | Out-Null
Check-Exit "private token ACL"
if ($NoStart) { Step "LOCAL_PREPARED: no task started or registered"; exit 0 }
$created = $false
if (-not $task) {
    $arguments = ('-u "{0}" --port {1}' -f $runner, $Port)
    $action = New-ScheduledTaskAction -Execute $venv -Argument $arguments -WorkingDirectory $root
    $trigger = New-ScheduledTaskTrigger -AtLogOn -User $identity
    $principal = New-ScheduledTaskPrincipal -UserId $identity -LogonType Interactive -RunLevel Limited
    $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Seconds 0) -MultipleInstances IgnoreNew -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description "WinOwner MCP read-only local adapter, current-user logon" | Out-Null
    $created = $true
}
try {
    Start-ScheduledTask -TaskName $taskName -ErrorAction Stop
    $ready = $false
    for ($i=0; $i -lt 60; $i++) {
        if (Healthy-And-Authenticated) { $ready = $true; break }
        Start-Sleep -Milliseconds 500
    }
    if (-not $ready) { throw "LOCAL_INSTALL_FAILED: health or anonymous-denial test failed" }
    $task = Managed-Task
    if ($task.State -ne "Running") { throw "LOCAL_INSTALL_FAILED: managed task not running" }
    $report = [ordered]@{
        status="LOCAL_INSTALL_PASS"; url="http://127.0.0.1:$Port/mcp";
        task_name=$taskName; auto_start_at_owner_logon=$true;
        profile="read_only"; anonymous_mcp_denied=$true;
        remote_oauth_paired=$false; owner_global_filesystem_enabled=$false
    }
    [IO.File]::WriteAllText((Join-Path $logDir "bootstrap-report.json"),($report | ConvertTo-Json),[Text.UTF8Encoding]::new($false))
    Step "LOCAL_INSTALL_PASS: $taskName running; auto-start at owner logon."
    Step "Remote OAuth/tunnel pairing is NOT complete; consult docs/CONNECT_CHATGPT.md."
} catch {
    if ($created) {
        Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
    }
    throw
}
