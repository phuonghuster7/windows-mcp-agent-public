#requires -Version 5.1
<#
.SYNOPSIS
  Safe first-run bootstrap for the standalone, loopback-only MCP owner adapter.
.DESCRIPTION
  Installs dependencies and starts a read-only LOCAL endpoint. Remote ChatGPT
  OAuth pairing and any owner-global permissions are separate explicit steps.
  Never modifies a running pre-existing instance, opens firewall, or grants owner.
.EXAMPLE
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\Bootstrap-WindowsMcp.ps1
#>
[CmdletBinding()]
param(
    [switch]$DryRun,
    [switch]$NoStart,
    [switch]$NoPythonInstall,
    [ValidateRange(1024,65535)][int]$Port = 8768
)
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$venv = Join-Path $root ".venv"
$venvPy = Join-Path $venv "Scripts\python.exe"
$adapter = Join-Path $root "mcp-gateway\cloud_autonomous_adapter.py"
$policyExample = Join-Path $root "config\policy.example.json"
$policyFile = Join-Path $root "config\policy.json"
$state = Join-Path $root "runtime"
$secrets = Join-Path $state "secrets"
$logs = Join-Path $state "logs"
$tokenFile = Join-Path $secrets "gateway_caller.token"
$stdout = Join-Path $logs "bootstrap-adapter.stdout.log"
$stderr = Join-Path $logs "bootstrap-adapter.stderr.log"

function Step([string]$message) { Write-Host "[WinOwner setup] $message" }
function Check-Exit([string]$step) {
    if ($LASTEXITCODE -ne 0) { throw "$step failed (exit $LASTEXITCODE)" }
}
function Test-PortAvailable([int]$p) {
    $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, $p)
    try {
        $listener.Start()
        return $true
    } catch {
        return $false
    } finally {
        try { $listener.Stop() } catch {}
    }
}
function Find-Python {
    $candidates = New-Object System.Collections.ArrayList
    $launcher = Get-Command py.exe -ErrorAction SilentlyContinue
    if ($launcher) { [void]$candidates.Add(@($launcher.Source, "-3.12")) }
    if ($env:LOCALAPPDATA) {
        [void]$candidates.Add(@((Join-Path $env:LOCALAPPDATA "Programs\Python\Python312\python.exe")))
    }
    $direct = Get-Command python.exe -ErrorAction SilentlyContinue
    if ($direct) { [void]$candidates.Add(@($direct.Source)) }
    foreach ($candidate in $candidates) {
        $exe = [string]$candidate[0]
        $args = @()
        if ($candidate.Count -gt 1) { $args = @($candidate[1]) }
        if (-not (Test-Path -LiteralPath $exe)) { continue }
        try {
            $version = & $exe @args -c "import sys; assert sys.version_info[:2] == (3,12); print('3.12 OK')" 2>$null
            if ($LASTEXITCODE -eq 0) { return @{Exe=$exe; Prefix=$args} }
        } catch {}
    }
    return $null
}
if (-not [Environment]::OSVersion.Platform.ToString().Equals("Win32NT")) { throw "Windows is required." }
foreach ($path in @($adapter, $policyExample, (Join-Path $root "requirements-dev.txt"))) {
    if (-not (Test-Path -LiteralPath $path)) { throw "Missing release file: $path" }
}
if (-not (Test-PortAvailable $Port) -and -not $NoStart) {
    throw "Port $Port already in use. Existing service was not touched. Use -Port to select a free port."
}
$python = Find-Python
if ($DryRun) {
    Step "DRY-RUN: source checked, port $Port available=$([bool](Test-PortAvailable $Port)); Python312=$([bool]$python)"
    Step "No installs, credentials, services, tasks, or policies were changed."
    if (-not $python -and $NoPythonInstall) { throw "Python 3.12 is missing and automatic installation is disabled." }
    exit 0
}
if (-not $python) {
    if ($NoPythonInstall) { throw "Install Python 3.12 first, or run without -NoPythonInstall." }
    $winget = Get-Command winget.exe -ErrorAction SilentlyContinue
    if (-not $winget) { throw "Python 3.12 missing; winget not available. Install Python 3.12 and rerun the same command." }
    Step "Installing Python 3.12 for current user with winget."
    & $winget.Source install --id Python.Python.3.12 --exact --scope user --silent --accept-source-agreements --accept-package-agreements
    Check-Exit "Python install"
    $python = Find-Python
    if (-not $python) { throw "Python installed but not found in this process. Open a new PowerShell and rerun." }
}
Step "Creating Python 3.12 isolated environment."
if (-not (Test-Path $venvPy)) {
    & $python.Exe @($python.Prefix) -m venv $venv
    Check-Exit "Create .venv"
}
& $venvPy -m pip install --disable-pip-version-check -r (Join-Path $root "requirements-dev.txt")
Check-Exit "Install pinned dependencies"
Step "Preparing read-only config (never overwrites an existing config)."
New-Item -ItemType Directory -Path $secrets, $logs -Force | Out-Null
if (-not (Test-Path $policyFile)) { Copy-Item -LiteralPath $policyExample -Destination $policyFile }
$policy = Get-Content -LiteralPath $policyFile -Raw -Encoding UTF8 | ConvertFrom-Json
if ($policy.default_profile -ne "read_only") {
    throw "Refusing automatic boot: current policy default is not read_only."
}
if (-not (Test-Path $tokenFile)) {
    $random = New-Object byte[] 48
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($random) } finally { $rng.Dispose() }
    $token = [Convert]::ToBase64String($random)
    [Array]::Clear($random,0,$random.Length)
    [IO.File]::WriteAllText($tokenFile,$token,[Text.UTF8Encoding]::new($false))
    $token=$null
}
# Deny other users access to the local bearer secret. Keep current account + SYSTEM.
$owner = [Security.Principal.WindowsIdentity]::GetCurrent().Name
& icacls.exe $tokenFile /inheritance:r /grant:r "$($owner):(F)" "SYSTEM:(F)" | Out-Null
Check-Exit "Lock token ACL"
if ($NoStart) {
    Step "LOCAL_PREPARED. Service not started; no ChatGPT pairing occurred."
    exit 0
}
Step "Starting standalone MCP adapter (loopback-only, read_only)."
$oldToken = [Environment]::GetEnvironmentVariable("WINDOWS_MCP_GATEWAY_TOKEN","Process")
$oldState = [Environment]::GetEnvironmentVariable("MCP_STATE_ROOT","Process")
$oldEnv = [Environment]::GetEnvironmentVariable("WINDOWS_MCP_BACKEND_ENV_FILE","Process")
$oldProfile = [Environment]::GetEnvironmentVariable("MCP_AGENT_PROFILE","Process")
try {
    $env:WINDOWS_MCP_GATEWAY_TOKEN = [IO.File]::ReadAllText($tokenFile,[Text.Encoding]::UTF8).Trim()
    $env:MCP_STATE_ROOT = $root
    $env:WINDOWS_MCP_BACKEND_ENV_FILE = Join-Path $root "runtime\not-configured.env"
    $env:MCP_AGENT_PROFILE = "read_only"
    $args = @("-u", ('"'+$adapter+'"'), "--host", "127.0.0.1", "--port", "$Port", "--profile", "read_only", "--policy-path", ('"'+$policyFile+'"'), "--db-path", ('"'+(Join-Path $state "oauth.db")+'"'))
    $process = Start-Process -FilePath $venvPy -ArgumentList $args -WorkingDirectory $root -WindowStyle Hidden -RedirectStandardOutput $stdout -RedirectStandardError $stderr -PassThru
} finally {
    [Environment]::SetEnvironmentVariable("WINDOWS_MCP_GATEWAY_TOKEN",$oldToken,"Process")
    [Environment]::SetEnvironmentVariable("MCP_STATE_ROOT",$oldState,"Process")
    [Environment]::SetEnvironmentVariable("WINDOWS_MCP_BACKEND_ENV_FILE",$oldEnv,"Process")
    [Environment]::SetEnvironmentVariable("MCP_AGENT_PROFILE",$oldProfile,"Process")
}
$ready = $false
for ($attempt=0; $attempt -lt 40; $attempt++) {
    if ($process.HasExited) { break }
    try {
        $health = Invoke-RestMethod -Uri "http://127.0.0.1:$Port/health" -TimeoutSec 1
        if ($health.status -eq "ok" -and $health.require_autonomous_auth -eq $true -and $health.allow_loopback_tunnel_identity -eq $false) {
            $ready = $true
            break
        }
    } catch {}
    Start-Sleep -Milliseconds 350
}
if (-not $ready) {
    if (-not $process.HasExited) { Stop-Process -Id $process.Id -ErrorAction SilentlyContinue }
    throw "LOCAL_INSTALL_FAILED: local adapter did not pass authenticated-health checks; inspect runtime/logs."
}
# Negative test: unauthenticated MCP call must be refused.
$refused = $false
try {
    $body = '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'
    $null = Invoke-WebRequest -Uri "http://127.0.0.1:$Port/mcp" -Method Post -Body $body -ContentType "application/json" -TimeoutSec 3 -UseBasicParsing
} catch {
    if ($_.Exception.Response -and [int]$_.Exception.Response.StatusCode -eq 401) { $refused = $true }
}
if (-not $refused) {
    Stop-Process -Id $process.Id -ErrorAction SilentlyContinue
    throw "LOCAL_INSTALL_FAILED: unauthenticated MCP request was not rejected with HTTP 401."
}
$report = [ordered]@{
    schema_version="1"; status="LOCAL_INSTALL_PASS"; port=$Port;
    url="http://127.0.0.1:$Port/mcp"; pid=$process.Id;
    profile="read_only"; anonymous_mcp_denied=$true;
    remote_oauth_paired=$false; owner_global_filesystem_enabled=$false
}
[IO.File]::WriteAllText((Join-Path $logs "bootstrap-report.json"),($report | ConvertTo-Json -Depth 5),[Text.UTF8Encoding]::new($false))
Step "LOCAL_INSTALL_PASS at 127.0.0.1:$Port (PID $($process.Id))."
Step "Remote ChatGPT OAuth pairing is NOT complete. Follow docs/CONNECT_CHATGPT.md before remote use."
