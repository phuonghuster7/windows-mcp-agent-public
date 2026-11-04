<#
.SYNOPSIS
    Registers, updates, queries, or unregisters the Windows Scheduled Task
    (`WindowsMcpAgentWatchdog`) for automatic startup at user logon.

.DESCRIPTION
    Configures `WindowsMcpAgentWatchdog` to launch `Start-WindowsMcpStack.ps1 -Daemon`
    at user logon with an Interactive token for the current user (`Admin`),
    hidden window style, and restart-on-failure policy.

    Parameters:
      -Unregister : Removes the `WindowsMcpAgentWatchdog` Scheduled Task.
      -Status     : Queries the current registration state without modifying it.
      -ProtectCredential : Also seals the tunnel profile credential into CurrentUser DPAPI
                           via Protect-TunnelCredential.ps1 for P0.5 readiness.
#>
[CmdletBinding()]
param(
    [string]$TaskName = "WindowsMcpAgentWatchdog",
    [switch]$Unregister,
    [switch]$Status,
    [switch]$ProtectCredential
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ProjectRoot = if ($PSScriptRoot) { (Resolve-Path (Join-Path $PSScriptRoot "..")).Path } else { (Get-Location).Path }
$StartScript = Join-Path $ProjectRoot "scripts\Start-WindowsMcpStack.ps1"
$ProtectScript = Join-Path $ProjectRoot "scripts\Protect-TunnelCredential.ps1"
$CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$ShortUser = $env:USERNAME

if ($Status) {
    $existing = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($null -eq $existing) {
        Write-Host "Scheduled Task '$TaskName' is NOT registered." -ForegroundColor Yellow
        exit 1
    }
    $info = Get-ScheduledTaskInfo -TaskName $TaskName -ErrorAction SilentlyContinue
    [PSCustomObject]@{
        TaskName       = $existing.TaskName
        State          = [string]$existing.State
        Author         = $existing.Author
        RunAsUser      = $existing.Principal.UserId
        LogonType      = [string]$existing.Principal.LogonType
        ActionExecute  = $existing.Actions[0].Execute
        ActionArgs     = $existing.Actions[0].Arguments
        LastRunTime    = $info.LastRunTime
        LastTaskResult = $info.LastTaskResult
    } | Format-List
    exit 0
}

if ($Unregister) {
    $existing = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($null -ne $existing) {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        Write-Host "Scheduled Task '$TaskName' unregistered successfully." -ForegroundColor Green
    } else {
        Write-Host "Scheduled Task '$TaskName' was not present (nothing to unregister)." -ForegroundColor Cyan
    }
    exit 0
}

if (-not (Test-Path $StartScript)) {
    throw "Start script not found at: $StartScript"
}

if ($ProtectCredential -and (Test-Path $ProtectScript)) {
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $ProtectScript -ProtectFromProfile
}

$actionArgs = "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$StartScript`" -Daemon"
$action = New-ScheduledTaskAction `
    -Execute "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" `
    -Argument $actionArgs `
    -WorkingDirectory $ProjectRoot

$trigger = New-ScheduledTaskTrigger -AtLogOn -User $ShortUser

$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -StartWhenAvailable `
    -MultipleInstances IgnoreNew `
    -ExecutionTimeLimit ([TimeSpan]::Zero) `
    -RestartCount 3 `
    -RestartInterval (New-TimeSpan -Minutes 1)

$principal = New-ScheduledTaskPrincipal `
    -UserId $CurrentUser `
    -LogonType Interactive `
    -RunLevel Limited

Register-ScheduledTask `
    -TaskName $TaskName `
    -Action $action `
    -Trigger $trigger `
    -Settings $settings `
    -Principal $principal `
    -Description "Supervises Windows MCP Agent Stack (FastAPI Backend 3080 -> MCP Bridge 8765 -> Secure Tunnel windows-mcp-isolated) in interactive user session." `
    -Force | Out-Null

$registered = Get-ScheduledTask -TaskName $TaskName
Write-Host "Registered Scheduled Task '$TaskName' successfully." -ForegroundColor Green
[PSCustomObject]@{
    TaskName      = $registered.TaskName
    State         = [string]$registered.State
    UserId        = $registered.Principal.UserId
    LogonType     = [string]$registered.Principal.LogonType
    RunLevel      = [string]$registered.Principal.RunLevel
    ActionExecute = $registered.Actions[0].Execute
    ActionArgs    = $registered.Actions[0].Arguments
} | Format-List
exit 0
