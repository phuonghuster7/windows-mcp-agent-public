<#
.SYNOPSIS
    Interactive DPAPI Password Setup for Owner Web Console (Port 8767).
.DESCRIPTION
    Prompts the owner for a password using a masked SecureString input,
    encrypts it via Windows DPAPI (CurrentUser scope), restarts ONLY
    Owner Console 8767, and verifies login without logging secrets.
#>
[CmdletBinding()]
param()

$pythonCmd = Get-Command python.exe -ErrorAction SilentlyContinue
if ($pythonCmd) {
    $pythonPath = $pythonCmd.Source
} else {
    $pythonPath = "python.exe"
}

$scriptPath = Join-Path $PSScriptRoot "Set-ConsoleOwnerPassword.py"
& $pythonPath $scriptPath
