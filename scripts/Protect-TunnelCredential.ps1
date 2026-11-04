<#
.SYNOPSIS
    DPAPI credential protection & rotation readiness helper (P0.5) for WinOwner MCP.

.DESCRIPTION
    Uses Windows Data Protection API (DPAPI CurrentUser scope) to encrypt, verify,
    and stage tunnel/backend credentials in `D:\ExampleProjects\Windows-MCP-Agent\runtime\secrets`
    with restricted NTFS ACLs, without revoking or breaking active tunnel credentials.

    Modes:
      -Verify (default): Verifies CurrentUser DPAPI encryption/decryption round-trip
                         and checks existing protected credential blobs.
      -ProtectFromProfile: Reads the active credential from windows-mcp-isolated.yaml
                           (without displaying it) and seals a CurrentUser DPAPI blob
                           at runtime\secrets\windows-mcp-isolated.api_key.dpapi.
      -SecretName / -SecretValue: Protects a supplied SecureString under the given name.
#>
[CmdletBinding()]
param(
    [switch]$Verify,
    [switch]$ProtectFromProfile,
    [string]$SecretName = "windows-mcp-isolated.api_key",
    [System.Security.SecureString]$SecretValue = $null,
    [string]$ProfilePath = $(if ($env:APPDATA) { Join-Path $env:APPDATA "tunnel-client\windows-mcp-isolated.yaml" } else { Join-Path $env:USERPROFILE "AppData\Roaming\tunnel-client\windows-mcp-isolated.yaml" }),
    [string]$SecretsDir = $(if ($PSScriptRoot) { Join-Path (Resolve-Path (Join-Path $PSScriptRoot "..")).Path "runtime\secrets" } else { Join-Path (Get-Location).Path "runtime\secrets" })
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Add-Type -AssemblyName System.Security

function Set-RestrictedDirectoryAcl {
    param([string]$Path)
    if (-not (Test-Path $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
    try {
        $acl = Get-Acl -Path $Path
        $acl.SetAccessRuleProtection($true, $false)
        $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        $ruleUser = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $currentUser, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow"
        )
        $ruleSystem = New-Object System.Security.AccessControl.FileSystemAccessRule(
            "NT AUTHORITY\SYSTEM", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow"
        )
        $acl.SetAccessRule($ruleUser)
        $acl.AddAccessRule($ruleSystem)
        Set-Acl -Path $Path -AclObject $acl
    } catch {
        Write-Verbose "ACL hardening warning: $($_.Exception.Message)"
    }
}

function Protect-StringDpapi {
    param([string]$PlainText, [byte[]]$EntropyBytes)
    $rawBytes = [System.Text.Encoding]::UTF8.GetBytes($PlainText)
    try {
        $cipherBytes = [System.Security.Cryptography.ProtectedData]::Protect(
            $rawBytes,
            $EntropyBytes,
            [System.Security.Cryptography.DataProtectionScope]::CurrentUser
        )
        return [Convert]::ToBase64String($cipherBytes)
    } finally {
        [Array]::Clear($rawBytes, 0, $rawBytes.Length)
    }
}

function Unprotect-StringDpapi {
    param([string]$Base64Cipher, [byte[]]$EntropyBytes)
    $cipherBytes = [Convert]::FromBase64String($Base64Cipher)
    $rawBytes = [System.Security.Cryptography.ProtectedData]::Unprotect(
        $cipherBytes,
        $EntropyBytes,
        [System.Security.Cryptography.DataProtectionScope]::CurrentUser
    )
    try {
        return [System.Text.Encoding]::UTF8.GetString($rawBytes)
    } finally {
        [Array]::Clear($rawBytes, 0, $rawBytes.Length)
    }
}

$entropy = [System.Text.Encoding]::UTF8.GetBytes("WindowsMcpAgent::P0.5::CredentialStore::v1")
Set-RestrictedDirectoryAcl -Path $SecretsDir
$targetBlobPath = Join-Path $SecretsDir "$SecretName.dpapi"

if ($ProtectFromProfile) {
    if (-not (Test-Path $ProfilePath)) {
        throw "Tunnel profile not found at: $ProfilePath"
    }
    $lines = Get-Content -Path $ProfilePath
    $extractedKey = $null
    foreach ($line in $lines) {
        if ($line -match "^\s*api_key\s*:\s*[`"']?([^`"'\s]+)[`"']?\s*$") {
            $extractedKey = $Matches[1]
            break
        }
    }
    if ([string]::IsNullOrWhiteSpace($extractedKey)) {
        throw "Could not locate api_key field in $ProfilePath"
    }
    $cipherB64 = Protect-StringDpapi -PlainText $extractedKey -EntropyBytes $entropy
    $extractedKey = $null

    $envelope = [ordered]@{
        schema_version = "1.0.0"
        secret_name    = $SecretName
        scope          = "CurrentUser"
        protected_at   = (Get-Date).ToString("o")
        user           = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        source_profile = $ProfilePath
        dpapi_blob     = $cipherB64
    }
    [System.IO.File]::WriteAllText(
        $targetBlobPath,
        ($envelope | ConvertTo-Json -Depth 4),
        [System.Text.UTF8Encoding]::new($false)
    )
    Write-Host "DPAPI credential sealed to: $targetBlobPath (active profile left untouched)." -ForegroundColor Green
}

if ($null -ne $SecretValue) {
    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecretValue)
    try {
        $plain = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
        $cipherB64 = Protect-StringDpapi -PlainText $plain -EntropyBytes $entropy
        $plain = $null
    } finally {
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    }
    $envelope = [ordered]@{
        schema_version = "1.0.0"
        secret_name    = $SecretName
        scope          = "CurrentUser"
        protected_at   = (Get-Date).ToString("o")
        user           = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        dpapi_blob     = $cipherB64
    }
    [System.IO.File]::WriteAllText(
        $targetBlobPath,
        ($envelope | ConvertTo-Json -Depth 4),
        [System.Text.UTF8Encoding]::new($false)
    )
    Write-Host "Custom SecureString sealed to: $targetBlobPath" -ForegroundColor Green
}

# Always run DPAPI self-test verification
$probeInput = "dpapi-readiness-probe-" + [Guid]::NewGuid().ToString("N")
$probeCipher = Protect-StringDpapi -PlainText $probeInput -EntropyBytes $entropy
$probeOutput = Unprotect-StringDpapi -Base64Cipher $probeCipher -EntropyBytes $entropy
$roundTripOk = ($probeInput -eq $probeOutput)

$blobVerified = $false
$blobLength = 0
if (Test-Path $targetBlobPath) {
    try {
        $envObj = Get-Content $targetBlobPath -Raw | ConvertFrom-Json
        $unprotected = Unprotect-StringDpapi -Base64Cipher $envObj.dpapi_blob -EntropyBytes $entropy
        $blobLength = $unprotected.Length
        $blobVerified = ($blobLength -gt 8)
        $unprotected = $null
    } catch {
        $blobVerified = $false
    }
}

$result = [PSCustomObject]@{
    DpapiRoundTripPassed = $roundTripOk
    SecretsDirectory     = $SecretsDir
    TargetBlobPath       = $targetBlobPath
    TargetBlobExists     = (Test-Path $targetBlobPath)
    TargetBlobVerified   = $blobVerified
    SecretCharLength     = $blobLength
    ActiveProfileIntact  = (Test-Path $ProfilePath)
}

$result | Format-List
if (-not $roundTripOk) {
    exit 1
}
exit 0
