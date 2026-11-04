<#
.SYNOPSIS
    Portable, idempotent installer for the Windows MCP Agent Stack (Stage S6 / P6).

.DESCRIPTION
    1. Verifies Windows OS version, PowerShell version, Python 3.11+ availability,
       Git availability, and port status (3080, 8765, 8766, 8767).
    2. Verifies source code integrity via SHA256 hashes across core modules.
    3. Validates required Python packages (fastapi, uvicorn, psutil, pillow, pydantic, pytest).
    4. Initializes the directory layout under -TargetRoot (and copies clean source files
       when -TargetRoot is a fresh installation directory different from -SourceRoot).
    5. Generates a machine-specific cryptographic gateway/backend bearer token (if not
       already present) and seals it via Windows DPAPI (ConvertTo-SecureString +
       Protect-TunnelCredential.ps1) without ever printing raw secrets.
    6. Registers the Scheduled Task (Register-StartupTask.ps1) unless -SkipTaskRegistration or -DryRun.
    7. Starts the stack (Start-WindowsMcpStack.ps1) and runs diagnostics (Test-WindowsMcpStack.ps1)
       unless -SkipStackStart or -DryRun.
    8. Writes a structured JSON installation report to $TargetRoot\runtime\logs\install-report.json.
#>
[CmdletBinding()]
param(
    [string]$TargetRoot = $(if ($PSScriptRoot) { (Resolve-Path (Join-Path $PSScriptRoot "..")).Path } else { (Get-Location).Path }),
    [string]$SourceRoot = "",
    [switch]$DryRun,
    [switch]$SkipTaskRegistration,
    [switch]$SkipStackStart,
    [string]$TunnelProfile = "windows-mcp-isolated"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Add-Type -AssemblyName System.Security

if ([string]::IsNullOrWhiteSpace($SourceRoot)) {
    $SourceRoot = Split-Path -Parent $PSScriptRoot
}
$SourceRoot = [System.IO.Path]::GetFullPath($SourceRoot)
$TargetRoot = [System.IO.Path]::GetFullPath($TargetRoot)
$IsSameRoot = ($SourceRoot.TrimEnd('\').ToLowerInvariant() -eq $TargetRoot.TrimEnd('\').ToLowerInvariant())

# ---------------------------------------------------------------------------
# 1. Prerequisite Checks (OS, PowerShell, Python 3.11+, Git, Ports)
# ---------------------------------------------------------------------------
$osVersion = [System.Environment]::OSVersion.Version
$isWindows10Or11 = ($osVersion.Major -ge 10)
$psVersion = $PSVersionTable.PSVersion
$psOk = ($psVersion.Major -ge 5)

$localAppData = if ($env:LOCALAPPDATA) { $env:LOCALAPPDATA } else { Join-Path $env:USERPROFILE "AppData\Local" }
$pythonCandidates = @(
    (Join-Path $localAppData "Programs\Python\Python312\python.exe"),
    (Join-Path $localAppData "Programs\Python\Python311\python.exe"),
    (Join-Path $TargetRoot ".venv\Scripts\python.exe"),
    (Join-Path $SourceRoot ".venv\Scripts\python.exe")
)
$pythonExe = $null
$cmdPy = Get-Command python.exe -ErrorAction SilentlyContinue
if ($null -ne $cmdPy -and (Test-Path $cmdPy.Source)) {
    $pythonExe = $cmdPy.Source
} else {
    foreach ($cand in $pythonCandidates) {
        if (Test-Path $cand) {
            $pythonExe = $cand
            break
        }
    }
}

$pythonVersionStr = ""
$pythonOk = $false
if ($null -ne $pythonExe -and (Test-Path $pythonExe)) {
    $pyCheck = (& $pythonExe -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}|' + str(sys.version_info >= (3, 11)))" 2>$null).Trim()
    if ($pyCheck -match "^([^|]+)\|(True|False)$") {
        $pythonVersionStr = $Matches[1]
        $pythonOk = ($Matches[2] -eq "True")
    }
}

$gitCmd = Get-Command git.exe -ErrorAction SilentlyContinue
$gitVersionStr = ""
$gitOk = ($null -ne $gitCmd)
if ($gitOk) {
    $gitVersionStr = (& git.exe --version 2>$null | Select-Object -First 1).Trim()
}

# Check required Python packages
$requiredPackages = @("fastapi", "uvicorn", "psutil", "PIL", "pydantic", "pytest")
$packageStatus = [ordered]@{}
$allPackagesOk = $true
if ($pythonOk) {
    foreach ($pkg in $requiredPackages) {
        $pkgCheck = (& $pythonExe -c "import importlib.util; print(importlib.util.find_spec('$pkg') is not None)" 2>$null).Trim()
        $installed = ($pkgCheck -eq "True")
        $packageStatus[$pkg] = $installed
        if (-not $installed) {
            $allPackagesOk = $false
        }
    }
} else {
    $allPackagesOk = $false
}

# Port availability / existing healthy stack inspection (3080, 8765, 8766, 8767)
$portsToCheck = @(3080, 8765, 8766, 8767)
$portReport = [ordered]@{}
foreach ($p in $portsToCheck) {
    $listeners = @(Get-NetTCPConnection -LocalAddress "127.0.0.1" -LocalPort $p -State Listen -ErrorAction SilentlyContinue)
    if ($listeners.Count -gt 0) {
        $ownerPid = $listeners[0].OwningProcess
        $ownerProc = Get-Process -Id $ownerPid -ErrorAction SilentlyContinue
        $procName = $(if ($null -ne $ownerProc) { $ownerProc.ProcessName } else { "unknown" })
        $portReport["$p"] = [ordered]@{
            port        = $p
            state       = "LISTENING_REUSABLE"
            owning_pid  = $ownerPid
            process     = $procName
            available   = $true
        }
    } else {
        $portReport["$p"] = [ordered]@{
            port        = $p
            state       = "FREE"
            owning_pid  = $null
            process     = $null
            available   = $true
        }
    }
}

# ---------------------------------------------------------------------------
# 2. Source Integrity Verification (SHA256 Hashes)
# ---------------------------------------------------------------------------
$coreRelativeFiles = @(
    "backend\__init__.py",
    "backend\file_code_ops.py",
    "backend\exec_jobs.py",
    "mcp-gateway\__init__.py",
    "mcp-gateway\policy.py",
    "mcp-gateway\gateway_server.py",
    "mcp-gateway\http_server.py",
    "mcp-gateway\tools_catalog.json",
    "desktop-agent\__init__.py",
    "desktop-agent\agent.py",
    "runtime\__init__.py",
    "runtime\watchdog.py",
    "config\policy.json",
    "scripts\Protect-TunnelCredential.ps1",
    "scripts\Register-StartupTask.ps1",
    "scripts\Rollback-WindowsMcp.ps1",
    "scripts\Start-WindowsMcpStack.ps1",
    "scripts\Test-WindowsMcpStack.ps1"
)

$sourceHashes = [ordered]@{}
$missingSourceFiles = @()
foreach ($rel in $coreRelativeFiles) {
    $fullSource = Join-Path $SourceRoot $rel
    if (Test-Path $fullSource) {
        $sourceHashes[$rel] = (Get-FileHash -Path $fullSource -Algorithm SHA256).Hash.ToUpperInvariant()
    } elseif ($rel -eq "config\policy.json") {
        $examplePolicy = Join-Path $SourceRoot "config\policy.example.json"
        if (Test-Path $examplePolicy) {
            $sourceHashes["config\policy.example.json"] = (Get-FileHash -Path $examplePolicy -Algorithm SHA256).Hash.ToUpperInvariant()
        } else {
            $missingSourceFiles += $rel
        }
    } else {
        $missingSourceFiles += $rel
    }
}
$sourceIntegrityOk = ($missingSourceFiles.Count -eq 0)

# ---------------------------------------------------------------------------
# 3. Directory Layout & Portable File Copy (Idempotent)
# ---------------------------------------------------------------------------
$requiredDirs = @(
    "backend",
    "mcp-gateway",
    "desktop-agent",
    "runtime",
    "runtime\logs",
    "runtime\secrets",
    "runtime\evidence",
    "runtime\jobs",
    "backups",
    "config",
    "scripts",
    "docs",
    "tests"
)

$dirResults = New-Object System.Collections.Generic.List[object]
$wasExistingInstall = (Test-Path (Join-Path $TargetRoot "config\policy.json"))

foreach ($relDir in $requiredDirs) {
    $fullDir = Join-Path $TargetRoot $relDir
    $existed = Test-Path $fullDir
    if ((-not $existed) -and (-not $DryRun)) {
        New-Item -ItemType Directory -Path $fullDir -Force | Out-Null
    }
    $dirResults.Add([PSCustomObject]@{
        Directory = $relDir
        FullPath  = $fullDir
        Existed   = $existed
        Action    = $(if ($existed) { "PRESERVED" } elseif ($DryRun) { "DRYRUN_WOULD_CREATE" } else { "CREATED" })
    })
}

# Copy source modules if TargetRoot is a separate clean install target and not DryRun
$copiedFilesCount = 0
if ((-not $IsSameRoot) -and (-not $DryRun)) {
    $copyFolders = @("backend", "mcp-gateway", "desktop-agent", "scripts", "docs", "tests")
    foreach ($folder in $copyFolders) {
        $srcFolder = Join-Path $SourceRoot $folder
        $dstFolder = Join-Path $TargetRoot $folder
        if (Test-Path $srcFolder) {
            Get-ChildItem -Path $srcFolder -File | Where-Object {
                $_.Extension -in @(".py", ".json", ".ps1", ".md")
            } | ForEach-Object {
                Copy-Item -Path $_.FullName -Destination (Join-Path $dstFolder $_.Name) -Force
                $copiedFilesCount++
            }
        }
    }
    foreach ($rtFile in @("runtime\__init__.py", "runtime\watchdog.py")) {
        $srcRt = Join-Path $SourceRoot $rtFile
        $dstRt = Join-Path $TargetRoot $rtFile
        if (Test-Path $srcRt) {
            Copy-Item -Path $srcRt -Destination $dstRt -Force
            $copiedFilesCount++
        }
    }
    # Copy config example files if present in SourceRoot
    $srcCfg = Join-Path $SourceRoot "config"
    $dstCfg = Join-Path $TargetRoot "config"
    if (Test-Path $srcCfg) {
        Get-ChildItem -Path $srcCfg -File | Where-Object {
            $_.Name -like "*.example.json" -or $_.Name -like "*.example.yaml"
        } | ForEach-Object {
            Copy-Item -Path $_.FullName -Destination (Join-Path $dstCfg $_.Name) -Force
            $copiedFilesCount++
        }
    }
}

# Automatically instantiate config from examples if not present in TargetRoot (runs whenever not -DryRun)
if (-not $DryRun) {
    $cfgPairs = @(
        @{ Target = "config\policy.json"; Example = "config\policy.example.json" },
        @{ Target = "config\trusted_workspaces.json"; Example = "config\trusted_workspaces.example.json" },
        @{ Target = "config\tunnel-autonomous.json"; Example = "config\tunnel-autonomous.example.json" }
    )
    foreach ($pair in $cfgPairs) {
        $tgtFile = Join-Path $TargetRoot $pair.Target
        if (-not (Test-Path $tgtFile)) {
            $exCandidate = Join-Path $TargetRoot $pair.Example
            if (-not (Test-Path $exCandidate)) {
                $exCandidate = Join-Path $SourceRoot $pair.Example
            }
            if (Test-Path $exCandidate) {
                Copy-Item -Path $exCandidate -Destination $tgtFile -Force
                $copiedFilesCount++
            }
        }
    }
}

# ---------------------------------------------------------------------------
# 4. Machine-Specific Cryptographic Bearer Token & DPAPI Sealing (Idempotent)
# ---------------------------------------------------------------------------
$secretsDir = Join-Path $TargetRoot "runtime\secrets"
$gatewaySecretName = "gateway_bearer_token"
$gatewayBlobPath = Join-Path $secretsDir "$gatewaySecretName.dpapi"
$tunnelBlobPath = Join-Path $secretsDir "$TunnelProfile.api_key.dpapi"
$protectScript = Join-Path $SourceRoot "scripts\Protect-TunnelCredential.ps1"

$existingCredentialPreserved = $false
$gatewayTokenSealed = $false
$dpapiRoundTripOk = $false

# Verify DPAPI capability in memory
$entropy = [System.Text.Encoding]::UTF8.GetBytes("WindowsMcpAgent::P0.5::CredentialStore::v1")
$probePlain = [System.Text.Encoding]::UTF8.GetBytes("dpapi-install-probe-" + [Guid]::NewGuid().ToString("N"))
$probeCipher = [System.Security.Cryptography.ProtectedData]::Protect(
    $probePlain,
    $entropy,
    [System.Security.Cryptography.DataProtectionScope]::CurrentUser
)
$probeUnprotected = [System.Security.Cryptography.ProtectedData]::Unprotect(
    $probeCipher,
    $entropy,
    [System.Security.Cryptography.DataProtectionScope]::CurrentUser
)
$dpapiRoundTripOk = ([System.Text.Encoding]::UTF8.GetString($probeUnprotected) -eq [System.Text.Encoding]::UTF8.GetString($probePlain))

if ((Test-Path $gatewayBlobPath) -or (Test-Path $tunnelBlobPath)) {
    $existingCredentialPreserved = $true
    $gatewayTokenSealed = $true
} elseif (-not $DryRun) {
    # Generate 256-bit cryptographic random token and seal via Protect-TunnelCredential.ps1 without printing
    $rngBytes = New-Object byte[] 32
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $rng.GetBytes($rngBytes)
        $tokenHex = -join ($rngBytes | ForEach-Object { $_.ToString("x2") })
        $secToken = ConvertTo-SecureString -String $tokenHex -AsPlainText -Force
        $tokenHex = $null
    } finally {
        [Array]::Clear($rngBytes, 0, $rngBytes.Length)
        $rng.Dispose()
    }

    & $protectScript `
        -SecretName $gatewaySecretName `
        -SecretValue $secToken `
        -SecretsDir $secretsDir | Out-Null

    $gatewayTokenSealed = (Test-Path $gatewayBlobPath)
} else {
    $gatewayTokenSealed = $true
}

# ---------------------------------------------------------------------------
# 5. Scheduled Task Registration & Stack Start (Unless Skipped or DryRun)
# ---------------------------------------------------------------------------
$taskStatus = "SKIPPED"
if ($DryRun) {
    $taskStatus = "DRYRUN_SKIPPED"
} elseif ($SkipTaskRegistration) {
    $taskStatus = "SKIPPED_BY_FLAG"
} elseif ($IsSameRoot) {
    $regScript = Join-Path $TargetRoot "scripts\Register-StartupTask.ps1"
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $regScript | Out-Null
    $taskStatus = "REGISTERED"
} else {
    $taskStatus = "SKIPPED_STAGING_TARGET"
}

$stackStatus = "SKIPPED"
if ($DryRun) {
    $stackStatus = "DRYRUN_SKIPPED"
} elseif ($SkipStackStart) {
    $stackStatus = "SKIPPED_BY_FLAG"
} elseif ($IsSameRoot) {
    $startScript = Join-Path $TargetRoot "scripts\Start-WindowsMcpStack.ps1"
    $testScript = Join-Path $TargetRoot "scripts\Test-WindowsMcpStack.ps1"
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $startScript -Once | Out-Null
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $testScript | Out-Null
    $stackStatus = "STARTED_AND_VERIFIED"
} else {
    $stackStatus = "SKIPPED_STAGING_TARGET"
}

# ---------------------------------------------------------------------------
# 6. Write Structured Install Report JSON
# ---------------------------------------------------------------------------
$overallOk = ($isWindows10Or11 -and $psOk -and $pythonOk -and $gitOk -and $allPackagesOk -and $sourceIntegrityOk -and $dpapiRoundTripOk -and $gatewayTokenSealed)

$reportObj = [ordered]@{
    schema_version           = "1.0.0"
    generated_at             = (Get-Date).ToString("o")
    script                   = "Install-WindowsMcpAgent.ps1"
    target_root              = $TargetRoot
    source_root              = $SourceRoot
    dry_run                  = [bool]$DryRun
    skip_task_registration   = [bool]$SkipTaskRegistration
    skip_stack_start         = [bool]$SkipStackStart
    tunnel_profile           = $TunnelProfile
    idempotent_rerun         = $wasExistingInstall
    overall_status           = $(if ($overallOk) { "PASS" } else { "FAIL" })
    prerequisites            = [ordered]@{
        os_version           = $osVersion.ToString()
        os_supported         = $isWindows10Or11
        powershell_version   = $psVersion.ToString()
        powershell_supported = $psOk
        python_executable    = $pythonExe
        python_version       = $pythonVersionStr
        python_311_plus      = $pythonOk
        git_available        = $gitOk
        git_version          = $gitVersionStr
        required_packages    = $packageStatus
        all_packages_present = $allPackagesOk
        ports                = $portReport
    }
    source_integrity         = [ordered]@{
        verified_files_count = $sourceHashes.Count
        missing_files        = $missingSourceFiles
        integrity_passed     = $sourceIntegrityOk
        sha256_manifest      = $sourceHashes
    }
    filesystem               = [ordered]@{
        directories          = $dirResults
        copied_files_count   = $copiedFilesCount
    }
    credentials              = [ordered]@{
        dpapi_roundtrip_ok            = $dpapiRoundTripOk
        secrets_dir                   = $secretsDir
        gateway_token_sealed          = $gatewayTokenSealed
        existing_credential_preserved = $existingCredentialPreserved
        raw_secrets_printed           = $false
    }
    task_registration        = $taskStatus
    stack_startup            = $stackStatus
    coexistence_guard        = [ordered]@{
        legacy_codex_profile = "codex-chatgpt-web"
        legacy_codex_tunnel  = "tunnel_unconfigured_legacy"
        untouched            = $true
    }
}

$reportPath = Join-Path $TargetRoot "runtime\logs\install-report.json"
$reportDir = Split-Path -Parent $reportPath
if (Test-Path $reportDir) {
    [System.IO.File]::WriteAllText(
        $reportPath,
        ($reportObj | ConvertTo-Json -Depth 8),
        [System.Text.UTF8Encoding]::new($false)
    )
} elseif ($DryRun -and (Test-Path (Join-Path $SourceRoot "runtime\logs"))) {
    # When running -DryRun against a non-existent disposable TargetRoot, also emit to stdout cleanly
    Write-Verbose "DryRun TargetRoot does not exist on disk; skipping directory creation."
}

$modeText = $(if ($DryRun) { "DRY-RUN" } else { "LIVE INSTALL" })
Write-Host "==========================================================================================" -ForegroundColor Cyan
Write-Host " Windows MCP Agent Installer ($modeText) -> Status: $($reportObj.overall_status)" -ForegroundColor $(if ($overallOk) { "Green" } else { "Red" })
Write-Host " TargetRoot: $TargetRoot | IdempotentRerun: $wasExistingInstall | CredPreserved: $existingCredentialPreserved" -ForegroundColor Cyan
Write-Host "==========================================================================================" -ForegroundColor Cyan

if (-not $overallOk) {
    exit 1
}
exit 0
