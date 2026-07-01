#Requires -RunAsAdministrator
# ============================================================
#  Sentinel Agent — Windows Installer
#  Usage:
#    irm https://YOUR_HOST/scripts/install.ps1 | iex
#  With arguments:
#    $env:SERVER_IP="1.2.3.4"; $env:AGENT_NAME="my-pc"; irm https://YOUR_HOST/scripts/install.ps1 | iex
# ============================================================

$ErrorActionPreference = "Stop"

# ============================================================
# CONFIG — YOUR_HOST is replaced at serve time by FastAPI
# ============================================================
$DownloadUrl   = "https://YOUR_HOST/api/v1/binaries/window_agent.exe"
$ExpectedSHA256 = ""   # optional: set to pin a build, leave empty to skip

$InstallDir    = "C:\sentinel-agent"
$BinaryPath    = "$InstallDir\sentinel-agent.exe"
$EnvFile       = "$InstallDir\.env"
$LogDir        = "$InstallDir\logs"
$ServiceName   = "sentinel-agent"

$NSSMUrl       = "https://nssm.cc/release/nssm-2.24.zip"
$NSSMZip       = "$env:TEMP\nssm.zip"
$NSSMDir       = "$env:TEMP\nssm"
$NSSMExe       = "$NSSMDir\nssm-2.24\win64\nssm.exe"

# ============================================================
# HELPERS
# ============================================================
function Log  { Write-Host "[+] $args" -ForegroundColor Green }
function Warn { Write-Host "[!] $args" -ForegroundColor Yellow }
function Die  {
    Write-Host "[x] $args" -ForegroundColor Red
    exit 1
}

# ============================================================
# COLLECT SERVER_IP AND AGENT_NAME
# ============================================================
# Can be passed as env vars before piping:
#   $env:SERVER_IP="1.2.3.4"; $env:AGENT_NAME="web-01"; irm ... | iex
# Or the script prompts interactively.

$ServerIP  = $env:SERVER_IP
$AgentName = $env:AGENT_NAME
$GroupName = $env:GROUP_NAME

if (-not $ServerIP) {
    $ServerIP = Read-Host "Server IP"
}
if (-not $ServerIP) {
    Die "SERVER_IP is required."
}

if (-not $AgentName) {
    $Default = $env:COMPUTERNAME
    $AgentName = Read-Host "Agent name [$Default]"
    if (-not $AgentName) { $AgentName = $Default }
}
if (-not $AgentName) {
    Die "AGENT_NAME is required."
}

Log "Server IP  : $ServerIP"
Log "Agent name : $AgentName"
Log "Group name  : $(if ($GroupName) { $GroupName } else { 'none' })"

# ============================================================
# CREATE DIRECTORIES
# ============================================================
foreach ($Dir in @($InstallDir, $LogDir)) {
    if (!(Test-Path $Dir)) {
        New-Item -ItemType Directory -Path $Dir | Out-Null
        Log "Created $Dir"
    }
}

# ============================================================
# DOWNLOAD BINARY
# ============================================================


$DownloadUrlWithParams = "${DownloadUrl}?agent_name=${AgentName}&group_name=${GroupName}"
Log "Downloading agent binary from $DownloadUrlWithParams"

try {
    Invoke-WebRequest -Uri $DownloadUrlWithParams -OutFile $BinaryPath -UseBasicParsing
} catch {
    Die "Download failed: $_"
}

# Optional SHA-256 check
if ($ExpectedSHA256) {
    $Got = (Get-FileHash -Path $BinaryPath -Algorithm SHA256).Hash
    if ($Got.ToLower() -ne $ExpectedSHA256.ToLower()) {
        Remove-Item $BinaryPath -Force
        Die "SHA-256 mismatch.`n  Expected: $ExpectedSHA256`n  Got:      $Got"
    }
    Log "SHA-256 verified."
}

Log "Binary installed at $BinaryPath"

# ============================================================
# WRITE .env
# ============================================================
$EnvContent = @"
# Sentinel Agent configuration - written by installer on $(Get-Date -Format 'yyyy-MM-ddTHH:mm:ssZ')
SERVER_IP=$ServerIP
AGENT_NAME=$AgentName
"@

Set-Content -Path $EnvFile -Value $EnvContent -Encoding UTF8

# Lock the file — readable by SYSTEM and Administrators only
$Acl = New-Object System.Security.AccessControl.FileSecurity
$Acl.SetAccessRuleProtection($true, $false)
$Acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
    "SYSTEM", "FullControl", "Allow")))
$Acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
    "Administrators", "FullControl", "Allow")))
Set-Acl -Path $EnvFile -AclObject $Acl

Log "Wrote $EnvFile (SYSTEM + Administrators only)"

# ============================================================
# DOWNLOAD AND EXTRACT NSSM
# ============================================================
Log "Downloading NSSM..."

try {
    Invoke-WebRequest -Uri $NSSMUrl -OutFile $NSSMZip -UseBasicParsing
} catch {
    Die "Failed to download NSSM: $_"
}

if (Test-Path $NSSMDir) {
    Remove-Item $NSSMDir -Recurse -Force
}

Expand-Archive -Path $NSSMZip -DestinationPath $NSSMDir -Force

$Found = Get-ChildItem -Path $NSSMDir -Recurse -Filter nssm.exe |
         Where-Object { $_.FullName -match "win64" } |
         Select-Object -First 1

if (-not $Found) { Die "nssm.exe not found after extraction." }
$NSSMExe = $Found.FullName

Log "NSSM ready at $NSSMExe"

# ============================================================
# REMOVE OLD SERVICE IF EXISTS
# ============================================================
$Existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($Existing) {
    Warn "Existing service found — removing..."
    & $NSSMExe stop    $ServiceName | Out-Null
    & $NSSMExe remove  $ServiceName confirm | Out-Null
    Start-Sleep -Seconds 2
    Log "Old service removed."
}

# ============================================================
# INSTALL AND CONFIGURE SERVICE
# ============================================================
Log "Installing Windows service..."

& $NSSMExe install $ServiceName $BinaryPath
if ($LASTEXITCODE -ne 0) { Die "NSSM install failed." }

& $NSSMExe set $ServiceName AppDirectory  $InstallDir
& $NSSMExe set $ServiceName Start         SERVICE_AUTO_START
& $NSSMExe set $ServiceName AppExit       Default Restart
& $NSSMExe set $ServiceName AppRestartDelay 5000
& $NSSMExe set $ServiceName AppStdout     "$LogDir\agent.log"
& $NSSMExe set $ServiceName AppStderr     "$LogDir\agent.err"
& $NSSMExe set $ServiceName AppRotateFiles 1
& $NSSMExe set $ServiceName AppRotateOnline 1
& $NSSMExe set $ServiceName AppRotateBytes 10485760   # rotate at 10MB
& $NSSMExe set $ServiceName Description  "Sentinel security agent"

Log "Service configured."

# ============================================================
# START AND VERIFY
# ============================================================
Log "Starting service..."
& $NSSMExe start $ServiceName | Out-Null

Start-Sleep -Seconds 3

$Service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if (-not $Service -or $Service.Status -ne "Running") {
    Warn "Service did NOT start cleanly. Last log lines:"
    if (Test-Path "$LogDir\agent.err") {
        Get-Content "$LogDir\agent.err" -Tail 20
    }
    sc.exe query $ServiceName
    Die "Installation failed — service is not running."
}

# ============================================================
# DONE
# ============================================================
Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  Sentinel Agent installed." -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Status        : $($Service.Status)"
Write-Host "  Binary        : $BinaryPath"
Write-Host "  Config file   : $EnvFile"
Write-Host "  Logs          : $LogDir\agent.log"
Write-Host "  Connected to  : $ServerIP"
Write-Host "  Agent name    : $AgentName"
Write-Host ""
Write-Host "  Useful commands:" -ForegroundColor Yellow
Write-Host "    Get-Service $ServiceName"
Write-Host "    Restart-Service $ServiceName"
Write-Host "    Stop-Service $ServiceName"
Write-Host "    Get-Content $LogDir\agent.log -Tail 50 -Wait"
Write-Host ""
Write-Host "  To uninstall:"
Write-Host "    & '$NSSMExe' stop $ServiceName"
Write-Host "    & '$NSSMExe' remove $ServiceName confirm"
Write-Host "    Remove-Item '$InstallDir' -Recurse -Force"
Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan