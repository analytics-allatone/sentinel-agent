#Requires -RunAsAdministrator
# ============================================================
#  Sentinel Agent — Windows Installer
#  Usage (non-interactive):
#    $env:SERVER_IP='1.2.3.4'; $env:AGENT_NAME='my-pc'; $env:GROUP_NAME='my-group'; irm https://YOUR_HOST/api/v1/scripts/windows_install.ps1 | iex
#  Usage (interactive):
#    irm https://YOUR_HOST/api/v1/scripts/windows_install.ps1 | iex
# ============================================================

$ErrorActionPreference = "Stop"

# ============================================================
# CONFIG — YOUR_HOST is replaced at serve time by FastAPI
# ============================================================
$DownloadUrl    = "https://YOUR_HOST/api/v1/binaries/window_agent.exe"
$ExpectedSHA256 = ""

$InstallDir  = "C:\sentinel-agent"
$BinaryPath  = "$InstallDir\sentinel-agent.exe"
$EnvFile     = "$InstallDir\.env"
$LogDir      = "$InstallDir\logs"
$ServiceName = "sentinel-agent"

$NSSMUrl  = "https://nssm.cc/release/nssm-2.24.zip"
$NSSMZip  = "$env:TEMP\nssm.zip"
$NSSMDir  = "$env:TEMP\nssm"

# ============================================================
# HELPERS
# ============================================================
function Log  { Write-Host "[+] $args" -ForegroundColor Green }
function Warn { Write-Host "[!] $args" -ForegroundColor Yellow }
function Die  { Write-Host "[x] $args" -ForegroundColor Red; exit 1 }

# ============================================================
# COLLECT VALUES
# ============================================================
$ServerIP  = $env:SERVER_IP
$AgentName = $env:AGENT_NAME
$GroupName = $env:GROUP_NAME

if (-not $ServerIP) {
    $ServerIP = Read-Host "Server IP"
}
if (-not $ServerIP) { Die "SERVER_IP is required." }

if (-not $AgentName) {
    $Default   = $env:COMPUTERNAME
    $AgentName = Read-Host "Agent name [$Default]"
    if (-not $AgentName) { $AgentName = $Default }
}
if (-not $AgentName) { Die "AGENT_NAME is required." }

if (-not $GroupName) {
    $GroupName = Read-Host "Group name (optional, press Enter to skip)"
}

Log "Server IP  : $ServerIP"
Log "Agent name : $AgentName"
Log "Group name : $(if ($GroupName) { $GroupName } else { 'none' })"

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
# STOP AND REMOVE OLD SERVICE IF EXISTS
# ============================================================
$Existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($Existing) {
    Warn "Existing service found — removing..."
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    sc.exe delete $ServiceName | Out-Null
    Start-Sleep -Seconds 2
    Log "Old service removed."
}

# ============================================================
# DOWNLOAD BINARY — group_name passed here only, not stored
# ============================================================
$DownloadUrlWithParams = "${DownloadUrl}?agent_name=${AgentName}&group_name=${GroupName}"
Log "Downloading agent binary from $DownloadUrlWithParams"

try {
    Invoke-WebRequest -Uri $DownloadUrlWithParams -OutFile $BinaryPath -UseBasicParsing
} catch {
    Die "Download failed: $_"
}

if ($ExpectedSHA256) {
    $Got = (Get-FileHash -Path $BinaryPath -Algorithm SHA256).Hash
    if ($Got.ToLower() -ne $ExpectedSHA256.ToLower()) {
        Remove-Item $BinaryPath -Force
        Die "SHA-256 mismatch.`n  Expected: $ExpectedSHA256`n  Got: $Got"
    }
    Log "SHA-256 verified."
}

Log "Binary installed at $BinaryPath"

# ============================================================
# WRITE .env — only SERVER_IP and AGENT_NAME, no GROUP_NAME
# ============================================================
$EnvContent = @"
# Sentinel Agent configuration - written by installer on $(Get-Date -Format 'yyyy-MM-ddTHH:mm:ssZ')
SERVER_IP=$ServerIP
AGENT_NAME=$AgentName
"@

Set-Content -Path $EnvFile -Value $EnvContent -Encoding UTF8

# Give SYSTEM and Administrators full access to .env
$Acl = New-Object System.Security.AccessControl.FileSecurity
$Acl.SetAccessRuleProtection($true, $false)
$Acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
    "SYSTEM", "FullControl", "Allow")))
$Acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
    "Administrators", "FullControl", "Allow")))
Set-Acl -Path $EnvFile -AclObject $Acl

Log "Wrote $EnvFile"

# ============================================================
# GIVE SYSTEM FULL ACCESS TO InstallDir
# ============================================================
$DirAcl = Get-Acl $InstallDir
$DirAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
    "SYSTEM", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")))
Set-Acl -Path $InstallDir -AclObject $DirAcl
Log "Permissions set on $InstallDir"

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
# INSTALL AND CONFIGURE SERVICE
# ============================================================
Log "Installing Windows service..."

& $NSSMExe install $ServiceName $BinaryPath
if ($LASTEXITCODE -ne 0) { Die "NSSM install failed." }

# Working directory same as binary so .env is found
& $NSSMExe set $ServiceName AppDirectory     $InstallDir

# Startup
& $NSSMExe set $ServiceName Start            SERVICE_AUTO_START
& $NSSMExe set $ServiceName AppExit          Default Restart
& $NSSMExe set $ServiceName AppRestartDelay  5000

# Logging
& $NSSMExe set $ServiceName AppStdout        "$LogDir\agent.log"
& $NSSMExe set $ServiceName AppStderr        "$LogDir\agent.err"
& $NSSMExe set $ServiceName AppRotateFiles   1
& $NSSMExe set $ServiceName AppRotateOnline  1
& $NSSMExe set $ServiceName AppRotateBytes   10485760

# Inject env vars directly — ensures service always has them
# GROUP_NAME is intentionally excluded here
& $NSSMExe set $ServiceName AppEnvironmentExtra "SERVER_IP=$ServerIP" "AGENT_NAME=$AgentName"

& $NSSMExe set $ServiceName Description      "Sentinel security agent"

Log "Service configured."

# ============================================================
# START AND VERIFY
# ============================================================
Log "Starting service..."
& $NSSMExe start $ServiceName | Out-Null

Start-Sleep -Seconds 5

$Service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if (-not $Service -or $Service.Status -ne "Running") {
    Warn "Service did NOT start cleanly."
    if (Test-Path "$LogDir\agent.err") {
        Warn "Last error log lines:"
        Get-Content "$LogDir\agent.err" -Tail 30
    } else {
        Warn "No error log found — try running manually:"
        Warn "  C:\sentinel-agent\sentinel-agent.exe"
    }
    sc.exe query $ServiceName
    Die "Installation failed — service is not running."
}

# ============================================================
# DONE
# ============================================================
Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  Sentinel Agent installed successfully." -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Status        : $($Service.Status)" -ForegroundColor Green
Write-Host "  Binary        : $BinaryPath"
Write-Host "  Config file   : $EnvFile"
Write-Host "  Logs (stdout) : $LogDir\agent.log"
Write-Host "  Logs (stderr) : $LogDir\agent.err"
Write-Host "  Connected to  : $ServerIP"
Write-Host "  Agent name    : $AgentName"
Write-Host ""
Write-Host "  Useful commands:" -ForegroundColor Yellow
Write-Host "    Get-Service $ServiceName"
Write-Host "    Restart-Service $ServiceName"
Write-Host "    Stop-Service $ServiceName"
Write-Host "    Get-Content $LogDir\agent.log -Tail 50 -Wait"
Write-Host "    Get-Content $LogDir\agent.err -Tail 50 -Wait"
Write-Host ""
Write-Host "  To uninstall:" -ForegroundColor Yellow
Write-Host "    Stop-Service $ServiceName"
Write-Host "    & '$NSSMExe' remove $ServiceName confirm"
Write-Host "    Remove-Item '$InstallDir' -Recurse -Force"
Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan