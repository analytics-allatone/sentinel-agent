# ========================================================
# SENTINEL AGENT - SSH HEADLESS INSTALLER
# ========================================================

# 1. Force TLS 1.2 for downloads
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# 2. Check for Admin Rights immediately
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "CRITICAL: You are logged in via SSH as a standard user."
    Write-Host "You MUST log in via SSH using an account that is part of the 'Administrators' group."
    Write-Host "Windows prevents service creation from standard SSH sessions for security."
    exit 1
}

# 3. Path Setup
$SERVICE_NAME = "SentinelAgent"
$ROOT_DIR     = Split-Path -Parent $MyInvocation.MyCommand.Path
$PROJECT_DIR  = Join-Path $ROOT_DIR "agent"
$VENV_DIR     = Join-Path $PROJECT_DIR "venv"
$PYTHON_EXE   = Join-Path $VENV_DIR "Scripts\python.exe"
$MAIN_FILE    = Join-Path $PROJECT_DIR "main.py"
$REQ_FILE     = Join-Path $PROJECT_DIR "requirements.txt"
$LOG_DIR      = Join-Path $ROOT_DIR "logs"
$NSSM_DIR     = "C:\nssm"
$NSSM_ZIP     = "C:\temp\nssm.zip"

Write-Host "Elevated rights confirmed. Starting Headless Install..." -ForegroundColor Green

# 4. Environment Setup
if (!(Test-Path "C:\temp")) { New-Item -ItemType Directory -Path "C:\temp" -Force | Out-Null }
if (!(Test-Path $LOG_DIR)) { New-Item -ItemType Directory -Path $LOG_DIR -Force | Out-Null }

Write-Host "Updating Python Environment..."
if (Test-Path $VENV_DIR) { Remove-Item -Recurse -Force $VENV_DIR }
python -m venv $VENV_DIR
& $PYTHON_EXE -m pip install --upgrade pip --quiet
& $PYTHON_EXE -m pip install -r $REQ_FILE --quiet

# 5. NSSM Download & Install
if (!(Test-Path $NSSM_ZIP)) {
    Write-Host "Downloading NSSM via WebRequest..."
    $url = "https://github.com/kohsuke/nssm/releases/download/v2.24/nssm-2.24.zip"
    Invoke-WebRequest -Uri $url -OutFile $NSSM_ZIP -UseBasicParsing
}

Expand-Archive -Path $NSSM_ZIP -DestinationPath $NSSM_DIR -Force
$NSSM = (Get-ChildItem -Path $NSSM_DIR -Recurse -Filter nssm.exe | Select-Object -First 1).FullName

# 6. Service Management
if (Get-Service -Name $SERVICE_NAME -ErrorAction SilentlyContinue) {
    Write-Host "Cleaning old service..."
    stop-service $SERVICE_NAME -Force -ErrorAction SilentlyContinue
    & $NSSM remove $SERVICE_NAME confirm
}

Write-Host "Installing Service: $SERVICE_NAME"
& $NSSM install $SERVICE_NAME $PYTHON_EXE $MAIN_FILE
& $NSSM set $SERVICE_NAME AppDirectory $PROJECT_DIR
& $NSSM set $SERVICE_NAME ObjectName LocalSystem
& $NSSM set $SERVICE_NAME Start SERVICE_AUTO_START

# 7. Logging
& $NSSM set $SERVICE_NAME AppStdout (Join-Path $LOG_DIR "out.log")
& $NSSM set $SERVICE_NAME AppStderr (Join-Path $LOG_DIR "err.log")
& $NSSM set $SERVICE_NAME AppStdoutCreationDisposition 4
& $NSSM set $SERVICE_NAME AppStderrCreationDisposition 4

# 8. Execution
Write-Host "Starting Service..."
Start-Service $SERVICE_NAME

Write-Host "Done! Service is running as LocalSystem (Administrator)." -ForegroundColor Green