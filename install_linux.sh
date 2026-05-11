#!/bin/bash

# ============================================
# SENTINEL AGENT LINUX SERVICE INSTALLER
# ============================================

SERVICE_NAME="sentinel-agent"
USER_NAME=$(whoami)

# Directory Setup
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$ROOT_DIR/agent"
VENV_DIR="$PROJECT_DIR/venv"
PYTHON_EXE="$VENV_DIR/bin/python"
MAIN_FILE="$PROJECT_DIR/main.py"
REQ_FILE="$PROJECT_DIR/requirements.txt"
LOG_DIR="$ROOT_DIR/logs"

echo "======================================="
echo " SENTINEL AGENT LINUX INSTALLER"
echo "======================================="

# 1. Check for Sudo (Required to create system services)
if [ "$EUID" -ne 0 ]; then
  echo "ERROR: Please run as root or using sudo"
  exit 1
fi

# 2. Validate Files
if [ ! -f "$MAIN_FILE" ]; then
  echo "ERROR: $MAIN_FILE not found"
  exit 1
fi

# 3. Install Dependencies (Python3-venv)
echo "Installing system dependencies..."
apt-get update && apt-get install -y python3-venv python3-pip

# 4. Create Log Directory
mkdir -p "$LOG_DIR"
chmod 755 "$LOG_DIR"

# 5. Setup Virtual Environment
echo "Setting up virtual environment..."
if [ -d "$VENV_DIR" ]; then
  rm -rf "$VENV_DIR"
fi

python3 -m venv "$VENV_DIR"
$PYTHON_EXE -m pip install --upgrade pip
$PYTHON_EXE -m pip install -r "$REQ_FILE"

# 6. Create systemd Service File
echo "Creating systemd service..."

SERVICE_FILE="/etc/systemd/system/$SERVICE_NAME.service"

cat <<EOF > $SERVICE_FILE
[Unit]
Description=Sentinel Agent Service
After=network.target

[Service]
Type=simple
User=$USER_NAME
WorkingDirectory=$PROJECT_DIR
ExecStart=$PYTHON_EXE $MAIN_FILE
Restart=always
RestartSec=5
StandardOutput=append:$LOG_DIR/out.log
StandardError=append:$LOG_DIR/err.log

[Install]
WantedBy=multi-user.target
EOF

# 7. Start and Enable Service
echo "Reloading systemd and starting service..."
systemctl daemon-reload
systemctl enable $SERVICE_NAME
systemctl restart $SERVICE_NAME

echo "======================================="
echo " INSTALLATION COMPLETE"
echo "======================================="
echo "Status: systemctl status $SERVICE_NAME"
echo "Logs: tail -f $LOG_DIR/out.log"