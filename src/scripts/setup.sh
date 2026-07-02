set -euo pipefail

# === CHANGE THESE TWO FOR YOUR ENVIRONMENT ================================
DOWNLOAD_URL="https://YOUR_HOST/api/v1/binaries/linux_agent"
EXPECTED_SHA256=""   # optional: set to pin a specific build, leave empty to skip
# ==========================================================================

BINARY_PATH="/usr/local/bin/sentinel-agent"    # exec-safe location
CONFIG_DIR="/etc/sentinel-agent"               # .env lives here
ENV_FILE="${CONFIG_DIR}/.env"
SERVICE_FILE="/etc/systemd/system/sentinel-agent.service"
LOG_DIR="/var/log/sentinel-agent"

SERVER_IP=""
AGENT_NAME=""
GROUP_NAME=""
ACTION="install"

# --- helpers ---------------------------------------------------------------

log()  { printf "\033[1;32m[+]\033[0m %s\n" "$*"; }
warn() { printf "\033[1;33m[!]\033[0m %s\n" "$*"; }
err()  { printf "\033[1;31m[x]\033[0m %s\n" "$*" >&2; }
die()  { err "$*"; exit 1; }

require_root() {
    [ "$(id -u)" -eq 0 ] || die "Run as root (use sudo)."
}

require_linux() {
    [ "$(uname -s)" = "Linux" ] || die "This installer is Linux only."
}

require_systemd() {
    command -v systemctl >/dev/null 2>&1 \
        || die "systemd not found. This installer only supports systemd-based distros."
}

parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            --server-ip)   SERVER_IP="$2";   shift 2 ;;
            --agent-name)  AGENT_NAME="$2";  shift 2 ;;
            --group-name)  GROUP_NAME="$2";  shift 2 ;;
            --uninstall)   ACTION="uninstall"; shift ;;
            -h|--help)
                sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'
                exit 0 ;;
            *) die "Unknown argument: $1" ;;
        esac
    done
}

prompt_if_missing() {
    if [ -z "$SERVER_IP" ]; then
        if [ -t 0 ]; then
            read -r -p "Server IP: " SERVER_IP
        else
            die "SERVER_IP not given and stdin is not a terminal. Use --server-ip <ip>."
        fi
    fi
    if [ -z "$AGENT_NAME" ]; then
        local default_name; default_name="$(hostname)"
        if [ -t 0 ]; then
            read -r -p "Agent name [${default_name}]: " AGENT_NAME
            AGENT_NAME="${AGENT_NAME:-$default_name}"
        else
            AGENT_NAME="$default_name"
            log "Using hostname as agent name: ${AGENT_NAME}"
        fi
    fi
    [ -n "$SERVER_IP" ]  || die "Server IP is required."
    [ -n "$AGENT_NAME" ] || die "Agent name is required."
}

download_binary() {
    local url="${DOWNLOAD_URL}?agent_name=${AGENT_NAME}&group_name=${GROUP_NAME}"
    log "Downloading agent from ${url}"
    local tmp; tmp="$(mktemp)"
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$url" -o "$tmp" \
            || die "Download failed. Check the URL or your network."
    elif command -v wget >/dev/null 2>&1; then
        wget -q "$url" -O "$tmp" \
            || die "Download failed. Check the URL or your network."
    else
        die "Neither curl nor wget is available. Install one and retry."
    fi

    if [ -n "$EXPECTED_SHA256" ]; then
        local got; got="$(sha256sum "$tmp" | awk '{print $1}')"
        if [ "$got" != "$EXPECTED_SHA256" ]; then
            rm -f "$tmp"
            die "SHA-256 mismatch: expected ${EXPECTED_SHA256}, got ${got}."
        fi
        log "SHA-256 verified."
    fi

    install -m 0755 "$tmp" "$BINARY_PATH"
    rm -f "$tmp"
    log "Installed binary at ${BINARY_PATH}"
}

write_env() {
    mkdir -p "$CONFIG_DIR"
    cat > "$ENV_FILE" <<EOF
# Sentinel Agent configuration - written by installer on $(date -u +%FT%TZ)
SERVER_IP=${SERVER_IP}
AGENT_NAME=${AGENT_NAME}
EOF
    chmod 600 "$ENV_FILE"
    chown root:root "$ENV_FILE"
    log "Wrote ${ENV_FILE} (mode 0600, root-only)"

    cp "$ENV_FILE" "$(dirname ${BINARY_PATH})/.env"
    chmod 600 "$(dirname ${BINARY_PATH})/.env"
    chown root:root "$(dirname ${BINARY_PATH})/.env"
    log "Copied .env to $(dirname ${BINARY_PATH})/.env"
}

write_service() {
    mkdir -p "$LOG_DIR"
    cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Sentinel security agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
EnvironmentFile=${ENV_FILE}
ExecStart=${BINARY_PATH}
Restart=on-failure
RestartSec=5s
StandardOutput=append:${LOG_DIR}/agent.log
StandardError=append:${LOG_DIR}/agent.err
NoNewPrivileges=false
ProtectSystem=false

[Install]
WantedBy=multi-user.target
EOF
    chmod 0644 "$SERVICE_FILE"
    log "Wrote ${SERVICE_FILE}"
}

enable_and_start() {
    log "Reloading systemd..."
    systemctl stop sentinel-agent.service 2>/dev/null || true
    systemctl disable sentinel-agent.service 2>/dev/null || true
    systemctl daemon-reload
    sleep 1

    systemctl enable sentinel-agent.service >/dev/null
    systemctl daemon-reload
    systemctl restart sentinel-agent.service

    sleep 3
    if systemctl is-active --quiet sentinel-agent.service; then
        log "sentinel-agent service is running."
    else
        warn "Service did NOT start cleanly. Last 20 log lines:"
        journalctl -u sentinel-agent.service -n 20 --no-pager || true
        if [ -f "${LOG_DIR}/agent.err" ]; then
            warn "Error log:"
            tail -20 "${LOG_DIR}/agent.err"
        fi
        exit 1
    fi
}

print_done() {
    cat <<EOF

============================================================
  Sentinel Agent installed.

  Status:       systemctl status sentinel-agent
  Logs (live):  journalctl -u sentinel-agent -f
  Logs (file):  ${LOG_DIR}/agent.log
  Error log:    ${LOG_DIR}/agent.err
  Config file:  ${ENV_FILE}
  Binary:       ${BINARY_PATH}

  Connected to: ${SERVER_IP}
  Agent name:   ${AGENT_NAME}
  Group name:   ${GROUP_NAME:-none}

  To uninstall:
      curl -fsSL http://${SERVER_IP}:8000/api/v1/scripts/setup.sh | sudo bash -s -- --uninstall
============================================================
EOF
}

# --- uninstall path --------------------------------------------------------

uninstall() {
    log "Stopping service..."
    systemctl stop    sentinel-agent.service 2>/dev/null || true
    systemctl disable sentinel-agent.service 2>/dev/null || true

    rm -f "$SERVICE_FILE"
    rm -f "$BINARY_PATH"
    systemctl daemon-reload

    # Leave .env and logs in place by default
    # Uncomment for fully clean uninstall:
    # rm -rf "$CONFIG_DIR"
    # rm -rf "$LOG_DIR"

    log "Sentinel Agent uninstalled."
    log "Config left at ${CONFIG_DIR} and logs at ${LOG_DIR} (delete manually if not needed)."
}

# --- main ------------------------------------------------------------------

parse_args "$@"
require_root
require_linux
require_systemd

if [ "$ACTION" = "uninstall" ]; then
    uninstall
    exit 0
fi

prompt_if_missing
download_binary
write_env
write_service
enable_and_start
print_done