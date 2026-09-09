#!/usr/bin/env bash
set -euo pipefail

# === CHANGE THESE FOR YOUR ENVIRONMENT ====================================
DOWNLOAD_URL="https://YOUR_HOST/api/v1/binaries/linux_agent"
EXPECTED_SHA256=""   # optional: pin a build, leave empty to skip
# ==========================================================================

BINARY_PATH="/usr/local/bin/sentinel-agent"
CONFIG_DIR="/etc/sentinel-agent"
ENV_FILE="${CONFIG_DIR}/.env"
SERVICE_FILE="/etc/systemd/system/sentinel-agent.service"
LOG_DIR="/var/log/sentinel-agent"
RUNTIME_DIR="/var/lib/sentinel-agent"          # PyInstaller unpacks here

SERVER_IP=""
AGENT_NAME=""
GROUP_NAME=""
ACTION="install"
TMP_BASE=""

log()  { printf "\033[1;32m[+]\033[0m %s\n" "$*"; }
warn() { printf "\033[1;33m[!]\033[0m %s\n" "$*"; }
err()  { printf "\033[1;31m[x]\033[0m %s\n" "$*" >&2; }
die()  { err "$*"; exit 1; }

require_root()    { [ "$(id -u)" -eq 0 ] || die "Run as root (use sudo)."; }
require_linux()   { [ "$(uname -s)" = "Linux" ] || die "This installer is Linux only."; }
require_systemd() { command -v systemctl >/dev/null 2>&1 || die "systemd not found."; }

parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            --server-ip)  SERVER_IP="$2";  shift 2 ;;
            --agent-name) AGENT_NAME="$2"; shift 2 ;;
            --group-name) GROUP_NAME="$2"; shift 2 ;;
            --uninstall)  ACTION="uninstall"; shift ;;
            -h|--help)    sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
            *) die "Unknown argument: $1" ;;
        esac
    done
}

prompt_if_missing() {
    if [ -z "$SERVER_IP" ]; then
        if [ -t 0 ]; then read -r -p "Server IP: " SERVER_IP
        else die "SERVER_IP not given and stdin is not a terminal. Use --server-ip <ip>."; fi
    fi
    if [ -z "$AGENT_NAME" ]; then
        local d; d="$(hostname)"
        if [ -t 0 ]; then read -r -p "Agent name [${d}]: " AGENT_NAME; AGENT_NAME="${AGENT_NAME:-$d}"
        else AGENT_NAME="$d"; log "Using hostname as agent name: ${AGENT_NAME}"; fi
    fi
    [ -n "$SERVER_IP" ]  || die "Server IP is required."
    [ -n "$AGENT_NAME" ] || die "Agent name is required."
}

# --- the fix: find a directory we can actually execute from ----------------
#
# A --onefile binary unpacks its bundled .so files to $TMPDIR and mmaps them
# with PROT_EXEC. On a hardened host /tmp is mounted noexec, the kernel
# refuses the mapping, and the binary dies with
#   "error while loading shared libraries: ...: failed to map segment"
# before Python ever starts. root does NOT override a noexec mount.
#
# Rather than parse mount options (which misses SELinux and other causes),
# write a real script and try to run it.

can_exec() {
    local dir="$1" probe
    mkdir -p "$dir" 2>/dev/null || return 1
    probe="${dir}/.exec-probe.$$"
    printf '#!/bin/sh\nexit 0\n' > "$probe" 2>/dev/null || return 1
    chmod +x "$probe" 2>/dev/null || { rm -f "$probe"; return 1; }
    if "$probe" >/dev/null 2>&1; then rm -f "$probe"; return 0; fi
    rm -f "$probe"; return 1
}

pick_tmpdir() {
    local candidates=("${RUNTIME_DIR}/tmp" "/opt/sentinel-agent/tmp" "/usr/local/lib/sentinel-agent/tmp")
    for d in "${candidates[@]}"; do
        if can_exec "$d"; then
            chmod 700 "$d"; chown root:root "$d"
            TMP_BASE="$d"
            log "Extraction directory: ${TMP_BASE} (verified executable)"
            return 0
        fi
        warn "Cannot execute from ${d}, trying next..."
    done
    die "No writable+executable directory found. Every candidate is noexec.
     Pick a partition without noexec and set RUNTIME_DIR at the top of this script,
     or rebuild the agent with --onedir so nothing is extracted at runtime."
}

remove_stale_installs() {
    # An older install left a binary in the config dir; its unit may still exist.
    for stale in "${CONFIG_DIR}/sentinel-agent" "/usr/bin/sentinel-agent" "/opt/sentinel-agent/sentinel-agent"; do
        if [ -e "$stale" ] && [ "$stale" != "$BINARY_PATH" ]; then
            rm -f "$stale"; warn "Removed stale binary: ${stale}"
        fi
    done
    # the old installer copied the secret-bearing .env next to the binary,
    # in a world-readable directory
    if [ -e "$(dirname "$BINARY_PATH")/.env" ]; then
        rm -f "$(dirname "$BINARY_PATH")/.env"
        warn "Removed world-readable .env copy from $(dirname "$BINARY_PATH")"
    fi
}

download_binary() {
    local url="${DOWNLOAD_URL}?agent_name=${AGENT_NAME}&group_name=${GROUP_NAME}"
    log "Downloading agent from ${url}"
    local tmp; tmp="$(mktemp)"
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$url" -o "$tmp" || die "Download failed. Check the URL or your network."
    elif command -v wget >/dev/null 2>&1; then
        wget -q "$url" -O "$tmp"    || die "Download failed. Check the URL or your network."
    else
        die "Neither curl nor wget is available."
    fi

    [ -s "$tmp" ] || { rm -f "$tmp"; die "Downloaded file is empty."; }

    if [ -n "$EXPECTED_SHA256" ]; then
        local got; got="$(sha256sum "$tmp" | awk '{print $1}')"
        [ "$got" = "$EXPECTED_SHA256" ] || { rm -f "$tmp"; die "SHA-256 mismatch: expected ${EXPECTED_SHA256}, got ${got}."; }
        log "SHA-256 verified."
    fi

    install -m 0755 -o root -g root "$tmp" "$BINARY_PATH"
    rm -f "$tmp"
    log "Installed binary at ${BINARY_PATH}"
}

# Catch loader failures HERE, at install time, instead of in a log file later.
smoke_test() {
    log "Smoke-testing the binary..."
    local out rc=0
    out="$(TMPDIR="$TMP_BASE" timeout 20 "$BINARY_PATH" --version 2>&1)" || rc=$?

    if printf '%s' "$out" | grep -q "error while loading shared libraries"; then
        err "The binary cannot load its bundled libraries:"
        printf '    %s\n' "$out" >&2
        die "Extraction directory is still not executable. Rebuild with --onedir."
    fi
    # rc 124 = timeout (it started and kept running: fine, it has no --version)
    # any other rc with no loader error is also fine; the service will report real errors
    log "Binary starts correctly."
}

write_env() {
    mkdir -p "$CONFIG_DIR"
    cat > "$ENV_FILE" <<EOF
# Sentinel Agent configuration - written by installer on $(date -u +%FT%TZ)
SERVER_IP=${SERVER_IP}
AGENT_NAME=${AGENT_NAME}
GROUP_NAME=${GROUP_NAME}
EOF
    chmod 600 "$ENV_FILE"; chown root:root "$ENV_FILE"
    log "Wrote ${ENV_FILE} (mode 0600, root-only)"
}

write_service() {
    mkdir -p "$LOG_DIR"
    cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Sentinel security agent
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
User=root
WorkingDirectory=${CONFIG_DIR}
EnvironmentFile=${ENV_FILE}

# Executable scratch space for the --onefile bundle. Without this the agent
# dies at startup on hosts where /tmp is mounted noexec.
Environment=TMPDIR=${TMP_BASE}

# Without this, print() output is block-buffered and never reaches the log.
Environment=PYTHONUNBUFFERED=1

ExecStart=${BINARY_PATH}

Restart=always
RestartSec=5s

# --onefile means a bootloader parent plus the real child process.
# mixed = SIGTERM to the parent only, SIGKILL to stragglers after the timeout.
KillMode=mixed
TimeoutStopSec=30

StandardOutput=append:${LOG_DIR}/agent.log
StandardError=append:${LOG_DIR}/agent.err

[Install]
WantedBy=multi-user.target
EOF
    chmod 0644 "$SERVICE_FILE"
    log "Wrote ${SERVICE_FILE}"
}

write_logrotate() {
    cat > /etc/logrotate.d/sentinel-agent <<EOF
${LOG_DIR}/*.log ${LOG_DIR}/*.err {
    weekly
    rotate 4
    compress
    missingok
    notifempty
    copytruncate
}
EOF
    log "Wrote /etc/logrotate.d/sentinel-agent"
}

enable_and_start() {
    # start clean so old output can't be mistaken for new
    : > "${LOG_DIR}/agent.log" 2>/dev/null || true
    : > "${LOG_DIR}/agent.err" 2>/dev/null || true

    systemctl stop sentinel-agent.service 2>/dev/null || true
    systemctl daemon-reload
    systemctl enable sentinel-agent.service >/dev/null
    systemctl restart sentinel-agent.service

    sleep 5
    if ! systemctl is-active --quiet sentinel-agent.service; then
        warn "Service did NOT start cleanly:"
        journalctl -u sentinel-agent.service -n 20 --no-pager || true
        [ -s "${LOG_DIR}/agent.err" ] && { warn "Error log:"; tail -20 "${LOG_DIR}/agent.err"; }
        exit 1
    fi

    # active is not enough: a crash-restart loop also reports active.
    local restarts; restarts="$(systemctl show -p NRestarts --value sentinel-agent.service 2>/dev/null || echo 0)"
    if [ "${restarts:-0}" -gt 0 ]; then
        warn "Service has already restarted ${restarts} time(s) — it is crash-looping."
        tail -20 "${LOG_DIR}/agent.err" 2>/dev/null || true
        exit 1
    fi

    log "sentinel-agent service is running (no restarts)."
}

print_done() {
    cat <<EOF

============================================================
  Sentinel Agent installed.

  Status:       systemctl status sentinel-agent
  Logs (live):  tail -f ${LOG_DIR}/agent.log
  Error log:    ${LOG_DIR}/agent.err
  Config file:  ${ENV_FILE}
  Binary:       ${BINARY_PATH}
  Scratch dir:  ${TMP_BASE}

  Connected to: ${SERVER_IP}
  Agent name:   ${AGENT_NAME}
  Group name:   ${GROUP_NAME:-none}

  To uninstall:
      curl -fsSL http://${SERVER_IP}:8000/api/v1/scripts/setup.sh | sudo bash -s -- --uninstall
============================================================
EOF
}

uninstall() {
    log "Stopping service..."
    systemctl stop    sentinel-agent.service 2>/dev/null || true
    systemctl disable sentinel-agent.service 2>/dev/null || true
    rm -f "$SERVICE_FILE" "$BINARY_PATH" /etc/logrotate.d/sentinel-agent
    rm -rf "${RUNTIME_DIR}/tmp" /opt/sentinel-agent/tmp /usr/local/lib/sentinel-agent/tmp
    systemctl daemon-reload
    log "Sentinel Agent uninstalled."
    log "Config left at ${CONFIG_DIR} and logs at ${LOG_DIR} (delete manually if not needed)."
}

# --- main ------------------------------------------------------------------
parse_args "$@"
require_root
require_linux
require_systemd

if [ "$ACTION" = "uninstall" ]; then uninstall; exit 0; fi

prompt_if_missing
pick_tmpdir
remove_stale_installs
download_binary
smoke_test
write_env
write_service
write_logrotate
enable_and_start
print_done