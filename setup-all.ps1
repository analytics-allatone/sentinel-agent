#requires -Version 5.1
<#
  setup-dind.ps1 - runs the whole sentinel stack INSIDE a Docker-in-Docker container.

  Host sees exactly one container: sentinel-dind
  Nested inside it: sentineldb, sentinel-mqtt, sentinel-grafana, sentinel-api

  Ports are published on the OUTER container, so http://localhost:3000 etc.
  still work from the host. Requires --privileged.

  Run:  .\setup-dind.ps1
        .\setup-dind.ps1 -Url https://your-host/code.zip
#>

[CmdletBinding()]
param(
    [string]$Url = ''
)

$ErrorActionPreference = 'Continue'

# ============================ CONFIG ============================
$DindContainer = 'sentinel-dind'
$DindImage     = 'docker:27-dind'
$DindLibVol    = 'sentinel_dind_lib'   # inner /var/lib/docker (images + volumes)

# Host ports -> published on the DinD container
$PgPort     = 5432
$MqttPort   = 1883
$MqttWsPort = 9001
$GrafPort   = 3000
$AppPort    = 8000

$InnerScript = Join-Path $PSScriptRoot 'stack-inside.sh'
# ===============================================================

function Log($m)  { Write-Host "[+] $m" -ForegroundColor Green }
function Warn($m) { Write-Host "[!] $m" -ForegroundColor Yellow }
function Err($m)  { Write-Host "[x] $m" -ForegroundColor Red }
function Reset-Exit { $global:LASTEXITCODE = 1 }

function Assert-HostDocker {
    Reset-Exit
    docker info *> $null
    if ($LASTEXITCODE -ne 0) { Err "Host Docker is not running. Start Docker Desktop and re-run."; exit 1 }
    if ((docker info --format '{{.OSType}}') -ne 'linux') {
        Err "Docker is in Windows-container mode. Switch to Linux containers and re-run."; exit 1
    }
    Log "Host Docker ready: $(docker --version)"
}

function Start-Dind {
    Reset-Exit
    docker inspect $DindContainer *> $null
    if ($LASTEXITCODE -eq 0) { Warn "Removing existing $DindContainer"; docker rm -f $DindContainer | Out-Null }

    Log "Pulling $DindImage ..."; docker pull $DindImage
    if ($LASTEXITCODE -ne 0) { Err "Failed to pull $DindImage."; exit 1 }

    docker volume create $DindLibVol | Out-Null

    # DOCKER_TLS_CERTDIR="" -> inner daemon on the unix socket only, no cert dance.
    # The inner daemon is never exposed outside this container.
    docker run -d --name $DindContainer --restart unless-stopped --privileged `
        -e "DOCKER_TLS_CERTDIR=" `
        -p "$($PgPort):5432" `
        -p "$($MqttPort):1883" `
        -p "$($MqttWsPort):9001" `
        -p "$($GrafPort):3000" `
        -p "$($AppPort):8000" `
        -v "$($DindLibVol):/var/lib/docker" `
        $DindImage | Out-Null
    if ($LASTEXITCODE -ne 0) { Err "Failed to start $DindContainer (ports in use?)."; exit 1 }
    Log "DinD container '$DindContainer' started."
}

function Wait-InnerDaemon {
    Log "Waiting for the inner Docker daemon..."
    for ($i = 0; $i -lt 40; $i++) {
        Reset-Exit
        docker exec $DindContainer docker info *> $null
        if ($LASTEXITCODE -eq 0) { Log "Inner Docker daemon is ready."; return }
        Start-Sleep -Seconds 3
    }
    Err "Inner daemon did not come up. Check: docker logs $DindContainer"
    exit 1
}

function Invoke-InnerStack {
    if (-not (Test-Path $InnerScript)) {
        Err "stack-inside.sh not found next to this script ($InnerScript)."
        exit 1
    }
    # Normalise to LF - sh will not run a CRLF script.
    $sh = [System.IO.File]::ReadAllText($InnerScript) -replace "`r`n", "`n"
    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("stack_" + [guid]::NewGuid().ToString('N') + ".sh")
    [System.IO.File]::WriteAllText($tmp, $sh, (New-Object System.Text.UTF8Encoding($false)))
    try {
        docker cp $tmp "$($DindContainer):/stack-inside.sh" | Out-Null
        docker exec $DindContainer chmod +x /stack-inside.sh | Out-Null
        Log "Running the stack inside '$DindContainer' ..."
        if ($Url) { docker exec -e "ZIP_URL=$Url" $DindContainer sh /stack-inside.sh }
        else       { docker exec $DindContainer sh /stack-inside.sh }
        if ($LASTEXITCODE -ne 0) { Err "Inner stack script failed with exit code $LASTEXITCODE."; exit 1 }
    } finally {
        Remove-Item -Force $tmp -ErrorAction SilentlyContinue
    }
}

function Show-Summary {
    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "  STACK IS UP INSIDE '$DindContainer'" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "From the HOST:"
    Write-Host "  Postgres : localhost:$PgPort"
    Write-Host "  MQTT     : localhost:$MqttPort   (ws: $MqttWsPort)"
    Write-Host "  Grafana  : http://localhost:$GrafPort"
    if ($Url) { Write-Host "  App      : http://localhost:$AppPort" }
    Write-Host ""
    Write-Host "Inner containers:"
    docker exec $DindContainer docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'
    Write-Host ""
    Write-Host "Talk to the inner daemon with:  docker exec $DindContainer docker <cmd>"
    Write-Host "============================================================" -ForegroundColor Cyan
}

Assert-HostDocker
Start-Dind
Wait-InnerDaemon
Invoke-InnerStack
Show-Summary

#!/bin/sh
# stack-inside.sh - runs INSIDE the DinD container. POSIX sh (no bash in docker:dind).
# Brings up: network -> PostgreSQL -> Mosquitto -> Grafana -> optional app.
# Set ZIP_URL in the environment to also build and run the app.
set -eu

# ============================ CONFIG ============================
NETWORK="sentinel-net"

PG_CONTAINER="sentineldb"
PG_USER="dbmasteruser"
PG_PASS="dbmasterpassword"
PG_DB="productiondb"
PG_IMAGE="postgres:16"
PG_VOLUME="sentinel_pgdata"

MQTT_CONTAINER="sentinel-mqtt"
MQTT_USER="mqttmasteruser"
MQTT_PASS="mqttmasterpassword"
MQTT_IMAGE="eclipse-mosquitto:2"
MQTT_DATA_VOL="sentinel_mqtt_data"
MQTT_LOG_VOL="sentinel_mqtt_log"
MQTT_CONFIG_DIR="/srv/sentinel/mosquitto/config"

GRAF_CONTAINER="sentinel-grafana"
GRAF_USER="admin"
GRAF_PASS="grafanamasterpassword"
GRAF_IMAGE="grafana/grafana-oss:11.1.0"
GRAF_VOLUME="sentinel_grafana_data"
GRAF_DS_DIR="/srv/sentinel/grafana/provisioning/datasources"

APP_IMAGE="sentinel-api"
APP_CONTAINER="sentinel-api"
APP_PORT="8000"
APP_MODULE="main:app"
ZIP_URL="${ZIP_URL:-}"
# ================================================================

log()  { printf '\n\033[1;32m[+] %s\033[0m\n' "$*"; }
warn() { printf '\n\033[1;33m[!] %s\033[0m\n' "$*"; }
err()  { printf '\n\033[1;31m[x] %s\033[0m\n' "$*" >&2; }

recreate() { docker rm -f "$1" >/dev/null 2>&1 || true; }

# --------------------------- network ----------------------------
if docker network inspect "$NETWORK" >/dev/null 2>&1; then
  log "Network '${NETWORK}' already exists."
else
  docker network create "$NETWORK" >/dev/null
  log "Created network '${NETWORK}'."
fi

# -------------------------- PostgreSQL --------------------------
log "Pulling ${PG_IMAGE} ..."; docker pull "$PG_IMAGE"
recreate "$PG_CONTAINER"
docker volume create "$PG_VOLUME" >/dev/null
docker run -d \
  --name "$PG_CONTAINER" \
  --restart unless-stopped \
  --network "$NETWORK" \
  -e POSTGRES_USER="$PG_USER" \
  -e POSTGRES_PASSWORD="$PG_PASS" \
  -e POSTGRES_DB="$PG_DB" \
  -p 5432:5432 \
  -v "${PG_VOLUME}:/var/lib/postgresql/data" \
  "$PG_IMAGE" >/dev/null
log "PostgreSQL container '${PG_CONTAINER}' started."

# --------------------------- Mosquitto --------------------------
mkdir -p "$MQTT_CONFIG_DIR"
cat > "${MQTT_CONFIG_DIR}/mosquitto.conf" <<'EOF'
persistence true
persistence_location /mosquitto/data/
log_dest file /mosquitto/log/mosquitto.log
log_dest stdout

listener 1883 0.0.0.0
protocol mqtt

listener 9001 0.0.0.0
protocol websockets

allow_anonymous false
password_file /mosquitto/config/passwordfile
EOF

log "Pulling ${MQTT_IMAGE} ..."; docker pull "$MQTT_IMAGE"
log "Generating MQTT password file for user '${MQTT_USER}'..."
docker run --rm --entrypoint mosquitto_passwd \
  -v "${MQTT_CONFIG_DIR}:/mosquitto/config" \
  "$MQTT_IMAGE" -b -c /mosquitto/config/passwordfile "$MQTT_USER" "$MQTT_PASS"
chmod 0644 "${MQTT_CONFIG_DIR}/passwordfile"

recreate "$MQTT_CONTAINER"
docker volume create "$MQTT_DATA_VOL" >/dev/null
docker volume create "$MQTT_LOG_VOL"  >/dev/null
docker run -d \
  --name "$MQTT_CONTAINER" \
  --restart unless-stopped \
  --network "$NETWORK" \
  -p 1883:1883 \
  -p 9001:9001 \
  -v "${MQTT_CONFIG_DIR}:/mosquitto/config" \
  -v "${MQTT_DATA_VOL}:/mosquitto/data" \
  -v "${MQTT_LOG_VOL}:/mosquitto/log" \
  "$MQTT_IMAGE" >/dev/null
sleep 3
if [ "$(docker inspect -f '{{.State.Running}}' "$MQTT_CONTAINER")" != "true" ]; then
  err "Mosquitto exited immediately:"; docker logs --tail 30 "$MQTT_CONTAINER"; exit 1
fi
log "Mosquitto (MQTT) container '${MQTT_CONTAINER}' started."

# ------------------------ wait for Postgres ---------------------
log "Waiting for PostgreSQL to accept connections..."
i=0
while [ "$i" -lt 30 ]; do
  if docker exec "$PG_CONTAINER" pg_isready -U "$PG_USER" -d "$PG_DB" >/dev/null 2>&1; then
    log "PostgreSQL is ready."; break
  fi
  i=$((i + 1)); sleep 2
done
[ "$i" -lt 30 ] || warn "Could not confirm PostgreSQL readiness."

# ---------------------------- Grafana ---------------------------
mkdir -p "$GRAF_DS_DIR"
cat > "${GRAF_DS_DIR}/sentineldb.yaml" <<EOF
apiVersion: 1
datasources:
  - name: SentinelDB
    type: postgres
    access: proxy
    url: ${PG_CONTAINER}:5432
    database: ${PG_DB}
    user: ${PG_USER}
    isDefault: true
    editable: true
    secureJsonData:
      password: ${PG_PASS}
    jsonData:
      sslmode: disable
      postgresVersion: 1600
EOF

log "Pulling ${GRAF_IMAGE} ..."; docker pull "$GRAF_IMAGE"
recreate "$GRAF_CONTAINER"
docker volume create "$GRAF_VOLUME" >/dev/null
docker run -d \
  --name "$GRAF_CONTAINER" \
  --restart unless-stopped \
  --network "$NETWORK" \
  -e GF_SECURITY_ADMIN_USER="$GRAF_USER" \
  -e GF_SECURITY_ADMIN_PASSWORD="$GRAF_PASS" \
  -e GF_USERS_ALLOW_SIGN_UP=false \
  -p 3000:3000 \
  -v "${GRAF_VOLUME}:/var/lib/grafana" \
  -v "${GRAF_DS_DIR}:/etc/grafana/provisioning/datasources" \
  "$GRAF_IMAGE" >/dev/null
log "Grafana container '${GRAF_CONTAINER}' started."

# -------------------------- Application -------------------------
if [ -n "$ZIP_URL" ]; then
  command -v curl  >/dev/null 2>&1 || apk add --no-cache curl  >/dev/null
  command -v unzip >/dev/null 2>&1 || apk add --no-cache unzip >/dev/null

  WORK="$(mktemp -d)"
  trap 'rm -rf "$WORK"' EXIT INT TERM

  log "Downloading and extracting app ..."
  curl -fsSL "$ZIP_URL" -o "$WORK/code.zip"
  ( cd "$WORK" && unzip -q code.zip && rm -f code.zip )

  CTX="$WORK"
  entries=$(find "$WORK" -mindepth 1 -maxdepth 1 ! -name '__MACOSX' | wc -l)
  lone_dir=$(find "$WORK" -mindepth 1 -maxdepth 1 -type d ! -name '__MACOSX' | head -n1)
  if [ "$entries" -eq 1 ] && [ -n "$lone_dir" ]; then CTX="$lone_dir"; fi

  if [ -f "$CTX/Dockerfile" ]; then
    log "Using the project's own Dockerfile."
  else
    warn "No Dockerfile found - generating the multi-stage Dockerfile."
    cat > "$CTX/Dockerfile" <<EOF
FROM node:20-alpine AS frontend-build
WORKDIR /app/frontend
COPY frontend/package*.json ./
RUN npm install
COPY frontend/ ./
RUN npm run build


FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update && apt-get install -y gcc \\
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

RUN pip install --no-cache-dir --upgrade pip && \\
    pip install --no-cache-dir -r requirements.txt

COPY src/ ./src
COPY agent/ ./agent

COPY --from=frontend-build /app/frontend/build ./frontend/build
WORKDIR /app/src

EXPOSE ${APP_PORT}

CMD ["uvicorn", "${APP_MODULE}", "--host", "0.0.0.0", "--port", "${APP_PORT}"]
EOF
  fi

  log "Building app image '${APP_IMAGE}' ..."
  docker build -t "$APP_IMAGE" "$CTX"

  recreate "$APP_CONTAINER"
  if [ -f "$CTX/.env" ]; then
    log "Using bundled .env"
    docker run -d --name "$APP_CONTAINER" --restart unless-stopped \
      --network "$NETWORK" -p "${APP_PORT}:${APP_PORT}" \
      --env-file "$CTX/.env" "$APP_IMAGE" >/dev/null
  else
    warn "No .env in the archive - injecting default DB/MQTT settings."
    docker run -d --name "$APP_CONTAINER" --restart unless-stopped \
      --network "$NETWORK" -p "${APP_PORT}:${APP_PORT}" \
      -e DATABASE_URL="postgresql+asyncpg://${PG_USER}:${PG_PASS}@${PG_CONTAINER}:5432/${PG_DB}" \
      -e MQTT_HOST="$MQTT_CONTAINER" \
      -e MQTT_PORT=1883 \
      -e MQTT_USERNAME="$MQTT_USER" \
      -e MQTT_PASSWORD="$MQTT_PASS" \
      "$APP_IMAGE" >/dev/null
  fi

  sleep 3
  if [ "$(docker inspect -f '{{.State.Running}}' "$APP_CONTAINER")" = "true" ]; then
    log "App container '${APP_CONTAINER}' started."
  else
    warn "App container exited immediately:"; docker logs --tail 40 "$APP_CONTAINER"
  fi
else
  warn "ZIP_URL not set - skipping the app deploy."
fi

log "Inner stack complete."
docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'