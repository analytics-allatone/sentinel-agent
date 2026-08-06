#!/usr/bin/env bash
#
# setup-all.sh — one-shot stack bring-up:
#   Docker (install if missing) -> network -> PostgreSQL -> Mosquitto (MQTT)
#   -> download + build + run your application. All on one shared network.
#
# Everything is hardcoded below. No arguments. Just:  ./setup-all.sh
#
# The app zip is streamed into memory (never saved) and extracted into an
# ephemeral dir wiped on exit. Postgres/MQTT data live in named volumes;
# Mosquitto config lives in ./mosquitto (kept, since the broker needs it).
#
set -euo pipefail

# ============================ CONFIG (edit these) ============================
# Shared network
NETWORK="sentinel-net"

# --- PostgreSQL ---
PG_CONTAINER="sentineldb"
PG_USER="dbmasteruser"
PG_PASS="dbmasterpassword"
PG_DB="productiondb"
PG_PORT="5432"
PG_IMAGE="postgres:16"
PG_VOLUME="sentinel_pgdata"

# --- Mosquitto (MQTT) ---
MQTT_CONTAINER="sentinel-mqtt"
MQTT_USER="mqttmasteruser"
MQTT_PASS="mqttmasterpassword"
MQTT_PORT="1883"
MQTT_WS_PORT="9001"
MQTT_IMAGE="eclipse-mosquitto:2"
MQTT_DATA_VOL="sentinel_mqtt_data"
MQTT_LOG_VOL="sentinel_mqtt_log"
MQTT_DIR="$(pwd)/mosquitto"
MQTT_CONFIG_DIR="${MQTT_DIR}/config"

# --- Application ---
ZIP_URL="https://REPLACE-WITH-YOUR-URL/code.zip"   # <-- set your zip URL here
APP_IMAGE="sentinel-api"
APP_CONTAINER="sentinel-api"
APP_PORT="8000"
APP_MODULE="main:app"
# =============================================================================

log()  { printf '\n\033[1;32m[+] %s\033[0m\n' "$*"; }
warn() { printf '\n\033[1;33m[!] %s\033[0m\n' "$*"; }
err()  { printf '\n\033[1;31m[x] %s\033[0m\n' "$*" >&2; }

# --- ephemeral workspace for app source, wiped on exit ---
WORK="$(mktemp -d)"
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT INT TERM

# --- sudo helper for install steps ---
if [ "$(id -u)" -eq 0 ]; then SUDO=""
elif command -v sudo >/dev/null 2>&1; then SUDO="sudo"
else SUDO=""; fi

# ----------------------------- Docker install --------------------------------
install_docker() {
  if command -v docker >/dev/null 2>&1; then
    log "Docker already installed: $(docker --version)"
  else
    log "Docker not found — installing via https://get.docker.com ..."
    if command -v curl >/dev/null 2>&1; then
      curl -fsSL https://get.docker.com -o /tmp/get-docker.sh
    elif command -v wget >/dev/null 2>&1; then
      wget -qO /tmp/get-docker.sh https://get.docker.com
    else
      err "Neither curl nor wget is available. Install one and re-run."; exit 1
    fi
    $SUDO sh /tmp/get-docker.sh
    rm -f /tmp/get-docker.sh
  fi
  if command -v systemctl >/dev/null 2>&1; then
    $SUDO systemctl enable docker >/dev/null 2>&1 || true
    $SUDO systemctl start  docker >/dev/null 2>&1 || true
  fi
}

wait_and_pick_docker() {
  log "Waiting for the Docker daemon..."
  for _ in $(seq 1 30); do
    if docker info >/dev/null 2>&1; then
      DOCKER() { docker "$@"; }; log "Docker engine is ready."; return 0
    fi
    if [ -n "$SUDO" ] && $SUDO docker info >/dev/null 2>&1; then
      DOCKER() { $SUDO docker "$@"; }; log "Docker engine is ready (via sudo)."; return 0
    fi
    sleep 2
  done
  err "Docker daemon did not become ready."; exit 1
}

ensure_network() {
  if DOCKER network inspect "$NETWORK" >/dev/null 2>&1; then
    log "Network '${NETWORK}' already exists."
  else
    DOCKER network create "$NETWORK" >/dev/null
    log "Created network '${NETWORK}'."
  fi
}

recreate() {  # $1 = container name
  if DOCKER ps -a --format '{{.Names}}' | grep -qx "$1"; then
    warn "Removing existing container: $1"
    DOCKER rm -f "$1" >/dev/null
  fi
}

# ------------------------------- PostgreSQL ----------------------------------
run_postgres() {
  log "Pulling ${PG_IMAGE} ..."; DOCKER pull "$PG_IMAGE"
  recreate "$PG_CONTAINER"
  DOCKER volume create "$PG_VOLUME" >/dev/null
  DOCKER run -d \
    --name "$PG_CONTAINER" \
    --restart unless-stopped \
    --network "$NETWORK" \
    -e POSTGRES_USER="$PG_USER" \
    -e POSTGRES_PASSWORD="$PG_PASS" \
    -e POSTGRES_DB="$PG_DB" \
    -p "${PG_PORT}:5432" \
    -v "${PG_VOLUME}:/var/lib/postgresql/data" \
    "$PG_IMAGE" >/dev/null
  log "PostgreSQL container '${PG_CONTAINER}' started."
}

wait_postgres() {
  log "Waiting for PostgreSQL to accept connections..."
  for _ in $(seq 1 30); do
    if DOCKER exec "$PG_CONTAINER" pg_isready -U "$PG_USER" -d "$PG_DB" >/dev/null 2>&1; then
      log "PostgreSQL is ready."; return 0
    fi
    sleep 2
  done
  warn "Could not confirm PostgreSQL readiness — check: docker logs ${PG_CONTAINER}"
}

# -------------------------------- Mosquitto ----------------------------------
setup_mosquitto() {
  mkdir -p "$MQTT_CONFIG_DIR"
  cat > "${MQTT_CONFIG_DIR}/mosquitto.conf" <<EOF
persistence true
persistence_location /mosquitto/data/
log_dest file /mosquitto/log/mosquitto.log
log_dest stdout

listener ${MQTT_PORT} 0.0.0.0
protocol mqtt

listener ${MQTT_WS_PORT} 0.0.0.0
protocol websockets

allow_anonymous false
password_file /mosquitto/config/passwordfile
EOF
  log "Pulling ${MQTT_IMAGE} ..."; DOCKER pull "$MQTT_IMAGE"
  log "Generating MQTT password file for user '${MQTT_USER}'..."
  DOCKER run --rm --entrypoint mosquitto_passwd \
    -v "${MQTT_CONFIG_DIR}:/mosquitto/config" \
    "$MQTT_IMAGE" -b -c /mosquitto/config/passwordfile "$MQTT_USER" "$MQTT_PASS"
  $SUDO chmod 0644 "${MQTT_CONFIG_DIR}/passwordfile" 2>/dev/null \
    || chmod 0644 "${MQTT_CONFIG_DIR}/passwordfile" 2>/dev/null || true
}

run_mosquitto() {
  recreate "$MQTT_CONTAINER"
  DOCKER volume create "$MQTT_DATA_VOL" >/dev/null
  DOCKER volume create "$MQTT_LOG_VOL"  >/dev/null
  DOCKER run -d \
    --name "$MQTT_CONTAINER" \
    --restart unless-stopped \
    --network "$NETWORK" \
    -p "${MQTT_PORT}:1883" \
    -p "${MQTT_WS_PORT}:9001" \
    -v "${MQTT_CONFIG_DIR}:/mosquitto/config" \
    -v "${MQTT_DATA_VOL}:/mosquitto/data" \
    -v "${MQTT_LOG_VOL}:/mosquitto/log" \
    "$MQTT_IMAGE" >/dev/null
  log "Mosquitto (MQTT) container '${MQTT_CONTAINER}' started."
}

# ------------------------------- Application ---------------------------------
deploy_app() {
  if [ -z "$ZIP_URL" ] || [ "$ZIP_URL" = "https://REPLACE-WITH-YOUR-URL/code.zip" ]; then
    err "Edit ZIP_URL at the top of the script and set your real zip URL."; exit 1
  fi

  log "Downloading and extracting app (in-memory, no zip saved) ..."
  if command -v curl >/dev/null 2>&1; then FETCH=(curl -fsSL "$ZIP_URL")
  elif command -v wget >/dev/null 2>&1; then FETCH=(wget -qO- "$ZIP_URL")
  else err "Neither curl nor wget is available."; exit 1; fi

  if command -v python3 >/dev/null 2>&1; then
    "${FETCH[@]}" | python3 -c "import sys,io,zipfile; zipfile.ZipFile(io.BytesIO(sys.stdin.buffer.read())).extractall('$WORK')"
  else
    warn "python3 not found — buffering the zip inside the ephemeral dir."
    "${FETCH[@]}" > "$WORK/.code.zip"
    ( cd "$WORK" && unzip -q .code.zip && rm -f .code.zip )
  fi

  # build context (descend into a lone top-level folder)
  CTX="$WORK"
  entries=$(find "$WORK" -mindepth 1 -maxdepth 1 | wc -l)
  lone_dir=$(find "$WORK" -mindepth 1 -maxdepth 1 -type d | head -n1)
  if [ "$entries" -eq 1 ] && [ -n "$lone_dir" ]; then CTX="$lone_dir"; fi

  if [ -f "$CTX/Dockerfile" ]; then
    log "Using the project's own Dockerfile."
  else
    warn "No Dockerfile found — generating the project's multi-stage Dockerfile."
    for expected in requirements.txt src frontend; do
      [ -e "$CTX/$expected" ] || warn "Expected '$expected' not found — the build may fail."
    done
    cat > "$CTX/Dockerfile" <<EOF
FROM node:20-alpine AS frontend-build
WORKDIR /app/frontend
COPY frontend/package*.json ./
RUN npm install
COPY frontend/ ./
RUN npm run build


FROM python:3.12-slim

# Python optimizations
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Install only system deps (keep minimal)
RUN apt-get update && apt-get install -y gcc \\
    && rm -rf /var/lib/apt/lists/*

# Copy only requirements first (best caching)
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir --upgrade pip && \\
    pip install --no-cache-dir -r requirements.txt

# Copy source code separately
COPY src/ ./src
COPY agent/ ./agent

# Bring in the built frontend, then work from src (imports like main:app)
COPY --from=frontend-build /app/frontend/build ./frontend/build
WORKDIR /app/src

EXPOSE ${APP_PORT}

CMD ["uvicorn", "${APP_MODULE}", "--host", "0.0.0.0", "--port", "${APP_PORT}"]
EOF
  fi

  log "Building app image '${APP_IMAGE}' ..."
  DOCKER build -t "$APP_IMAGE" "$CTX"

  recreate "$APP_CONTAINER"
  ENV_ARGS=()
  if [ -f "$CTX/.env" ]; then ENV_ARGS=(--env-file "$CTX/.env"); log "Using bundled .env"; fi

  log "Starting app container '${APP_CONTAINER}' ..."
  DOCKER run -d \
    --name "$APP_CONTAINER" \
    --restart unless-stopped \
    --network "$NETWORK" \
    -p "${APP_PORT}:${APP_PORT}" \
    "${ENV_ARGS[@]}" \
    "$APP_IMAGE" >/dev/null
  log "App container '${APP_CONTAINER}' started."
}

# --------------------------------- Summary -----------------------------------
summary() {
  cat <<EOF

============================================================
  STACK IS UP  (network: ${NETWORK})
============================================================
PostgreSQL   container ${PG_CONTAINER}
  external : postgresql+asyncpg://${PG_USER}:${PG_PASS}@localhost:${PG_PORT}/${PG_DB}
  in-app   : postgresql+asyncpg://${PG_USER}:${PG_PASS}@${PG_CONTAINER}:5432/${PG_DB}

MQTT         container ${MQTT_CONTAINER}
  external : localhost:${MQTT_PORT}   (ws: ${MQTT_WS_PORT})   ${MQTT_USER}/${MQTT_PASS}
  in-app   : ${MQTT_CONTAINER}:1883

Application  container ${APP_CONTAINER}
  URL      : http://localhost:${APP_PORT}
  logs     : docker logs -f ${APP_CONTAINER}

Your app should reach the DB/broker by CONTAINER NAME (in-app URLs above),
not localhost. All containers use --restart unless-stopped.
============================================================
EOF
}

main() {
  install_docker
  wait_and_pick_docker
  ensure_network
  run_postgres
  setup_mosquitto
  run_mosquitto
  wait_postgres
  deploy_app
  summary
}
main "$@"
