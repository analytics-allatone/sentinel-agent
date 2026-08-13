#!/usr/bin/env bash
# postgres + mosquitto + grafana (+ optional app) on one docker network
# usage: ./setup-all.sh            ZIP_URL=https://host/code.zip ./setup-all.sh
set -euo pipefail

NET=sentinel-net
PG_USER=dbmasteruser; PG_PASS=dbmasterpassword; PG_DB=productiondb
MQ_USER=mqttmasteruser; MQ_PASS=mqttmasterpassword
GF_USER=admin; GF_PASS=grafanamasterpassword
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MQ_DIR="$DIR/mosquitto/config"; GF_DIR="$DIR/grafana/datasources"
APP_IMAGE=sentinel-api; APP_PORT=8000; APP_MODULE=main:app
ZIP_URL="${ZIP_URL:-}"

log() { printf '\033[1;32m[+] %s\033[0m\n' "$*"; }
die() { printf '\033[1;31m[x] %s\033[0m\n' "$*" >&2; exit 1; }

# --- docker ---
command -v docker >/dev/null || die "docker not installed: curl -fsSL https://get.docker.com | sh"
docker info >/dev/null 2>&1 || die "docker daemon unreachable (try: sudo usermod -aG docker \$USER, then re-login)"
docker network create "$NET" >/dev/null 2>&1 || true

# --- postgres ---
docker rm -f sentineldb >/dev/null 2>&1 || true
docker run -d --name sentineldb --restart unless-stopped --network "$NET" \
  -e POSTGRES_USER="$PG_USER" -e POSTGRES_PASSWORD="$PG_PASS" -e POSTGRES_DB="$PG_DB" \
  -p 5432:5432 -v sentinel_pgdata:/var/lib/postgresql/data postgres:16 >/dev/null
log "postgres started"

# --- mosquitto (listeners are container-internal; host ports set by -p) ---
mkdir -p "$MQ_DIR"
cat > "$MQ_DIR/mosquitto.conf" <<'EOF'
persistence true
persistence_location /mosquitto/data/
log_dest stdout
listener 1883 0.0.0.0
protocol mqtt
listener 9001 0.0.0.0
protocol websockets
allow_anonymous false
password_file /mosquitto/config/passwordfile
EOF
docker run --rm --entrypoint mosquitto_passwd -v "$MQ_DIR:/mosquitto/config" \
  eclipse-mosquitto:2 -b -c /mosquitto/config/passwordfile "$MQ_USER" "$MQ_PASS"
chmod 0644 "$MQ_DIR/passwordfile" 2>/dev/null || true
[ -s "$MQ_DIR/passwordfile" ] || die "MQTT password file not created"

docker rm -f sentinel-mqtt >/dev/null 2>&1 || true
docker run -d --name sentinel-mqtt --restart unless-stopped --network "$NET" \
  -p 1883:1883 -p 9001:9001 -v "$MQ_DIR:/mosquitto/config" \
  -v sentinel_mqtt_data:/mosquitto/data -v sentinel_mqtt_log:/mosquitto/log eclipse-mosquitto:2 >/dev/null
sleep 3
[ "$(docker inspect -f '{{.State.Running}}' sentinel-mqtt)" = true ] || {
  docker logs --tail 20 sentinel-mqtt; die "mosquitto exited"; }
log "mosquitto started"

# --- wait for postgres ---
for _ in $(seq 1 30); do
  docker exec sentineldb pg_isready -U "$PG_USER" -d "$PG_DB" >/dev/null 2>&1 && { log "postgres ready"; break; }
  sleep 2
done

# --- grafana (postgres datasource auto-provisioned) ---
mkdir -p "$GF_DIR"
cat > "$GF_DIR/sentineldb.yaml" <<EOF
apiVersion: 1
datasources:
  - name: SentinelDB
    type: postgres
    access: proxy
    url: sentineldb:5432
    database: $PG_DB
    user: $PG_USER
    isDefault: true
    secureJsonData:
      password: $PG_PASS
    jsonData:
      sslmode: disable
      postgresVersion: 1600
EOF
docker rm -f sentinel-grafana >/dev/null 2>&1 || true
docker run -d --name sentinel-grafana --restart unless-stopped --network "$NET" \
  -e GF_SECURITY_ADMIN_USER="$GF_USER" -e GF_SECURITY_ADMIN_PASSWORD="$GF_PASS" -e GF_USERS_ALLOW_SIGN_UP=false \
  -p 3000:3000 -v sentinel_grafana_data:/var/lib/grafana \
  -v "$GF_DIR:/etc/grafana/provisioning/datasources" grafana/grafana-oss:11.1.0 >/dev/null
log "grafana started"

# --- app (only if ZIP_URL set) ---
if [ -n "$ZIP_URL" ]; then
  WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT INT TERM
  curl -fsSL "$ZIP_URL" -o "$WORK/c.zip"
  ( cd "$WORK" && unzip -q c.zip && rm -f c.zip )

  CTX="$WORK"
  n=$(find "$WORK" -mindepth 1 -maxdepth 1 ! -name __MACOSX | wc -l)
  d=$(find "$WORK" -mindepth 1 -maxdepth 1 -type d ! -name __MACOSX | head -n1)
  [ "$n" -eq 1 ] && [ -n "$d" ] && CTX="$d"

  [ -f "$CTX/Dockerfile" ] || cat > "$CTX/Dockerfile" <<EOF
FROM node:20-alpine AS frontend-build
WORKDIR /app/frontend
COPY frontend/package*.json ./
RUN npm install
COPY frontend/ ./
RUN npm run build

FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
RUN apt-get update && apt-get install -y gcc && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY src/ ./src
COPY agent/ ./agent
COPY --from=frontend-build /app/frontend/build ./frontend/build
WORKDIR /app/src
EXPOSE ${APP_PORT}
CMD ["uvicorn", "${APP_MODULE}", "--host", "0.0.0.0", "--port", "${APP_PORT}"]
EOF

  docker build -t "$APP_IMAGE" "$CTX"
  if [ -f "$CTX/.env" ]; then
    ENV_ARGS=(--env-file "$CTX/.env")
  else
    ENV_ARGS=(-e "DATABASE_URL=postgresql+asyncpg://${PG_USER}:${PG_PASS}@sentineldb:5432/${PG_DB}"
              -e MQTT_HOST=sentinel-mqtt -e MQTT_PORT=1883
              -e MQTT_USERNAME="$MQ_USER" -e MQTT_PASSWORD="$MQ_PASS")
  fi
  docker rm -f sentinel-api >/dev/null 2>&1 || true
  docker run -d --name sentinel-api --restart unless-stopped --network "$NET" \
    -p "${APP_PORT}:${APP_PORT}" ${ENV_ARGS[@]+"${ENV_ARGS[@]}"} "$APP_IMAGE" >/dev/null
  sleep 3
  if [ "$(docker inspect -f '{{.State.Running}}' sentinel-api)" = true ]; then log "app started"
  else docker logs --tail 30 sentinel-api; fi
fi

cat <<EOF

postgres  localhost:5432   $PG_USER/$PG_PASS  db=$PG_DB
mqtt      localhost:1883   ws:9001   $MQ_USER/$MQ_PASS
grafana   http://localhost:3000   $GF_USER/$GF_PASS
$([ -n "$ZIP_URL" ] && echo "app       http://localhost:$APP_PORT")
in-app hosts: sentineldb:5432, sentinel-mqtt:1883
EOF

#!/usr/bin/env bash
#
# setup-dind.sh — runs the whole sentinel stack INSIDE a Docker-in-Docker container.
#
#   Host sees exactly one container:  sentinel-dind
#   Nested inside it:                 sentineldb, sentinel-mqtt, sentinel-grafana, sentinel-api
#
# Ports are published on the OUTER container, so http://localhost:3000 etc. still
# work from the host. Requires --privileged (effectively host root — dev/CI only).
#
# Needs stack-inside.sh in the same directory.
#
# Run:   ./setup-dind.sh
#        ZIP_URL=https://your-host/code.zip ./setup-dind.sh
#
set -euo pipefail

# ============================ CONFIG (edit these) ============================
DIND_CONTAINER="sentinel-dind"
DIND_IMAGE="docker:27-dind"
DIND_LIB_VOL="sentinel_dind_lib"      # inner /var/lib/docker (images + volumes)

# Host ports -> published on the DinD container
PG_PORT="5432"
MQTT_PORT="1883"
MQTT_WS_PORT="9001"
GRAF_PORT="3000"
APP_PORT="8000"

ZIP_URL="${ZIP_URL:-}"                # set to also build and run the app

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INNER_SCRIPT="${SCRIPT_DIR}/stack-inside.sh"
# =============================================================================

log()  { printf '\n\033[1;32m[+] %s\033[0m\n' "$*"; }
warn() { printf '\n\033[1;33m[!] %s\033[0m\n' "$*"; }
err()  { printf '\n\033[1;31m[x] %s\033[0m\n' "$*" >&2; }

# --- sudo helper ---
if [ "$(id -u)" -eq 0 ]; then SUDO=""
elif command -v sudo >/dev/null 2>&1; then SUDO="sudo"
else SUDO=""; fi

# --------------------------- host Docker check --------------------------------
check_host_docker() {
  if ! command -v docker >/dev/null 2>&1; then
    err "Docker is not installed on the host. Install it first (see setup-all.sh)."; exit 1
  fi
  if docker info >/dev/null 2>&1; then
    DOCKER() { docker "$@"; }
  elif [ -n "$SUDO" ] && $SUDO docker info >/dev/null 2>&1; then
    DOCKER() { $SUDO docker "$@"; }
    warn "Using sudo for docker — add yourself to the 'docker' group to avoid this."
  else
    err "Host Docker daemon is not reachable."; exit 1
  fi
  log "Host Docker ready: $(DOCKER --version)"
}

check_inner_script() {
  if [ ! -f "$INNER_SCRIPT" ]; then
    err "stack-inside.sh not found next to this script (${INNER_SCRIPT})."; exit 1
  fi
}

# ------------------------------ DinD container --------------------------------
start_dind() {
  if DOCKER ps -a --format '{{.Names}}' | grep -qx "$DIND_CONTAINER"; then
    warn "Removing existing container: ${DIND_CONTAINER}"
    DOCKER rm -f "$DIND_CONTAINER" >/dev/null
  fi

  log "Pulling ${DIND_IMAGE} ..."; DOCKER pull "$DIND_IMAGE"
  DOCKER volume create "$DIND_LIB_VOL" >/dev/null

  # DOCKER_TLS_CERTDIR="" -> inner daemon on the unix socket only, no cert dance.
  # The inner daemon is never exposed outside this container.
  DOCKER run -d \
    --name "$DIND_CONTAINER" \
    --restart unless-stopped \
    --privileged \
    -e DOCKER_TLS_CERTDIR="" \
    -p "${PG_PORT}:5432" \
    -p "${MQTT_PORT}:1883" \
    -p "${MQTT_WS_PORT}:9001" \
    -p "${GRAF_PORT}:3000" \
    -p "${APP_PORT}:8000" \
    -v "${DIND_LIB_VOL}:/var/lib/docker" \
    "$DIND_IMAGE" >/dev/null
  log "DinD container '${DIND_CONTAINER}' started."
}

wait_inner_daemon() {
  log "Waiting for the inner Docker daemon..."
  for _ in $(seq 1 40); do
    if DOCKER exec "$DIND_CONTAINER" docker info >/dev/null 2>&1; then
      log "Inner Docker daemon is ready."; return 0
    fi
    sleep 3
  done
  err "Inner daemon did not come up — check: docker logs ${DIND_CONTAINER}"; exit 1
}

# ------------------------------- inner stack ----------------------------------
run_inner_stack() {
  # Strip CRLF — sh will not run a Windows-saved script.
  TMP="$(mktemp)"
  trap 'rm -f "$TMP"' EXIT INT TERM
  tr -d '\r' < "$INNER_SCRIPT" > "$TMP"

  DOCKER cp "$TMP" "${DIND_CONTAINER}:/stack-inside.sh" >/dev/null
  DOCKER exec "$DIND_CONTAINER" chmod +x /stack-inside.sh

  log "Running the stack inside '${DIND_CONTAINER}' ..."
  if [ -n "$ZIP_URL" ]; then
    DOCKER exec -e ZIP_URL="$ZIP_URL" "$DIND_CONTAINER" sh /stack-inside.sh
  else
    DOCKER exec "$DIND_CONTAINER" sh /stack-inside.sh
  fi
}

# --------------------------------- summary ------------------------------------
summary() {
  cat <<EOF

============================================================
  STACK IS UP INSIDE '${DIND_CONTAINER}'
============================================================
From the HOST:
  Postgres : localhost:${PG_PORT}      dbmasteruser/dbmasterpassword
  MQTT     : localhost:${MQTT_PORT}      (ws: ${MQTT_WS_PORT})   mqttmasteruser/mqttmasterpassword
  Grafana  : http://localhost:${GRAF_PORT}   admin/grafanamasterpassword
EOF
  [ -n "$ZIP_URL" ] && printf '  App      : http://localhost:%s\n' "$APP_PORT"

  cat <<EOF

Inner containers:
EOF
  DOCKER exec "$DIND_CONTAINER" docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'

  cat <<EOF

Talk to the inner daemon with:  docker exec ${DIND_CONTAINER} docker <cmd>
Tear everything down with:      docker rm -f ${DIND_CONTAINER} && docker volume rm ${DIND_LIB_VOL}
============================================================
EOF
}

main() {
  check_host_docker
  check_inner_script
  start_dind
  wait_inner_daemon
  run_inner_stack
  summary
}
main "$@"