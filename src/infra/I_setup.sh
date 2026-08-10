set -euo pipefail

# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------
MQTT_USER="my_mqtt_user"
MQTT_PASS="mqttpassword"

# Agent binary settings — CHANGE THESE
AGENT_BINARY_URL="http://141.148.220.11:8000/run"
AGENT_BINARY_NAME="sentinel-agent"
AGENT_IMAGE_NAME="sentinel-agent"
AGENT_IMAGE_TAG="latest"
AGENT_CONTAINER_NAME="sentinel-agent"
AGENT_HTTP_PORT=8000

cd "$(dirname "$(readlink -f "$0")")"

log() { printf ">> %s\n" "$*"; }
ok()  { printf "[OK] %s\n" "$*"; }
die() { printf "[ERROR] %s\n" "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "Run with sudo."

# ---------------------------------------------------------------------------
# 1. Docker
# ---------------------------------------------------------------------------
if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
    ok "Docker is already installed."
elif [[ -f /etc/os-release ]] && grep -qE '^ID="?(ol|rhel|rocky|almalinux|centos)' /etc/os-release; then
    log "Detected RHEL family - installing Docker from the docker-ce repo..."
    dnf install -y dnf-utils
    dnf config-manager --add-repo=https://download.docker.com/linux/centos/docker-ce.repo
    dnf install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
    systemctl enable --now docker
    ok "Docker installed."
else
    log "Installing Docker via get.docker.com (works on most distros)..."
    curl -fsSL https://get.docker.com -o /tmp/get-docker.sh
    sh /tmp/get-docker.sh
    systemctl enable --now docker || true
    ok "Docker installed."
fi

# ---------------------------------------------------------------------------
# 2. Mosquitto config + password file
# ---------------------------------------------------------------------------
mkdir -p mosquitto/config

if [[ -f mosquitto/config/mosquitto.conf ]]; then
    ok "Mosquitto config already exists."
else
    log "Writing Mosquitto config..."
    cat > mosquitto/config/mosquitto.conf <<'CONF'
listener 1883
allow_anonymous false
password_file /mosquitto/config/passwd

persistence true
persistence_location /mosquitto/data/

log_dest file /mosquitto/log/mosquitto.log
log_dest stdout
log_type all
CONF
    ok "Mosquitto config written."
fi

if [[ -f mosquitto/config/passwd ]]; then
    ok "Mosquitto password file already exists."
else
    log "Generating Mosquitto password file..."
    docker run --rm \
        -v "$(pwd)/mosquitto/config:/mosquitto/config" \
        eclipse-mosquitto:2 \
        mosquitto_passwd -b -c /mosquitto/config/passwd "$MQTT_USER" "$MQTT_PASS"

    chown 1883:1883 mosquitto/config/passwd
    chmod 600 mosquitto/config/passwd
    ok "Mosquitto password file created."
fi

# ---------------------------------------------------------------------------
# 3. Host firewall
# ---------------------------------------------------------------------------
open_port() {
    local p=$1
    if command -v ufw >/dev/null 2>&1; then
        ufw allow "${p}/tcp" >/dev/null && ok "ufw: allowed ${p}/tcp"
    elif command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
        firewall-cmd --permanent --add-port="${p}/tcp" >/dev/null
        firewall-cmd --reload >/dev/null
        ok "firewalld: allowed ${p}/tcp"
    elif command -v iptables >/dev/null 2>&1; then
        iptables -C INPUT -p tcp --dport "$p" -j ACCEPT 2>/dev/null \
            || iptables -I INPUT -p tcp --dport "$p" -j ACCEPT
        ok "iptables: allowed ${p}/tcp (not persistent unless saved)"
    else
        log "No firewall tool found — assuming no host firewall is active."
    fi
}
open_port 5433
open_port 1884
open_port "$AGENT_HTTP_PORT"

# ---------------------------------------------------------------------------
# 4. Bring up Postgres + Mosquitto stack
# ---------------------------------------------------------------------------
log "Starting Postgres + Mosquitto..."
docker compose up -d
docker compose ps

log "Waiting for Postgres to be ready..."
for i in $(seq 1 30); do
    if docker exec sentinel-postgres pg_isready -U developer -d developmentdb >/dev/null 2>&1; then
        break
    fi
    sleep 1
done

log "Enabling TimescaleDB extension..."
docker exec sentinel-postgres psql -U developer -d developmentdb \
    -c "CREATE EXTENSION IF NOT EXISTS timescaledb;" >/dev/null 2>&1 || true

log "Verifying TimescaleDB extension..."
TSDB_VERSION=$(docker exec sentinel-postgres psql -U developer -d developmentdb -tAc \
    "SELECT extversion FROM pg_extension WHERE extname='timescaledb';" 2>/dev/null || true)
if [[ -n "$TSDB_VERSION" ]]; then
    ok "TimescaleDB $TSDB_VERSION installed."
else
    log "WARNING: TimescaleDB extension not detected. Check: docker logs sentinel-postgres"
fi

# ---------------------------------------------------------------------------
# 5. Download the agent executable
# ---------------------------------------------------------------------------
mkdir -p agent
if [[ -f agent/"$AGENT_BINARY_NAME" ]]; then
    ok "Agent binary already downloaded."
else
    log "Downloading agent binary from $AGENT_BINARY_URL ..."
    if ! curl -fSL -o agent/"$AGENT_BINARY_NAME" "$AGENT_BINARY_URL"; then
        die "Failed to download agent binary from $AGENT_BINARY_URL"
    fi
    chmod +x agent/"$AGENT_BINARY_NAME"
    ok "Agent binary downloaded to agent/$AGENT_BINARY_NAME"
fi

# ---------------------------------------------------------------------------
# 6. Create Dockerfile for the agent (if it doesn't exist)
# ---------------------------------------------------------------------------
if [[ -f agent/Dockerfile ]]; then
    ok "Agent Dockerfile already exists."
else

    log "Writing agent Dockerfile..."
    cat > agent/Dockerfile <<DOCKERFILE
# Minimal image for a static Linux binary.
# If your binary needs libc / other libs, swap alpine for debian:stable-slim.
#FROM alpine:3.20
#FROM debian:stable-slim
FROM python:3.13-slim

# ca-certificates lets the agent make HTTPS calls (very common need).
# tzdata gives correct timestamps.
#RUN apk add --no-cache ca-certificates tzdata
WORKDIR /app
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates tzdata \
 && rm -rf /var/lib/apt/lists/*
# 2. Assign the build arg to an ENV variable so ENTRYPOINT can see it
#ENV BINARY_PATH=/usr/local/bin/\.env

# Copy the binary in.
COPY $AGENT_BINARY_NAME /usr/local/bin/$AGENT_BINARY_NAME

RUN chmod +x /usr/local/bin/$AGENT_BINARY_NAME

COPY . .
# Adjust if your agent uses different env-var names for its config.
ENV MQTT_HOST=sentinel-mosquitto \\
    MQTT_PORT=1883 \\
    MQTT_USER=$MQTT_USER \\
    MQTT_PASS=$MQTT_PASS \\
    DB_ENDPOINT="80.225.239.163" \\  # change DB_ENDPOINT
    DB_PORT=5432 \\                          
    DB_USER=dbmasteruser \\
    DB_PASSWORD=dbmasterpassword \\
    DB_NAME=testdb

EXPOSE $AGENT_HTTP_PORT
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
ENTRYPOINT ["/usr/local/bin/$AGENT_BINARY_NAME"]
DOCKERFILE
    ok "Agent Dockerfile written to agent/Dockerfile"
fi

# ---------------------------------------------------------------------------
# 7. Build agent Docker image
# ---------------------------------------------------------------------------
log "Building agent Docker image: $AGENT_IMAGE_NAME:$AGENT_IMAGE_TAG ..."
docker build \
    --tag "$AGENT_IMAGE_NAME:$AGENT_IMAGE_TAG" \
    --file agent/Dockerfile \
    agent
ok "Agent image built."

# ---------------------------------------------------------------------------
# 8. Run the agent container
# ---------------------------------------------------------------------------
# Stop + remove any previous instance so re-runs are safe.
if docker ps -a --format '{{.Names}}' | grep -q "^${AGENT_CONTAINER_NAME}$"; then
    log "Removing existing $AGENT_CONTAINER_NAME container..."
    docker rm -f "$AGENT_CONTAINER_NAME" >/dev/null
fi

# Fiure out the docker-compose network so the agent can reach postgres/mqtt by name.
COMPOSE_NETWORK=$(docker network ls --format '{{.Name}}' | grep -E "_default$|sentinel" | head -1)
[[ -z "$COMPOSE_NETWORK" ]] && COMPOSE_NETWORK="bridge"

log "Starting agent container on network '$COMPOSE_NETWORK'..."
docker run -d \
    --name "$AGENT_CONTAINER_NAME" \
    --network "$COMPOSE_NETWORK" \
    --restart unless-stopped \
    -p "${AGENT_HTTP_PORT}:${AGENT_HTTP_PORT}" \
    "$AGENT_IMAGE_NAME:$AGENT_IMAGE_TAG"

sleep 3
if docker ps --format '{{.Names}}' | grep -q "^${AGENT_CONTAINER_NAME}$"; then
    ok "Agent container is running."
else
    log "WARNING: Agent container did not stay up. Check: docker logs $AGENT_CONTAINER_NAME"
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
HOST_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
[[ -z "$HOST_IP" ]] && HOST_IP="localhost"

cat <<EOF

------------------------------------------------------------------
 Stack is up.

 PostgreSQL  (container: sentinel-postgres)
   host       $HOST_IP
   port       5433
   user       developer
   password   password
   database   developmentdb

 Mosquitto MQTT  (container: sentinel-mosquitto)
   host       $HOST_IP
   port       1884
   user       $MQTT_USER
   password   $MQTT_PASS

 Agent  (container: $AGENT_CONTAINER_NAME)
   image      $AGENT_IMAGE_NAME:$AGENT_IMAGE_TAG
   port       $AGENT_HTTP_PORT
   URL        http://$HOST_IP:$AGENT_HTTP_PORT
   logs       docker logs -f $AGENT_CONTAINER_NAME

 IMPORTANT — cloud firewalls
 On AWS / Azure / GCP / OCI, also open 5432, 1883, and $AGENT_HTTP_PORT
 in your security group / network rules.
------------------------------------------------------------------
EOF
