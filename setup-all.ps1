#requires -Version 5.1
<#
  setup-all.ps1 - one-shot stack bring-up:
    Docker (install if missing) -> network -> PostgreSQL -> Mosquitto (MQTT)
    -> optionally download + build + run your application. One shared network.

  No editing or commenting needed. Just run:  .\setup-all.ps1
  The app step runs ONLY if you set a real $Url below; otherwise it is skipped.
#>

$ErrorActionPreference = 'Continue'

# ============================ CONFIG ============================
$Network = 'sentinel-net'

# --- PostgreSQL ---
$PgContainer = 'sentineldb'
$PgUser      = 'dbmasteruser'
$PgPass      = 'dbmasterpassword'
$PgDb        = 'productiondb'
$PgPort      = 5432
$PgImage     = 'postgres:16'
$PgVolume    = 'sentinel_pgdata'

# --- Mosquitto (MQTT) ---
$MqttContainer = 'sentinel-mqtt'
$MqttUser      = 'mqttmasteruser'
$MqttPass      = 'mqttmasterpassword'
$MqttPort      = 1883
$MqttWsPort    = 9001
$MqttImage     = 'eclipse-mosquitto:2'
$MqttDataVol   = 'sentinel_mqtt_data'
$MqttLogVol    = 'sentinel_mqtt_log'
$MqttDir       = 'C:\sentinel\mosquitto'
$MqttConfigDir = Join-Path $MqttDir 'config'

# --- Application (leave $Url as-is to SKIP the app; set it to deploy) ---
$Url          = 'https://REPLACE-WITH-YOUR-URL/code.zip'
$AppImage     = 'sentinel-api'
$AppContainer = 'sentinel-api'
$AppPort      = 8000
$AppModule    = 'main:app'
$UrlPlaceholder = 'https://REPLACE-WITH-YOUR-URL/code.zip'
# ===============================================================

function Log($m)  { Write-Host "[+] $m" -ForegroundColor Green }
function Warn($m) { Write-Host "[!] $m" -ForegroundColor Yellow }
function Err($m)  { Write-Host "[x] $m" -ForegroundColor Red }
function Test-Cmd($n) { [bool](Get-Command $n -ErrorAction SilentlyContinue) }

function Install-DockerEngine {
    if (Test-Cmd docker) { Log "Docker already installed: $(docker --version)"; return }
    Log "Docker not found. Attempting install via winget (Docker Desktop)..."
    if (Test-Cmd winget) {
        winget install -e --id Docker.DockerDesktop --accept-package-agreements --accept-source-agreements
        Warn "Docker Desktop installed. You may need to sign out/in or REBOOT,"
        Warn "ensure Virtualization + WSL2 are enabled, then re-run this script."
    } else {
        Err "winget unavailable. Install Docker Desktop: https://www.docker.com/products/docker-desktop/"
        exit 1
    }
}

function Wait-Docker {
    Log "Waiting for the Docker engine..."
    for ($i = 0; $i -lt 60; $i++) {
        docker info *> $null
        if ($LASTEXITCODE -eq 0) { Log "Docker engine is ready."; return }
        if ($i -eq 0) {
            $dd = Join-Path $Env:ProgramFiles 'Docker\Docker\Docker Desktop.exe'
            if (Test-Path $dd) { Warn "Starting Docker Desktop..."; Start-Process $dd | Out-Null }
        }
        Start-Sleep -Seconds 5
    }
    Err "Docker engine did not become ready. Start Docker Desktop and re-run."
    exit 1
}

function Ensure-Network {
    docker network inspect $Network *> $null
    if ($LASTEXITCODE -eq 0) { Log "Network '$Network' already exists." }
    else { docker network create $Network | Out-Null; Log "Created network '$Network'." }
}

function Remove-IfExists($name) {
    $x = docker ps -a --format '{{.Names}}' | Where-Object { $_ -eq $name }
    if ($x) { Warn "Removing existing container: $name"; docker rm -f $name | Out-Null }
}

function Run-Postgres {
    Log "Pulling $PgImage ..."; docker pull $PgImage
    Remove-IfExists $PgContainer
    docker volume create $PgVolume | Out-Null
    docker run -d --name $PgContainer --restart unless-stopped --network $Network -e "POSTGRES_USER=$PgUser" -e "POSTGRES_PASSWORD=$PgPass" -e "POSTGRES_DB=$PgDb" -p "$($PgPort):5432" -v "$($PgVolume):/var/lib/postgresql/data" $PgImage | Out-Null
    Log "PostgreSQL container '$PgContainer' started."
}

function Wait-Postgres {
    Log "Waiting for PostgreSQL to accept connections..."
    for ($i = 0; $i -lt 30; $i++) {
        docker exec $PgContainer pg_isready -U $PgUser -d $PgDb *> $null
        if ($LASTEXITCODE -eq 0) { Log "PostgreSQL is ready."; return }
        Start-Sleep -Seconds 2
    }
    Warn "Could not confirm PostgreSQL readiness. Check: docker logs $PgContainer"
}

function Setup-Mosquitto {
    New-Item -ItemType Directory -Force -Path $MqttConfigDir | Out-Null
    $confB64 = 'cGVyc2lzdGVuY2UgdHJ1ZQpwZXJzaXN0ZW5jZV9sb2NhdGlvbiAvbW9zcXVpdHRvL2RhdGEvCmxvZ19kZXN0IGZpbGUgL21vc3F1aXR0by9sb2cvbW9zcXVpdHRvLmxvZwpsb2dfZGVzdCBzdGRvdXQKCmxpc3RlbmVyIF9fTVFUVF9QT1JUX18gMC4wLjAuMApwcm90b2NvbCBtcXR0CgpsaXN0ZW5lciBfX01RVFRfV1NfUE9SVF9fIDAuMC4wLjAKcHJvdG9jb2wgd2Vic29ja2V0cwoKYWxsb3dfYW5vbnltb3VzIGZhbHNlCnBhc3N3b3JkX2ZpbGUgL21vc3F1aXR0by9jb25maWcvcGFzc3dvcmRmaWxlCg=='
    $conf = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($confB64))
    $conf = $conf.Replace('__MQTT_PORT__', "$MqttPort").Replace('__MQTT_WS_PORT__', "$MqttWsPort")
    [System.IO.File]::WriteAllText((Join-Path $MqttConfigDir 'mosquitto.conf'), $conf, (New-Object System.Text.UTF8Encoding($false)))
    Log "Pulling $MqttImage ..."; docker pull $MqttImage
    Log "Generating MQTT password file for user '$MqttUser'..."
    docker run --rm --entrypoint mosquitto_passwd -v "$($MqttConfigDir):/mosquitto/config" $MqttImage -b -c /mosquitto/config/passwordfile $MqttUser $MqttPass
}

function Run-Mosquitto {
    Remove-IfExists $MqttContainer
    docker volume create $MqttDataVol | Out-Null
    docker volume create $MqttLogVol  | Out-Null
    docker run -d --name $MqttContainer --restart unless-stopped --network $Network -p "$($MqttPort):1883" -p "$($MqttWsPort):9001" -v "$($MqttConfigDir):/mosquitto/config" -v "$($MqttDataVol):/mosquitto/data" -v "$($MqttLogVol):/mosquitto/log" $MqttImage | Out-Null
    Log "Mosquitto (MQTT) container '$MqttContainer' started."
}

function Deploy-App {
    $work = Join-Path ([System.IO.Path]::GetTempPath()) ("deploy_" + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Force -Path $work | Out-Null
    try {
        Log "Downloading and extracting app (in-memory, no zip saved) ..."
        Add-Type -AssemblyName System.IO.Compression
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $wc = New-Object System.Net.WebClient
        try { [byte[]]$bytes = $wc.DownloadData($Url) } finally { $wc.Dispose() }
        $ms = New-Object System.IO.MemoryStream(,$bytes)
        try {
            $zip = New-Object System.IO.Compression.ZipArchive($ms)
            try { [System.IO.Compression.ZipFileExtensions]::ExtractToDirectory($zip, $work) } finally { $zip.Dispose() }
        } finally { $ms.Dispose() }

        $ctx = $work
        $top = Get-ChildItem -Force $ctx
        if ($top.Count -eq 1 -and $top[0].PSIsContainer) { $ctx = $top[0].FullName }

        $dockerfile = Join-Path $ctx 'Dockerfile'
        if (Test-Path $dockerfile) {
            Log "Using the project's own Dockerfile."
        } else {
            Warn "No Dockerfile found. Generating the multi-stage Dockerfile."
            $dfB64 = 'RlJPTSBub2RlOjIwLWFscGluZSBBUyBmcm9udGVuZC1idWlsZApXT1JLRElSIC9hcHAvZnJvbnRlbmQKQ09QWSBmcm9udGVuZC9wYWNrYWdlKi5qc29uIC4vClJVTiBucG0gaW5zdGFsbApDT1BZIGZyb250ZW5kLyAuLwpSVU4gbnBtIHJ1biBidWlsZAoKCkZST00gcHl0aG9uOjMuMTItc2xpbQoKIyBQeXRob24gb3B0aW1pemF0aW9ucwpFTlYgUFlUSE9ORE9OVFdSSVRFQllURUNPREU9MQpFTlYgUFlUSE9OVU5CVUZGRVJFRD0xCgpXT1JLRElSIC9hcHAKCiMgSW5zdGFsbCBvbmx5IHN5c3RlbSBkZXBzIChrZWVwIG1pbmltYWwpClJVTiBhcHQtZ2V0IHVwZGF0ZSAmJiBhcHQtZ2V0IGluc3RhbGwgLXkgZ2NjIFwKICAgICYmIHJtIC1yZiAvdmFyL2xpYi9hcHQvbGlzdHMvKgoKIyBDb3B5IG9ubHkgcmVxdWlyZW1lbnRzIGZpcnN0IChiZXN0IGNhY2hpbmcpCkNPUFkgcmVxdWlyZW1lbnRzLnR4dCAuCgojIEluc3RhbGwgZGVwZW5kZW5jaWVzClJVTiBwaXAgaW5zdGFsbCAtLW5vLWNhY2hlLWRpciAtLXVwZ3JhZGUgcGlwICYmIFwKICAgIHBpcCBpbnN0YWxsIC0tbm8tY2FjaGUtZGlyIC1yIHJlcXVpcmVtZW50cy50eHQKCiMgQ29weSBzb3VyY2UgY29kZSBzZXBhcmF0ZWx5CkNPUFkgc3JjLyAuL3NyYwpDT1BZIGFnZW50LyAuL2FnZW50CgojIEJyaW5nIGluIHRoZSBidWlsdCBmcm9udGVuZCwgdGhlbiB3b3JrIGZyb20gc3JjIChpbXBvcnRzIGxpa2UgbWFpbjphcHApCkNPUFkgLS1mcm9tPWZyb250ZW5kLWJ1aWxkIC9hcHAvZnJvbnRlbmQvYnVpbGQgLi9mcm9udGVuZC9idWlsZApXT1JLRElSIC9hcHAvc3JjCgpFWFBPU0UgX19QT1JUX18KCkNNRCBbInV2aWNvcm4iLCAiX19BUFBfXyIsICItLWhvc3QiLCAiMC4wLjAuMCIsICItLXBvcnQiLCAiX19QT1JUX18iXQo='
            $content = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($dfB64))
            $content = $content.Replace('__PORT__', "$AppPort").Replace('__APP__', $AppModule)
            [System.IO.File]::WriteAllText($dockerfile, $content, (New-Object System.Text.UTF8Encoding($false)))
        }

        Log "Building app image '$AppImage' ..."
        docker build -t $AppImage $ctx
        if ($LASTEXITCODE -ne 0) { throw "Docker build failed." }

        Remove-IfExists $AppContainer
        $envArgs = @()
        $envFile = Join-Path $ctx '.env'
        if (Test-Path $envFile) { $envArgs = @('--env-file', $envFile); Log "Using bundled .env" }

        Log "Starting app container '$AppContainer' ..."
        docker run -d --name $AppContainer --restart unless-stopped --network $Network -p "$($AppPort):$($AppPort)" @envArgs $AppImage | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "Docker run failed." }
        Log "App container '$AppContainer' started."
    } finally {
        if (Test-Path $work) { Remove-Item -Recurse -Force $work }
    }
}

function Show-Summary {
    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "  STACK IS UP  (network: $Network)" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "PostgreSQL   container $PgContainer"
    Write-Host "  external : postgresql+asyncpg://$($PgUser):$($PgPass)@localhost:$($PgPort)/$PgDb"
    Write-Host "  in-app   : postgresql+asyncpg://$($PgUser):$($PgPass)@$($PgContainer):5432/$PgDb"
    Write-Host ""
    Write-Host "MQTT         container $MqttContainer"
    Write-Host "  external : localhost:$MqttPort   (ws: $MqttWsPort)   $MqttUser/$MqttPass"
    Write-Host "  in-app   : $($MqttContainer):1883"
    Write-Host ""
    Write-Host "Application  container $AppContainer"
    Write-Host "  URL      : http://localhost:$AppPort"
    Write-Host "  logs     : docker logs -f $AppContainer"
    Write-Host "============================================================" -ForegroundColor Cyan
}

Install-DockerEngine
Wait-Docker
Ensure-Network
Run-Postgres
Setup-Mosquitto
Run-Mosquitto
Wait-Postgres

if ($Url -and $Url -ne $UrlPlaceholder) {
    Deploy-App
} else {
    Warn "Skipping app deploy: `$Url is not set (still the placeholder)."
    Warn "Set `$Url and re-run to build and start the app."
}

Show-Summary