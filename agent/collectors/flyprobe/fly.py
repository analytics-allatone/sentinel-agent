import os
import json
import shutil
import subprocess
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

DRIVER = "urllib.request"                 # always present; API path needs nothing extra
FLY_CLI = None                            # resolved lazily
API_BASE = "https://api.machines.dev/v1"
GRAPHQL = "https://api.fly.io/graphql"


# ---------- helpers ----------------------------------------------------------
def _find_cli() -> Optional[str]:
    global FLY_CLI
    if FLY_CLI is not None:
        return FLY_CLI or None
    for name in ("fly", "flyctl"):
        path = shutil.which(name)
        if path:
            FLY_CLI = path
            return path
    FLY_CLI = ""
    return None


def _run(args: List[str], timeout: float = 20.0) -> Tuple[int, str, str]:
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as ex:
        return 1, "", str(ex)


def _cli_json(cli: str, args: List[str]) -> Any:
    rc, out, err = _run([cli] + args + ["--json"])
    if rc != 0:
        raise RuntimeError((err or out or "flyctl error").strip()[:300])
    out = out.strip()
    return json.loads(out) if out else None


def _api(path: str, token: str, base: str = API_BASE, timeout: float = 15.0) -> Any:
    req = urllib.request.Request(
        f"{base}{path}",
        headers={"Authorization": f"Bearer {token}", "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = resp.read().decode("utf-8", "ignore")
    return json.loads(body) if body else None


def _graphql(token: str, query: str, variables: dict = None, timeout: float = 15.0) -> Any:
    data = json.dumps({"query": query, "variables": variables or {}}).encode()
    req = urllib.request.Request(
        GRAPHQL, data=data,
        headers={"Authorization": f"Bearer {token}",
                 "Content-Type": "application/json", "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8", "ignore"))


# ---------- CLI backend ------------------------------------------------------
def _cli_version(cli: str) -> Dict[str, Any]:
    rc, out, err = _run([cli, "version"])
    return {"backend": "cli", "flyctl": (out or err).strip()[:120], "path": cli}


def _cli_apps(cli: str, org: Optional[str]) -> List[Dict[str, Any]]:
    args = ["apps", "list"]
    if org!="string":
        args += ["--org", org]
    data = _cli_json(cli, args) or []
    apps = data if isinstance(data, list) else data.get("Apps", data.get("apps", []))
    out = []
    for a in apps or []:
        out.append({"name": a.get("Name") or a.get("name"),
                    "org": (a.get("Organization") or {}).get("Slug") if isinstance(a.get("Organization"), dict) else a.get("org"),
                    "status": a.get("Status") or a.get("status"),
                    "deployed": a.get("Deployed", a.get("deployed"))})
    return out


def _cli_machines(cli: str, app: str) -> List[Dict[str, Any]]:
    data = _cli_json(cli, ["machine", "list", "-a", app]) or []
    rows = data if isinstance(data, list) else data.get("Machines", [])
    out = []
    for m in rows or []:
        checks = m.get("checks") or m.get("Checks") or []
        passing = sum(1 for c in checks if (c.get("status") or c.get("Status")) == "passing")
        out.append({"id": m.get("id") or m.get("ID"),
                    "state": m.get("state") or m.get("State"),
                    "region": m.get("region") or m.get("Region"),
                    "checks_total": len(checks), "checks_passing": passing})
    return out


# ---------- API backend ------------------------------------------------------
def _api_apps(token: str, org: Optional[str], base: str) -> List[Dict[str, Any]]:
    # Machines API lists apps per org; org slug defaults to "personal"
    org = org or "personal"
    data = _api(f"/apps?org_slug={org}", token, base) or {}
    apps = data.get("apps", data if isinstance(data, list) else [])
    return [{"name": a.get("name"), "org": org,
             "status": a.get("status"), "deployed": a.get("deployed")} for a in apps]


def _api_machines(token: str, app: str, base: str) -> List[Dict[str, Any]]:
    rows = _api(f"/apps/{app}/machines", token, base) or []
    out = []
    for m in rows if isinstance(rows, list) else []:
        checks = m.get("checks") or []
        passing = sum(1 for c in checks if c.get("status") == "passing")
        out.append({"id": m.get("id"), "state": m.get("state"),
                    "region": m.get("region"),
                    "checks_total": len(checks), "checks_passing": passing,
                    "restarts": (m.get("config", {}) or {}).get("restart", {}).get("count")})
    return out


# ---------- availability (used by detect) -----------------------------------
def availability(params: Dict[str, Any] = None) -> Dict[str, Any]:
    """What can we reach? Drives detect() and backend auto-pick."""
    p = params or {}
    cli = _find_cli()
    cli_authed = False
    if cli:
        rc, out, err = _run([cli, "auth", "whoami"])
        cli_authed = rc == 0 and out.strip() and "not logged in" not in (out + err).lower()
    tok = p.get("token")
    token_present = isinstance(tok, str) and tok.strip() != "string"
    return {"cli_installed": bool(cli), "cli_path": cli, "cli_authenticated": bool(cli_authed),
            "api_token_present": bool(token_present)}


# ---------- extra per-app fetchers (opt-in) ---------------------------------
# All use the unified runner so they work on host OR inside a container the same
# way. Each is wrapped by the caller in try/except so one failure never kills
# the whole inspect.
def _flyj(fly_bin, args, container=None):
    from . import _docker
    return _docker.fly_json(fly_bin, args, container=container)


def _app_status(fly_bin, app, container=None) -> Dict[str, Any]:
    d = _flyj(fly_bin, ["status", "-a", app], container) or {}
    # normalise the bits worth keeping
    return {"deployed": d.get("Deployed", d.get("deployed")),
            "status": d.get("Status") or d.get("status"),
            "version": d.get("Version") or d.get("version"),
            "hostname": d.get("Hostname") or d.get("hostname")}


def _app_releases(fly_bin, app, container=None, limit=5) -> List[Dict[str, Any]]:
    d = _flyj(fly_bin, ["releases", "-a", app], container) or []
    rows = d if isinstance(d, list) else d.get("Releases", [])
    out = []
    for r in (rows or [])[:limit]:
        out.append({"version": r.get("Version") or r.get("version"),
                    "status": r.get("Status") or r.get("status"),
                    "description": r.get("Description") or r.get("description"),
                    "user": (r.get("User") or {}).get("Email") if isinstance(r.get("User"), dict) else r.get("user"),
                    "created_at": r.get("CreatedAt") or r.get("created_at")})
    return out


def _app_checks(fly_bin, app, container=None) -> Dict[str, Any]:
    d = _flyj(fly_bin, ["checks", "list", "-a", app], container) or []
    rows = d if isinstance(d, list) else d.get("checks", [])
    passing = warning = critical = 0
    for c in rows or []:
        st = (c.get("Status") or c.get("status") or "").lower()
        if st == "passing":
            passing += 1
        elif st in ("warning", "warn"):
            warning += 1
        elif st in ("critical", "crit"):
            critical += 1
    return {"total": len(rows or []), "passing": passing,
            "warning": warning, "critical": critical}


def _app_volumes(fly_bin, app, container=None) -> List[Dict[str, Any]]:
    d = _flyj(fly_bin, ["volumes", "list", "-a", app], container) or []
    rows = d if isinstance(d, list) else d.get("Volumes", [])
    return [{"id": v.get("id") or v.get("ID"),
             "name": v.get("name") or v.get("Name"),
             "region": v.get("region") or v.get("Region"),
             "size_gb": v.get("size_gb") or v.get("SizeGb"),
             "attached": bool(v.get("attached_machine_id") or v.get("AttachedMachine")),
             "encrypted": v.get("encrypted", v.get("Encrypted"))} for v in (rows or [])]


def _app_ips(fly_bin, app, container=None) -> List[Dict[str, Any]]:
    d = _flyj(fly_bin, ["ips", "list", "-a", app], container) or []
    rows = d if isinstance(d, list) else d.get("IPAddresses", [])
    return [{"address": i.get("Address") or i.get("address"),
             "type": i.get("Type") or i.get("type"),
             "region": i.get("Region") or i.get("region")} for i in (rows or [])]


def _app_scale(fly_bin, app, container=None) -> Any:
    return _flyj(fly_bin, ["scale", "show", "-a", app], container)


def _app_certs(fly_bin, app, container=None) -> List[Dict[str, Any]]:
    d = _flyj(fly_bin, ["certs", "list", "-a", app], container) or []
    rows = d if isinstance(d, list) else d.get("Certificates", [])
    return [{"hostname": c.get("Hostname") or c.get("hostname"),
             "status": c.get("ClientStatus") or c.get("status"),
             "created_at": c.get("CreatedAt") or c.get("created_at")} for c in (rows or [])]


# ---------- Prometheus metrics (HTTP + token, not a CLI call) ---------------
def _prometheus(token: str, org: str, app: str,
                base: str = "https://api.fly.io/prometheus") -> Dict[str, Any]:
    """Instant-query a few key series for one app. Needs org slug + token."""
    if not (token and org):
        return {"error": "prometheus needs org + token"}
    queries = {
        "cpu": f'avg(rate(fly_instance_cpu{{app="{app}"}}[5m]))',
        "memory_pct": f'avg(fly_instance_memory_mem_percent{{app="{app}"}})',
        "req_per_sec": f'sum(rate(fly_edge_http_responses_count{{app="{app}"}}[5m]))',
        "5xx_per_sec": f'sum(rate(fly_edge_http_responses_count{{app="{app}",status=~"5.."}}[5m]))',
    }
    out = {}
    for name, q in queries.items():
        try:
            url = f"{base}/{org}/api/v1/query?query={urllib.request.quote(q)}"
            req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode("utf-8", "ignore"))
            result = (data.get("data") or {}).get("result") or []
            out[name] = float(result[0]["value"][1]) if result else None
        except Exception as ex:
            out[name] = {"error": str(ex)[:120]}
    return out


# ---------- main entry -------------------------------------------------------
def inspect(params: Dict[str, Any]) -> Dict[str, Any]:
    p = params or {}
    base = p.get("api_base") or API_BASE
    # token must be a real non-empty STRING — never True/1/os.getenv here.
    token = p.get("token")
    if token is True or token == "string" or token is None:
        token = None
    else:
        token = str(token)
    org =None if p.get("org") != "string" else p.get('org')
    want_apps = p.get("apps")                 # optional explicit app list
    container = p.get("container")            # if set -> run flyctl inside this container
    fly_bin = p.get("fly_bin") or "fly"
    avail = availability(p)

    backend = (p.get("backend") or "auto").lower()
    if backend == "auto":
        # explicit token -> API; else local flyctl; else container; else none
        if token:
            backend = "api"
        elif avail["cli_authenticated"]:
            backend = "cli"
        elif container:
            backend = "cli-docker"
        else:
            backend = None
    # if caller asked for api but gave no real token, don't silently succeed
    if backend == "api" and not token:
        return {"version": None, "server": "fly", "backend": None,
                "metrics": {"reachable": False},
                "sections": {"connectivity_version": {"backend": "api", **avail,
                    "error": "api backend selected but no token provided (must be a string, not true/env)"},
                    "health_summary": {"reachable": False}}}

    conn = {"backend": backend, **avail}
    if container:
        conn["container"] = container
    if backend is None:
        return {"version": None, "server": "fly", "backend": None,
                "metrics": {"reachable": False},
                "sections": {"connectivity_version": {**conn, "error":
                    "no backend: flyctl not authenticated, no FLY_API_TOKEN, no container"},
                    "health_summary": {"reachable": False}}}

    apps_list: List[Dict[str, Any]] = []
    machines: Dict[str, List[Dict[str, Any]]] = {}
    version = None
    try:
        if backend == "cli-docker":
            from . import _docker
            version = f"docker:{container}"
            conn["fly_bin"] = fly_bin
            data = _docker.fly_json_in(container, fly_bin, ["apps", "list"]) or []
            rows = data if isinstance(data, list) else data.get("Apps", data.get("apps", []))
            apps_list = [{"name": a.get("Name") or a.get("name"),
                          "status": a.get("Status") or a.get("status"),
                          "deployed": a.get("Deployed", a.get("deployed"))} for a in (rows or [])]
        elif backend == "cli":
            cli = avail["cli_path"]
            conn.update(_cli_version(cli))
            version = conn.get("flyctl")
            apps_list = _cli_apps(cli, org)
        else:
            version = "machines-api"
            apps_list = _api_apps(token, org, base)
    except Exception as ex:
        conn["error"] = str(ex)[:300]

    # limit to requested apps if given
    if want_apps:
        want = set(want_apps)
        apps_list = [a for a in apps_list if a.get("name") in want]

    up = down = 0
    regions = set()
    for a in apps_list:
        name = a.get("name")
        if not name:
            continue
        try:
            if backend == "cli-docker":
                from . import _docker
                data = _docker.fly_json_in(container, fly_bin, ["machine", "list", "-a", name]) or []
                rows = data if isinstance(data, list) else data.get("Machines", [])
                m = [{"id": x.get("id") or x.get("ID"),
                      "state": x.get("state") or x.get("State"),
                      "region": x.get("region") or x.get("Region")} for x in (rows or [])]
            elif backend == "cli":
                m = _cli_machines(avail["cli_path"], name)
            else:
                m = _api_machines(token, name, base)
        except Exception as ex:
            m = [{"error": str(ex)[:200]}]
        machines[name] = m
        for mm in m:
            st = mm.get("state")
            if st == "started":
                up += 1
            elif st:
                down += 1
            if mm.get("region"):
                regions.add(mm["region"])

    # ---- opt-in extras (CLI/docker backends only; each guarded) ----
    # toggles from params: want_status, want_releases, want_checks, want_volumes,
    # want_ips, want_scale, want_certs, want_metrics
    fly_cli = fly_bin if backend == "cli-docker" else avail.get("cli_path")
    cont = container if backend == "cli-docker" else None
    can_cli = backend in ("cli", "cli-docker") and fly_cli
    status_sec: Dict[str, Any] = {}
    releases_sec: Dict[str, Any] = {}
    checks_sec: Dict[str, Any] = {}
    volumes_sec: Dict[str, Any] = {}
    ips_sec: Dict[str, Any] = {}
    scale_sec: Dict[str, Any] = {}
    certs_sec: Dict[str, Any] = {}
    metrics_sec: Dict[str, Any] = {}
    checks_roll = {"passing": 0, "warning": 0, "critical": 0}

    def _try(fn, *a):
        try:
            return fn(*a)
        except Exception as ex:
            return {"error": str(ex)[:200]}

    for a in apps_list:
        name = a.get("name")
        if not name:
            continue
        if can_cli and p.get("want_status"):
            status_sec[name] = _try(_app_status, fly_cli, name, cont)
        if can_cli and p.get("want_releases"):
            releases_sec[name] = _try(_app_releases, fly_cli, name, cont)
        if can_cli and p.get("want_checks"):
            c = _try(_app_checks, fly_cli, name, cont)
            checks_sec[name] = c
            if isinstance(c, dict):
                for k in checks_roll:
                    checks_roll[k] += c.get(k, 0) or 0
        if can_cli and p.get("want_volumes"):
            volumes_sec[name] = _try(_app_volumes, fly_cli, name, cont)
        if can_cli and p.get("want_ips"):
            ips_sec[name] = _try(_app_ips, fly_cli, name, cont)
        if can_cli and p.get("want_scale"):
            scale_sec[name] = _try(_app_scale, fly_cli, name, cont)
        if can_cli and p.get("want_certs"):
            certs_sec[name] = _try(_app_certs, fly_cli, name, cont)
        if p.get("want_metrics"):
            metrics_sec[name] = _try(_prometheus, token, org, name,
                                     p.get("prometheus_base", "https://api.fly.io/prometheus"))

    hs = {"reachable": True, "backend": backend,
          "apps_total": len(apps_list),
          "machines_up": up, "machines_down": down,
          "regions": sorted(regions)}
    if checks_sec:
        hs["checks"] = checks_roll

    sections = {
        "connectivity_version": conn,
        "apps": {"apps": apps_list, "status": status_sec or None},
        "machines": machines,
        "releases": releases_sec or None,
        "volumes_ips": {"volumes": volumes_sec or None, "ips": ips_sec or None,
                        "scale": scale_sec or None, "certs": certs_sec or None}
                       if (volumes_sec or ips_sec or scale_sec or certs_sec) else None,
        "checks": checks_sec or None,
        "metrics": metrics_sec or None,
        "system_resources": None,
        "health_summary": hs,
    }
    metrics = {"apps_total": len(apps_list), "machines_up": up,
               "machines_down": down, "regions": len(regions),
               "checks_critical": checks_roll["critical"] if checks_sec else None,
               "reachable": True}
    return {"version": version, "server": "fly", "backend": backend,
            "metrics": metrics, "sections": sections}