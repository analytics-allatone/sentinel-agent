from ._util import (mgmt_call, read_resource, read_attr, find_cli, cli_command,
                    na, safe, jsonable)

DRIVER = "urllib.request"          # api backend needs nothing; cli checked separately

# Values that are NOT a real host — API/Swagger placeholders, blanks, etc.
# Any of these means "use local", never a remote controller like "string:9990".
_BAD_HOSTS = {"", "string", "none", "null", "host", "hostname", "example.com",
              "127.0.0.1", "localhost", "::1", "0.0.0.0"}


def _clean_host(host):
    """Return a usable host. Placeholder/blank values collapse to 127.0.0.1 so
    we never build a bogus controller such as 'string:9990'."""
    h = str(host or "").strip()
    if h.lower() in _BAD_HOSTS:
        return "127.0.0.1"
    return h


def _is_local(host):
    return _clean_host(host) in ("127.0.0.1", "localhost", "::1", "0.0.0.0")


# ---------- helpers over whichever backend ----------------------------------
class _Backend:
    """Thin wrapper so sections don't care whether it's HTTP or CLI."""
    def __init__(self, p):
        self.p = p
        self.mode = (p.get("backend") or "api").lower()
        self.host = _clean_host(p.get("host"))
        self.port = int(p.get("port") or 9990)
        self.user = p.get("user")
        self.password = p.get("password")
        # only look for jboss-cli when this backend actually needs it.
        # api backend never touches the CLI, so don't waste a process scan.
        if self.mode == "cli":
            self.cli = p.get("cli_path") or find_cli()
        else:
            self.cli = p.get("cli_path")     # kept if given, but unused for api
        raw_ctrl = str(p.get("controller") or "").strip()
        if raw_ctrl.lower() in ("", "none", "null", "string"):
            raw_ctrl = None
        self.controller = raw_ctrl or (f"{self.host}:{self.port}"
                                       if not _is_local(self.host) else None)

    def read(self, address, recursive=False, runtime=True):
        if self.mode == "cli":
            addr = "".join(f"/{address[i]}={address[i+1]}" for i in range(0, len(address), 2)) or "/"
            cmd = f"{addr}:read-resource(include-runtime={str(runtime).lower()},recursive={str(recursive).lower()})"
            return cli_command(self.cli, cmd, self.controller, self.user, self.password)
        return read_resource(self.host, self.port, address, self.user, self.password,
                             include_runtime=runtime, recursive=recursive)

    def attr(self, address, name):
        if self.mode == "cli":
            addr = "".join(f"/{address[i]}={address[i+1]}" for i in range(0, len(address), 2)) or "/"
            return cli_command(self.cli, f"{addr}:read-attribute(name={name})",
                               self.controller, self.user, self.password)
        return read_attr(self.host, self.port, address, name, self.user, self.password)


def _connectivity(b: _Backend):
    root = b.read([], recursive=False, runtime=True)
    if not isinstance(root, dict):
        root = {}
    return {"backend": b.mode,
            "product_name": root.get("product-name") or root.get("product_name"),
            "product_version": root.get("product-version") or root.get("release-version"),
            "release_codename": root.get("release-codename"),
            "server_state": root.get("server-state"),
            "launch_type": root.get("launch-type"),
            "name": root.get("name")}


def _jvm(b: _Backend):
    m = b.read(["core-service", "platform-mbean", "type", "memory"], runtime=True)
    mem = m if isinstance(m, dict) else {}
    heap = mem.get("heap-memory-usage") or {}
    nonheap = mem.get("non-heap-memory-usage") or {}
    # runtime + GC
    rt = safe(lambda: b.read(["core-service", "platform-mbean", "type", "runtime"]), {})
    uptime = rt.get("uptime") if isinstance(rt, dict) else None
    gc = safe(lambda: b.read(["core-service", "platform-mbean", "type", "garbage-collector"],
                             recursive=True), {})
    gc_count = gc_time = 0
    if isinstance(gc, dict):
        for name, col in (gc.get("name") or {}).items() if isinstance(gc.get("name"), dict) else []:
            pass
        # WildFly nests collectors under "name"
        collectors = gc.get("name") if isinstance(gc.get("name"), dict) else {}
        for _, c in collectors.items():
            if isinstance(c, dict):
                gc_count += c.get("collection-count") or 0
                gc_time += c.get("collection-time") or 0
    heap_used = heap.get("used"); heap_max = heap.get("max")
    return {"heap_used": heap_used, "heap_max": heap_max,
            "heap_committed": heap.get("committed"),
            "heap_pct": round(heap_used * 100.0 / heap_max, 1) if heap_used and heap_max and heap_max > 0 else None,
            "nonheap_used": nonheap.get("used"),
            "uptime_ms": uptime, "gc_count": gc_count, "gc_time_ms": gc_time}


def _threads(b: _Backend):
    t = b.read(["core-service", "platform-mbean", "type", "threading"], runtime=True)
    t = t if isinstance(t, dict) else {}
    return {"thread_count": t.get("thread-count"),
            "daemon_thread_count": t.get("daemon-thread-count"),
            "peak_thread_count": t.get("peak-thread-count"),
            "total_started": t.get("total-started-thread-count")}


def _datasources(b: _Backend):
    """Per-datasource connection pool stats (in-use / available / max)."""
    try:
        ds = b.read(["subsystem", "datasources"], recursive=True, runtime=True)
    except Exception as ex:
        return {"error": str(ex)[:150]}
    out = []
    dblock = (ds or {}).get("data-source") if isinstance(ds, dict) else None
    if isinstance(dblock, dict):
        for name, cfg in dblock.items():
            stats = ((cfg or {}).get("statistics") or {}).get("pool") or {}
            out.append({"name": name,
                        "enabled": cfg.get("enabled"),
                        "in_use": stats.get("InUseCount"),
                        "available": stats.get("AvailableCount"),
                        "active": stats.get("ActiveCount"),
                        "max_used": stats.get("MaxUsedCount"),
                        "wait_count": stats.get("WaitCount"),
                        "blocking_avg_ms": stats.get("AverageBlockingTime")})
    return {"datasources": out}


def _deployments(b: _Backend):
    try:
        d = b.read(["deployment", "*"], runtime=True) if b.mode == "api" else b.read(["deployment"], runtime=True)
    except Exception:
        d = None
    out = []
    if isinstance(d, list):
        for item in d:
            r = item.get("result", item) if isinstance(item, dict) else {}
            out.append({"name": r.get("name"), "enabled": r.get("enabled"),
                        "status": r.get("status"), "runtime_name": r.get("runtime-name")})
    elif isinstance(d, dict):
        for name, cfg in d.items():
            if isinstance(cfg, dict):
                out.append({"name": name, "enabled": cfg.get("enabled"),
                            "status": cfg.get("status")})
    up = sum(1 for x in out if x.get("status") == "OK" or x.get("enabled"))
    return {"deployments": out, "total": len(out), "ok": up}


def inspect(params):
    p = params or {}
    b = _Backend(p)
    if b.mode == "cli" and not b.cli:
        return {"version": None, "server": "wildfly", "backend": "cli",
                "metrics": {"reachable": False},
                "sections": {"connectivity_version": {"backend": "cli",
                    "error": "jboss-cli not found (set cli_path or JBOSS_HOME/WILDFLY_HOME)"},
                    "health_summary": {"reachable": False}}}

    # connectivity is the auth gate: if it fails (401) or comes back empty, the
    # whole inspect is unreachable — do NOT report healthy with blank sections.
    conn_err = None
    try:
        conn = _connectivity(b)
    except Exception as ex:
        conn = {}
        conn_err = str(ex)[:200]
    # a real WildFly always returns product-version + server-state; if those are
    # missing, auth failed or the endpoint isn't WildFly mgmt.
    if conn_err or not conn.get("product_version") or not conn.get("server_state"):
        msg = conn_err or "no data from management API (check mgmt user/password — 401 = bad credentials)"
        return {"version": None, "server": "wildfly", "backend": b.mode,
                "server_state": None,
                "metrics": {"reachable": False},
                "sections": {"connectivity_version": {"backend": b.mode, "error": msg, **conn},
                             "health_summary": {"reachable": False, "error": msg}}}

    jvm = safe(lambda: _jvm(b), {})
    threads = safe(lambda: _threads(b), {})
    ds = safe(lambda: _datasources(b), na("datasources unavailable")) if p.get("want_datasources", True) else na("disabled")
    deploys = safe(lambda: _deployments(b), na("deployments unavailable"))

    ds_list = ds.get("datasources") if isinstance(ds, dict) else []
    ds_wait = sum((d.get("wait_count") or 0) for d in (ds_list or []) if isinstance(d, dict))

    hs = {"reachable": True, "backend": b.mode,
          "server_state": conn.get("server_state"),
          "product": f"{conn.get('product_name')} {conn.get('product_version')}".strip(),
          "heap_pct": jvm.get("heap_pct"),
          "thread_count": threads.get("thread_count"),
          "datasource_wait_total": ds_wait,
          "deployments_ok": deploys.get("ok") if isinstance(deploys, dict) else None,
          "deployments_total": deploys.get("total") if isinstance(deploys, dict) else None}

    sections = {
        "connectivity_version": {"backend": b.mode, **conn},
        "jvm": jvm,
        "threads": threads,
        "thread_pools": None,
        "datasources": ds,
        "deployments": deploys,
        "system_resources": None,
        "health_summary": hs,
    }
    metrics = {
        "heap_pct": jvm.get("heap_pct"),
        "heap_used": jvm.get("heap_used"),
        "gc_time_ms": jvm.get("gc_time_ms"),
        "thread_count": threads.get("thread_count"),
        "datasource_wait_total": ds_wait,
        "deployments_ok": hs["deployments_ok"],
        "deployments_total": hs["deployments_total"],
        "uptime_ms": jvm.get("uptime_ms"),
        "reachable": True,
    }
    version = conn.get("product_version")
    return {"version": version, "server": "wildfly", "backend": b.mode,
            "server_state": conn.get("server_state"),
            "metrics": metrics, "sections": sections}