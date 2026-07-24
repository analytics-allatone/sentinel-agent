"""
collectors/webprobe/nginx.py
============================
Nginx health probe. Returns {version, metrics, sections} like the db probes.

Sections (each -> its own JSONB column on web_server_events):
  connectivity_version   binary path, version, config test result
  live_status            stub_status (active/reading/writing/waiting, req/conn totals)
  process_ports          worker/master pids, listening ports, uptime
  vhosts_tls             server_names + TLS cert expiry per HTTPS vhost
  access_log             sampled rates, 4xx/5xx, top paths/clients
  error_log              recent error lines + counts by level
  system_resources       filled by the collector (host CPU/mem/disk)
  health_summary         rolled-up headline numbers

params (from the collector / selection): may include
  status_url (default http://127.0.0.1/nginx_status), access_log, error_log,
  bin (nginx binary), tls_hosts [ "host:443", ... ], log_lines
"""
import os
import re
from ._util import (http_get, run_cmd, tail_lines, cert_info,
                    analyze_access_log, na, safe)

DRIVER = "urllib.request"      # always available; keeps the collector's find_spec happy


def _version(bin_):
    rc, out, err = run_cmd([bin_, "-v"])
    txt = (err or out or "").strip()
    m = re.search(r"nginx/([0-9.]+)", txt)
    return {"binary": bin_, "version": m.group(1) if m else None, "raw": txt[:200]}


def _config_test(bin_):
    rc, out, err = run_cmd([bin_, "-t"])
    return {"ok": rc == 0, "output": (err or out).strip()[:500]}


def _stub_status(url):
    st, body = http_get(url)
    if st != 200:
        return {"reachable": False, "http_status": st, "url": url}
    # Active connections: 3
    # server accepts handled requests
    #  16 16 21
    # Reading: 0 Writing: 1 Waiting: 2
    d = {"reachable": True, "url": url}
    m = re.search(r"Active connections:\s+(\d+)", body)
    if m:
        d["active_connections"] = int(m.group(1))
    nums = re.search(r"\n\s*(\d+)\s+(\d+)\s+(\d+)", body)
    if nums:
        d["accepts"] = int(nums.group(1))
        d["handled"] = int(nums.group(2))
        d["requests"] = int(nums.group(3))
        d["dropped"] = d["accepts"] - d["handled"]
    rww = re.search(r"Reading:\s+(\d+)\s+Writing:\s+(\d+)\s+Waiting:\s+(\d+)", body)
    if rww:
        d["reading"], d["writing"], d["waiting"] = (int(rww.group(1)),
                                                    int(rww.group(2)), int(rww.group(3)))
    return d


def _error_log(path, n=2000):
    lines = tail_lines(path, n)
    by_level = {}
    recent = []
    for ln in lines:
        m = re.search(r"\[(emerg|alert|crit|error|warn|notice|info)\]", ln)
        lvl = m.group(1) if m else "other"
        by_level[lvl] = by_level.get(lvl, 0) + 1
    for ln in reversed(lines):
        if re.search(r"\[(emerg|alert|crit|error)\]", ln):
            recent.append(ln.strip()[:400])
        if len(recent) >= 20:
            break
    return {"path": path, "sampled_lines": len(lines), "by_level": by_level,
            "recent_errors": recent}


def inspect(params):
    p = params or {}
    bin_ = p.get("bin") or ("nginx" if os.name != "nt" else "nginx.exe")
    status_url = p.get("status_url") or "http://127.0.0.1/nginx_status"
    access_log = p.get("access_log") or "/var/log/nginx/access.log"
    error_log = p.get("error_log") or "/var/log/nginx/error.log"
    log_lines = int(p.get("log_lines", 5000))
    tls_hosts = p.get("tls_hosts") or []

    ver = safe(lambda: _version(bin_), {})
    live = safe(lambda: _stub_status(status_url), {})
    access = safe(lambda: analyze_access_log(tail_lines(access_log, log_lines)), na("access log unavailable"))
    err = safe(lambda: _error_log(error_log), na("error log unavailable"))

    tls = []
    for hp in tls_hosts:
        host, _, port = str(hp).partition(":")
        tls.append(cert_info(host, int(port) if port else 443))

    active = live.get("active_connections")
    hs = {
        "reachable": bool(live.get("reachable")),
        "active_connections": active,
        "requests_total": live.get("requests"),
        "error_rate_pct": access.get("error_rate_pct") if isinstance(access, dict) else None,
        "server_error_rate_pct": access.get("server_error_rate_pct") if isinstance(access, dict) else None,
        "config_ok": None,
    }
    cfg = safe(lambda: _config_test(bin_), {})
    hs["config_ok"] = cfg.get("ok")

    sections = {
        "connectivity_version": {**ver, "config_test": cfg},
        "live_status": live,
        "vhosts_tls": {"certs": tls} if tls else na("no TLS hosts configured to check"),
        "access_log": access,
        "error_log": err,
        "system_resources": None,             # collector fills host resources
        "health_summary": hs,
    }
    metrics = {
        "active_connections": active,
        "requests_total": live.get("requests"),
        "error_rate_pct": hs["error_rate_pct"],
        "config_ok": hs["config_ok"],
        "version": ver.get("version"),
    }
    return {"version": ver.get("version"), "server": "nginx",
            "metrics": metrics, "sections": sections}
