"""
collectors/webprobe/apache.py
=============================
Apache httpd health probe. Same {version, metrics, sections} contract as nginx,
so it maps onto the same web_server_events table (server='apache' distinguishes).

Sections mirror nginx where possible:
  connectivity_version   binary, version, MPM, config test (apachectl -t)
  live_status            mod_status (?auto): busy/idle workers, req/sec, bytes
  vhosts_tls             TLS cert expiry per configured HTTPS host
  access_log / error_log same analysis as nginx
  system_resources / health_summary
"""
import os
import re
from ._util import (http_get, run_cmd, tail_lines, cert_info,
                    analyze_access_log, na, safe)

DRIVER = "urllib.request"


def _bin(p):
    if p.get("bin"):
        return p["bin"]
    for c in ("apachectl", "apache2ctl", "httpd"):
        rc, out, err = run_cmd([c, "-v"])
        if rc == 0 or "Server version" in (out + err):
            return c
    return "httpd"


def _version(bin_):
    rc, out, err = run_cmd([bin_, "-v"])
    txt = (out or err or "")
    m = re.search(r"Apache/([0-9.]+)", txt)
    mpm = None
    rc2, o2, e2 = run_cmd([bin_, "-V"])
    mm = re.search(r"-D APACHE_MPM_DIR=\"server/mpm/(\w+)\"", o2 + e2) or \
        re.search(r"MPM:\s+(\w+)", o2 + e2)
    if mm:
        mpm = mm.group(1)
    return {"binary": bin_, "version": m.group(1) if m else None, "mpm": mpm,
            "raw": txt.strip()[:200]}


def _config_test(bin_):
    rc, out, err = run_cmd([bin_, "-t"])
    return {"ok": rc == 0, "output": (err or out).strip()[:500]}


def _server_status(url):
    # mod_status machine-readable endpoint: http://127.0.0.1/server-status?auto
    if "?auto" not in url:
        url = url + ("&auto" if "?" in url else "?auto")
    st, body = http_get(url)
    if st != 200:
        return {"reachable": False, "http_status": st, "url": url}
    d = {"reachable": True, "url": url}
    keymap = {
        "Total Accesses": ("total_accesses", int),
        "Total kBytes": ("total_kbytes", int),
        "BusyWorkers": ("busy_workers", int),
        "IdleWorkers": ("idle_workers", int),
        "ReqPerSec": ("req_per_sec", float),
        "BytesPerSec": ("bytes_per_sec", float),
        "Uptime": ("uptime_seconds", int),
        "ConnsTotal": ("conns_total", int),
    }
    for line in body.splitlines():
        if ":" not in line:
            continue
        k, _, v = line.partition(":")
        k, v = k.strip(), v.strip()
        if k in keymap:
            name, cast = keymap[k]
            try:
                d[name] = cast(float(v)) if cast is int else cast(v)
            except ValueError:
                pass
    return d


def _error_log(path, n=2000):
    lines = tail_lines(path, n)
    by_level = {}
    recent = []
    for ln in lines:
        m = re.search(r"\[[^\]]*:(emerg|alert|crit|error|warn|notice|info|debug)\]", ln)
        lvl = m.group(1) if m else "other"
        by_level[lvl] = by_level.get(lvl, 0) + 1
    for ln in reversed(lines):
        if re.search(r":(emerg|alert|crit|error)\]", ln):
            recent.append(ln.strip()[:400])
        if len(recent) >= 20:
            break
    return {"path": path, "sampled_lines": len(lines), "by_level": by_level,
            "recent_errors": recent}


def inspect(params):
    p = params or {}
    bin_ = _bin(p)
    status_url = p.get("status_url") or "http://127.0.0.1/server-status?auto"
    access_log = p.get("access_log") or "/var/log/apache2/access.log"
    error_log = p.get("error_log") or "/var/log/apache2/error.log"
    log_lines = int(p.get("log_lines", 5000))
    tls_hosts = p.get("tls_hosts") or []

    ver = safe(lambda: _version(bin_), {})
    cfg = safe(lambda: _config_test(bin_), {})
    live = safe(lambda: _server_status(status_url), {})
    access = safe(lambda: analyze_access_log(tail_lines(access_log, log_lines)), na("access log unavailable"))
    err = safe(lambda: _error_log(error_log), na("error log unavailable"))

    tls = []
    for hp in tls_hosts:
        host, _, port = str(hp).partition(":")
        tls.append(cert_info(host, int(port) if port else 443))

    hs = {
        "reachable": bool(live.get("reachable")),
        "busy_workers": live.get("busy_workers"),
        "idle_workers": live.get("idle_workers"),
        "req_per_sec": live.get("req_per_sec"),
        "uptime_seconds": live.get("uptime_seconds"),
        "error_rate_pct": access.get("error_rate_pct") if isinstance(access, dict) else None,
        "server_error_rate_pct": access.get("server_error_rate_pct") if isinstance(access, dict) else None,
        "config_ok": cfg.get("ok"),
    }
    sections = {
        "connectivity_version": {**ver, "config_test": cfg},
        "live_status": live,
        "vhosts_tls": {"certs": tls} if tls else na("no TLS hosts configured to check"),
        "access_log": access,
        "error_log": err,
        "system_resources": None,
        "health_summary": hs,
    }
    metrics = {
        "busy_workers": live.get("busy_workers"),
        "idle_workers": live.get("idle_workers"),
        "req_per_sec": live.get("req_per_sec"),
        "uptime_seconds": live.get("uptime_seconds"),
        "error_rate_pct": hs["error_rate_pct"],
        "config_ok": hs["config_ok"],
        "version": ver.get("version"),
    }
    return {"version": ver.get("version"), "server": "apache",
            "metrics": metrics, "sections": sections}
