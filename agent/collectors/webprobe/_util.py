"""
collectors/webprobe/_util.py
============================
Shared helpers for the web-server probes (nginx / apache). Mirrors the dbprobe
util style: everything JSON/MQTT-safe, no exceptions leak out of a probe.
"""
import os
import re
import ssl
import time
import socket
import subprocess
import urllib.request
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple


def jsonable(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [jsonable(v) for v in obj]
    if isinstance(obj, (datetime,)):
        return obj.isoformat()
    if isinstance(obj, (bytes, bytearray)):
        return bytes(obj).decode("utf-8", "ignore")
    return obj


def na(reason: str) -> Dict[str, Any]:
    return {"not_applicable": reason}


def safe(fn, default=None):
    try:
        return fn()
    except Exception as ex:                     # never let a section kill the probe
        return {"error": str(ex)[:200]} if default is None else default


def http_get(url: str, timeout: float = 4.0) -> Tuple[int, str]:
    """GET a URL, return (status, body). Used for stub_status / server-status."""
    req = urllib.request.Request(url, headers={"User-Agent": "sentinel-webprobe"})
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE            # status endpoints are often self-signed/local
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
        return resp.status, resp.read().decode("utf-8", "ignore")


def run_cmd(args: List[str], timeout: float = 8.0) -> Tuple[int, str, str]:
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as ex:
        return 1, "", str(ex)


def tail_lines(path: str, n: int = 5000, max_bytes: int = 8_000_000) -> List[str]:
    """Read up to the last n lines of a (possibly large) log file, bounded by bytes."""
    if not path or not os.path.isfile(path):
        return []
    try:
        size = os.path.getsize(path)
        with open(path, "rb") as fh:
            if size > max_bytes:
                fh.seek(-max_bytes, os.SEEK_END)
                fh.readline()                   # drop partial first line
            data = fh.read()
        return data.decode("utf-8", "ignore").splitlines()[-n:]
    except OSError:
        return []


# ---- TLS certificate expiry -------------------------------------------------
def cert_info(host: str, port: int = 443, timeout: float = 4.0) -> Dict[str, Any]:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                cert = ss.getpeercert()
        if not cert:
            # peercert can be empty when verify is disabled; re-fetch with binary
            der = ssl.get_server_certificate((host, port))
            return {"host": host, "port": port, "note": "cert present (details unverified)"}
        not_after = cert.get("notAfter")
        exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        days = round((exp - datetime.now(timezone.utc)).total_seconds() / 86400, 1)
        subject = dict(x[0] for x in cert.get("subject", []))
        issuer = dict(x[0] for x in cert.get("issuer", []))
        return {"host": host, "port": port,
                "common_name": subject.get("commonName"),
                "issuer": issuer.get("organizationName") or issuer.get("commonName"),
                "not_after": exp.isoformat(), "days_to_expiry": days,
                "expired": days < 0}
    except Exception as ex:
        return {"host": host, "port": port, "error": str(ex)[:200]}


# ---- access-log analysis (Common / Combined Log Format) ---------------------
_CLF = re.compile(
    r'(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>\S+)[^"]*"\s+(?P<status>\d{3})\s+(?P<size>\S+)'
)


def analyze_access_log(lines: List[str], top: int = 10) -> Dict[str, Any]:
    total = 0
    status_class = {"2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0}
    by_status: Dict[str, int] = {}
    by_ip: Dict[str, int] = {}
    by_path: Dict[str, int] = {}
    bytes_total = 0
    for ln in lines:
        m = _CLF.search(ln)
        if not m:
            continue
        total += 1
        st = m.group("status")
        by_status[st] = by_status.get(st, 0) + 1
        cls = f"{st[0]}xx"
        if cls in status_class:
            status_class[cls] += 1
        ip = m.group("ip"); by_ip[ip] = by_ip.get(ip, 0) + 1
        path = m.group("path"); by_path[path] = by_path.get(path, 0) + 1
        sz = m.group("size")
        if sz.isdigit():
            bytes_total += int(sz)

    def topn(d):
        return [{"key": k, "count": v} for k, v in
                sorted(d.items(), key=lambda kv: kv[1], reverse=True)[:top]]

    err = status_class["4xx"] + status_class["5xx"]
    return {
        "sampled_requests": total,
        "status_class": status_class,
        "error_rate_pct": round(err * 100.0 / total, 2) if total else 0.0,
        "server_error_rate_pct": round(status_class["5xx"] * 100.0 / total, 2) if total else 0.0,
        "bytes_total": bytes_total,
        "top_status": topn(by_status),
        "top_paths": topn(by_path),
        "top_clients": topn(by_ip),
    }
