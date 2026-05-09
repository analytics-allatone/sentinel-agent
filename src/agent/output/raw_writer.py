# """
# Sentinel Agent - Raw Log Writer
# Writes ALL collector events into a single sentinel-raw.log file.
# Each section is clearly labelled by collector type.
# No JSON, no CSV - plain human readable text.

# Sample output:

# ============================================================
# [FILE RAW LOG]
# ============================================================
# Timestamp   : 2024-01-15 10:23:45 UTC
# Severity    : HIGH
# Action      : file_modified
# Outcome     : success
# Collector   : file_watcher
# Host        : DESKTOP-ABC (192.168.1.15) Windows
# User        : admin  UID=1000  GID=1000  HOME=/home/admin
# File        : C:\Users\admin\secret.txt
# Size        : 2048 bytes
# Permissions : -rw-r--r--
# Owner       : admin / staff
# Inode       : 123456
# Modified At : 2024-01-15T10:23:44+00:00
# SHA256      : abc123...
# SHA1        : def456...
# MD5         : ghi789...
# Tags        : filesystem|high_value_path
# ------------------------------------------------------------

# ============================================================
# [AUTH RAW LOG]
# ============================================================
# Timestamp   : 2024-01-15 10:24:00 UTC
# Severity    : HIGH
# Action      : login_failed
# Outcome     : failure
# Collector   : auth_monitor
# Host        : DESKTOP-ABC (192.168.1.15) Windows
# User        : admin  UID=0  TTY=pts/0  FROM=192.168.1.99
# Auth Method : password
# Fail Reason : incorrect password
# Event ID    : 4625
# Tags        : auth|failed_login|brute_force_risk
# ------------------------------------------------------------

# ============================================================
# [NETWORK RAW LOG]
# ============================================================
# Timestamp   : 2024-01-15 10:24:10 UTC
# Severity    : CRITICAL
# Action      : connection_established
# Outcome     : success
# Collector   : network_monitor
# Host        : DESKTOP-ABC (192.168.1.15) Windows
# Direction   : outbound
# Transport   : tcp
# Protocol    : https
# Source      : 192.168.1.15:54231
# Destination : 142.250.80.46:443
# Conn Status : ESTABLISHED
# Private IP  : False
# Process     : chrome.exe PID=4521 USER=admin
# Executable  : C:\Program Files\Google\Chrome\chrome.exe
# Command     : chrome.exe --type=renderer
# Tags        : network|external
# ------------------------------------------------------------

# ============================================================
# [PROCESS RAW LOG]
# ============================================================
# Timestamp   : 2024-01-15 10:24:20 UTC
# Severity    : MEDIUM
# Action      : process_started
# Outcome     : success
# Collector   : process_monitor
# Host        : DESKTOP-ABC (192.168.1.15) Windows
# PID         : 4521
# PPID        : 1234
# Name        : powershell.exe
# Executable  : C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
# Command     : powershell.exe -enc BASE64STRING
# Working Dir : C:\Users\admin
# User        : admin
# Started At  : 2024-01-15T10:24:19+00:00
# SHA256      : abc123...
# Tags        : process|lolbin|suspicious_args
# MITRE       : Execution / T1059
# ------------------------------------------------------------

# ============================================================
# [USB / PENDRIVE RAW LOG]
# ============================================================
# Timestamp   : 2024-01-15 10:25:00 UTC
# Severity    : LOW
# Action      : usb_connected
# Outcome     : success
# Collector   : usb_monitor
# Host        : DESKTOP-ABC (192.168.1.15) Windows
# Mount Point : E:\
# Label       : KINGSTON
# Device      : \\.\PHYSICALDRIVE1
# Fstype      : FAT32
# Serial      : AA040217
# Model       : DataTraveler
# Size        : 32.0GB
# Tags        : usb|removable_media
# ------------------------------------------------------------

# ============================================================
# [HARD DISK RAW LOG]
# ============================================================
# Timestamp   : 2024-01-15 10:26:00 UTC
# Severity    : HIGH
# Action      : disk_space_critical
# Outcome     : failure
# Collector   : harddisk_monitor
# Host        : DESKTOP-ABC (192.168.1.15) Windows
# Mount Point : C:\
# Device      : C:\
# Percent     : 96.2%
# Notes       : Disk critically full - potential DoS risk
# Tags        : disk|disk_full|disk_space_critical
# ------------------------------------------------------------
# """

import threading
import gzip
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from ..logger import Logger

logger = Logger.get_logger(__name__)

DIVIDER = "=" * 60
SUBDIV  = "-" * 60


def _ts(raw: str) -> str:
    try:
        dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return raw or datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _val(*values) -> str:
    for v in values:
        if v is not None and str(v).strip() not in ("", "None", "0", "null"):
            return str(v)
    return ""


def _tags(event: dict) -> str:
    tags = event.get("tags") or []
    return "|".join(str(t) for t in tags) if isinstance(tags, list) else str(tags)


# ─────────────────────────────────────────────────────────────
#  COMMON HEADER / FOOTER
# ─────────────────────────────────────────────────────────────

def _header(event: dict, label: str) -> list:
    host = event.get("host") or {}
    hostname = _val(host.get("hostname"), host.get("name"))
    host_ip  = _val(host.get("ip"), host.get("ip_address"))
    host_os  = _val(host.get("os"), host.get("platform"))
    return [
        "",
        DIVIDER,
        f"[{label}]",
        DIVIDER,
        f"Timestamp   : {_ts(event.get('timestamp', ''))}",
        f"Severity    : {(event.get('severity') or 'info').upper()}",
        f"Action      : {event.get('action', '')}",
        f"Outcome     : {event.get('outcome', '')}",
        f"Collector   : {event.get('collector', '')}",
        f"Host        : {hostname} ({host_ip}) {host_os}",
    ]


def _footer(event: dict) -> list:
    lines = []
    notes        = event.get("notes") or ""
    mitre_tactic = event.get("mitre_tactic") or ""
    mitre_tech   = event.get("mitre_technique") or ""
    tags         = _tags(event)

    if notes:        lines.append(f"Notes       : {notes}")
    if mitre_tactic: lines.append(f"MITRE       : {mitre_tactic} / {mitre_tech}")
    if tags:         lines.append(f"Tags        : {tags}")
    lines.append(SUBDIV)
    return lines


# ─────────────────────────────────────────────────────────────
#  PER-COLLECTOR FORMATTERS
# ─────────────────────────────────────────────────────────────

def _fmt_file(event: dict) -> str:
    lines = _header(event, "FILE RAW LOG")

    # User details
    u = event.get("user") or {}
    if _val(u.get("name")):
        uline = f"User        : {u['name']}"
        if _val(u.get("uid")):           uline += f"  UID={u['uid']}"
        if _val(u.get("gid")):           uline += f"  GID={u['gid']}"
        if _val(u.get("effective_uid")): uline += f"  EUID={u['effective_uid']}"
        if _val(u.get("home_dir")):      uline += f"  HOME={u['home_dir']}"
        if _val(u.get("shell")):         uline += f"  SHELL={u['shell']}"
        lines.append(uline)

    # File details
    f = event.get("file") or {}
    if _val(f.get("path")):        lines.append(f"File        : {f['path']}")
    if _val(f.get("old_path")):    lines.append(f"Old Path    : {f['old_path']}")
    if _val(f.get("extension")):   lines.append(f"Extension   : {f['extension']}")
    if _val(f.get("size_bytes")):  lines.append(f"Size        : {f['size_bytes']} bytes")
    if _val(f.get("permissions")): lines.append(f"Permissions : {f['permissions']}")
    if _val(f.get("owner")):       lines.append(f"Owner       : {f['owner']} / {f.get('group','')}")
    if _val(f.get("inode")):       lines.append(f"Inode       : {f['inode']}")
    if _val(f.get("modified_at")): lines.append(f"Modified At : {f['modified_at']}")
    if _val(f.get("created_at")):  lines.append(f"Created At  : {f['created_at']}")
    if _val(f.get("sha256")):      lines.append(f"SHA256      : {f['sha256']}")
    if _val(f.get("sha1")):        lines.append(f"SHA1        : {f['sha1']}")
    if _val(f.get("md5")):         lines.append(f"MD5         : {f['md5']}")
    if _val(f.get("old_sha256")):  lines.append(f"Old SHA256  : {f['old_sha256']}")

    lines += _footer(event)
    return "\n".join(lines)


def _fmt_auth(event: dict) -> str:
    lines = _header(event, "AUTH RAW LOG")

    u = event.get("user") or {}
    if _val(u.get("name")):
        uline = f"User        : {u['name']}"
        if _val(u.get("uid")):       uline += f"  UID={u['uid']}"
        if _val(u.get("gid")):       uline += f"  GID={u['gid']}"
        if _val(u.get("terminal")): uline += f"  TTY={u['terminal']}"
        if _val(u.get("remote_ip")):uline += f"  FROM={u['remote_ip']}"
        lines.append(uline)

    if _val(u.get("auth_method")):   lines.append(f"Auth Method : {u['auth_method']}")
    if _val(u.get("session_id")):    lines.append(f"Session ID  : {u['session_id']}")
    if _val(u.get("sudo_command")):  lines.append(f"Sudo Cmd    : {u['sudo_command']}")
    if _val(u.get("target_user")):   lines.append(f"Target User : {u['target_user']}")
    if _val(u.get("failure_reason")):lines.append(f"Fail Reason : {u['failure_reason']}")
    if _val(u.get("event_id")):      lines.append(f"Event ID    : {u['event_id']}")
    if _val(u.get("logon_type")):    lines.append(f"Logon Type  : {u['logon_type']}")

    lines += _footer(event)
    return "\n".join(lines)


def _fmt_network(event: dict) -> str:
    lines = _header(event, "NETWORK RAW LOG")

    net = event.get("network") or {}
    if _val(net.get("direction")):         lines.append(f"Direction   : {net['direction']}")
    if _val(net.get("transport")):         lines.append(f"Transport   : {net['transport']}")
    if _val(net.get("protocol")):          lines.append(f"Protocol    : {net['protocol']}")

    src_ip   = _val(net.get("src_ip"))
    src_port = _val(net.get("src_port"))
    dst_ip   = _val(net.get("dst_ip"))
    dst_port = _val(net.get("dst_port"))

    if src_ip:
        lines.append(f"Source      : {src_ip}:{src_port}" if src_port else f"Source      : {src_ip}")
    if dst_ip:
        lines.append(f"Destination : {dst_ip}:{dst_port}" if dst_port else f"Destination : {dst_ip}")

    if _val(net.get("connection_status")): lines.append(f"Conn Status : {net['connection_status']}")
    if _val(net.get("is_private_ip")):     lines.append(f"Private IP  : {net['is_private_ip']}")
    if _val(net.get("bytes_sent")):        lines.append(f"Bytes Sent  : {net['bytes_sent']}")
    if _val(net.get("bytes_recv")):        lines.append(f"Bytes Recv  : {net['bytes_recv']}")
    if _val(net.get("dns_query")):         lines.append(f"DNS Query   : {net['dns_query']}")
    if _val(net.get("dns_response")):      lines.append(f"DNS Response: {net['dns_response']}")

    proc = event.get("process") or {}
    if _val(proc.get("pid")):
        lines.append(f"Process     : {_val(proc.get('name'))}  PID={proc['pid']}  USER={_val(proc.get('user'))}")
        if _val(proc.get("executable")):   lines.append(f"Executable  : {proc['executable']}")
        if _val(proc.get("command_line")): lines.append(f"Command     : {proc['command_line']}")
        if _val(proc.get("ppid")):         lines.append(f"Parent PID  : {proc['ppid']}")

    lines += _footer(event)
    return "\n".join(lines)


def _fmt_process(event: dict) -> str:
    lines = _header(event, "PROCESS RAW LOG")

    proc = event.get("process") or {}
    if _val(proc.get("pid")):          lines.append(f"PID         : {proc['pid']}")
    if _val(proc.get("ppid")):         lines.append(f"PPID        : {proc['ppid']}")
    if _val(proc.get("name")):         lines.append(f"Name        : {proc['name']}")
    if _val(proc.get("executable")):   lines.append(f"Executable  : {proc['executable']}")
    if _val(proc.get("command_line")): lines.append(f"Command     : {proc['command_line']}")
    if _val(proc.get("working_dir")):  lines.append(f"Working Dir : {proc['working_dir']}")
    if _val(proc.get("user")):         lines.append(f"User        : {proc['user']}")
    if _val(proc.get("start_time")):   lines.append(f"Started At  : {proc['start_time']}")
    if _val(proc.get("status")):       lines.append(f"Status      : {proc['status']}")
    if _val(proc.get("sha256")):       lines.append(f"SHA256      : {proc['sha256']}")
    if _val(proc.get("cpu_percent")):  lines.append(f"CPU Usage   : {proc['cpu_percent']}%")
    if _val(proc.get("memory_rss_mb")):lines.append(f"Memory RSS  : {proc['memory_rss_mb']} MB")

    lines += _footer(event)
    return "\n".join(lines)


def _fmt_usb(event: dict) -> str:
    lines = _header(event, "USB / PENDRIVE RAW LOG")

    f = event.get("file") or {}
    if _val(f.get("path")): lines.append(f"Mount Point : {f['path']}")
    if _val(f.get("name")): lines.append(f"Label       : {f['name']}")

    # Parse structured fields from notes
    notes = event.get("notes") or ""
    for part in notes.split("  "):
        part = part.strip()
        if "=" in part:
            k, _, v = part.partition("=")
            k = k.strip()
            v = v.strip().strip("'")
            if not v or k.lower() in ("mount point", "label"):
                continue
            k_fmt = {
                "device":  "Device",
                "fs":      "Filesystem",
                "fstype":  "Filesystem",
                "serial":  "Serial",
                "model":   "Model",
                "vendor":  "Vendor",
                "size":    "Size",
            }.get(k.lower(), k.capitalize())
            lines.append(f"{k_fmt:<12}: {v}")

    lines += _footer(event)
    return "\n".join(lines)


def _fmt_harddisk(event: dict) -> str:
    lines = _header(event, "HARD DISK RAW LOG")

    f = event.get("file") or {}
    if _val(f.get("path")): lines.append(f"Mount Point : {f['path']}")
    if _val(f.get("name")): lines.append(f"Device Name : {f['name']}")

    notes = event.get("notes") or ""
    for part in notes.split("  "):
        part = part.strip()
        if "=" in part:
            k, _, v = part.partition("=")
            k = k.strip()
            v = v.strip()
            k_fmt = {
                "device":  "Device",
                "mount":   "Mount",
                "percent": "Used %",
                "used":    "Used",
                "free":    "Free",
                "total":   "Total",
            }.get(k.lower(), k.capitalize())
            lines.append(f"{k_fmt:<12}: {v}")

    lines += _footer(event)
    return "\n".join(lines)


def _fmt_generic(event: dict) -> str:
    lines = _header(event, "RAW LOG")
    notes = event.get("notes") or ""
    if notes: lines.append(f"Notes       : {notes}")
    lines += _footer(event)
    return "\n".join(lines)


# ─────────────────────────────────────────────────────────────
#  ROUTER
# ─────────────────────────────────────────────────────────────

COLLECTOR_MAP = {
    "file_watcher":     _fmt_file,
    "auth_monitor":     _fmt_auth,
    "network_monitor":  _fmt_network,
    "dns_monitor":      _fmt_network,
    "process_monitor":  _fmt_process,
    "usb_monitor":      _fmt_usb,
    "harddisk_monitor": _fmt_harddisk,
}

CATEGORY_MAP = {
    "file":           _fmt_file,
    "authentication": _fmt_auth,
    "network":        _fmt_network,
    "process":        _fmt_process,
}


def format_event(event: dict) -> str:
    collector = event.get("collector", "")
    category  = event.get("category", "")
    fmt = COLLECTOR_MAP.get(collector) or CATEGORY_MAP.get(category) or _fmt_generic
    return fmt(event)


# ─────────────────────────────────────────────────────────────
#  WRITER CLASS
# ─────────────────────────────────────────────────────────────

class RawLogWriter:
    """
    Writes all events to sentinel-raw.log as clearly labelled
    human-readable blocks. One block per event. Thread-safe.
    Rotates and gzip-compresses when file exceeds max_size_mb.
    """

    def __init__(
        self,
        output_dir:  str   = "./logs",
        base_name:   str   = "sentinel-raw",
        max_size_mb: float = 50.0,
        max_files:   int   = 20,
        compress:    bool  = True,
    ):
        self.output_dir = Path(output_dir)
        self.base_name  = base_name
        self.max_size   = int(max_size_mb * 1024 * 1024)
        self.max_files  = max_files
        self.compress   = compress
        self._lock      = threading.Lock()
        self._fh        = None
        self._current_path: Optional[Path] = None

        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._open_file()
        logger.info(f"Raw log writer started -> {self._current_path}")

    def _log_path(self) -> Path:
        return self.output_dir / f"{self.base_name}.log"

    def _open_file(self):
        self._current_path = self._log_path()
        self._fh = open(self._current_path, "a", encoding="utf-8")

    def _rotate(self):
        if self._fh:
            self._fh.close()
        ts      = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        rotated = self.output_dir / f"{self.base_name}.{ts}.log"
        self._current_path.rename(rotated)
        if self.compress:
            gz_path = rotated.with_suffix(".log.gz")
            with open(rotated, "rb") as fin, gzip.open(gz_path, "wb") as fout:
                fout.write(fin.read())
            rotated.unlink()
        archives = sorted(
            self.output_dir.glob(f"{self.base_name}.*.log*"),
            key=lambda p: p.stat().st_mtime,
        )
        while len(archives) > self.max_files:
            archives.pop(0).unlink(missing_ok=True)
        self._open_file()

    def write(self, event: dict):
        block = format_event(event) + "\n"
        with self._lock:
            try:
                self._fh.write(block)
                self._fh.flush()
                if self._current_path.stat().st_size > self.max_size:
                    self._rotate()
            except Exception as e:
                logger.error(f"Raw log write error: {e}")

    def close(self):
        with self._lock:
            if self._fh:
                self._fh.close()
