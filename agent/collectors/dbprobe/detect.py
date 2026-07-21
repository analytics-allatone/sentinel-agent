"""
detect.py — credential-free detection of local database engines.

Uses psutil only: listening TCP ports + running process names/exe. No connection
or credentials required. Returns one entry per detected engine:
    {engine, running, port, pid, exe_path, service_name}

Detection signatures (extend SIGNATURES to add engines):
  engine        default port   process names
  postgresql    5432           postgres, postmaster
  mysql         3306           mysqld
  mariadb       3306           mariadbd
  oracle        1521           tnslsnr, ora_pmon_<SID>
  sqlserver     1433           sqlservr
  mongodb       27017          mongod
  redis         6379           redis-server
"""

from typing import List, Dict, Any, Optional
import psutil

# port -> engine (first match wins; mysql/mariadb share 3306 and are
# disambiguated by process name below)
PORT_ENGINE = {
    5432: "postgresql",
    3306: "mysql",
    1521: "oracle",
    1433: "sqlserver",
    27017: "mongodb",
    6379: "redis",
}

# process-name substring -> engine
PROC_ENGINE = [
    ("postmaster", "postgresql"),
    ("postgres",   "postgresql"),
    ("mariadbd",   "mariadb"),
    ("mysqld",     "mysql"),
    ("tnslsnr",    "oracle"),
    ("ora_pmon",   "oracle"),
    ("sqlservr",   "sqlserver"),
    ("mongod",     "mongodb"),
    ("redis-server", "redis"),
]

DEFAULT_PORT = {
    "postgresql": 5432, "mysql": 3306, "mariadb": 3306, "oracle": 1521,
    "sqlserver": 1433, "mongodb": 27017, "redis": 6379,
}


def _proc_engine(name: str, exe: str):
    hay = f"{name or ''} {exe or ''}".lower()
    for needle, engine in PROC_ENGINE:
        if needle in hay:
            return engine
    return None


def _sid_from_pmon(name: str) -> Optional[str]:
    # ora_pmon_<SID>
    if name and name.lower().startswith("ora_pmon_"):
        return name[len("ora_pmon_"):]
    return None


def detect_engines() -> List[Dict[str, Any]]:
    
    found: Dict[str, Dict[str, Any]] = {}

    def add(engine, port=None, pid=None, exe=None, service=None):
        e = found.get(engine)
        if e is None:
            e = {"engine": engine, "running": True, "port": port or DEFAULT_PORT.get(engine),
                 "pid": pid, "exe_path": exe, "service_name": service}
            found[engine] = e
        else:
            # enrich missing fields
            if port and not e.get("port"):
                e["port"] = port
            if pid and not e.get("pid"):
                e["pid"] = pid
            if exe and not e.get("exe_path"):
                e["exe_path"] = exe
            if service and not e.get("service_name"):
                e["service_name"] = service

    # 1) Listening TCP ports
    try:
        for c in psutil.net_connections(kind="inet"):
            if c.status != psutil.CONN_LISTEN or not c.laddr:
                continue
            engine = PORT_ENGINE.get(c.laddr.port)
            if engine:
                add(engine, port=c.laddr.port, pid=c.pid)
    except Exception:
        pass

    # 2) Process names (also disambiguates mysql vs mariadb, derives Oracle SID)
    try:
        for p in psutil.process_iter(["pid", "name", "exe"]):
            info = p.info
            engine = _proc_engine(info.get("name"), info.get("exe"))
            if not engine:
                continue
            service = _sid_from_pmon(info.get("name"))
            add(engine, pid=info.get("pid"), exe=info.get("exe"), service=service)
    except Exception:
        pass

    # If both mysql (from port) and mariadb (from process) detected, the process
    # name is authoritative — drop the generic mysql entry.
    if "mariadb" in found and "mysql" in found and found["mysql"].get("pid") is None:
        found.pop("mysql", None)
    return list(found.values())
