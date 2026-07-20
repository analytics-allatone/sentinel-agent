import os
import sys
import json
import time
import getpass
import threading
import importlib
import importlib.util
import urllib.request
from typing import Callable, List, Dict, Any, Optional, Tuple

from schema.db_event_base import EventOutcome, Severity  # enums (old DatabaseHealthEvent no longer used)
from schema.db_events import EVENT_FOR_ENGINE   # per-engine health events -> separate tables
from dotenv import load_dotenv

load_dotenv() 
INSPECTORS = {"postgresql": "postgres", "mysql": "mysql", "mariadb": "mysql",
              "oracle": "oracle", "redis": "redis", "mongodb": "mongo"}

# engines that legitimately connect with no credentials when the user ticks them
NO_AUTH_OK = {"mongodb"}
# engines that require a login before we will connect
NEEDS_LOGIN = {"postgresql", "mysql", "mariadb", "oracle","redis"}


def _app_dir() -> str:
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


def _resolve_config_file(explicit):
    for p in [explicit, os.getenv("DB_INSPECT_FILE"),
              os.path.join(_app_dir(), "..", "config", "db_inspect.json"),
              os.path.join(_app_dir(), "db_inspect.json")]:
        if p and os.path.isfile(p):
            return os.path.abspath(p)
    return None


def _auth_candidates(engine: str, creds: Optional[Dict[str, Any]],
                     allow_auto: bool) -> List[Tuple[str, Dict[str, Any]]]:
    """Login attempts to try, in order.

    Default (allow_auto=False): ONLY the user-provided credentials, plus no-auth
    for Redis/Mongo. No guessing of local peer/trust/root logins — we wait for
    the user to provide details.
    """
    out: List[Tuple[str, Dict[str, Any]]] = []
    if creds:
        c = dict(creds)
        env = c.get("password_env")
        if env and os.getenv(env):
            c["password"] = os.getenv(env)
        out.append(("configured", c))
    if engine in ("redis", "mongodb"):
        out.append(("no-auth", {}))
    if not allow_auto:
        return out
    # ---- opt-in only: guessed local logins ----
    win = sys.platform == "win32"
    if engine == "postgresql":
        if not win:
            out.append(("peer-socket", {"host": None, "user": getpass.getuser(), "dbname": "postgres"}))
            out.append(("peer-postgres", {"host": None, "user": "postgres", "dbname": "postgres"}))
        out.append(("trust-local", {"host": "127.0.0.1", "user": "postgres", "password": "", "dbname": "postgres"}))
    elif engine in ("mysql", "mariadb"):
        if not win:
            out.append(("socket-root", {"user": "root", "unix_socket": "/var/run/mysqld/mysqld.sock"}))
        out.append(("root-nopw", {"user": "root", "password": ""}))
    return out


def _os_resources() -> Dict[str, Any]:
    try:
        import psutil
        vm = psutil.virtual_memory()
        path = "C:\\" if sys.platform == "win32" else "/"
        du = psutil.disk_usage(path)
        res = {"cpu_percent": psutil.cpu_percent(interval=0.3),
               "memory_total_bytes": vm.total, "memory_used_bytes": vm.used, "memory_percent": vm.percent,
               "disk_total_bytes": du.total, "disk_used_bytes": du.used, "disk_percent": du.percent}
        try:
            res["load_avg_1_5_15"] = [round(x, 2) for x in psutil.getloadavg()]
        except Exception:
            pass
        return res
    except Exception as ex:
        return {"error": str(ex)}


def _severity(points: Dict[str, Any]) -> str:
    try:
        wrap = (points.get("transaction_wraparound") or {}).get("databases") or []
        if any((d.get("xid_age") or 0) > 1500000000 for d in wrap):
            return Severity.CRITICAL
        lr = (points.get("active_connections") or {}).get("long_running") or []
        if any((q.get("duration_seconds") or 0) >= 300 for q in lr):
            return Severity.HIGH
    except Exception:
        pass
    return Severity.INFO


class DatabaseDiscoveryCollector:
    def __init__(self, dispatch: Callable, machine_info: dict,
                 config_file: Optional[str] = None, poll_interval: float = 300.0,
                 control_url: Optional[str] = None):
        self._dispatch = dispatch
        self._machine_info = machine_info
        self._config_file = _resolve_config_file(config_file)
        self._control_url = control_url or os.getenv("DB_CONTROL_URL")
        print(self._control_url)
        self._poll_interval = poll_interval
        self._engines_cfg: Dict[str, Any] = {}
        self._targets: List[Dict[str, Any]] = []
        self._enabled: set = set()
        self._enabled_targets: set = set()
        self._allow_auto_auth: bool = False
        self._os: Dict[str, Any] = {}
        self._stop = threading.Event()
        self._thread = None

    # ── control source ────────────────────────────────
    def _agent_name(self) -> str:
        return (self._machine_info or {}).get("agent_name") or \
               (self._machine_info or {}).get("host_name") or "agent"
    def _read_control(self):
        cfg = {}
        if self._config_file and os.path.isfile(self._config_file):
            with open(self._config_file) as fh:
                cfg.update(json.load(fh) or {})
        file_targets = list(cfg.get("targets", []))          # keep file targets

        if self._control_url:
            try:
                url = self._control_url
                sep = "&" if "?" in url else "?"
                req = urllib.request.Request(f"{url}{sep}agent={self._agent_name()}",
                                            headers={"Accept": "application/json"})
                with urllib.request.urlopen(req, timeout=5) as resp:
                    remote = json.loads(resp.read().decode("utf-8")) or {}
                # remote = _http_get_json(self._control_url, self._agent_name())
                if "enabled_engines" not in remote and self._agent_name() in remote:
                    remote = remote[self._agent_name()]
                # union targets by name instead of overwriting
                by_name = {t.get("name"): t for t in file_targets}
                for t in remote.pop("targets", []) or []:
                    by_name[t.get("name")] = t
                cfg.update(remote)
                cfg["targets"] = list(by_name.values())
            except Exception as ex:
                print(f"control fetch failed: {ex}")
        return cfg
    # def _read_control(self) -> Optional[Dict[str, Any]]:
    #     """Merge control from HTTP (if set) over the local file. HTTP wins."""
    #     cfg: Dict[str, Any] = {}
    #     if self._config_file and os.path.isfile(self._config_file):
    #         try:
    #             with open(self._config_file, "r", encoding="utf-8") as fh:
    #                 cfg.update(json.load(fh) or {})
    #         except Exception as ex:
    #             print(f"DB discovery: config unreadable ({ex})")
    #     if self._control_url:
    #         try:
    #             url = self._control_url
    #             sep = "&" if "?" in url else "?"
    #             req = urllib.request.Request(f"{url}{sep}agent={self._agent_name()}",
    #                                         headers={"Accept": "application/json"})
    #             with urllib.request.urlopen(req, timeout=5) as resp:
    #                 remote = json.loads(resp.read().decode("utf-8")) or {}
    #             # shape B: keyed by agent name
    #             if "enabled_engines" not in remote and self._agent_name() in remote:
    #                 remote = remote.get(self._agent_name()) or {}
    #             cfg.update(remote)
    #         except Exception as ex:
    #             print(f"DB discovery: control URL fetch failed ({ex})")
    #     return cfg or None

    def _load_config(self):
        cfg = self._read_control() or {}
        self._poll_interval    = float(cfg.get("poll_interval", self._poll_interval))
        self._engines_cfg      = cfg.get("engines", {}) or {}
        self._targets          = cfg.get("targets", []) or []
        self._allow_auto_auth  = bool(cfg.get("allow_auto_auth", False))
        enabled = {e for e in cfg.get("enabled_engines", []) if isinstance(e, str)}
        # mysql/mariadb share an inspector — enabling one enables the other
        if "mysql" in enabled:
            enabled.add("mariadb")
        if "mariadb" in enabled:
            enabled.add("mysql")
        self._enabled = enabled
        # remote/declared endpoints are gated too — only those the user enabled
        self._enabled_targets = {t for t in cfg.get("enabled_targets", []) if isinstance(t, str)}

    # ── emit ──────────────────────────────────────────
    def _send(self, ev):
        self._dispatch(ev.to_dict(), self._machine_info)

    def _event_for(self, engine: str):
        """The per-engine event class (postgresql/mysql/mariadb/oracle/redis/mongodb)."""
        return EVENT_FOR_ENGINE.get(engine)

    def _base(self, d: Dict[str, Any]):
        """DETECT: build the engine's OWN event with detect fields. Returns None
        for an engine we have no event class for (so nothing spurious is emitted)."""
        EventCls = self._event_for(d["engine"])
        if EventCls is None:
            return None
        ev = EventCls()
        ev.action = "db_detected"
        ev.outcome = EventOutcome.SUCCESS
        ev.detected = True
        ev.running = bool(d.get("running", True))
        ev.db_host = d.get("host")            # None for local engines (kept local by the API)
        ev.db_port = d.get("port")
        ev.process_pid = d.get("pid")
        ev.exe_path = d.get("exe_path")
        ev.service_name = d.get("service_name")
        ev.system_resources = self._os or None
        ev.target_name = d.get("name") or d.get("target_name")   # None for locals -> kind="local"
        ev.tags = ["database", "discovery", d["engine"]]
        return ev

    # ── inspection (only reached for enabled engines) ──
    def _inspect(self, ev, d: Dict[str, Any]):
        engine = d["engine"]
        mod_name = INSPECTORS.get(engine)
        if not mod_name:
            ev.inspected = False
            ev.notes = "detected (no inspector for this engine yet)"
            return
        inspector = importlib.import_module(f"collectors.dbprobe.{mod_name}")
        if importlib.util.find_spec(inspector.DRIVER) is None:
            ev.inspected = False
            ev.notes = f"detected (driver '{inspector.DRIVER}' not installed: pip install {inspector.DRIVER})"
            return

        creds = self._engines_cfg.get(engine) or \
                (self._engines_cfg.get("mysql") if engine == "mariadb" else None)
        print(creds)
        # user ticked an engine that needs a login but gave no credentials
        if engine in NEEDS_LOGIN and not creds and not self._allow_auto_auth:
            ev.inspected = False
            ev.severity = Severity.INFO
            ev.notes = "enabled — awaiting credentials (add this engine's login to db_inspect.json)"
            return

        candidates = _auth_candidates(engine, creds, self._allow_auto_auth)
        if not candidates:
            ev.inspected = False
            ev.notes = "enabled — awaiting credentials"
            return

        last_err = None
        for method, cand in candidates:
            params = {"host": d.get("host") or "127.0.0.1", "port": d.get("port")}
            params.update(cand)
            try:
                res = inspector.inspect(params)
                print(res)
                ev.auth_method = method
                ev.apply_inspect(res)         # fills health onto the same event
                return
            except Exception as e:
                last_err = e
                continue

        ev.inspected = False
        ev.severity = Severity.LOW
        ev.inspect_error = (str(last_err)[:300] if last_err else None)
        ev.notes = "enabled but login failed (check credentials in db_inspect.json)"

    def _inspect_target(self, t: Dict[str, Any]):
        print(t)
        """Explicitly-declared endpoint (local or remote). GATED like local
        engines: it is listed as a target but only connected to once the user
        enables it (name in enabled_targets) AND supplies the login it needs."""
        engine = t.get("engine")
        host = t.get("host", "127.0.0.1")
        name = t.get("name") or f"{engine}@{host}"
        is_remote = host not in ("127.0.0.1", "localhost", "::1")
        EventCls = self._event_for(engine)
        if EventCls is None:
            print(f"DB discovery: no event class for engine '{engine}' — target '{name}' skipped")
            return
        ev = EventCls()
        ev.action = "db_detected"
        ev.outcome = EventOutcome.SUCCESS
        ev.detected = True
        ev.running = None
        ev.db_host = host
        ev.db_port = t.get("port")
        ev.service_name = t.get("service_name")
        ev.system_resources = self._os or None
        ev.target_name = name
        ev.tags = ["database", "discovery", engine or "unknown",
                   "remote" if is_remote else "local"]

        # GATE 1: not enabled -> list only, do NOT connect
        if name not in self._enabled_targets:
            ev.inspected = False
            ev.notes = "declared target — awaiting user selection (enable + provide login to connect)"
            self._send(ev); return

        # GATE 2: enabled but a login-engine with no credentials -> wait for them
        needs_login = engine in ("postgresql", "mysql", "mariadb", "oracle")
        has_creds = bool(t.get("user") or t.get("password") or t.get("password_env") or t.get("service_name"))
        if needs_login and not has_creds and not self._allow_auto_auth:
            ev.inspected = False
            ev.notes = "enabled — awaiting credentials for this target"
            self._send(ev); return

        mod_name = INSPECTORS.get(engine)
        if not mod_name:
            ev.running = None
            ev.inspected = False
            ev.notes = f"configured target '{ev.target_name}' (no inspector for engine '{engine}')"
            self._send(ev); return
        inspector = importlib.import_module(f"collectors.dbprobe.{mod_name}")
        if importlib.util.find_spec(inspector.DRIVER) is None:
            ev.running = None
            ev.inspected = False
            ev.notes = f"configured target (driver '{inspector.DRIVER}' not installed: pip install {inspector.DRIVER})"
            self._send(ev); return
        params = dict(t)
        env = params.get("password_env")
        if env and os.getenv(env):
            params["password"] = os.getenv(env)

        try:
            res = inspector.inspect(params)
            print(res)
            ev.running = True
            ev.auth_method = "configured"
            ev.apply_inspect(res)              # fills health onto the same event
        except Exception as e:
            ev.running = False
            ev.inspected = False
            ev.severity = Severity.LOW
            ev.inspect_error = str(e)[:300]
            ev.notes = f"configured target unreachable or login failed ({host})"
        self._send(ev)

    # ── loop ──────────────────────────────────────────
    def _poll(self):
        from collectors.dbprobe.detect import detect_engines
        while not self._stop.is_set():
            try:
                self._load_config()          # re-read selection + creds each cycle
                self._os = _os_resources()
                for d in detect_engines():
                    ev = self._base(d)
                    if ev is None:                 # no per-engine event class for this engine
                        continue
                    try:
                        self._inspect(ev, d)
                    except Exception as ex:
                        ev.inspected = False
                        ev.inspect_error = str(ex)[:300]
                    self._send(ev)
                # explicitly declared endpoints are always inspected
                for t in self._targets:
                    try:
                        self._inspect_target(t)
                    except Exception as ex:
                        print(f"DB discovery target error ({t.get('name')}): {ex}")
            except Exception as ex:
                print(f"DB discovery cycle error: {ex}")
            slept = 0.0
            while slept < self._poll_interval and not self._stop.is_set():
                # pass
                time.sleep(0.5); slept += 0.5

    def start(self):
        if importlib.util.find_spec("psutil") is None:
            print("DB discovery collector unavailable: psutil not installed"); return
        self._load_config()
        self._thread = threading.Thread(target=self._poll, daemon=True, name="db-discovery")
        self._thread.start()
        print("DB discovery started (detecting; inspection waits for engine selection)")

    def stop(self):
        self._stop.set()