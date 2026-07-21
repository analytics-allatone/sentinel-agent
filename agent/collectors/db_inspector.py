"""
collectors/db_inspector.py
==========================
INSPECTION ONLY — the thread side. Detection is NOT here; it's the plain
function collectors/db_detect.py::run_detect().

    inspector = DatabaseInspector(dispatch, machine_info, control_url=...)
    inspector.set_detected(run_detect(dispatch, machine_info))   # feed the inventory
    inspector.start()        # thread runs ONLY while something is ticked

The thread:
  * re-reads the selection (cheap) every control_interval,
  * inspects only engines/targets the user ticked, on poll_interval,
  * exits on its own when nothing is enabled.
"""
import os
import sys
import json
import time
import threading
import importlib
import importlib.util
import urllib.request
from typing import Callable, List, Dict, Any, Optional, Tuple

from schema.db_event_base import EventOutcome, Severity
from schema.db_events import EVENT_FOR_ENGINE
from collectors.db_detect import _os_resources

INSPECTORS = {"postgresql": "postgres", "mysql": "mysql", "mariadb": "mysql",
              "oracle": "oracle", "redis": "redis", "mongodb": "mongo"}
NEEDS_LOGIN = {"postgresql", "mysql", "mariadb", "oracle", "redis"}
_ALIAS = {"postgres": "postgresql", "pg": "postgresql", "psql": "postgresql",
          "mongo": "mongodb"}


def _canon(e: str) -> str:
    return _ALIAS.get(str(e).strip().lower(), str(e).strip().lower())


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


def _auth_candidates(engine, creds, allow_auto) -> List[Tuple[str, Dict[str, Any]]]:
    out = []
    if creds:
        c = dict(creds)
        env = c.get("password_env")
        if env and os.getenv(env):
            c["password"] = os.getenv(env)
        out.append(("configured", c))
    if engine in ("redis", "mongodb"):
        out.append(("no-auth", {}))
    return out


class DatabaseInspector:
    def __init__(self, dispatch: Callable, machine_info: dict,
                 config_file: Optional[str] = None, poll_interval: float = 300.0,
                 control_url: Optional[str] = None):
        self._dispatch = dispatch
        self._machine_info = machine_info
        self._config_file = _resolve_config_file(config_file)
        self._control_url = control_url 
        # or os.getenv("DB_CONTROL_URL")
        self._poll_interval = poll_interval
        self._control_interval = 10.0
        self._engines_cfg: Dict[str, Any] = {}
        self._targets: List[Dict[str, Any]] = []
        self._enabled: set = set()
        self._enabled_targets: set = set()
        self._allow_auto_auth = False
        self._detected: List[Dict[str, Any]] = []
        self._os: Dict[str, Any] = {}
        self._stop = threading.Event()
        self._thread = None
        self._last_cfg: Optional[Dict[str, Any]] = None

    # ── the detect function feeds this ────────────────
    def set_detected(self, found: List[Dict[str, Any]]):
        """Hand in the inventory from run_detect(). Call again after any re-detect."""
        self._detected = list(found or [])

    # ── control ───────────────────────────────────────
    def _agent_name(self) -> str:
        return (self._machine_info or {}).get("agent_name") or \
               (self._machine_info or {}).get("host_name") or "agent"

    def _read_control(self) -> Dict[str, Any]:
        cfg: Dict[str, Any] = {}
        if self._config_file and os.path.isfile(self._config_file):
            try:
                with open(self._config_file) as fh:
                    cfg.update(json.load(fh) or {})
            except Exception as ex:
                print(f"control file unreadable: {ex}")
        if self._agent_name() in cfg and "enabled_engines" not in cfg:
            cfg = cfg[self._agent_name()]
        file_targets = list(cfg.get("targets", []))
        if self._control_url:
            try:
                sep = "&" if "?" in self._control_url else "?"
                req = urllib.request.Request(
                    f"{self._control_url}{sep}agent={self._agent_name()}",
                    headers={"Accept": "application/json"})
                with urllib.request.urlopen(req, timeout=8) as resp:
                    remote = json.loads(resp.read().decode("utf-8")) or {}
                if "enabled_engines" not in remote and self._agent_name() in remote:
                    remote = remote[self._agent_name()]
                by_name = {t.get("name"): t for t in file_targets}
                for t in remote.pop("targets", []) or []:
                    by_name[t.get("name")] = t
                cfg.update(remote)
                cfg["targets"] = list(by_name.values())
                self._last_cfg = dict(cfg)
            except Exception as ex:
                print(f"control fetch failed: {ex}")
                if self._last_cfg is not None:
                    return dict(self._last_cfg)
        return cfg

    def _load_config(self):
        cfg = self._read_control() or {}
        self._poll_interval = float(cfg.get("poll_interval", self._poll_interval))
        self._control_interval = float(cfg.get("control_interval", self._control_interval))
        self._engines_cfg = {_canon(k): v for k, v in (cfg.get("engines", {}) or {}).items()}
        self._targets = cfg.get("targets", []) or []
        self._allow_auto_auth = bool(cfg.get("allow_auto_auth", False))
        enabled = {_canon(e) for e in cfg.get("enabled_engines", []) if isinstance(e, str)}
        if "mysql" in enabled:
            enabled.add("mariadb")
        if "mariadb" in enabled:
            enabled.add("mysql")
        self._enabled = enabled
        self._enabled_targets = {t for t in cfg.get("enabled_targets", []) if isinstance(t, str)}

    # ── emit ──────────────────────────────────────────
    def _send(self, ev):
        self._dispatch(ev.to_dict(), self._machine_info)

    def _base(self, d: Dict[str, Any]):
        EventCls = EVENT_FOR_ENGINE.get(d["engine"])
        if EventCls is None:
            return None
        ev = EventCls()
        ev.action = "db_detected"
        ev.outcome = EventOutcome.SUCCESS
        ev.detected = True
        ev.running = bool(d.get("running", True))
        ev.db_host = d.get("host")
        ev.db_port = d.get("port")
        ev.process_pid = d.get("pid")
        ev.exe_path = d.get("exe_path")
        ev.service_name = d.get("service_name")
        ev.system_resources = self._os or None
        ev.target_name = d.get("name") or d.get("target_name")
        ev.tags = ["database", "discovery", d["engine"]]
        return ev

    # ── inspect one detected engine ───────────────────
    def _inspect(self, ev, d: Dict[str, Any]):
        engine = d["engine"]
        mod_name = INSPECTORS.get(engine)
        if not mod_name:
            ev.inspected = False
            ev.notes = "no inspector for this engine"
            return
        probe = importlib.import_module(f"collectors.dbprobe.{mod_name}")
        if importlib.util.find_spec(probe.DRIVER) is None:
            ev.inspected = False
            ev.notes = f"driver '{probe.DRIVER}' not installed (pip install {probe.DRIVER})"
            return
        creds = self._engines_cfg.get(engine) or \
            (self._engines_cfg.get("mysql") if engine == "mariadb" else None)
        if engine in NEEDS_LOGIN and not creds and not self._allow_auto_auth:
            ev.inspected = False
            ev.notes = "enabled — awaiting credentials"
            return
        last_err = None
        for method, cand in _auth_candidates(engine, creds, self._allow_auto_auth):
            params = {"host": d.get("host") or "127.0.0.1", "port": d.get("port")}
            params.update(cand)
            try:
                res = probe.inspect(params)
                ev.auth_method = method
                ev.apply_inspect(res)
                return
            except Exception as e:
                last_err = e
        ev.inspected = False
        ev.severity = Severity.LOW
        ev.inspect_error = str(last_err)[:300] if last_err else None
        ev.notes = "enabled but login failed (check credentials)"

    def _inspect_target(self, t: Dict[str, Any]):
        engine = _canon(t.get("engine"))
        host = t.get("host", "127.0.0.1")
        name = t.get("name") or f"{engine}@{host}"
        EventCls = EVENT_FOR_ENGINE.get(engine)
        if EventCls is None:
            return
        ev = EventCls()
        ev.action = "db_detected"
        ev.outcome = EventOutcome.SUCCESS
        ev.detected = True
        ev.db_host = host
        ev.db_port = t.get("port")
        ev.service_name = t.get("service_name")
        ev.system_resources = self._os or None
        ev.target_name = name
        ev.tags = ["database", "discovery", engine, "remote"]
        mod_name = INSPECTORS.get(engine)
        if not mod_name:
            ev.inspected = False
            ev.notes = f"no inspector for '{engine}'"
            self._send(ev); return
        probe = importlib.import_module(f"collectors.dbprobe.{mod_name}")
        params = dict(t)
        env = params.get("password_env")
        if env and os.getenv(env):
            params["password"] = os.getenv(env)
        try:
            res = probe.inspect(params)
            ev.running = True
            ev.auth_method = "configured"
            ev.apply_inspect(res)
        except Exception as e:
            ev.running = False
            ev.inspected = False
            ev.severity = Severity.LOW
            ev.inspect_error = str(e)[:300]
            ev.notes = f"target unreachable or login failed ({host})"
        self._send(ev)

    # ── one inspection pass over ENABLED items only ───
    def inspect_once(self):
        self._os = _os_resources()
        for d in list(self._detected):
            if d.get("engine") not in self._enabled:
                continue
            ev = self._base(d)
            if ev is None:
                continue
            try:
                self._inspect(ev, d)
            except Exception as ex:
                ev.inspected = False
                ev.inspect_error = str(ex)[:300]
            self._send(ev)
        for t in self._targets:
            if (t.get("name") or "") in self._enabled_targets:
                try:
                    self._inspect_target(t)
                except Exception as ex:
                    print(f"target error ({t.get('name')}): {ex}")

    # ── thread ────────────────────────────────────────
    def _loop(self):
        print("[inspect] thread started")
        while not self._stop.is_set():
            try:
                self._load_config()
                if not (self._enabled or self._enabled_targets):
                    print("[inspect] nothing enabled — thread exiting")
                    return
                self.inspect_once()
            except Exception as ex:
                print(f"[inspect] cycle error: {ex}")
            slept = 0.0
            while slept < self._poll_interval and not self._stop.is_set():
                time.sleep(0.5); slept += 0.5

    def start(self):
        """Start the inspection thread (safe to call repeatedly — no-op if alive)."""
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True, name="db-inspect")
        self._thread.start()

    def stop(self):
        self._stop.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)
