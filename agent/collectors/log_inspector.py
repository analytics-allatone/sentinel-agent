import time
import threading
import importlib
import importlib.util
import sys
from schema.db_event_base import EventOutcome, Severity
from schema.db_events import EVENT_FOR_ENGINE

INSPECTORS = {"postgresql": "postgres", "mysql": "mysql", "mariadb": "mysql",
              "oracle": "oracle", "redis": "redis", "mongodb": "mongo"}
_ALIAS = {"postgres": "postgresql", "pg": "postgresql", "psql": "postgresql",
          "mongo": "mongodb"}
_DEFAULT_PORT = {"postgresql": 5432, "mysql": 3306, "mariadb": 3306,
                 "oracle": 1521, "redis": 6379, "mongodb": 27017}

# keys used by this class only — everything else in the detail dict is passed
# through to the probe untouched (dbname, service_name, sid, sslmode, ...).
_CONTROL_KEYS = {"engine", "action"}


def _canon(e):
    e = str(e or "").strip().lower()
    return _ALIAS.get(e, e)


def _driver_status(name):
    
    if not name:
        return "ok", None
    if name in sys.modules:            # already imported successfully
        return "ok", None
    try:
        importlib.import_module(name)
        return "ok", None
    except ModuleNotFoundError as e:
        # Only "missing" if the driver ITSELF is absent. If it raised because
        # one of its own imports is absent, the driver is installed but broken.
        if (getattr(e, "name", "") or "").split(".")[0] == name.split(".")[0]:
            return "missing", f"driver '{name}' not installed (pip install {name})"
        return "broken", f"driver '{name}' installed but unusable: {e}"
    except BaseException as e: 
        # Blocked DLL / bad build / missing .so surface as ImportError, OSError
        # or occasionally SystemError. None of these should kill the thread.
        return "broken", f"driver '{name}' installed but unusable: {e}"
 

def _build_params(engine, detail):
    
    params = {k: v for k, v in (detail or {}).items() if k not in _CONTROL_KEYS}
    # accept user_name (API naming) but hand the probe the usual "user"
    if "user_name" in params :
        params["user"] = params.pop("user_name")
    params["host"] = params.get("host", "127.0.0.1")
    if not params.get("port"):
        params["port"] = _DEFAULT_PORT.get(engine)
    return params


class LogInspector:
    def __init__(self, dispatch, machine_info, interval=60.0):
        self._dispatch = dispatch
        self._machine_info = machine_info
        self._interval = interval
        self._threads = {}   # engine -> Thread
        self._stops = {}     # engine -> Event
        self._driver_error = {}   

    # ── start one engine, or many if a list of details is given ──
    def start(self, detail):
        if isinstance(detail, (list, tuple)):
            return [self._start_one(d) for d in detail]
        return self._start_one(detail)

    def _start_one(self, detail):
        engine = _canon((detail or {}).get("engine"))
        if engine not in INSPECTORS:
            return {"ok": False, "engine": engine, "error": "unknown engine"}
        if engine in self._threads and self._threads[engine].is_alive():
            return {"ok": False, "engine": engine, "error": "already running"}

        params = _build_params(engine, detail)

        stop = threading.Event()
        self._stops[engine] = stop
        t = threading.Thread(target=self._loop, name=f"inspect-{engine}",
                             daemon=True, args=(engine, params, stop))
        self._threads[engine] = t
        t.start()
        return {"ok": True, "engine": engine, "status": "started",
                "host": params.get("host"), "port": params.get("port")}

    # ── the per-engine thread: loop inspect() -> send() ──
    def _loop(self, engine, params, stop):
        print(f"[inspect] {engine}: thread started")
        while not stop.is_set():
            try:
                ev = self.inspect(engine, params)
                if ev is not None:
                    self.send(ev)
            except Exception as ex:
                print(f"[inspect] {engine}: error {ex}")
            slept = 0.0
            while slept < self._interval and not stop.is_set():
                time.sleep(0.5)
                slept += 0.5
        print(f"[inspect] {engine}: thread stopped")

    # ── inspect: build the engine event, call dbprobe with params ──
    def inspect(self, engine, params):
        EventCls = EVENT_FOR_ENGINE.get(engine)
        
        if EventCls is None:
            return None

        host = params.get("host")
        
        ev = EventCls()
        ev.action = "db_detected"
        ev.outcome = EventOutcome.SUCCESS
        ev.detected = True
        ev.db_host = host
        ev.db_port = params.get("port")
        ev.db_name  = params.get("dbname") 
        ev.service_name = params.get("service_name")        
        ev.target_name = f"{engine}@{host}"
        print(ev.target_name)
        ev.tags = ["database", "inspect", engine]
        try:
            probe = importlib.import_module(f"collectors.dbprobe.{INSPECTORS[engine]}")
            status, msg = _driver_status(getattr(probe, "DRIVER", None))
            if status != "ok":
                raise ImportError(msg)
            # probe = importlib.import_module(f"collectors.dbprobe.{INSPECTORS[engine]}")
            # if importlib.util.find_spec(probe.DRIVER) is None:
            #     raise ImportError(f"driver '{probe.DRIVER}' not installed "
            #                       f"(pip install {probe.DRIVER})")
        except BaseException as e:
            # BaseException: a blocked DLL surfaces as OSError/ImportError, but
            # some loaders raise SystemError — none of them should kill the thread.
            msg = str(e)[:300]
            self._driver_error[engine] = msg
            ev.running = False
            ev.inspected = False
            ev.severity = Severity.LOW
            ev.inspect_error = msg
            ev.notes = f"driver unavailable for {engine}: {msg}"
            return ev
        # print(ev)
        # print(engine)
        # probe = print(importlib.import_module(f"collectors.dbprobe.{INSPECTORS[engine]}"))
        # print(probe)
        # if importlib.util.find_spec(probe.DRIVER) is None:
        #     print("soni")
        #     ev.running = False
        #     ev.inspected = False
        #     ev.severity = Severity.LOW
        #     ev.notes = f"driver '{probe.DRIVER}' not installed (pip install {probe.DRIVER})"
            return ev

        try:
            print(params)
            print(probe)
            res = probe.inspect(params)          # whole dict goes to the probe
            print(res)
            ev.running = True
            ev.auth_method = "configured"
            ev.apply_inspect(res)
        except Exception as e:
            ev.running = False
            ev.inspected = False
            ev.severity = Severity.LOW
            ev.inspect_error = str(e)[:300]
            ev.notes = f"unreachable or login failed ({host})"
        return ev

    # ── send: dispatch the event out (same as the inspector's _send) ──
    def send(self, ev):
        self._dispatch(ev.to_dict(), self._machine_info)

    # ── stop one engine by name, or many if a list is given ──
    def stop(self, engine):
        if isinstance(engine, (list, tuple)):
            return [self._stop_one(e) for e in engine]
        return self._stop_one(engine)

    def _stop_one(self, engine):
        engine = _canon(engine)
        stop = self._stops.get(engine)
        if not stop:
            return {"ok": False, "engine": engine, "error": "not running"}
        stop.set()
        t = self._threads.get(engine)
        if t:
            t.join(timeout=5)
        self._threads.pop(engine, None)
        self._stops.pop(engine, None)
        return {"ok": True, "engine": engine, "status": "stopped"}
