# utils/command_registry.py — shared handles that commands operate on
#
# Lock discipline (the important part): _lock guards the dicts ONLY. Every
# handler.start()/stop() and collector.start()/stop() call happens with the
# lock released and behind a timeout, because a collector that wedges while
# holding _lock would freeze the entire command channel.
#
# No disk state: if the process exits, nothing is running when it comes back.
# The control server re-issues start_* commands on reconnect.

import threading

from utils.shutdown import call_with_result

_lock = threading.RLock()

_registry: dict = {}
_status = "active"
_status_busy = False                # a transition is already in flight
_static_collectors: dict = {}
_running_threads: dict = {}
_paused_threads: dict = {}

VALID_STATUS = ("active", "pause")

START_TIMEOUT = 15.0                # collectors can do real work on start
STOP_TIMEOUT = 5.0


# --------------------------------------------------------------------------- #
# registration
# --------------------------------------------------------------------------- #

def add_static_collector(collector_name, collector):
    with _lock:
        if collector_name in _static_collectors:
            return
        _static_collectors[collector_name] = collector


def register(name, obj):
    with _lock:
        _registry[name] = obj


def get_handler(name):
    with _lock:
        return _registry.get(name)


def list_threads() -> dict:
    """What the agent believes it is running. Safe to call at any time — it
    never waits on a collector."""
    with _lock:
        return {
            "status": _status,
            "transitioning": _status_busy,
            "running": sorted(_running_threads),
            "paused": sorted(_paused_threads),
            "static": sorted(_static_collectors),
        }


# --------------------------------------------------------------------------- #
# global status
# --------------------------------------------------------------------------- #

def get_status():
    return _status


def set_status(st):
    """Pause or resume everything. Returns the resulting status string."""
    global _status, _status_busy

    if st not in VALID_STATUS:
        print(f"[registry] ignoring unknown status {st!r}")
        return _status

    # ---- phase 1: decide and update bookkeeping, holding the lock briefly ----
    with _lock:
        if st == _status:
            return _status                  # idempotent: no double stop/start
        if _status_busy:
            print("[registry] a status change is already in progress")
            return _status
        _status_busy = True

        collectors = list(_static_collectors.items())
        targets = []

        if st == "pause":
            for svc in list(_running_threads):
                entry = _running_threads.pop(svc)
                entry["paused_by"] = "status"       # so resume knows to revive it
                _paused_threads[svc] = entry
                targets.append((svc, entry))
        else:
            # revive only what the status change paused, not hand-paused services
            for svc in [s for s, v in _paused_threads.items()
                        if v.get("paused_by") == "status"]:
                entry = _paused_threads.pop(svc)
                entry.pop("paused_by", None)
                _running_threads[svc] = entry
                targets.append((svc, entry))

        _status = st

    # ---- phase 2: the slow calls, lock released, each on a deadline ----------
    try:
        pausing = (st == "pause")
        timeout = STOP_TIMEOUT if pausing else START_TIMEOUT

        for name, collector in collectors:
            print(name)
            fn = collector.stop if pausing else collector.start
            call_with_result(fn, timeout, f"{name}.{'stop' if pausing else 'start'}")

        for svc, entry in targets:
            fn = entry["handler"].stop if pausing else entry["handler"].start
            ok, _, err = call_with_result(fn, timeout, f"{svc}.{'stop' if pausing else 'start'}",
                                          entry["args"])
            if not ok and not pausing:
                # it never came back up — record it as paused, not running
                with _lock:
                    _running_threads.pop(svc, None)
                    entry["paused_by"] = "status"
                    _paused_threads[svc] = entry
                print(f"[registry] {svc} failed to resume: {err}")
    finally:
        with _lock:
            _status_busy = False

    return _status


# --------------------------------------------------------------------------- #
# per-service control
# --------------------------------------------------------------------------- #

def register_thread(service_name, handler, args):
    if not service_name:
        return {"success": False, "error": "service_name is required"}

    with _lock:
        if service_name in _running_threads:
            return {"success": False, "error": f"{service_name} already running"}
        _paused_threads.pop(service_name, None)
        entry = {"handler": handler, "args": args}
        _running_threads[service_name] = entry

    ok, value, err = call_with_result(handler.start, START_TIMEOUT,
                                      f"{service_name}.start", args)
    if not ok:
        with _lock:                     # roll back so the record stays truthful
            _running_threads.pop(service_name, None)
        return {"success": False, "error": str(err)}
    return value if value is not None else {"success": True}


def pause_thread(service_name):
    with _lock:
        entry = _running_threads.pop(service_name, None)
        if entry is None:
            if service_name in _paused_threads:
                return {"success": True, "already_paused": True}
            return {"success": False, "error": f"{service_name} is not running"}
        entry["paused_by"] = "user"
        _paused_threads[service_name] = entry

    ok, value, err = call_with_result(entry["handler"].stop, STOP_TIMEOUT,
                                      f"{service_name}.stop", entry["args"])
    if not ok:
        return {"success": False, "error": str(err)}
    return value if value is not None else {"success": True}


def restart_thread(service_name):
    with _lock:
        entry = _paused_threads.pop(service_name, None)      # read the PAUSED dict
        if entry is None:
            if service_name in _running_threads:
                return {"success": True, "already_running": True}
            return {"success": False, "error": f"{service_name} is not paused"}
        entry.pop("paused_by", None)
        _running_threads[service_name] = entry

    ok, value, err = call_with_result(entry["handler"].start, START_TIMEOUT,
                                      f"{service_name}.start", entry["args"])
    if not ok:
        with _lock:
            _running_threads.pop(service_name, None)
            entry["paused_by"] = "user"
            _paused_threads[service_name] = entry
        return {"success": False, "error": str(err)}
    return value if value is not None else {"success": True}


def remove_thread(service_name):
    with _lock:
        entry = _running_threads.pop(service_name, None)
        was_running = entry is not None
        if entry is None:
            entry = _paused_threads.pop(service_name, None)
        else:
            _paused_threads.pop(service_name, None)

    if entry is None:
        return {"success": False, "error": f"unknown service {service_name}"}
    if not was_running:
        return {"success": True}                # paused: already stopped

    ok, value, err = call_with_result(entry["handler"].stop, STOP_TIMEOUT,
                                      f"{service_name}.stop", entry["args"])
    if not ok:
        return {"success": False, "error": str(err)}
    return value if value is not None else {"success": True}


# --------------------------------------------------------------------------- #
# shutdown
# --------------------------------------------------------------------------- #

def stop_dynamic_collectors(timeout: float = STOP_TIMEOUT) -> None:
    """Stop every per-service inspector. Called on agent shutdown, before the
    dispatcher is flushed."""
    with _lock:
        targets = [(svc, _running_threads.pop(svc)) for svc in list(_running_threads)]

    for svc, entry in targets:
        call_with_result(entry["handler"].stop, timeout, f"{svc}.stop", entry["args"])