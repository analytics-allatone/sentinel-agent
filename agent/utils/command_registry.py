import threading

_lock = threading.RLock()

_registry: dict = {}
_status = "active"
_static_collectors: list = []
_running_threads: dict = {}
_paused_threads: dict = {}


# --------------------------------------------------------------------------- #
# registration
# --------------------------------------------------------------------------- #

def add_static_collector(collector):
    with _lock:
        _static_collectors.append(collector)


def register(name, obj):
    with _lock:
        _registry[name] = obj


def get_handler(name):
    return _registry.get(name)


def list_threads() -> dict:
    """What the agent believes it is running."""
    with _lock:
        return {
            "status": _status,
            "running": sorted(_running_threads),
            "paused": sorted(_paused_threads),
        }


# --------------------------------------------------------------------------- #
# global status
# --------------------------------------------------------------------------- #

def get_status():
    return _status


def set_status(st):
    global _status                      # <-- was missing; status never changed
    print(f"updating status to {st}")

    with _lock:
        if st == _status:
            return _status              # idempotent: no double stop/start

        if st == "pause":
            for collector in _static_collectors:
                try:
                    collector.stop()
                except Exception as e:
                    print(f"[registry] collector stop failed: {e}")

            for svc in list(_running_threads):          # copy: we mutate below
                entry = _running_threads.pop(svc)
                entry["paused_by"] = "status"           # so resume knows to revive it
                _paused_threads[svc] = entry
                try:
                    entry["handler"].stop(entry["args"])
                except Exception as e:
                    print(f"[registry] stop {svc} failed: {e}")

        elif st == "active":
            for collector in _static_collectors:
                try:
                    collector.start()
                except Exception as e:
                    print(f"[registry] collector start failed: {e}")

            # revive only what the status change paused, not hand-paused services
            for svc in [s for s, v in _paused_threads.items()
                        if v.get("paused_by") == "status"]:
                entry = _paused_threads.pop(svc)
                entry.pop("paused_by", None)
                try:
                    entry["handler"].start(entry["args"])
                    _running_threads[svc] = entry
                except Exception as e:
                    print(f"[registry] start {svc} failed: {e}")
                    _paused_threads[svc] = entry

        _status = st
    return _status


# --------------------------------------------------------------------------- #
# per-service control
# --------------------------------------------------------------------------- #

def register_thread(service_name, handler, args):
    with _lock:
        if service_name in _running_threads:
            return {"success": False, "error": f"{service_name} already running"}
        _paused_threads.pop(service_name, None)
        entry = {"handler": handler, "args": args}
        _running_threads[service_name] = entry

    try:
        return handler.start(args)
    except Exception as e:
        with _lock:                     # roll back so the record stays truthful
            _running_threads.pop(service_name, None)
        return {"success": False, "error": str(e)}


def pause_thread(service_name):
    with _lock:
        entry = _running_threads.pop(service_name, None)
        if entry is None:
            if service_name in _paused_threads:
                return {"success": True, "already_paused": True}
            return {"success": False, "error": f"{service_name} is not running"}
        entry["paused_by"] = "user"
        _paused_threads[service_name] = entry

    try:
        return entry["handler"].stop(entry["args"])
    except Exception as e:
        return {"success": False, "error": str(e)}


def restart_thread(service_name):
    with _lock:
        entry = _paused_threads.pop(service_name, None)      # read the PAUSED dict
        if entry is None:
            if service_name in _running_threads:
                return {"success": True, "already_running": True}
            return {"success": False, "error": f"{service_name} is not paused"}
        entry.pop("paused_by", None)
        _running_threads[service_name] = entry

    try:
        return entry["handler"].start(entry["args"])
    except Exception as e:
        with _lock:
            _running_threads.pop(service_name, None)
            _paused_threads[service_name] = entry
        return {"success": False, "error": str(e)}


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

    try:
        return entry["handler"].stop(entry["args"])     # stop AFTER de-registering
    except Exception as e:
        return {"success": False, "error": str(e)}