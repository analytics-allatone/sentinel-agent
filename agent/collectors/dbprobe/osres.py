"""system_resources (check #13) — host OS metrics via psutil (engine-independent)."""

def system_resources():
    try:
        import psutil
    except Exception as ex:
        return {"error": f"psutil unavailable: {ex}"}
    out = {}
    try:
        out["cpu_percent"] = psutil.cpu_percent(interval=0.3)
        out["cpu_count"] = psutil.cpu_count()
    except Exception:
        pass
    try:
        vm = psutil.virtual_memory()
        out["memory"] = {"total_bytes": vm.total, "available_bytes": vm.available, "used_percent": vm.percent}
    except Exception:
        pass
    try:
        du = psutil.disk_usage("/")
        out["disk_root"] = {"total_bytes": du.total, "used_bytes": du.used, "used_percent": du.percent}
    except Exception:
        pass
    try:
        import os
        if hasattr(os, "getloadavg"):
            la = os.getloadavg()
            out["load_avg"] = {"1m": la[0], "5m": la[1], "15m": la[2]}
    except Exception:
        pass
    return out
