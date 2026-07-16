
from typing import Callable, Dict, Any, List, Optional
import sys


def _os_resources() -> Dict[str, Any]:
    try:
        import psutil
        vm = psutil.virtual_memory()
        path = "C:\\" if sys.platform == "win32" else "/"
        du = psutil.disk_usage(path)
        res = {"cpu_percent": psutil.cpu_percent(interval=0.3),
               "memory_total_bytes": vm.total, "memory_used_bytes": vm.used,
               "memory_percent": vm.percent, "disk_total_bytes": du.total,
               "disk_used_bytes": du.used, "disk_percent": du.percent}
        try:
            res["load_avg_1_5_15"] = [round(x, 2) for x in psutil.getloadavg()]
        except Exception:
            pass
        return res
    except Exception as ex:
        return {"error": str(ex)}


def build_detect_event(d: Dict[str, Any], os_res: Optional[Dict[str, Any]] = None):
    """One detect event for one found engine. Returns None if we have no event
    class for that engine."""
    from schema.db_events import EVENT_FOR_ENGINE
    from schema.db_event_base import EventOutcome

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
    ev.system_resources = os_res or None
    ev.target_name = d.get("name") or d.get("target_name")
    ev.tags = ["database", "discovery", d["engine"]]
    ev.inspected = False
    ev.notes = "detected — awaiting user selection (enable in dashboard to inspect)"
    return ev


def run_detect(dispatch: Callable, machine_info: dict,
               emit: bool = True) -> List[Dict[str, Any]]:
    """THE FUNCTION. Detect local DB engines once and emit a detect event each.

        found = run_detect(dispatch, machine_info)

    Args:
        dispatch: the agent's dispatch(event_dict, machine_info)
        emit:     False -> just return the list, send nothing
    Returns:
        list of dicts: [{"engine":"mysql","running":True,"port":3306,"pid":..,...}]
    """
    from collectors.dbprobe.detect import detect_engines

    os_res = _os_resources()
    try:
        found = detect_engines()
    except Exception as ex:
        print(f"[detect] error: {ex}")
        return []
    print(f"[detect] found {len(found)} -> {[d.get('engine') for d in found]}")
    if emit:
        for d in found:
            ev = build_detect_event(d, os_res)
            if ev is not None:
                dispatch(ev.to_dict(), machine_info)
    return found
