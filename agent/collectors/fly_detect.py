"""
collectors/fly_detect.py
========================
DETECT AS A FUNCTION (no thread, no loop). Call run_fly_detect(...) on startup or
when an event fires. It reports every place Fly is reachable from this host:

  1. host flyctl        (installed + `fly auth whoami` ok)
  2. remote API token   ($FLY_API_TOKEN or passed token)
  3. docker containers  (any running container that has flyctl inside)

Emits one fly_detected event per reachable "source" (inspected=False) and returns
the list of sources so the inspector knows what it can inspect.
"""

from collectors.flyprobe import fly as _fly
from collectors.flyprobe import _docker
from typing import Callable, Dict, Any, List, Optional
import psutil

import os


# def _os_resources() -> Dict[str, Any]:
#     try:
#         return {"cpu_percent": psutil.cpu_percent(interval=0.2),
#                 "memory_percent": psutil.virtual_memory().percent}
#     except Exception as ex:
#         return {"error": str(ex)}


def discover_sources(token: Optional[str] = None) -> List[Dict[str, Any]]:
    """Return every Fly source reachable from here. No app listing yet."""
   
    sources: List[Dict[str, Any]] = []

    # 1 + 2: host flyctl and/or API token
    a = _fly.availability({"token": token})
    if a["cli_authenticated"]:
        sources.append({"source": "host", "backend": "cli",
                        "fly_bin": a["cli_path"], "authenticated": True,
                        "cli_installed": True, "api_token_present": a["api_token_present"]})
    if token or a["api_token_present"]:
        sources.append({"source": "host", "backend": "api",
                        "authenticated": True, "api_token_present": True,
                        "cli_installed": a["cli_installed"]})

    # 3: docker containers with flyctl
    dock = _docker.docker_available()
    if dock["available"]:
        for c in _docker.find_flyctl_containers():
            sources.append({"source": "docker", "backend": "cli-docker",
                            "container": c["container"], "container_name": c["name"],
                            "image": c["image"], "fly_bin": c["fly_bin"],
                            "authenticated": c["authenticated"],
                            "docker_backend": dock["backend"]})
    return sources


# def build_detect_event(src: Dict[str, Any], os_res=None):
    
#     from schema.fly_event import FlyEvent,EventOutcome
#     # from schema.db_event_base import EventOutcome
    
#     ev = FlyEvent()
#     ev.server = "fly"
#     ev.backend = src.get("backend")
#     ev.action = "fly_detected"
#     ev.outcome = EventOutcome.SUCCESS
#     ev.detected = True
#     ev.running = bool(src.get("authenticated") or src.get("api_token_present"))
#     ev.exe_path = src.get("fly_bin")
#     ev.system_resources = os_res or None
#     # a stable id per source so the dashboard can tick each independently
#     if src.get("source") == "docker":
#         ev.target_name = f"docker:{src.get('container_name') or src.get('container')}"
#         loc = f"container {src.get('container_name')} ({src.get('image')})"
#     else:
#         ev.target_name = f"host:{src.get('backend')}"
#         loc = f"host {src.get('backend')}"
#     ev.tags = ["fly", "discovery", src.get("source"), src.get("backend")]
#     ev.notes = (f"detected on {loc} — awaiting user selection "
#                 f"(auth={'yes' if src.get('authenticated') else 'token' if src.get('api_token_present') else 'no'})")
#     ev.inspected = False
#     return ev


def run_fly_detect( token: Optional[str] = None, emit: bool = True) -> List[Dict[str, Any]]:#dispatch: Callable, machine_info: dict,
                #    token: Optional[str] = None, emit: bool = True) -> List[Dict[str, Any]]:
    from schema.fly_event import FlyEvent

    """THE FUNCTION. Discover Fly sources once and emit a detect event per source."""
    # os_res = _os_resources()
    sources = discover_sources(token)                                                                                                                                                                                                                                   
    print(f"[fly detect] sources={len(sources)}: "
          f"{[(s.get('source'), s.get('backend')) for s in sources]}")
    # if emit:
        # if not sources:
        #     ev = FlyEvent(); ev.server = "fly"; ev.action = "fly_detected"
        #     ev.detected = False; ev.running = False
        #     ev.notes = "fly not available (no host flyctl, no token, no container flyctl)"
        #     ev.system_resources = os_res or None
        #     dispatch(ev.to_dict(), machine_info)
        # for s in sources:
        #     dispatch(build_detect_event(s, os_res).to_dict(), machine_info)
    return sources
