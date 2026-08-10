from typing import List, Dict, Any
from . import fly as _fly


def detect_fly() -> List[Dict[str, Any]]:
    """Return a single 'fly' entry if any backend is available, else []."""
    a = _fly.availability({})
    reachable = a["cli_authenticated"] or a["api_token_present"]
    if not (a["cli_installed"] or a["api_token_present"]):
        return []                       # nothing Fly-related on this host at all
    backend = "cli" if a["cli_authenticated"] else ("api" if a["api_token_present"] else None)
    return [{
        "server": "fly", "engine": "fly",
        "running": reachable,           # "running" = reachable via some backend
        "backend": backend,
        "cli_installed": a["cli_installed"],
        "cli_authenticated": a["cli_authenticated"],
        "api_token_present": a["api_token_present"],
        "exe_path": a["cli_path"],
        "port": None,
    }]
