import json
from typing import Any, Dict, List, Optional

from utils.crypto import decrypt

VALID_SERVERS = {"nginx", "apache"}
_ALIAS = {"httpd": "apache", "apache2": "apache"}

# Swagger's "Try it out" fills optional strings with "string". Treat these as
# unset so placeholders never reach a probe or pollute the upsert key.
_PLACEHOLDER = {"", "string", "null", "none"}


def canon_server(s: str) -> str:
    s = str(s or "").strip().lower()
    return _ALIAS.get(s, s)


def clean(v: Any) -> Any:
    """Turn Swagger placeholders and blank strings into None."""
    if isinstance(v, str) and v.strip().lower() in _PLACEHOLDER:
        return None
    return v


def load_tls_hosts(raw: Optional[str]) -> List[str]:
    if not raw:
        return []
    try:
        value = json.loads(raw)
        return value if isinstance(value, list) else []
    except Exception:
        return []


def dump_tls_hosts(hosts: Optional[List[str]]) -> Optional[str]:
    hosts = [h for h in (hosts or []) if clean(h)]
    return json.dumps(hosts) if hosts else None


def row_to_params(row) -> Dict[str, Any]:
    """Row -> the params dict a webprobe's inspect() expects.

    Empty values are dropped so a probe never receives status_url=None.
    """
    params = {
        "server": row.server,
        "name": row.target_name,
        "host": row.host,
        "port": row.port,
        "status_url": row.status_url,
        "access_log": row.access_log,
        "error_log": row.error_log,
        "tls_hosts": load_tls_hosts(row.tls_hosts),
        "user": row.user_name,
        "password": decrypt(row.password_enc),
    }
    return {k: v for k, v in params.items() if v not in (None, "", [])}


def row_to_control(row) -> Dict[str, Any]:
    """The per-server config block inside the control JSON's "servers" key."""
    block = row_to_params(row)
    block.pop("server", None)
    block.pop("name", None)
    return block


def build_control_json(rows) -> Dict[str, Any]:
    """Assemble control JSON in WebDiscoveryCollector's existing format.

    Rows with no target_name become entries in enabled_servers/servers.
    Rows with a target_name become entries in enabled_targets/targets.
    """
    enabled_servers: List[str] = []
    servers: Dict[str, Any] = {}
    enabled_targets: List[str] = []
    targets: List[Dict[str, Any]] = []

    for row in rows:
        if row.target_name:
            target = row_to_params(row)
            target["name"] = row.target_name
            targets.append(target)
            enabled_targets.append(row.target_name)
        else:
            servers[row.server] = row_to_control(row)
            if row.server not in enabled_servers:
                enabled_servers.append(row.server)

    return {
        "enabled_servers": enabled_servers,
        "servers": servers,
        "enabled_targets": enabled_targets,
        "targets": targets,
    }
