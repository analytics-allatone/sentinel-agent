"""
schema/web_server_event.py
==========================
One consolidated web-server health event per server per poll, mirroring the DB
per-engine events. Reuses BaseDbEvent so detect fields, apply_inspect, rollup and
to_dict behave identically. category="web_server_health" -> web_server_events.

`server` ('nginx' | 'apache') is the discriminator (like `engine` for DBs).
"""
from dataclasses import dataclass
from typing import Optional, Any, ClassVar, List
from schema.web_event_base import BaseWebEvent

WEB_SECTIONS = [
    "connectivity_version", "live_status", "vhosts_tls",
    "access_log", "error_log", "system_resources", "health_summary",
]


@dataclass
class WebServerEvent(BaseWebEvent):
    engine: str = "webserver"                 # generic; `server` holds nginx/apache
    category: str = "web_server_health"
    server: Optional[str] = None              # nginx | apache

    # promoted scalar metrics (nullable per server; nginx vs apache differ)
    active_connections: Optional[int] = None
    requests_total: Optional[int] = None
    req_per_sec: Optional[float] = None
    busy_workers: Optional[int] = None
    idle_workers: Optional[int] = None
    uptime_seconds: Optional[int] = None
    error_rate_pct: Optional[float] = None
    config_ok: Optional[bool] = None

    # sections (one JSONB column each)
    connectivity_version: Optional[Any] = None
    live_status: Optional[Any] = None
    vhosts_tls: Optional[Any] = None
    access_log: Optional[Any] = None
    error_log: Optional[Any] = None
    health_summary: Optional[Any] = None
    # system_resources already declared on BaseDbEvent

    SECTIONS: ClassVar[List[str]] = WEB_SECTIONS
    METRICS: ClassVar[List[tuple]] = [
        ("active_connections", "active_connections"),
        ("requests_total", "requests_total"),
        ("req_per_sec", "req_per_sec"),
        ("busy_workers", "busy_workers"),
        ("idle_workers", "idle_workers"),
        ("uptime_seconds", "uptime_seconds"),
        ("error_rate_pct", "error_rate_pct"),
        ("config_ok", "config_ok"),
    ]

    def apply_inspect(self, res):
        super().apply_inspect(res)
        if (res or {}).get("server"):
            self.server = res["server"]
        return self
