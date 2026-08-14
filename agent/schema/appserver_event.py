"""
schema/appserver_event.py  — STANDALONE (does not inherit BaseDbEvent)
=====================================================================
WildFly/JBoss (and future Tomcat/Jetty) health event -> appserver_events table.
`server` (wildfly|jboss|tomcat) is the discriminator; `backend` = api|cli.
Carries its own to_dict()/apply_inspect() so nothing silently drops.
"""
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Optional, Any, List, Dict, ClassVar
from enum import Enum


class EventOutcome(str, Enum):
    SUCCESS = "success"; FAILURE = "failure"; UNKNOWN = "unknown"


class Severity(str, Enum):
    INFO = "info"; LOW = "low"; MEDIUM = "medium"; HIGH = "high"; CRITICAL = "critical"


class HealthStatus(str, Enum):
    HEALTHY = "healthy"; DEGRADED = "degraded"; CRITICAL = "critical"; UNREACHABLE = "unreachable"


APP_SECTIONS = ["connectivity_version", "jvm", "threads", "thread_pools",
                "datasources", "deployments", "system_resources", "health_summary"]


@dataclass
class AppServerEvent:
    category: str = "appserver_health"
    engine: str = "appserver"
    server: Optional[str] = None            # wildfly | jboss | tomcat
    backend: Optional[str] = None           # api | cli
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"))
    action: str = "appserver_detected"
    outcome: str = EventOutcome.SUCCESS
    severity: str = Severity.INFO
    collector: str = "appserver_inspect"
    tags: List[str] = field(default_factory=list)
    notes: Optional[str] = None
    inspected: Optional[bool] = None
    health_status: Optional[str] = None

    # detect fields
    detected: Optional[bool] = None
    running: Optional[bool] = None
    process_pid: Optional[int] = None
    exe_path: Optional[str] = None
    auth_method: Optional[str] = None
    inspect_error: Optional[str] = None
    system_resources: Optional[Any] = None

    # identity
    target_name: Optional[str] = None       # wildfly@host:9990
    app_host: Optional[str] = None
    app_port: Optional[int] = None
    app_version: Optional[str] = None       # product-version
    server_state: Optional[str] = None      # running | reload-required | ...

    # promoted metrics
    heap_pct: Optional[float] = None
    heap_used: Optional[int] = None
    gc_time_ms: Optional[int] = None
    thread_count: Optional[int] = None
    datasource_wait_total: Optional[int] = None
    deployments_ok: Optional[int] = None
    deployments_total: Optional[int] = None
    uptime_ms: Optional[int] = None

    # sections
    connectivity_version: Optional[Any] = None
    jvm: Optional[Any] = None
    threads: Optional[Any] = None
    thread_pools: Optional[Any] = None
    datasources: Optional[Any] = None
    deployments: Optional[Any] = None
    health_summary: Optional[Any] = None

    issues: List[Dict[str, Any]] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)

    SECTIONS: ClassVar[List[str]] = APP_SECTIONS

    def apply_inspect(self, res: Dict[str, Any]):
        res = res or {}
        self.action = "appserver_health"
        self.inspected = True
        if res.get("backend"):
            self.backend = res["backend"]
        if res.get("server"):
            self.server = res["server"]
        if res.get("version"):
            self.app_version = res["version"]
        if res.get("server_state"):
            self.server_state = res["server_state"]

        metrics = res.get("metrics") or {}
        for m in ("heap_pct", "heap_used", "gc_time_ms", "thread_count",
                  "datasource_wait_total", "deployments_ok", "deployments_total", "uptime_ms"):
            if metrics.get(m) is not None:
                setattr(self, m, metrics[m])

        for key in APP_SECTIONS:
            sec = (res.get("sections") or {}).get(key)
            if key != "system_resources" and sec is not None:
                setattr(self, key, sec)

        # severity: unreachable/heap high/reload-required/ds waits -> degrade
        sev = Severity.INFO
        if metrics.get("reachable") is False:
            sev = Severity.HIGH
        elif (self.heap_pct or 0) >= 90 or (self.datasource_wait_total or 0) > 0:
            sev = Severity.MEDIUM
        elif self.server_state and self.server_state not in ("running", "ok"):
            sev = Severity.MEDIUM
        self.severity = sev
        self.health_status = (HealthStatus.HEALTHY if sev == Severity.INFO
                              else HealthStatus.CRITICAL if sev == Severity.CRITICAL
                              else HealthStatus.DEGRADED)
        return self

    def to_dict(self) -> Dict[str, Any]:
        def clean(o):
            if isinstance(o, dict):
                return {k: clean(v) for k, v in o.items()}
            if isinstance(o, list):
                return [clean(i) for i in o]
            if isinstance(o, datetime):
                return o.isoformat()
            if isinstance(o, Enum):
                return o.value
            return o
        out = {}
        for k, v in asdict(self).items():
            if k == "issues":
                out[k] = clean(v)
            elif k == "details":
                if v:
                    out[k] = clean(v)
            elif v is not None:
                out[k] = clean(v)
        return out
