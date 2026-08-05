from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Optional, Any, List, Dict, ClassVar
from enum import Enum


class EventOutcome(str, Enum):
    SUCCESS = "success"
    FAILURE = "failure"
    UNKNOWN = "unknown"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class HealthStatus(str, Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    CRITICAL = "critical"
    UNREACHABLE = "unreachable"


FLY_SECTIONS = ["connectivity_version", "apps", "machines", "releases",
                "volumes_ips", "metrics", "system_resources", "health_summary"]


@dataclass
class FlyEvent:
    # ── routing / meta ──
    category: str = "fly_health"
    engine: str = "fly"
    server: str = "fly"
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"))
    action: str = "fly_detected"
    outcome: str = EventOutcome.SUCCESS
    severity: str = Severity.INFO
    collector: str = "fly_inspect"
    tags: List[str] = field(default_factory=list)
    notes: Optional[str] = None
    inspected: Optional[bool] = None
    health_status: Optional[str] = None

    # ── detect fields ──
    detected: Optional[bool] = None
    running: Optional[bool] = None
    backend: Optional[str] = None            # cli | api | cli-docker
    process_pid: Optional[int] = None
    exe_path: Optional[str] = None           # flyctl path
    auth_method: Optional[str] = None
    inspect_error: Optional[str] = None
    system_resources: Optional[Any] = None

    # ── identity (Fly-worded, not db_*) ──
    target_name: Optional[str] = None        # host:cli | host:api | docker:<name>
    fly_host: Optional[str] = None
    fly_port: Optional[int] = None
    fly_version: Optional[str] = None        # flyctl version / "machines-api"
    org: Optional[str] = None
    container: Optional[str] = None          # container id when backend=cli-docker

    # ── promoted metrics ──
    apps_total: Optional[int] = None
    machines_up: Optional[int] = None
    machines_down: Optional[int] = None
    regions: Optional[int] = None

    # ── sections (one JSONB column each) ──
    connectivity_version: Optional[Any] = None
    apps: Optional[Any] = None
    machines: Optional[Any] = None
    releases: Optional[Any] = None
    volumes_ips: Optional[Any] = None
    metrics_section: Optional[Any] = None
    health_summary: Optional[Any] = None

    issues: List[Dict[str, Any]] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)

    SECTIONS: ClassVar[List[str]] = FLY_SECTIONS

    # ── fill health from a probe result {version, backend, metrics, sections} ──
    def apply_inspect(self, res: Dict[str, Any]):
        res = res or {}
        self.action = "fly_health"
        self.inspected = True
        if res.get("backend"):
            self.backend = res["backend"]
        if res.get("version"):
            self.fly_version = res["version"]

        metrics = res.get("metrics") or {}
        for m in ("apps_total", "machines_up", "machines_down", "regions"):
            if metrics.get(m) is not None:
                setattr(self, m, metrics[m])

        sections = res.get("sections") or {}
        for key in FLY_SECTIONS:
            if key == "metrics":
                if sections.get("metrics") is not None:
                    self.metrics_section = sections["metrics"]
            elif sections.get(key) is not None:
                setattr(self, key, sections[key])

        # severity: down machines / unreachable -> degrade
        sev = Severity.INFO
        hs = sections.get("health_summary") or {}
        if hs.get("reachable") is False:
            sev = Severity.HIGH
        elif (self.machines_down or 0) > 0:
            sev = Severity.MEDIUM
        self.severity = sev
        self.health_status = (HealthStatus.HEALTHY if sev == Severity.INFO
                              else HealthStatus.CRITICAL if sev == Severity.CRITICAL
                              else HealthStatus.DEGRADED)
        return self

    # ── own to_dict: drop None, drop empty details, serialize enums/datetime ──
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
        out: Dict[str, Any] = {}
        for k, v in asdict(self).items():
            if k == "issues":
                out[k] = clean(v)
            elif k == "details":
                if v:
                    out[k] = clean(v)
            elif v is not None:
                out[k] = clean(v)
        return out