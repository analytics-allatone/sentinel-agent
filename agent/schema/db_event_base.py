from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict
from typing import Optional, List, Dict, Any, ClassVar
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


_SEV_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class BaseDbEvent:
    # --- routing + meta ---
    category: str = "db_health"
    engine: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"))
    action: str = "db_health"
    outcome: str = EventOutcome.SUCCESS
    severity: str = Severity.INFO
    collector: str = "db_discovery"
    tags: List[str] = field(default_factory=list)
    notes: Optional[str] = None
    inspected: Optional[bool] = None
    health_status: Optional[str] = None

    # --- detect fields (MUST be declared or asdict/to_dict drops them) ---
    detected: Optional[bool] = None
    running: Optional[bool] = None
    process_pid: Optional[int] = None
    exe_path: Optional[str] = None
    service_name: Optional[str] = None
    auth_method: Optional[str] = None
    inspect_error: Optional[str] = None
    system_resources: Optional[Any] = None      # host CPU/mem/disk (14-point #13)

    # --- identity ---
    target_name: Optional[str] = None
    db_host: Optional[str] = None
    db_port: Optional[int] = None
    db_version: Optional[str] = None
    current_database: Optional[str] = None
    database_count: Optional[int] = None
    table_count: Optional[int] = None
    total_size_bytes: Optional[int] = None
    databases: Optional[List[Dict[str, Any]]] = None

    # --- roll-up ---
    issues: List[Dict[str, Any]] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)

    # subclasses set these
    SECTIONS: ClassVar[List[str]] = []
    METRICS: ClassVar[List[tuple]] = []          # (event_attr, metrics_key)

    # ------------------------------------------------------------------ #
    @classmethod
    def from_inspect(cls, target: Dict[str, Any], res: Dict[str, Any]):
        ev = cls()
        ev.target_name = target.get("name") or target.get("target_name") or ev.engine
        ev.db_host = target.get("host")
        ev.db_port = target.get("port")
        ev.service_name = target.get("service_name") or target.get("sid")
        ev.apply_inspect(res or {})
        return ev

    def apply_inspect(self, res: Dict[str, Any]):
        """Fill health data onto THIS event (which may already hold detect fields).
        Reads either {version, metrics, sections} or {db_version, points}."""
        res = res or {}
        sections = res.get("sections") or res.get("points") or {}
        metrics = res.get("metrics") or {}
        if res.get("version") or res.get("db_version"):
            self.db_version = res.get("version") or res.get("db_version")
        if res.get("current_database"):
            self.current_database = res["current_database"]
        for k in ("database_count", "table_count", "total_size_bytes", "databases"):
            if res.get(k) is not None:
                setattr(self, k, res[k])
        if res.get("issues"):
            self.issues = res["issues"]
        for attr, key in self.METRICS:
            v = metrics.get(key)
            if v is not None:
                setattr(self, attr, v)
        for key in self.SECTIONS:
            if sections.get(key) is not None:
                setattr(self, key, sections[key])
        self.inspected = True
        self.action = "db_health"
        sev_issue, _ = self._rollup()
        sev_deriv = self._derive_severity(sections)
        final = max([sev_issue, sev_deriv], key=lambda s: _SEV_ORDER[s.value])
        self.severity = final
        self.health_status = (HealthStatus.HEALTHY if final == Severity.INFO
                              else HealthStatus.CRITICAL if final == Severity.CRITICAL
                              else HealthStatus.DEGRADED)
        return self

    def _rollup(self):
        if not self.issues:
            return Severity.INFO, HealthStatus.HEALTHY
        worst = max(self.issues, key=lambda i: _SEV_ORDER.get(str(i.get("severity", "info")).lower(), 0))
        sev = str(worst.get("severity", "info")).lower()
        status = HealthStatus.CRITICAL if sev == "critical" else HealthStatus.DEGRADED
        try:
            sev_enum = Severity(sev)
        except ValueError:
            sev_enum = Severity.INFO
        return sev_enum, status

    @staticmethod
    def _derive_severity(sections: Dict[str, Any]) -> "Severity":
        sev = Severity.INFO

        def bump(s):
            nonlocal sev
            if _SEV_ORDER[s.value] > _SEV_ORDER[sev.value]:
                sev = s
        ac = sections.get("active_connections")
        if isinstance(ac, dict) and isinstance(ac.get("long_running"), list) and ac["long_running"]:
            bump(Severity.MEDIUM)
        lb = sections.get("locks_blocking")
        if (isinstance(lb, list) and lb) or (isinstance(lb, dict) and lb.get("blocked") or (isinstance(lb, dict) and lb.get("blocking"))):
            bump(Severity.MEDIUM)
        tw = sections.get("transaction_wraparound")
        if isinstance(tw, dict):
            for db in (tw.get("databases") or []):
                try:
                    if isinstance(db, dict) and float(db.get("pct_toward_wraparound") or 0) >= 80:
                        bump(Severity.HIGH)
                except (TypeError, ValueError):
                    pass
        return sev

    # ------------------------------------------------------------------ #
    def to_dict(self) -> Dict[str, Any]:
        def clean(obj):
            if isinstance(obj, dict):
                return {k: clean(v) for k, v in obj.items()}
            if isinstance(obj, list):
                return [clean(i) for i in obj]
            if isinstance(obj, datetime):
                return obj.isoformat()
            if isinstance(obj, Enum):
                return obj.value
            return obj
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