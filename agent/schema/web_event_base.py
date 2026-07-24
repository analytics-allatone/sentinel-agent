"""
schema/web_event_base.py
========================
Shared base for the per-server web health events, mirroring db_event_base.

Each web server gets its OWN event class (nginx_web_event, apache_web_event, ...)
and its OWN table, so a column is never NULL just because another server lacks it.
This base holds only the fields every web server has (identity + roll-up) and the
generic mapper/serializer; each subclass adds its own section + metric fields and
declares SECTIONS / METRICS so `from_inspect` knows how to fill them.

IMPORTANT (same trap as the DB base): every field the collector sets MUST be a
declared dataclass field. `to_dict()` -> `dataclasses.asdict()` only serializes
declared fields, so anything set dynamically is silently dropped from the emitted
dict / API / table.

Probe-contract tolerant: reads either the rich `{version, metrics, sections}`
shape or a flat `{server_version, points}` shape returned by
collectors/webprobe/<server>.py.
"""

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

# Thresholds used by _derive_severity. Override per-subclass if a server needs
# different tolerances.
ERROR_RATE_MEDIUM = 5.0      # % of sampled requests that are 4xx/5xx
ERROR_RATE_HIGH = 15.0
SERVER_ERROR_RATE_MEDIUM = 1.0   # % that are 5xx specifically
SERVER_ERROR_RATE_HIGH = 5.0
TLS_EXPIRY_HIGH_DAYS = 14
TLS_EXPIRY_MEDIUM_DAYS = 30


@dataclass
class BaseWebEvent:
    # --- routing + meta (subclass overrides category/server defaults) ---
    category: str = "web_server_health"
    server: str = ""                      # "nginx" | "apache" (mirrors db "engine")
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"))
    action: str = "web_health"
    outcome: str = EventOutcome.SUCCESS
    severity: str = Severity.INFO
    collector: str = "web_discovery"
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

    # --- host context ---
    # `agent_resources` is the box the AGENT runs on. For a remote target this is
    # NOT the web server's CPU/mem/disk -- naming it honestly stops dashboards
    # from attributing the agent's load to the monitored host.
    agent_resources: Optional[Any] = None
    system_resources: Optional[Any] = None   # only set when target is local
    is_local: Optional[bool] = None
    remote: Optional[bool] = None

    # --- identity ---
    target_name: Optional[str] = None
    web_host: Optional[str] = None
    web_port: Optional[int] = None
    server_version: Optional[str] = None
    status_url: Optional[str] = None
    config_path: Optional[str] = None
    config_ok: Optional[bool] = None
    vhost_count: Optional[int] = None
    worker_count: Optional[int] = None
    uptime_seconds: Optional[int] = None

    # --- common roll-up metrics (every web server exposes these) ---
    active_connections: Optional[int] = None
    requests_total: Optional[int] = None
    error_rate_pct: Optional[float] = None
    server_error_rate_pct: Optional[float] = None

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
        ev.target_name = target.get("name") or target.get("target_name") or ev.server
        ev.web_host = target.get("host")
        ev.web_port = target.get("port")
        ev.status_url = target.get("status_url")
        ev.service_name = target.get("service_name")
        ev.apply_inspect(res or {})
        return ev

    def apply_inspect(self, res: Dict[str, Any]):
        """Fill health data onto THIS event (which may already hold detect fields).
        Reads either {version, metrics, sections} or {server_version, points}."""
        res = res or {}
        sections = res.get("sections") or res.get("points") or {}
        metrics = res.get("metrics") or {}

        if res.get("version") or res.get("server_version"):
            self.server_version = res.get("version") or res.get("server_version")
        for k in ("config_ok", "config_path", "vhost_count", "worker_count",
                  "uptime_seconds", "status_url"):
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

        self._promote_common(sections)

        self.inspected = True
        self.action = "web_health"

        sev_issue, _ = self._rollup()
        sev_deriv = self._derive_severity(sections)
        final = max([sev_issue, sev_deriv], key=lambda s: _SEV_ORDER[s.value])
        self.severity = final

        if self._unreachable(sections):
            self.health_status = HealthStatus.UNREACHABLE
            self.running = False
        else:
            self.health_status = (HealthStatus.HEALTHY if final == Severity.INFO
                                  else HealthStatus.CRITICAL if final == Severity.CRITICAL
                                  else HealthStatus.DEGRADED)
        return self

    # ------------------------------------------------------------------ #
    def _promote_common(self, sections: Dict[str, Any]):
        """Lift the handful of numbers every server has out of its sections so
        the top level is comparable across nginx/apache without opening blobs."""
        live = sections.get("live_status") or {}
        if isinstance(live, dict):
            if self.active_connections is None and live.get("active_connections") is not None:
                self.active_connections = live["active_connections"]
            if self.requests_total is None and live.get("requests") is not None:
                self.requests_total = live["requests"]

        alog = sections.get("access_log") or {}
        # Only promote log-derived rates when the log was actually sampled -- a
        # 0.0 from an unread log is "no data", not "no errors".
        if isinstance(alog, dict) and (alog.get("sampled_requests") or 0) > 0:
            if alog.get("error_rate_pct") is not None:
                self.error_rate_pct = alog["error_rate_pct"]
            if alog.get("server_error_rate_pct") is not None:
                self.server_error_rate_pct = alog["server_error_rate_pct"]

    @staticmethod
    def _unreachable(sections: Dict[str, Any]) -> bool:
        live = sections.get("live_status")
        return isinstance(live, dict) and live.get("reachable") is False

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
        """Web-native signals, the counterpart to the DB base's locks/wraparound.

        Deliberately does NOT bump on config_ok=False when the check could not
        run (e.g. remote target, no local binary) -- an unrunnable check is
        reported as not_applicable, never as a failure.
        """
        sev = Severity.INFO

        def bump(s):
            nonlocal sev
            if _SEV_ORDER[s.value] > _SEV_ORDER[sev.value]:
                sev = s

        def num(v):
            try:
                return float(v)
            except (TypeError, ValueError):
                return None

        # 1. status endpoint unreachable -> the server is not answering
        live = sections.get("live_status")
        if isinstance(live, dict):
            if live.get("reachable") is False:
                bump(Severity.CRITICAL)
            dropped = num(live.get("dropped"))
            if dropped and dropped > 0:
                bump(Severity.MEDIUM)

        # 2. error rates from sampled access log (only when there IS a sample)
        alog = sections.get("access_log")
        if isinstance(alog, dict) and (alog.get("sampled_requests") or 0) > 0:
            er = num(alog.get("error_rate_pct"))
            if er is not None:
                if er >= ERROR_RATE_HIGH:
                    bump(Severity.HIGH)
                elif er >= ERROR_RATE_MEDIUM:
                    bump(Severity.MEDIUM)
            ser = num(alog.get("server_error_rate_pct"))
            if ser is not None:
                if ser >= SERVER_ERROR_RATE_HIGH:
                    bump(Severity.HIGH)
                elif ser >= SERVER_ERROR_RATE_MEDIUM:
                    bump(Severity.MEDIUM)

        # 3. error log severity mix
        elog = sections.get("error_log")
        if isinstance(elog, dict) and (elog.get("sampled_lines") or 0) > 0:
            by_level = elog.get("by_level") or {}
            if isinstance(by_level, dict):
                if num(by_level.get("emerg")) or num(by_level.get("alert")):
                    bump(Severity.CRITICAL)
                elif num(by_level.get("crit")):
                    bump(Severity.HIGH)
                elif num(by_level.get("error")):
                    bump(Severity.MEDIUM)

        # 4. config test -- only when it actually ran
        cfg = sections.get("connectivity_version")
        if isinstance(cfg, dict):
            ct = cfg.get("config_test")
            if isinstance(ct, dict) and ct.get("ok") is False and not ct.get("not_applicable"):
                bump(Severity.HIGH)

        # 5. TLS expiry
        tls = sections.get("vhosts_tls")
        if isinstance(tls, dict) and not tls.get("not_applicable"):
            for host in (tls.get("hosts") or []):
                if not isinstance(host, dict):
                    continue
                if host.get("valid") is False or host.get("expired") is True:
                    bump(Severity.CRITICAL)
                d = num(host.get("days_to_expiry"))
                if d is not None:
                    if d <= TLS_EXPIRY_HIGH_DAYS:
                        bump(Severity.HIGH)
                    elif d <= TLS_EXPIRY_MEDIUM_DAYS:
                        bump(Severity.MEDIUM)
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
