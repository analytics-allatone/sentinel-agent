import math
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Query, HTTPException, Depends
from sqlalchemy import select, func, or_, and_
from sqlalchemy.ext.asyncio import AsyncSession

from auth.jwt_auth import verify_token
from db.db import get_async_db
from models.event_model import (
    AuthEvents, FileEvents, NetworkEvents, ProcessEvents, USBEvents,
)
from schemas.v1.standard_schema import standard_success_response

drilldown_router = APIRouter()

MAX_LIMIT = 500
HIGH = ["high", "critical"]
OUTCOME_SUCCESS = "success"
OUTCOME_FAILURE = "failure"


# ─────────────────────────────────────────────────────────────────────
#  Per-category configuration
#    columns   : table headers (key -> label), in display order
#    select    : model columns to fetch
#    row       : row dict builder (keys must match column keys)
#    search    : columns an ilike q= scans
#    metrics   : which drill-downs this category supports
#    threat    : has anomaly / ioc_match / risk_score columns
# ─────────────────────────────────────────────────────────────────────
def _mitre(r):
    return " / ".join(x for x in [getattr(r, "mitre_tactic", None),
                                  getattr(r, "mitre_technique", None)] if x) or None


AUTH_CFG = {
    "model": AuthEvents,
    "threat": False,
    "columns": [
        {"key": "timestamp", "label": "Time"},
        {"key": "username", "label": "User"},
        {"key": "action", "label": "Action"},
        {"key": "outcome", "label": "Outcome"},
        {"key": "severity", "label": "Severity"},
        {"key": "auth_method", "label": "Method"},
        {"key": "source_ip", "label": "Source IP"},
        {"key": "failure_reason", "label": "Failure reason"},
        {"key": "sudo_command", "label": "Sudo command"},
    ],
    "select": lambda M: [
        M.id, M.timestamp, M.agent_name, M.username, M.action, M.outcome, M.severity,
        M.auth_method, M.auth_source_ip, M.auth_failure_reason, M.auth_sudo_command,
        M.auth_session_type, M.process_name,
    ],
    "row": lambda r: {
        "id": r.id, "timestamp": r.timestamp, "agent_name": r.agent_name,
        "username": r.username, "action": r.action, "outcome": r.outcome,
        "severity": r.severity, "auth_method": r.auth_method,
        "source_ip": r.auth_source_ip, "failure_reason": r.auth_failure_reason,
        "sudo_command": r.auth_sudo_command, "session_type": r.auth_session_type,
        "process_name": r.process_name,
    },
    "search": lambda M: [M.username, M.auth_source_ip, M.auth_failure_reason],
    "metrics": ["all", "successful", "failed", "privileged", "high_severity", "unrecorded"],
}

FILE_CFG = {
    "model": FileEvents,
    "threat": True,
    "columns": [
        {"key": "timestamp", "label": "Time"},
        {"key": "action", "label": "Action"},
        {"key": "file_path", "label": "File"},
        {"key": "user_name", "label": "User"},
        {"key": "outcome", "label": "Outcome"},
        {"key": "severity", "label": "Severity"},
        {"key": "risk_score", "label": "Risk"},
        {"key": "ioc_match", "label": "IOC"},
        {"key": "mitre", "label": "MITRE"},
    ],
    "select": lambda M: [
        M.id, M.timestamp, M.agent_name, M.action, M.file_path, M.user_name,
        M.outcome, M.severity, M.anomaly, M.ioc_match, M.risk_score,
        M.mitre_tactic, M.mitre_technique, M.file_sha256,
    ],
    "row": lambda r: {
        "id": r.id, "timestamp": r.timestamp, "agent_name": r.agent_name,
        "action": r.action, "file_path": r.file_path, "user_name": r.user_name,
        "outcome": r.outcome, "severity": r.severity, "anomaly": r.anomaly,
        "ioc_match": r.ioc_match, "risk_score": r.risk_score, "mitre": _mitre(r),
        "sha256": r.file_sha256,
    },
    "search": lambda M: [M.file_path, M.user_name, M.ioc_match],
    "metrics": ["all", "successful", "failed", "high_severity", "anomalies", "ioc", "unrecorded"],
}

NETWORK_CFG = {
    "model": NetworkEvents,
    "threat": True,
    "columns": [
        {"key": "timestamp", "label": "Time"},
        {"key": "direction", "label": "Direction"},
        {"key": "protocol", "label": "Proto"},
        {"key": "source_ip", "label": "Source"},
        {"key": "dest_ip", "label": "Destination"},
        {"key": "dest_port", "label": "Port"},
        {"key": "process_name", "label": "Process"},
        {"key": "outcome", "label": "Outcome"},
        {"key": "severity", "label": "Severity"},
        {"key": "ioc_match", "label": "IOC"},
    ],
    "select": lambda M: [
        M.id, M.timestamp, M.agent_name, M.network_direction, M.network_protocol,
        M.network_src_ip, M.network_dst_ip, M.network_dst_port, M.process_name,
        M.outcome, M.severity, M.anomaly, M.ioc_match, M.risk_score,
        M.network_bytes_sent, M.network_bytes_recv, M.mitre_tactic, M.mitre_technique,
    ],
    "row": lambda r: {
        "id": r.id, "timestamp": r.timestamp, "agent_name": r.agent_name,
        "direction": r.network_direction, "protocol": r.network_protocol,
        "source_ip": r.network_src_ip, "dest_ip": r.network_dst_ip,
        "dest_port": r.network_dst_port, "process_name": r.process_name,
        "outcome": r.outcome, "severity": r.severity, "anomaly": r.anomaly,
        "ioc_match": r.ioc_match, "risk_score": r.risk_score,
        "bytes_sent": r.network_bytes_sent, "bytes_received": r.network_bytes_recv,
        "mitre": _mitre(r),
    },
    "search": lambda M: [M.network_dst_ip, M.network_src_ip, M.network_dns_query, M.process_name],
    "metrics": ["all", "successful", "failed", "high_severity", "anomalies", "ioc", "unrecorded"],
}

PROCESS_CFG = {
    "model": ProcessEvents,
    "threat": True,
    "columns": [
        {"key": "timestamp", "label": "Time"},
        {"key": "process_name", "label": "Process"},
        {"key": "process_user", "label": "User"},
        {"key": "command_line", "label": "Command line"},
        {"key": "outcome", "label": "Outcome"},
        {"key": "severity", "label": "Severity"},
        {"key": "cpu_percent", "label": "CPU %"},
        {"key": "memory_rss_mb", "label": "Mem (MB)"},
        {"key": "ioc_match", "label": "IOC"},
    ],
    "select": lambda M: [
        M.id, M.timestamp, M.agent_name, M.process_name, M.process_user,
        M.process_command_line, M.process_pid, M.outcome, M.severity,
        M.process_cpu_percent, M.process_memory_rss_mb, M.anomaly, M.ioc_match,
        M.risk_score, M.process_sha256, M.mitre_tactic, M.mitre_technique,
    ],
    "row": lambda r: {
        "id": r.id, "timestamp": r.timestamp, "agent_name": r.agent_name,
        "process_name": r.process_name, "process_user": r.process_user,
        "command_line": r.process_command_line, "pid": r.process_pid,
        "outcome": r.outcome, "severity": r.severity,
        "cpu_percent": r.process_cpu_percent, "memory_rss_mb": r.process_memory_rss_mb,
        "anomaly": r.anomaly, "ioc_match": r.ioc_match, "risk_score": r.risk_score,
        "sha256": r.process_sha256, "mitre": _mitre(r),
    },
    "search": lambda M: [M.process_name, M.process_user, M.process_command_line, M.ioc_match],
    "metrics": ["all", "successful", "failed", "high_severity", "anomalies", "ioc", "unrecorded", "cpu_peak"],
}

USB_CFG = {
    "model": USBEvents,
    "threat": True,
    "columns": [
        {"key": "timestamp", "label": "Time"},
        {"key": "action", "label": "Action"},
        {"key": "device", "label": "Device"},
        {"key": "serial_number", "label": "Serial"},
        {"key": "outcome", "label": "Outcome"},
        {"key": "severity", "label": "Severity"},
        {"key": "transfer_bytes", "label": "Transferred"},
        {"key": "ioc_match", "label": "IOC"},
    ],
    "select": lambda M: [
        M.id, M.timestamp, M.agent_name, M.action, M.usb_vendor, M.usb_model,
        M.usb_serial_number, M.usb_mountpoint, M.usb_fstype, M.outcome, M.severity,
        M.usb_transfer_delta_bytes, M.anomaly, M.ioc_match, M.risk_score,
        M.file_name, M.mitre_tactic, M.mitre_technique,
    ],
    "row": lambda r: {
        "id": r.id, "timestamp": r.timestamp, "agent_name": r.agent_name,
        "action": r.action,
        "device": " ".join(x for x in [r.usb_vendor, r.usb_model] if x) or None,
        "vendor": r.usb_vendor, "model": r.usb_model,
        "serial_number": r.usb_serial_number, "mountpoint": r.usb_mountpoint,
        "fstype": r.usb_fstype, "outcome": r.outcome, "severity": r.severity,
        "transfer_bytes": r.usb_transfer_delta_bytes, "anomaly": r.anomaly,
        "ioc_match": r.ioc_match, "risk_score": r.risk_score,
        "file_name": r.file_name, "mitre": _mitre(r),
    },
    "search": lambda M: [M.usb_vendor, M.usb_model, M.usb_serial_number, M.file_name],
    "metrics": ["all", "successful", "failed", "high_severity", "anomalies", "ioc", "unrecorded"],
}

CATEGORIES = {
    "auth": AUTH_CFG, "file": FILE_CFG, "network": NETWORK_CFG,
    "process": PROCESS_CFG, "usb": USB_CFG,
}


def _metric_filter(M, cfg, metric):
    """Return (list_of_where_conditions, order_override_or_None) for a metric."""
    if metric in (None, "all"):
        return [], None
    if metric == "successful":
        return [M.outcome == OUTCOME_SUCCESS], None
    if metric == "failed":
        return [M.outcome == OUTCOME_FAILURE], None
    if metric == "high_severity":
        return [M.severity.in_(HIGH)], None
    if metric == "unrecorded":
        # Outcome is neither success nor failure (includes NULL / 'unknown').
        return [or_(M.outcome.is_(None), M.outcome.notin_([OUTCOME_SUCCESS, OUTCOME_FAILURE]))], None
    if metric == "privileged":
        return [M.auth_sudo_command.isnot(None)], None
    if metric == "anomalies":
        return [M.anomaly.is_(True)], None
    if metric == "ioc":
        return [M.ioc_match.isnot(None)], None
    if metric == "cpu_peak":
        # No filter — order by CPU desc so the rows explain the avg/peak figures.
        return [M.process_cpu_percent.isnot(None)], M.process_cpu_percent.desc()
    raise HTTPException(status_code=400, detail=f"Unknown metric '{metric}'")


@drilldown_router.get("/soc2-report/{category}/events", status_code=200)
async def drilldown_events(
    category: str,
    from_dt: datetime = Query(..., description="Window start (ISO-8601)"),
    to_dt: datetime = Query(..., description="Window end (ISO-8601)"),
    metric: str = Query("all", description="Which bar to explain; see module docstring"),
    agent_name: Optional[str] = Query(None, description="Filter to one agent; omit for all"),
    q: Optional[str] = Query(None, description="Free-text search within the category"),
    order: str = Query("desc", pattern="^(asc|desc)$", description="Sort by time"),
    limit: int = Query(50, ge=1, le=MAX_LIMIT),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_async_db),
    _claims: dict = Depends(verify_token),
):
    cfg = CATEGORIES.get(category)
    if cfg is None:
        raise HTTPException(status_code=404,
                            detail=f"Unknown category '{category}'. Use one of: {', '.join(CATEGORIES)}")
    if metric not in cfg["metrics"]:
        raise HTTPException(status_code=400,
                            detail=f"metric '{metric}' not valid for '{category}'. "
                                   f"Allowed: {', '.join(cfg['metrics'])}")
    if from_dt >= to_dt:
        raise HTTPException(status_code=400, detail="from_dt must be before to_dt")

    M = cfg["model"]
    filt = [M.timestamp >= from_dt, M.timestamp <= to_dt]
    if agent_name:
        filt.append(M.agent_name == agent_name)

    metric_conds, order_override = _metric_filter(M, cfg, metric)
    filt.extend(metric_conds)

    if q:
        like = f"%{q}%"
        filt.append(or_(*[col.ilike(like) for col in cfg["search"](M)]))

    total = (await db.execute(select(func.count()).where(*filt))).scalar_one()

    if order_override is not None:
        order_by = order_override
    else:
        order_by = M.timestamp.asc() if order == "asc" else M.timestamp.desc()

    rows_q = (select(*cfg["select"](M)).where(*filt)
              .order_by(order_by).limit(limit).offset(offset))
    rows = (await db.execute(rows_q)).all()
    data = [cfg["row"](r) for r in rows]

    return standard_success_response(
        data={
            "category": category,
            "metric": metric,
            "total": total,
            "returned": len(data),
            "limit": limit,
            "offset": offset,
            "page": (offset // limit) + 1,
            "pages": math.ceil(total / limit) if total else 0,
            "available_metrics": cfg["metrics"],
            "filters": {
                "agent_name": agent_name, "metric": metric, "q": q,
                "from_dt": from_dt, "to_dt": to_dt, "order": order,
            },
            "columns": cfg["columns"],
            "rows": data,
        },
        message=f"{category} events ({metric})",
    )
