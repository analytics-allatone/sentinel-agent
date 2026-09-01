from datetime import datetime, timezone
from typing import Optional , List

from fastapi import APIRouter, Query, HTTPException, Depends
from sqlalchemy import select, func, case, distinct
from sqlalchemy.ext.asyncio import AsyncSession

from auth.jwt_auth import verify_token
from db.db import get_async_db
from models.event_model import AuthEvents, FileEvents, NetworkEvents, ProcessEvents, USBEvents
from schemas.v1.standard_schema import standard_success_response


agent_report_router = APIRouter()

# ---- shared vocabulary -------------------------------------------------------
OUTCOME_SUCCESS = "success"
OUTCOME_FAILURE = "failure"
HIGH_SEVERITIES = ["high", "critical"]

# Row cap for the "detail table" style payloads (notable events, etc.).
DETAIL_LIMIT = 200


# ---- shared helpers ----------------------------------------------------------
def validate_window(from_dt: datetime, to_dt: datetime) -> None:
    """Reject an inverted or empty time window before we touch the DB."""
    if from_dt >= to_dt:
        raise HTTPException(status_code=400, detail="from_dt must be before to_dt")


def build_meta(agent_name: Optional[str | List]|None, from_dt: datetime, to_dt: datetime, total: int) -> dict:
    """Uniform meta block so every report is self-describing / auditable."""
    return {
        "agent_name": agent_name,
        "from_dt": from_dt,
        "to_dt": to_dt,
        "generated_at": datetime.now(timezone.utc),
        "total_events": total,
    }


def num(value, digits: int = 2):
    """
    Normalise a numeric aggregate for JSON.

    Postgres AVG() comes back as Decimal, which many JSON encoders choke on.
    Coerce to float (or None) and round so the payload is always serialisable.
    """
    if value is None:
        return None
    return round(float(value), digits)


async def top_breakdown(
    db: AsyncSession,
    column,
    base_filters: list,
    *,
    limit: int = 10,
    where_extra=None,
    exclude_null: bool = True,
):
    """Generic "top N values of `column` by event count" breakdown."""
    conds = list(base_filters)
    if exclude_null:
        conds.append(column.isnot(None))
    if where_extra is not None:
        conds.append(where_extra)

    q = (
        select(column.label("label"), func.count().label("cnt"))
        .where(*conds)
        .group_by(column)
        .order_by(func.count().desc())
        .limit(limit)
    )
    rows = (await db.execute(q)).all()
    return [{"label": str(r.label), "count": r.cnt} for r in rows]


async def bucketed(db: AsyncSession, timestamp_col, base_filters: list, bucket: str, *value_exprs):
    """
    Group rows into `hour`/`day` buckets and compute the supplied labelled
    aggregate expressions per bucket. Callers read results by their label,
    e.g. `func.count().label("events")` -> `row.events`.
    """
    b = func.date_trunc(bucket, timestamp_col).label("bucket")
    q = (
        select(b, *value_exprs)
        .where(*base_filters)
        .group_by(b)
        .order_by(b.asc())
    )
    return (await db.execute(q)).all()


# =============================================================================
# FILE  — integrity / change-management
# =============================================================================
@agent_report_router.get("/soc2-report/file", status_code=200)
async def soc2_file_report(
    from_dt: datetime = Query(..., description="Window start (ISO-8601)"),
    to_dt: datetime = Query(..., description="Window end (ISO-8601)"),
    agent_name: Optional[List[str]] = Query(None, description="Filter to one agent; omit for all"),
    bucket: str = Query("hour", pattern="^(hour|day)$", description="Timeseries resolution"),
    db: AsyncSession = Depends(get_async_db),
    _claims: dict = Depends(verify_token),
):
    """File integrity / change-management report (SOC2 CC7-style monitoring)."""
    validate_window(from_dt, to_dt)
    F = FileEvents

    filt = [F.timestamp >= from_dt, F.timestamp <= to_dt]
    if agent_name:
        filt.append(F.agent_name.in_(agent_name))

    is_success = case((F.outcome == OUTCOME_SUCCESS, 1), else_=0)
    is_failure = case((F.outcome == OUTCOME_FAILURE, 1), else_=0)
    is_anomaly = case((F.anomaly.is_(True), 1), else_=0)
    has_ioc = case((F.ioc_match.isnot(None), 1), else_=0)
    is_high = case((F.severity.in_(HIGH_SEVERITIES), 1), else_=0)

    # ---- 1. SUMMARY ----
    summary_q = select(
        func.count().label("total"),
        func.sum(is_success).label("successful"),
        func.sum(is_failure).label("failed"),
        func.count(distinct(F.file_path)).label("unique_files"),
        func.count(distinct(F.user_name)).label("unique_users"),
        func.sum(is_anomaly).label("anomalies"),
        func.sum(has_ioc).label("ioc_matches"),
        func.sum(is_high).label("high_sev"),
        func.max(F.risk_score).label("max_risk"),
        func.avg(F.risk_score).label("avg_risk"),
    ).where(*filt)
    s = (await db.execute(summary_q)).one()
    total = s.total or 0

    # ---- 2. TIMESERIES ----
    ts_rows = await bucketed(
        db, F.timestamp, filt, bucket,
        func.count().label("events"),
        func.sum(is_anomaly).label("anomalies"),
        func.sum(is_high).label("high_sev"),
    )

    # ---- 3. BREAKDOWNS ----
    top_actions       = await top_breakdown(db, F.action, filt)
    file_extensions   = await top_breakdown(db, F.file_extension, filt)
    top_directories   = await top_breakdown(db, F.file_directory, filt)
    most_active_files = await top_breakdown(db, F.file_path, filt)
    severity_dist     = await top_breakdown(db, F.severity, filt, limit=20)
    top_users         = await top_breakdown(db, F.user_name, filt)
    ioc_matches       = await top_breakdown(db, F.ioc_match, filt)
    mitre_tactics     = await top_breakdown(db, F.mitre_tactic, filt)
    mitre_techniques  = await top_breakdown(db, F.mitre_technique, filt)

    # ---- 4. NOTABLE (high/critical) ----
    notable_q = (
        select(F.timestamp, F.action, F.file_path, F.user_name, F.severity,
               F.outcome, F.risk_score, F.ioc_match)
        .where(*filt, F.severity.in_(HIGH_SEVERITIES))
        .order_by(F.timestamp.desc()).limit(DETAIL_LIMIT)
    )
    notable_rows = (await db.execute(notable_q)).all()

    # ---- 5. ANOMALOUS ----
    anomalous_q = (
        select(F.timestamp, F.action, F.file_path, F.user_name,
               F.risk_score, F.mitre_tactic, F.mitre_technique)
        .where(*filt, F.anomaly.is_(True))
        .order_by(F.timestamp.desc()).limit(DETAIL_LIMIT)
    )
    anomalous_rows = (await db.execute(anomalous_q)).all()

    # ---- 6. INTEGRITY CHANGES (renames / hash changes) ----
    integrity_q = (
        select(F.timestamp, F.file_path, F.file_old_path, F.file_sha256,
               F.file_old_sha256, F.user_name, F.action)
        .where(*filt, (F.file_old_sha256.isnot(None)) | (F.file_old_path.isnot(None)))
        .order_by(F.timestamp.desc()).limit(DETAIL_LIMIT)
    )
    integrity_rows = (await db.execute(integrity_q)).all()

    return standard_success_response(
        data={
            "meta": build_meta(agent_name, from_dt, to_dt, total),
            "summary": {
                "total_file_events": total,
                "successful": s.successful or 0,
                "failed": s.failed or 0,
                "unique_files": s.unique_files or 0,
                "unique_users": s.unique_users or 0,
                "anomalies": s.anomalies or 0,
                "ioc_matches": s.ioc_matches or 0,
                "high_severity_events": s.high_sev or 0,
                "max_risk_score": num(s.max_risk),
                "avg_risk_score": num(s.avg_risk),
            },
            "file_timeseries": [
                {"t": r.bucket, "events": r.events or 0,
                 "anomalies": r.anomalies or 0, "high_severity": r.high_sev or 0}
                for r in ts_rows
            ],
            "top_actions": top_actions,
            "file_extensions": file_extensions,
            "top_directories": top_directories,
            "most_active_files": most_active_files,
            "severity_distribution": severity_dist,
            "top_users": top_users,
            "ioc_matches": ioc_matches,
            "mitre_tactics": mitre_tactics,
            "mitre_techniques": mitre_techniques,
            "notable_events": [
                {"timestamp": r.timestamp, "action": r.action, "file_path": r.file_path,
                 "user_name": r.user_name, "severity": r.severity, "outcome": r.outcome,
                 "risk_score": r.risk_score, "ioc_match": r.ioc_match}
                for r in notable_rows
            ],
            "anomalous_events": [
                {"timestamp": r.timestamp, "action": r.action, "file_path": r.file_path,
                 "user_name": r.user_name, "risk_score": r.risk_score,
                 "mitre_tactic": r.mitre_tactic, "mitre_technique": r.mitre_technique}
                for r in anomalous_rows
            ],
            "integrity_changes": [
                {"timestamp": r.timestamp, "file_path": r.file_path, "old_path": r.file_old_path,
                 "sha256": r.file_sha256, "old_sha256": r.file_old_sha256,
                 "user_name": r.user_name, "action": r.action}
                for r in integrity_rows
            ],
        },
        message="File integrity activity report generated",
    )


# =============================================================================
# NETWORK  — boundary / data-transfer
# =============================================================================
@agent_report_router.get("/soc2-report/network", status_code=200)
async def soc2_network_report(
    from_dt: datetime = Query(..., description="Window start (ISO-8601)"),
    to_dt: datetime = Query(..., description="Window end (ISO-8601)"),
    agent_name: Optional[List[str]] = Query(None, description="Filter to one agent; omit for all"),
    bucket: str = Query("hour", pattern="^(hour|day)$", description="Timeseries resolution"),
    db: AsyncSession = Depends(get_async_db),
    _claims: dict = Depends(verify_token),
):
    """Network boundary / data-transfer report (egress + top talkers)."""
    validate_window(from_dt, to_dt)
    N = NetworkEvents

    filt = [N.timestamp >= from_dt, N.timestamp <= to_dt]
    if agent_name:
        filt.append(N.agent_name.in_(agent_name))

    is_success = case((N.outcome == OUTCOME_SUCCESS, 1), else_=0)
    is_failure = case((N.outcome == OUTCOME_FAILURE, 1), else_=0)
    is_anomaly = case((N.anomaly.is_(True), 1), else_=0)
    has_ioc = case((N.ioc_match.isnot(None), 1), else_=0)
    is_high = case((N.severity.in_(HIGH_SEVERITIES), 1), else_=0)

    sent = func.coalesce(N.network_bytes_sent, 0)
    recv = func.coalesce(N.network_bytes_recv, 0)
    total_bytes = sent + recv

    # ---- 1. SUMMARY ----
    summary_q = select(
        func.count().label("total"),
        func.sum(is_success).label("successful"),
        func.sum(is_failure).label("failed"),
        func.count(distinct(N.network_src_ip)).label("unique_src"),
        func.count(distinct(N.network_dst_ip)).label("unique_dst"),
        func.count(distinct(N.network_dns_query)).label("unique_dns"),
        func.sum(sent).label("bytes_sent"),
        func.sum(recv).label("bytes_recv"),
        func.sum(is_anomaly).label("anomalies"),
        func.sum(has_ioc).label("ioc_matches"),
        func.sum(is_high).label("high_sev"),
        func.max(N.risk_score).label("max_risk"),
    ).where(*filt)
    s = (await db.execute(summary_q)).one()
    total = s.total or 0

    # ---- 2. TIMESERIES (event count + bytes in/out) ----
    ts_rows = await bucketed(
        db, N.timestamp, filt, bucket,
        func.count().label("events"),
        func.sum(sent).label("bytes_sent"),
        func.sum(recv).label("bytes_recv"),
        func.sum(is_anomaly).label("anomalies"),
    )

    # ---- 3. BREAKDOWNS ----
    top_dst_ips       = await top_breakdown(db, N.network_dst_ip, filt)
    top_dst_ports     = await top_breakdown(db, N.network_dst_port, filt)
    top_src_ips       = await top_breakdown(db, N.network_src_ip, filt)
    protocols         = await top_breakdown(db, N.network_protocol, filt)
    transports        = await top_breakdown(db, N.network_transport, filt)
    directions        = await top_breakdown(db, N.network_direction, filt)
    connection_status = await top_breakdown(db, N.network_connection_status, filt)
    top_dns_queries   = await top_breakdown(db, N.network_dns_query, filt)
    top_processes     = await top_breakdown(db, N.process_name, filt)
    severity_dist     = await top_breakdown(db, N.severity, filt, limit=20)
    mitre_tactics     = await top_breakdown(db, N.mitre_tactic, filt)

    # ---- 4. TOP TALKERS (destinations by total bytes) ----
    talkers_q = (
        select(
            N.network_dst_ip.label("dst_ip"),
            func.sum(total_bytes).label("bytes"),
            func.count().label("connections"),
        )
        .where(*filt, N.network_dst_ip.isnot(None))
        .group_by(N.network_dst_ip)
        .order_by(func.sum(total_bytes).desc())
        .limit(20)
    )
    talker_rows = (await db.execute(talkers_q)).all()

    # ---- 5. EXTERNAL CONNECTIONS (public destinations only) ----
    external_q = (
        select(N.network_dst_ip.label("dst_ip"), func.count().label("cnt"))
        .where(*filt, N.network_is_private_ip.is_(False), N.network_dst_ip.isnot(None))
        .group_by(N.network_dst_ip)
        .order_by(func.count().desc())
        .limit(20)
    )
    external_rows = (await db.execute(external_q)).all()

    # ---- 6. NOTABLE (high/critical) ----
    notable_q = (
        select(N.timestamp, N.network_direction, N.network_protocol,
               N.network_src_ip, N.network_dst_ip, N.network_dst_port,
               N.process_name, N.severity, N.outcome, N.risk_score, N.ioc_match)
        .where(*filt, N.severity.in_(HIGH_SEVERITIES))
        .order_by(N.timestamp.desc()).limit(DETAIL_LIMIT)
    )
    notable_rows = (await db.execute(notable_q)).all()

    return standard_success_response(
        data={
            "meta": build_meta(agent_name, from_dt, to_dt, total),
            "summary": {
                "total_network_events": total,
                "successful": s.successful or 0,
                "failed": s.failed or 0,
                "unique_source_ips": s.unique_src or 0,
                "unique_dest_ips": s.unique_dst or 0,
                "unique_dns_queries": s.unique_dns or 0,
                "total_bytes_sent": int(s.bytes_sent or 0),
                "total_bytes_received": int(s.bytes_recv or 0),
                "anomalies": s.anomalies or 0,
                "ioc_matches": s.ioc_matches or 0,
                "high_severity_events": s.high_sev or 0,
                "max_risk_score": num(s.max_risk),
            },
            "network_timeseries": [
                {"t": r.bucket, "events": r.events or 0,
                 "bytes_sent": int(r.bytes_sent or 0), "bytes_received": int(r.bytes_recv or 0),
                 "anomalies": r.anomalies or 0}
                for r in ts_rows
            ],
            "top_dest_ips": top_dst_ips,
            "top_dest_ports": top_dst_ports,
            "top_source_ips": top_src_ips,
            "protocols": protocols,
            "transports": transports,
            "directions": directions,
            "connection_status": connection_status,
            "top_dns_queries": top_dns_queries,
            "top_processes": top_processes,
            "severity_distribution": severity_dist,
            "mitre_tactics": mitre_tactics,
            "top_talkers": [
                {"dest_ip": r.dst_ip, "total_bytes": int(r.bytes or 0), "connections": r.connections}
                for r in talker_rows
            ],
            "external_connections": [
                {"dest_ip": r.dst_ip, "count": r.cnt} for r in external_rows
            ],
            "notable_events": [
                {"timestamp": r.timestamp, "direction": r.network_direction,
                 "protocol": r.network_protocol, "source_ip": r.network_src_ip,
                 "dest_ip": r.network_dst_ip, "dest_port": r.network_dst_port,
                 "process_name": r.process_name, "severity": r.severity,
                 "outcome": r.outcome, "risk_score": r.risk_score, "ioc_match": r.ioc_match}
                for r in notable_rows
            ],
        },
        message="Network activity report generated",
    )


# =============================================================================
# PROCESS  — execution / workload
# =============================================================================
@agent_report_router.get("/soc2-report/process", status_code=200)
async def soc2_process_report(
    from_dt: datetime = Query(..., description="Window start (ISO-8601)"),
    to_dt: datetime = Query(..., description="Window end (ISO-8601)"),
    agent_name: Optional[List[str]] = Query(None, description="Filter to one agent; omit for all"),
    bucket: str = Query("hour", pattern="^(hour|day)$", description="Timeseries resolution"),
    db: AsyncSession = Depends(get_async_db),
    _claims: dict = Depends(verify_token),
):
    """Process execution / workload report (malware & resource anomalies)."""
    validate_window(from_dt, to_dt)
    P = ProcessEvents

    filt = [P.timestamp >= from_dt, P.timestamp <= to_dt]
    if agent_name:
        filt.append(P.agent_name.in_(agent_name))

    is_success = case((P.outcome == OUTCOME_SUCCESS, 1), else_=0)
    is_failure = case((P.outcome == OUTCOME_FAILURE, 1), else_=0)
    is_anomaly = case((P.anomaly.is_(True), 1), else_=0)
    has_ioc = case((P.ioc_match.isnot(None), 1), else_=0)
    is_high = case((P.severity.in_(HIGH_SEVERITIES), 1), else_=0)

    # ---- 1. SUMMARY ----
    summary_q = select(
        func.count().label("total"),
        func.sum(is_success).label("successful"),
        func.sum(is_failure).label("failed"),
        func.count(distinct(P.process_name)).label("unique_processes"),
        func.count(distinct(P.process_executable)).label("unique_executables"),
        func.count(distinct(P.process_user)).label("unique_users"),
        func.sum(is_anomaly).label("anomalies"),
        func.sum(has_ioc).label("ioc_matches"),
        func.sum(is_high).label("high_sev"),
        func.avg(P.process_cpu_percent).label("avg_cpu"),
        func.max(P.process_cpu_percent).label("max_cpu"),
        func.avg(P.process_memory_rss_mb).label("avg_mem"),
        func.max(P.risk_score).label("max_risk"),
    ).where(*filt)
    s = (await db.execute(summary_q)).one()
    total = s.total or 0

    # ---- 2. TIMESERIES ----
    ts_rows = await bucketed(
        db, P.timestamp, filt, bucket,
        func.count().label("events"),
        func.sum(is_anomaly).label("anomalies"),
        func.sum(is_high).label("high_sev"),
    )

    # ---- 3. BREAKDOWNS ----
    top_process_names = await top_breakdown(db, P.process_name, filt)
    top_executables   = await top_breakdown(db, P.process_executable, filt)
    top_users         = await top_breakdown(db, P.process_user, filt)
    top_working_dirs  = await top_breakdown(db, P.process_working_dir, filt)
    severity_dist     = await top_breakdown(db, P.severity, filt, limit=20)
    ioc_matches       = await top_breakdown(db, P.ioc_match, filt)
    mitre_tactics     = await top_breakdown(db, P.mitre_tactic, filt)
    mitre_techniques  = await top_breakdown(db, P.mitre_technique, filt)

    # ---- 4. TOP CPU EVENTS ----
    top_cpu_q = (
        select(P.timestamp, P.process_name, P.process_pid, P.process_user,
               P.process_cpu_percent, P.process_memory_rss_mb)
        .where(*filt, P.process_cpu_percent.isnot(None))
        .order_by(P.process_cpu_percent.desc()).limit(20)
    )
    top_cpu_rows = (await db.execute(top_cpu_q)).all()

    # ---- 5. NOTABLE (high/critical) ----
    notable_q = (
        select(P.timestamp, P.process_name, P.process_executable, P.process_command_line,
               P.process_user, P.severity, P.outcome, P.risk_score, P.ioc_match)
        .where(*filt, P.severity.in_(HIGH_SEVERITIES))
        .order_by(P.timestamp.desc()).limit(DETAIL_LIMIT)
    )
    notable_rows = (await db.execute(notable_q)).all()

    # ---- 6. ANOMALOUS ----
    anomalous_q = (
        select(P.timestamp, P.process_name, P.process_command_line, P.process_user,
               P.risk_score, P.mitre_tactic, P.mitre_technique)
        .where(*filt, P.anomaly.is_(True))
        .order_by(P.timestamp.desc()).limit(DETAIL_LIMIT)
    )
    anomalous_rows = (await db.execute(anomalous_q)).all()

    # ---- 7. FLAGGED HASHES (IOC hits) ----
    flagged_q = (
        select(P.timestamp, P.process_name, P.process_sha256, P.ioc_match, P.process_user)
        .where(*filt, P.ioc_match.isnot(None))
        .order_by(P.timestamp.desc()).limit(DETAIL_LIMIT)
    )
    flagged_rows = (await db.execute(flagged_q)).all()

    return standard_success_response(
        data={
            "meta": build_meta(agent_name, from_dt, to_dt, total),
            "summary": {
                "total_process_events": total,
                "successful": s.successful or 0,
                "failed": s.failed or 0,
                "unique_processes": s.unique_processes or 0,
                "unique_executables": s.unique_executables or 0,
                "unique_users": s.unique_users or 0,
                "anomalies": s.anomalies or 0,
                "ioc_matches": s.ioc_matches or 0,
                "high_severity_events": s.high_sev or 0,
                "avg_cpu_percent": num(s.avg_cpu),
                "max_cpu_percent": num(s.max_cpu),
                "avg_memory_rss_mb": num(s.avg_mem),
                "max_risk_score": num(s.max_risk),
            },
            "process_timeseries": [
                {"t": r.bucket, "events": r.events or 0,
                 "anomalies": r.anomalies or 0, "high_severity": r.high_sev or 0}
                for r in ts_rows
            ],
            "top_process_names": top_process_names,
            "top_executables": top_executables,
            "top_users": top_users,
            "top_working_dirs": top_working_dirs,
            "severity_distribution": severity_dist,
            "ioc_matches": ioc_matches,
            "mitre_tactics": mitre_tactics,
            "mitre_techniques": mitre_techniques,
            "top_cpu_events": [
                {"timestamp": r.timestamp, "process_name": r.process_name, "pid": r.process_pid,
                 "user": r.process_user, "cpu_percent": num(r.process_cpu_percent),
                 "memory_rss_mb": num(r.process_memory_rss_mb)}
                for r in top_cpu_rows
            ],
            "notable_events": [
                {"timestamp": r.timestamp, "process_name": r.process_name,
                 "executable": r.process_executable, "command_line": r.process_command_line,
                 "user": r.process_user, "severity": r.severity, "outcome": r.outcome,
                 "risk_score": r.risk_score, "ioc_match": r.ioc_match}
                for r in notable_rows
            ],
            "anomalous_events": [
                {"timestamp": r.timestamp, "process_name": r.process_name,
                 "command_line": r.process_command_line, "user": r.process_user,
                 "risk_score": r.risk_score, "mitre_tactic": r.mitre_tactic,
                 "mitre_technique": r.mitre_technique}
                for r in anomalous_rows
            ],
            "flagged_hashes": [
                {"timestamp": r.timestamp, "process_name": r.process_name,
                 "sha256": r.process_sha256, "ioc_match": r.ioc_match, "user": r.process_user}
                for r in flagged_rows
            ],
        },
        message="Process execution report generated",
    )


# =============================================================================
# AUTH  — authentication / access control
# =============================================================================
@agent_report_router.get("/soc2-report/auth", status_code=200)
async def soc2_auth_report(
    from_dt: datetime = Query(..., description="Window start (ISO-8601)"),
    to_dt: datetime = Query(..., description="Window end (ISO-8601)"),
    agent_name: Optional[List[str]] = Query(None, description="Filter to one agent; omit for all"),
    bucket: str = Query("hour", pattern="^(hour|day)$", description="Timeseries resolution"),
    db: AsyncSession = Depends(get_async_db),
    _claims: dict = Depends(verify_token),
):
    """Authentication / access-control report (logins, failures, privilege use)."""
    validate_window(from_dt, to_dt)
    A = AuthEvents

    filt = [A.timestamp >= from_dt, A.timestamp <= to_dt]
    if agent_name:
        filt.append(A.agent_name.in_(agent_name))

    is_success = case((A.outcome == OUTCOME_SUCCESS, 1), else_=0)
    is_failure = case((A.outcome == OUTCOME_FAILURE, 1), else_=0)

    # ---- 1. SUMMARY ----
    summary_q = select(
        func.count().label("total"),
        func.sum(is_success).label("successful"),
        func.sum(is_failure).label("failed"),
        func.count(distinct(A.username)).label("unique_users"),
        func.count(distinct(A.auth_source_ip)).label("unique_ips"),
        func.sum(case((A.auth_sudo_command.isnot(None), 1), else_=0)).label("privileged"),
        func.sum(case((A.severity.in_(HIGH_SEVERITIES), 1), else_=0)).label("high_sev"),
    ).where(*filt)
    s = (await db.execute(summary_q)).one()

    total = s.total or 0
    failed = s.failed or 0
    failure_rate = round((failed / total * 100), 2) if total else 0.0

    # ---- 2. TIMESERIES (success vs failure) ----
    ts_rows = await bucketed(
        db, A.timestamp, filt, bucket,
        func.sum(is_success).label("succ"),
        func.sum(is_failure).label("fail"),
    )

    # ---- 3. BREAKDOWNS ----
    failed_by_user  = await top_breakdown(db, A.username, filt, where_extra=(A.outcome == OUTCOME_FAILURE))
    failed_by_ip    = await top_breakdown(db, A.auth_source_ip, filt, where_extra=(A.outcome == OUTCOME_FAILURE))
    failure_reasons = await top_breakdown(db, A.auth_failure_reason, filt)
    auth_methods    = await top_breakdown(db, A.auth_method, filt)
    severity_dist   = await top_breakdown(db, A.severity, filt, limit=20)
    session_types   = await top_breakdown(db, A.auth_session_type, filt)
    top_users       = await top_breakdown(db, A.username, filt)

    # ---- 4. PRIVILEGED ACCESS (all sudo in window) ----
    priv_q = (
        select(A.timestamp, A.username, A.auth_sudo_command, A.outcome, A.auth_source_ip)
        .where(*filt, A.auth_sudo_command.isnot(None))
        .order_by(A.timestamp.desc()).limit(DETAIL_LIMIT)
    )
    priv_rows = (await db.execute(priv_q)).all()

    # ---- 5. NOTABLE (high/critical) ----
    notable_q = (
        select(A.timestamp, A.username, A.action, A.outcome, A.severity,
               A.auth_source_ip, A.auth_failure_reason)
        .where(*filt, A.severity.in_(HIGH_SEVERITIES))
        .order_by(A.timestamp.desc()).limit(DETAIL_LIMIT)
    )
    notable_rows = (await db.execute(notable_q)).all()

    return standard_success_response(
        data={
            "meta": build_meta(agent_name, from_dt, to_dt, total),
            "summary": {
                "total_auth_events": total,
                "successful_auths": s.successful or 0,
                "failed_auths": failed,
                "failure_rate_pct": failure_rate,
                "unique_users": s.unique_users or 0,
                "unique_source_ips": s.unique_ips or 0,
                "privileged_actions": s.privileged or 0,
                "high_severity_events": s.high_sev or 0,
            },
            "auth_timeseries": [
                {"t": r.bucket, "successful": r.succ or 0, "failed": r.fail or 0}
                for r in ts_rows
            ],
            "failed_by_user": failed_by_user,
            "failed_by_source_ip": failed_by_ip,
            "failure_reasons": failure_reasons,
            "auth_methods": auth_methods,
            "severity_distribution": severity_dist,
            "session_types": session_types,
            "top_active_users": top_users,
            "privileged_access": [
                {"timestamp": r.timestamp, "username": r.username,
                 "sudo_command": r.auth_sudo_command, "outcome": r.outcome,
                 "source_ip": r.auth_source_ip}
                for r in priv_rows
            ],
            "notable_events": [
                {"timestamp": r.timestamp, "username": r.username, "action": r.action,
                 "outcome": r.outcome, "severity": r.severity,
                 "source_ip": r.auth_source_ip, "failure_reason": r.auth_failure_reason}
                for r in notable_rows
            ],
        },
        message="Authentication activity report generated",
    )


# =============================================================================
# USB  — removable media
# =============================================================================
@agent_report_router.get("/soc2-report/usb", status_code=200)
async def soc2_usb_report(
    from_dt: datetime = Query(..., description="Window start (ISO-8601)"),
    to_dt: datetime = Query(..., description="Window end (ISO-8601)"),
    agent_name: Optional[List[str]] = Query(None, description="Filter to one agent; omit for all"),
    bucket: str = Query("hour", pattern="^(hour|day)$", description="Timeseries resolution"),
    db: AsyncSession = Depends(get_async_db),
    _claims: dict = Depends(verify_token),
):
    """Removable-media report (device usage + data-transfer / exfil watch)."""
    validate_window(from_dt, to_dt)
    U = USBEvents

    filt = [U.timestamp >= from_dt, U.timestamp <= to_dt]
    if agent_name:
        filt.append(U.agent_name.in_(agent_name))

    is_success = case((U.outcome == OUTCOME_SUCCESS, 1), else_=0)
    is_failure = case((U.outcome == OUTCOME_FAILURE, 1), else_=0)
    is_anomaly = case((U.anomaly.is_(True), 1), else_=0)
    has_ioc = case((U.ioc_match.isnot(None), 1), else_=0)
    is_high = case((U.severity.in_(HIGH_SEVERITIES), 1), else_=0)

    transferred = func.coalesce(U.usb_transfer_delta_bytes, 0)

    # ---- 1. SUMMARY ----
    summary_q = select(
        func.count().label("total"),
        func.sum(is_success).label("successful"),
        func.sum(is_failure).label("failed"),
        func.count(distinct(U.usb_serial_number)).label("unique_devices"),
        func.count(distinct(U.usb_vendor)).label("unique_vendors"),
        func.sum(transferred).label("bytes_transferred"),
        func.sum(is_anomaly).label("anomalies"),
        func.sum(has_ioc).label("ioc_matches"),
        func.sum(is_high).label("high_sev"),
        func.max(U.risk_score).label("max_risk"),
    ).where(*filt)
    s = (await db.execute(summary_q)).one()
    total = s.total or 0

    # ---- 2. TIMESERIES ----
    ts_rows = await bucketed(
        db, U.timestamp, filt, bucket,
        func.count().label("events"),
        func.sum(transferred).label("bytes_transferred"),
        func.sum(is_anomaly).label("anomalies"),
    )

    # ---- 3. BREAKDOWNS ----
    top_vendors   = await top_breakdown(db, U.usb_vendor, filt)
    top_models    = await top_breakdown(db, U.usb_model, filt)
    top_devices   = await top_breakdown(db, U.usb_serial_number, filt)
    fstypes       = await top_breakdown(db, U.usb_fstype, filt)
    top_actions   = await top_breakdown(db, U.action, filt)
    severity_dist = await top_breakdown(db, U.severity, filt, limit=20)
    mitre_tactics = await top_breakdown(db, U.mitre_tactic, filt)

    # ---- 4. DEVICE ACTIVITY (mounts / insertions) ----
    device_q = (
        select(U.timestamp, U.action, U.usb_vendor, U.usb_model, U.usb_serial_number,
               U.usb_label, U.usb_mountpoint, U.usb_fstype, U.usb_size_bytes)
        .where(*filt, U.usb_serial_number.isnot(None))
        .order_by(U.timestamp.desc()).limit(DETAIL_LIMIT)
    )
    device_rows = (await db.execute(device_q)).all()

    # ---- 5. DATA TRANSFERS (bytes actually moved) ----
    transfer_q = (
        select(U.timestamp, U.usb_serial_number, U.usb_vendor, U.usb_model,
               U.usb_transfer_delta_bytes, U.file_name, U.file_path, U.usb_mountpoint)
        .where(*filt, U.usb_transfer_delta_bytes.isnot(None), U.usb_transfer_delta_bytes > 0)
        .order_by(U.usb_transfer_delta_bytes.desc()).limit(DETAIL_LIMIT)
    )
    transfer_rows = (await db.execute(transfer_q)).all()

    # ---- 6. NOTABLE (high/critical) ----
    notable_q = (
        select(U.timestamp, U.action, U.usb_vendor, U.usb_model, U.usb_serial_number,
               U.file_name, U.severity, U.outcome, U.risk_score, U.ioc_match)
        .where(*filt, U.severity.in_(HIGH_SEVERITIES))
        .order_by(U.timestamp.desc()).limit(DETAIL_LIMIT)
    )
    notable_rows = (await db.execute(notable_q)).all()

    return standard_success_response(
        data={
            "meta": build_meta(agent_name, from_dt, to_dt, total),
            "summary": {
                "total_usb_events": total,
                "successful": s.successful or 0,
                "failed": s.failed or 0,
                "unique_devices": s.unique_devices or 0,
                "unique_vendors": s.unique_vendors or 0,
                "total_bytes_transferred": int(s.bytes_transferred or 0),
                "anomalies": s.anomalies or 0,
                "ioc_matches": s.ioc_matches or 0,
                "high_severity_events": s.high_sev or 0,
                "max_risk_score": num(s.max_risk),
            },
            "usb_timeseries": [
                {"t": r.bucket, "events": r.events or 0,
                 "bytes_transferred": int(r.bytes_transferred or 0), "anomalies": r.anomalies or 0}
                for r in ts_rows
            ],
            "top_vendors": top_vendors,
            "top_models": top_models,
            "top_devices": top_devices,
            "filesystem_types": fstypes,
            "top_actions": top_actions,
            "severity_distribution": severity_dist,
            "mitre_tactics": mitre_tactics,
            "device_activity": [
                {"timestamp": r.timestamp, "action": r.action, "vendor": r.usb_vendor,
                 "model": r.usb_model, "serial_number": r.usb_serial_number, "label": r.usb_label,
                 "mountpoint": r.usb_mountpoint, "fstype": r.usb_fstype,
                 "size_bytes": r.usb_size_bytes}
                for r in device_rows
            ],
            "data_transfers": [
                {"timestamp": r.timestamp, "serial_number": r.usb_serial_number,
                 "vendor": r.usb_vendor, "model": r.usb_model,
                 "transfer_bytes": int(r.usb_transfer_delta_bytes or 0),
                 "file_name": r.file_name, "file_path": r.file_path}
                for r in transfer_rows
            ],
            "notable_events": [
                {"timestamp": r.timestamp, "action": r.action, "vendor": r.usb_vendor,
                 "model": r.usb_model, "serial_number": r.usb_serial_number,
                 "file_name": r.file_name, "severity": r.severity, "outcome": r.outcome,
                 "risk_score": r.risk_score, "ioc_match": r.ioc_match}
                for r in notable_rows
            ],
        },
        message="Removable media (USB) report generated",
    )