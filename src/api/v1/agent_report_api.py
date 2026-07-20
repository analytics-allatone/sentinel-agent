from fastapi import APIRouter , Query, HTTPException, Depends
from sqlalchemy import select, func, case, distinct
from sqlalchemy.ext.asyncio import AsyncSession
from datetime import datetime, timezone
from typing import Optional

from auth.jwt_auth import verify_token
from db.db import get_async_db
from models.event_model import AuthEvents
from schemas.v1.standard_schema import standard_success_response



agent_report_router = APIRouter()


OUTCOME_SUCCESS = "success"
OUTCOME_FAILURE = "failure"

@agent_report_router.get("/soc2-report/auth", status_code=200)
async def soc2_auth_report(
    from_dt: datetime = Query(..., description="Window start (ISO-8601)"),
    to_dt: datetime = Query(..., description="Window end (ISO-8601)"),
    agent_name: Optional[str] = Query(None, description="Filter to one agent; omit for all"),
    bucket: str = Query("hour", pattern="^(hour|day)$", description="Timeseries resolution"),
    db: AsyncSession = Depends(get_async_db),
):
    if from_dt >= to_dt:
        raise HTTPException(400, "from_dt must be before to_dt")

    A = AuthEvents  # your model

    # shared WHERE
    filt = [A.timestamp >= from_dt, A.timestamp <= to_dt]
    if agent_name:
        filt.append(A.agent_name == agent_name)

    # reusable success/failure expressions
    is_success = case((A.outcome == OUTCOME_SUCCESS, 1), else_=0)
    is_failure = case((A.outcome == OUTCOME_FAILURE, 1), else_=0)

    # ---- 1. SUMMARY (single row) ----
    summary_q = select(
        func.count().label("total"),
        func.sum(is_success).label("successful"),
        func.sum(is_failure).label("failed"),
        func.count(distinct(A.username)).label("unique_users"),
        func.count(distinct(A.auth_source_ip)).label("unique_ips"),
        func.sum(case((A.auth_sudo_command.isnot(None), 1), else_=0)).label("privileged"),
        func.sum(case((A.severity.in_(["high", "critical"]), 1), else_=0)).label("high_sev"),
    ).where(*filt)
    s = (await db.execute(summary_q)).one()

    total = s.total or 0
    failed = s.failed or 0
    failure_rate = round((failed / total * 100), 2) if total else 0.0

    # ---- 2. TIMESERIES (bucketed success vs failure) ----
    b = func.date_trunc(bucket, A.timestamp).label("bucket")
    ts_q = (
        select(b, func.sum(is_success).label("succ"), func.sum(is_failure).label("fail"))
        .where(*filt).group_by(b).order_by(b.asc())
    )
    ts_rows = (await db.execute(ts_q)).all()

    # ---- helper: top-N label/count breakdown ----
    async def breakdown(column, limit=10, where_extra=None, exclude_null=True):
        conds = list(filt)
        if exclude_null:
            conds.append(column.isnot(None))
        if where_extra is not None:
            conds.append(where_extra)
        q = (
            select(column.label("label"), func.count().label("cnt"))
            .where(*conds).group_by(column).order_by(func.count().desc()).limit(limit)
        )
        rows = (await db.execute(q)).all()
        return [{"label": str(r.label), "count": r.cnt} for r in rows]

    # ---- 3. BREAKDOWNS ----
    failed_by_user   = await breakdown(A.username,            where_extra=(A.outcome == OUTCOME_FAILURE))
    failed_by_ip     = await breakdown(A.auth_source_ip,      where_extra=(A.outcome == OUTCOME_FAILURE))
    failure_reasons  = await breakdown(A.auth_failure_reason)
    auth_methods     = await breakdown(A.auth_method)
    severity_dist    = await breakdown(A.severity, limit=20)
    session_types    = await breakdown(A.auth_session_type)
    top_users        = await breakdown(A.username, limit=10)

    # ---- 4. PRIVILEGED ACCESS table (all sudo in window) ----
    priv_q = (
        select(A.timestamp, A.username, A.auth_sudo_command, A.outcome, A.auth_source_ip)
        .where(*filt, A.auth_sudo_command.isnot(None))
        .order_by(A.timestamp.desc()).limit(200)
    )
    priv_rows = (await db.execute(priv_q)).all()

    # ---- 5. NOTABLE (high/critical) table ----
    notable_q = (
        select(A.timestamp, A.username, A.action, A.outcome, A.severity,
               A.auth_source_ip, A.auth_failure_reason)
        .where(*filt, A.severity.in_(["high", "critical"]))
        .order_by(A.timestamp.desc()).limit(200)
    )
    notable_rows = (await db.execute(notable_q)).all()

    # ---- assemble ----
    return standard_success_response(
        data={
            "meta": {
                "agent_name": agent_name,
                "from_dt": from_dt, "to_dt": to_dt,
                "generated_at": datetime.now(timezone.utc),
                "total_events": total,
            },
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