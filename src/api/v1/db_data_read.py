from datetime import datetime, date
from typing import Optional, Dict, Any, List

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from db.db import get_async_db
from models.db_events_models import (
    PostgresDbEvents, MysqlDbEvents, OracleDbEvents, RedisDbEvents, MongoDbEvents,
)

try:
    from schemas.v1.standard_schema import standard_success_response          # adjust path if different
except Exception:
    def standard_success_response(data=None, message="ok"):
        return {"success": True, "message": message, "data": data}

router = APIRouter(prefix="/api/db", tags=["db-data"])

ENGINE_MODEL = {"postgresql": PostgresDbEvents, "mysql": MysqlDbEvents, "mariadb": MysqlDbEvents,
                "oracle": OracleDbEvents, "redis": RedisDbEvents, "mongodb": MongoDbEvents}
ALIASES = {"postgres": "postgresql", "postgre": "postgresql", "pg": "postgresql",
           "psql": "postgresql", "mongo": "mongodb", "maria": "mariadb"}
UNIQUE = [("postgresql", PostgresDbEvents), ("mysql", MysqlDbEvents), ("oracle", OracleDbEvents),
          ("redis", RedisDbEvents), ("mongodb", MongoDbEvents)]


def _canon(engine):
    e = (engine or "").strip().lower()
    return ALIASES.get(e, e)


def _row_to_dict(row, model, compact=False):
    """Serialize exactly the columns THIS engine's table has — same as stored."""
    out = {}
    for c in model.__table__.columns:
        v = getattr(row, c.name)
        if isinstance(v, (datetime, date)):
            v = v.isoformat()
        if compact and v is None:
            continue
        out[c.name] = v
    return out


@router.get("/started")
async def started_dbs(agent_name: str, db: AsyncSession = Depends(get_async_db)):
    """List the databases that have stored data for this agent (by agent_name)."""
    items = []
    for engine, model in UNIQUE:
        dcols = [getattr(model, c) for c in ("db_host", "service_name", "target_name")
                 if hasattr(model, c)]
        base = select(model).where(model.agent_name == agent_name)
        try:  # latest row per (host, service_name, target) — Postgres DISTINCT ON
            stmt = base.distinct(*dcols).order_by(*dcols, model.timestamp.desc()) if dcols \
                   else base.order_by(model.timestamp.desc())
            rows = (await db.execute(stmt)).scalars().all()
        except Exception:  # fallback: dedup in python
            rows_all = (await db.execute(
                base.order_by(model.timestamp.desc()).limit(200))).scalars().all()
            seen, rows = set(), []
            for r in rows_all:
                k = (getattr(r, "db_host", None), getattr(r, "service_name", None),
                     getattr(r, "target_name", None))
                if k in seen:
                    continue
                seen.add(k); rows.append(r)
        for r in rows:
            ts = getattr(r, "timestamp", None)
            items.append({
                "agent_name": agent_name, "engine": engine,
                "host": getattr(r, "db_host", None), "port": getattr(r, "db_port", None),
                "service_name": getattr(r, "service_name", None),
                "target_name": getattr(r, "target_name", None),
                "running": getattr(r, "running", None), "inspected": getattr(r, "inspected", None),
                "health_status": getattr(r, "health_status", None),
                "db_version": getattr(r, "db_version", None),
                "last_seen": ts.isoformat() if ts else None,
            })
    return standard_success_response(data=items, message="started databases")


@router.get("/data")
async def db_data(
    agent_name: str,
    engine: str = Query(..., description="postgresql|mysql|mariadb|oracle|redis|mongodb"),
    host: Optional[str] = Query(None, description="db_host; omit for any"),
    service_name: Optional[str] = Query(None, description="oracle service; omit for any"),
    limit: int = Query(1, ge=1, le=500, description=">1 returns a time series"),
    compact: bool = Query(False, description="drop null columns"),
    db: AsyncSession = Depends(get_async_db),
):
    """Fetch the stored health row(s) for one started database, as stored."""
    model = ENGINE_MODEL.get(_canon(engine))
    if model is None:
        raise HTTPException(400, f"unknown engine '{engine}'")

    stmt = select(model).where(model.agent_name == agent_name)
    if host is not None:
        stmt = stmt.where(model.db_host == host)
    if service_name is not None and hasattr(model, "service_name"):
        stmt = stmt.where(model.service_name == service_name)
    stmt = stmt.order_by(model.timestamp.desc()).limit(limit)

    rows = (await db.execute(stmt)).scalars().all()
    data = [_row_to_dict(r, model, compact) for r in rows]
    if not data:
        raise HTTPException(404, "no stored data yet for that database "
                                 "(not inspected yet, or host/service filter too narrow)")

    return standard_success_response(
        data={"engine": _canon(engine), "host": host, "service_name": service_name,
              "count": len(data), "latest": data[0], "rows": data},
        message="stored database data")