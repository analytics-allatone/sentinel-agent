import logging
from datetime import datetime, date
from typing import Optional, Dict, Any, List
import json
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from db.db import get_async_db
from models.db_events_models import (
    PostgresDbEvents, MysqlDbEvents, OracleDbEvents, RedisDbEvents, MongoDbEvents,
)
try:
    from models.credential_model import CredentialStorage
except Exception:
    try:
        from models.credential_model import CredentialStorage
    except Exception:
        CredentialStorage = None

try:
    from schemas.v1.standard_schema import standard_success_response
except Exception:
    def standard_success_response(data=None, message="ok"):
        return {"success": True, "message": message, "data": data}

log = logging.getLogger("db_data_read")
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
def _service_col(model):
    """The column that holds the service identifier for a row. Prefer a real
    service_name column; fall back to target_name."""
    if hasattr(model, "service_name"):
        return model.service_name
    if hasattr(model, "target_name"):
        return model.target_name
    return None


@router.get("/started")
async def started_dbs(agent_name: str, db: AsyncSession = Depends(get_async_db)):
    # ---- fallback: events-only (no credential model available) ----
    if CredentialStorage is None:
        items = []
        for engine, model in UNIQUE:
            try:
                rows = (await db.execute(
                    select(model).where(model.agent_name == agent_name)
                    .order_by(model.timestamp.desc()).limit(500))).scalars().all()
            except Exception as ex:                      # noqa: BLE001
                await db.rollback(); log.warning("started_dbs: skip %s (%s)", engine, ex); continue
            seen = set()
            for r in rows:
                k = (getattr(r, "db_host", None), getattr(r, "service_name", None),
                     getattr(r, "target_name", None))
                if k in seen: continue
                seen.add(k); ts = getattr(r, "timestamp", None)
                items.append({"agent_name": agent_name, "engine": engine,
                    "host": getattr(r, "db_host", None), "port": getattr(r, "db_port", None),
                    "service_name": getattr(r, "service_name", None),
                    "target_name": getattr(r, "target_name", None),
                    "health_status": getattr(r, "health_status", None),
                    "inspected": getattr(r, "inspected", None),
                    "db_version": getattr(r, "db_version", None),
                    "last_seen": ts.isoformat() if ts else None})
        return standard_success_response(data=items, message="started databases")

    # ---- credential-driven: the started DBs come from the credential table ----
    try:
        creds = (await db.execute(
            select(CredentialStorage).where(
                CredentialStorage.agent_name == agent_name,
                CredentialStorage.is_active.is_(True)))).scalars().all()
    except Exception as ex:                              # noqa: BLE001
        await db.rollback()
        log.exception("started_dbs: reading credentials failed")
        raise HTTPException(500, f"reading credentials failed: {ex}")

    items = []
    for c in creds:
        engine = _canon(getattr(c, "engine", None))
        model = ENGINE_MODEL.get(engine)
        latest = None
        if model is not None:
            svc = _service_col(model)
            stmt = select(model)
            if svc is not None and getattr(c, "service_name", None):
                stmt = stmt.where(svc == c.service_name)
            elif hasattr(model, "db_host") and getattr(c, "host", None):
                stmt = stmt.where(model.db_host == c.host)
            if hasattr(model, "agent_name"):
                stmt = stmt.where(model.agent_name == agent_name)
            stmt = stmt.order_by(model.timestamp.desc()).limit(1)
            try:
                latest = (await db.execute(stmt)).scalars().first()
            except Exception as ex:                      # noqa: BLE001
                await db.rollback()
                log.warning("started_dbs: health lookup failed for %s/%s (%s)",
                            engine, getattr(c, "service_name", None), ex)
                latest = None
        ts = getattr(latest, "timestamp", None) if latest else None
        items.append({
            # from the credential table (what you started)
            "agent_name": getattr(c, "agent_name", agent_name),
            "engine": engine,
            "host": getattr(c, "host", None),
            "port": getattr(c, "port", None),
            "service_name": getattr(c, "service_name", None),
            "dbname": getattr(c, "dbname", None),
            "user_name": getattr(c, "user_name", None),
            "is_active": getattr(c, "is_active", None),
            # from the latest health event (may be None if not inspected yet)
            "inspected": getattr(latest, "inspected", None) if latest else False,
            "health_status": getattr(latest, "health_status", None) if latest else None,
            "db_version": getattr(latest, "db_version", None) if latest else None,
            "last_seen": ts.isoformat() if ts else None,
        })
    return standard_success_response(data=items, message="started databases")


def _service_col(model):
    """The column that holds the service identifier for a row. Prefer a real
    service_name column; fall back to target_name (where Oracle's service is
    stored when the table has no service_name column)."""
    if hasattr(model, "service_name"):
        return model.service_name
    if hasattr(model, "target_name"):
        return model.target_name
    return None


@router.get("/data")
async def db_data(
    engine: str = Query(..., description="postgresql|mysql|mariadb|oracle|redis|mongodb"),
    service_name: str = Query(..., description="the service / target name you started"),
    agent_name: Optional[str] = Query(None, description="optional: narrow to one agent"),
    limit: int = Query(1, ge=1, le=500, description=">1 returns a time series"),
    compact: bool = Query(False, description="drop null columns"),
    db: AsyncSession = Depends(get_async_db),
):
    model = ENGINE_MODEL.get(_canon(engine))
    if model is None:
        raise HTTPException(400, f"unknown engine '{engine}'")

    svc = _service_col(model)
    if svc is None:
        raise HTTPException(400, f"{engine} table has no service_name/target_name column to match on")

    stmt = select(model).where(svc == service_name)
    if agent_name and hasattr(model, "agent_name"):
        stmt = stmt.where(model.agent_name == agent_name)
    stmt = stmt.order_by(model.timestamp.desc()).limit(limit)

    # try:
    #     rows = (await db.execute(stmt)).scalars().all()
    # except Exception as ex:                      # noqa: BLE001
    #     await db.rollback()                      # don't hand a poisoned session back to the pool
    #     log.exception("db_data query failed for %s", engine)
    #     raise HTTPException(500, f"query failed for {engine}: {ex}")

    # data = [_row_to_dict(r, model, compact) for r in rows]
    # if not data:
    #     raise HTTPException(404, f"no stored data for {engine} service '{service_name}' "
    #                              "(not inspected yet, or name doesn't match what was stored)")
    data= {
  "status": "success",
  "message": "stored database data",
  "data": {
    "engine": "oracle",
    "service_name": "freepdb1",
    "matched_on": "service_name",
    "count": 1,
    "rows": [
      {
        "sessions_current": 1,
        "sessions_active": 1,
        "sessions_blocked": 0,
        "is_cdb": True,
        "uptime_seconds": 29128,
        "database_role": "PRIMARY",
        "open_mode": "READ WRITE",
        "cache_hit_pct": 98.87,
        "library_hit_pct": 95.75,
        "dict_hit_pct": 92.72,
        "connectivity_version": {
          "version": "23.26.2.0.0",
          "log_mode": "ARCHIVELOG",
          "host_name": "274ae7bf37d4",
          "open_mode": "READ WRITE",
          "server_host": "274ae7bf37d4",
          "current_user": "SYSTEM",
          "database_role": "PRIMARY",
          "instance_name": "FREE",
          "uptime_seconds": 29128,
          "instance_status": "OPEN",
          "current_database": "FREEPDB1"
        },
        "database_sizes": [
          {
            "max_mb": 33554432,
            "datname": "SYSAUX",
            "free_mb": 30.1,
            "ts_type": "PERMANENT",
            "used_mb": 509.9,
            "pct_used": 94.43,
            "total_mb": 540,
            "pct_of_max": 0,
            "size_bytes": 566231040
          },
          {
            "max_mb": 33554432,
            "datname": "SYSTEM",
            "free_mb": 1.1,
            "ts_type": "PERMANENT",
            "used_mb": 298.9,
            "pct_used": 99.65,
            "total_mb": 300,
            "pct_of_max": 0,
            "size_bytes": 314572800
          },
          {
            "max_mb": 33554432,
            "datname": "UNDOTBS1",
            "free_mb": 78.7,
            "ts_type": "PERMANENT",
            "used_mb": 21.3,
            "pct_used": 21.31,
            "total_mb": 100,
            "pct_of_max": 0,
            "size_bytes": 104857600
          },
          {
            "max_mb": 33554432,
            "datname": "USERS",
            "free_mb": 0.9,
            "ts_type": "PERMANENT",
            "used_mb": 6.1,
            "pct_used": 86.61,
            "total_mb": 7,
            "pct_of_max": 0,
            "size_bytes": 7340032
          },
          {
            "max_mb": 32768,
            "datname": "TEMP",
            "free_mb": 16,
            "ts_type": "TEMP",
            "used_mb": 4,
            "pct_used": 20,
            "total_mb": 20,
            "pct_of_max": 0.01,
            "size_bytes": 20971520
          }
        ],
        "active_connections": [
          {
            "status": "ACTIVE",
            "connections": 84
          }
        ],
        "session_summary": {
          "total": 1,
          "active": 1,
          "blocked": 0,
          "inactive": 0
        },
        "sessions_by_user": [
          {
            "machine": "274ae7bf37d4",
            "program": "oracle@274ae7bf37d4 (BG00)",
            "sessions": 11,
            "username": "(background)"
          },
          {
            "machine": "274ae7bf37d4",
            "program": "oracle@274ae7bf37d4 (BG01)",
            "sessions": 7,
            "username": "(background)"
          },
          {
            "machine": "274ae7bf37d4",
            "program": "oracle@274ae7bf37d4 (SCMN)",
            "sessions": 6,
            "username": "(background)"
          },
          {
            "machine": "274ae7bf37d4",
            "program": "oracle@274ae7bf37d4 (BG03)",
            "sessions": 6,
            "username": "(background)"
          },
          {
            "machine": "274ae7bf37d4",
            "program": "oracle@274ae7bf37d4 (BG02)",
            "sessions": 6,
            "username": "(background)"
          },
          {
            "machine": "274ae7bf37d4",
            "program": "oracle@274ae7bf37d4 (PMON)",
            "sessions": 1,
            "username": "(background)"
          },
          {
            "machine": "274ae7bf37d4",
            "program": "oracle@274ae7bf37d4 (PSP0)",
            "sessions": 1,
            "username": "(background)"
          },
          {
            "machine": "274ae7bf37d4",
            "program": "oracle@274ae7bf37d4 (GEN0)",
            "sessions": 1,
            "username": "(background)"
          },
          {
            "machine": "274ae7bf37d4",
            "program": "oracle@274ae7bf37d4 (TT00)",
            "sessions": 1,
            "username": "(background)"
          },
          {
            "machine": "274ae7bf37d4",
            "program": "oracle@274ae7bf37d4 (DIAG)",
            "sessions": 1,
            "username": "(background)"
          },
          {
            "machine": "274ae7bf37d4",
            "program": "oracle@274ae7bf37d4 (VKRM)",
            "sessions": 1,
            "username": "(background)"
          },
          {
            "machine": "274ae7bf37d4",
            "program": "oracle@274ae7bf37d4 (DIA0)",
            "sessions": 1,
            "username": "(background)"
          },
          {
            "machine": "274ae7bf37d4",
            "program": "oracle@274ae7bf37d4 (SMON)",
            "sessions": 1,
            "username": "(background)"
          },
          {
            "machine": "274ae7bf37d4",
            "program": "oracle@274ae7bf37d4 (RECO)",
            "sessions": 1,
            "username": "(background)"
          },
          {
            "machine": "274ae7bf37d4",
            "program": "oracle@274ae7bf37d4 (PXMN)",
            "sessions": 1,
            "username": "(background)"
          },
          {
            "machine": "274ae7bf37d4",
            "program": "oracle@274ae7bf37d4 (MMON)",
            "sessions": 1,
            "username": "(background)"
          },
          {
            "machine": "274ae7bf37d4",
            "program": "oracle@274ae7bf37d4 (LGWR)",
            "sessions": 1,
            "username": "(background)"
          },
          {
            "machine": "274ae7bf37d4",
            "program": "oracle@274ae7bf37d4 (M005)",
            "sessions": 1,
            "username": "(background)"
          },
          {
            "machine": "274ae7bf37d4",
            "program": "oracle@274ae7bf37d4 (M003)",
            "sessions": 1,
            "username": "(background)"
          },
          {
            "machine": "274ae7bf37d4",
            "program": "oracle@274ae7bf37d4 (DT01)",
            "sessions": 1,
            "username": "(background)"
          },
          {
            "machine": "274ae7bf37d4",
            "program": "oracle@274ae7bf37d4 (RCBG)",
            "sessions": 1,
            "username": "(background)"
          },
          {
            "machine": "274ae7bf37d4",
            "program": "oracle@274ae7bf37d4 (TT01)",
            "sessions": 1,
            "username": "(background)"
          },
          {
            "machine": "274ae7bf37d4",
            "program": "oracle@274ae7bf37d4 (ARC0)",
            "sessions": 1,
            "username": "(background)"
          },
          {
            "machine": "274ae7bf37d4",
            "program": "oracle@274ae7bf37d4 (ARC2)",
            "sessions": 1,
            "username": "(background)"
          },
          {
            "machine": "274ae7bf37d4",
            "program": "oracle@274ae7bf37d4 (CJQ0)",
            "sessions": 1,
            "username": "(background)"
          },
          {
            "machine": "274ae7bf37d4",
            "program": "oracle@274ae7bf37d4 (M004)",
            "sessions": 1,
            "username": "(background)"
          },
          {
            "machine": "WINDOWS-EP8PIFQ",
            "program": "D:\\Final\\sentinel-agent\\agent\\venv\\Scripts\\python.exe",
            "sessions": 1,
            "username": "SYSTEM"
          },
          {
            "machine": "274ae7bf37d4",
            "program": "oracle@274ae7bf37d4 (QM02)",
            "sessions": 1,
            "username": "(background)"
          },
          {
            "machine": "274ae7bf37d4",
            "program": "oracle@274ae7bf37d4 (M002)",
            "sessions": 1,
            "username": "(background)"
          },
          {
            "machine": "274ae7bf37d4",
            "program": "oracle@274ae7bf37d4 (CLMN)",
            "sessions": 1,
            "username": "(background)"
          },
          {
            "machine": "274ae7bf37d4",
            "program": "oracle@274ae7bf37d4 (VKTM)",
            "sessions": 1,
            "username": "(background)"
          },
          {
            "machine": "274ae7bf37d4",
            "program": "oracle@274ae7bf37d4 (MMAN)",
            "sessions": 1,
            "username": "(background)"
          },
          {
            "machine": "274ae7bf37d4",
            "program": "oracle@274ae7bf37d4 (GEN2)",
            "sessions": 1,
            "username": "(background)"
          },
          {
            "machine": "274ae7bf37d4",
            "program": "oracle@274ae7bf37d4 (DBRM)",
            "sessions": 1,
            "username": "(background)"
          },
          {
            "machine": "274ae7bf37d4",
            "program": "oracle@274ae7bf37d4 (GWPD)",
            "sessions": 1,
            "username": "(background)"
          },
          {
            "machine": "274ae7bf37d4",
            "program": "oracle@274ae7bf37d4 (OFSD)",
            "sessions": 1,
            "username": "SYS"
          },
          {
            "machine": "274ae7bf37d4",
            "program": "oracle@274ae7bf37d4 (PMAN)",
            "sessions": 1,
            "username": "(background)"
          },
          {
            "machine": "274ae7bf37d4",
            "program": "oracle@274ae7bf37d4 (DBW0)",
            "sessions": 1,
            "username": "(background)"
          },
          {
            "machine": "274ae7bf37d4",
            "program": "oracle@274ae7bf37d4 (CKPT)",
            "sessions": 1,
            "username": "(background)"
          },
          {
            "machine": "274ae7bf37d4",
            "program": "oracle@274ae7bf37d4 (SMCO)",
            "sessions": 1,
            "username": "(background)"
          },
          {
            "machine": "274ae7bf37d4",
            "program": "oracle@274ae7bf37d4 (LREG)",
            "sessions": 1,
            "username": "(background)"
          },
          {
            "machine": "274ae7bf37d4",
            "program": "oracle@274ae7bf37d4 (MMNL)",
            "sessions": 1,
            "username": "(background)"
          },
          {
            "machine": "274ae7bf37d4",
            "program": "oracle@274ae7bf37d4 (DT00)",
            "sessions": 1,
            "username": "(background)"
          },
          {
            "machine": "274ae7bf37d4",
            "program": "oracle@274ae7bf37d4 (TMON)",
            "sessions": 1,
            "username": "(background)"
          },
          {
            "machine": "274ae7bf37d4",
            "program": "oracle@274ae7bf37d4 (TT02)",
            "sessions": 1,
            "username": "(background)"
          },
          {
            "machine": "274ae7bf37d4",
            "program": "oracle@274ae7bf37d4 (ARC1)",
            "sessions": 1,
            "username": "(background)"
          },
          {
            "machine": "274ae7bf37d4",
            "program": "oracle@274ae7bf37d4 (ARC3)",
            "sessions": 1,
            "username": "(background)"
          },
          {
            "machine": "274ae7bf37d4",
            "program": "oracle@274ae7bf37d4 (AQPC)",
            "sessions": 1,
            "username": "(background)"
          },
          {
            "machine": "274ae7bf37d4",
            "program": "oracle@274ae7bf37d4 (W001)",
            "sessions": 1,
            "username": "(background)"
          },
          {
            "machine": "274ae7bf37d4",
            "program": "oracle@274ae7bf37d4 (M007)",
            "sessions": 1,
            "username": "(background)"
          }
        ],
        "idle_sessions": [],
        "long_running_queries": [
          {
            "sid": 169,
            "event": "OFS idle",
            "serial": 10141,
            "sql_id": "null",
            "status": "ACTIVE",
            "machine": "274ae7bf37d4",
            "program": "oracle@274ae7bf37d4 (OFSD)",
            "sql_text": "null",
            "username": "SYS",
            "sql_child": 0,
            "wait_class": "Idle",
            "blocking_session": "null",
            "duration_seconds": 29126
          }
        ],
        "locks_blocking": [],
        "cache_hit_ratio": {
          "library_hit_ratio": 95.75,
          "dictionary_hit_ratio": 92.72,
          "buffer_cache_hit_ratio": 98.87
        },
        "memory": "null",
        "resource_limits": [],
        "top_sql_elapsed": [
          {
            "cpu_s": 5.13,
            "avg_ms": 200.51,
            "sql_id": "ampw9ddqufjd3",
            "sql_text": "begin /*KAPI:capture*/ dbms_auto_index_internal.capture_sts; end;",
            "elapsed_s": 6.42,
            "disk_reads": 835,
            "executions": 32,
            "buffer_gets": 222612,
            "parsing_schema": "SYS",
            "rows_processed": 32
          },
          {
            "cpu_s": 5.76,
            "avg_ms": 8.19,
            "sql_id": "f6w8rqdkx0bnv",
            "sql_text": "SELECT * FROM ( SELECT /*+ ordered use_nl(o c cu h) index(u i_user1) index(o i_obj2)                index(ci_obj#) index(cu i_col_usage$)                index(h i_hh_obj#_intcol#)                 OPT_PARAM('_parallel_syspls_obey_force' 'false') */ C.NAME COL_NAME, C.TYPE# COL_TYPE, C.CHARSETFORM COL_CSF, CASE WHEN C.DEFLENGTH <= 32767 THEN C.DEFAULT$ ELSE NULL END COL_DEF, C.NULL$ COL_NULL, C.PROP",
            "elapsed_s": 5.9,
            "disk_reads": 1,
            "executions": 720,
            "buffer_gets": 282744,
            "parsing_schema": "SYS",
            "rows_processed": 11784
          },
          {
            "cpu_s": 4.48,
            "avg_ms": 62.35,
            "sql_id": "b39m8n96gxk7c",
            "sql_text": "call dbms_autotask_prvt.run_autotask ( :0,:1 )",
            "elapsed_s": 5.42,
            "disk_reads": 1,
            "executions": 87,
            "buffer_gets": 190069,
            "parsing_schema": "SYS",
            "rows_processed": 0
          },
          {
            "cpu_s": 3.16,
            "avg_ms": 100.37,
            "sql_id": "avzy19hxu6gg4",
            "sql_text": "SELECT VALUE(P) FROM TABLE(DBMS_SQLTUNE.SELECT_CURSOR_CACHE( BASIC_FILTER=> q'# (module is null or (module != '#' || :B1 || q'#' and module != '#' || :B2 || q'#')) and sql_text not like 'SELECT /* DS_SVC */%'                  and sql_text not like 'SELECT /* OPT_DYN_SAMP */%'                  and sql_text not like '/*AUTO_INDEX:ddl*/%'                  and sql_text not like '%/*+%dbms_stats%'     ",
            "elapsed_s": 3.21,
            "disk_reads": 64,
            "executions": 32,
            "buffer_gets": 7847,
            "parsing_schema": "SYS",
            "rows_processed": 0
          },
          {
            "cpu_s": 1.97,
            "avg_ms": 86.5,
            "sql_id": "afcz0dh295hzp",
            "sql_text": " SELECT /*+ first_rows(1) */ sql_id, force_matching_signature, sql_text, cast(NULL as SQL_OBJECTS) object_list, bind_data, parsing_schema_name, module, action, elapsed_time, cpu_time, buffer_gets, disk_reads, direct_writes,rows_processed, fetches, executions, end_of_fetch_count, optimizer_cost, optimizer_env,NULL priority, command_type, first_load_time, null stat_period, null active_stat_period, N",
            "elapsed_s": 1.99,
            "disk_reads": 0,
            "executions": 23,
            "buffer_gets": 4108,
            "parsing_schema": "SYS",
            "rows_processed": 0
          },
          {
            "cpu_s": 1.68,
            "avg_ms": 99.68,
            "sql_id": "61znfd8fvgha6",
            "sql_text": "SELECT  new.sql_seq, old.plan_hash_value, sqlset_row(new.sql_id,new.force_matching_signature,  new.sql_text, new.object_list,  new.bind_data, new.parsing_schema_name,  new.module, new.action, new.elapsed_time,  new.cpu_time, new.buffer_gets,  new.disk_reads, new.direct_writes,  new.rows_processed, new.fetches, new.executions,  new.end_of_fetch_count,  new.optimizer_cost, new.optimizer_env,  new.pr",
            "elapsed_s": 1.69,
            "disk_reads": 0,
            "executions": 17,
            "buffer_gets": 3589,
            "parsing_schema": "SYS",
            "rows_processed": 0
          },
          {
            "cpu_s": 0.13,
            "avg_ms": 1.06,
            "sql_id": "3un99a0zwp4vd",
            "sql_text": "select owner#,name,namespace,remoteowner,linkname,p_timestamp,p_obj#, nvl(property,0),subname,type#,flags,d_attrs from dependency$ d, obj$ o where d_obj#=:1 and p_obj#=obj#(+) order by order#",
            "elapsed_s": 1.33,
            "disk_reads": 278,
            "executions": 1255,
            "buffer_gets": 12661,
            "parsing_schema": "SYS",
            "rows_processed": 4662
          },
          {
            "cpu_s": 0.43,
            "avg_ms": 242.71,
            "sql_id": "fnx04kam5mqya",
            "sql_text": "SELECT df.tablespace_name AS datname, df.total_bytes AS size_bytes, 'PERMANENT' AS ts_type, ROUND((df.total_bytes-NVL(fs.free_bytes,0))/1048576,1) AS used_mb, ROUND(NVL(fs.free_bytes,0)/1048576,1) AS free_mb, ROUND(df.total_bytes/1048576,1) AS total_mb, ROUND(df.max_bytes/1048576,1) AS max_mb, ROUND((df.total_bytes-NVL(fs.free_bytes,0))*100/NULLIF(df.total_bytes,0),2) AS pct_used, ROUND((df.total_",
            "elapsed_s": 1.21,
            "disk_reads": 11481,
            "executions": 5,
            "buffer_gets": 35765,
            "parsing_schema": "SYSTEM",
            "rows_processed": 20
          },
          {
            "cpu_s": 0.95,
            "avg_ms": 0.09,
            "sql_id": "5rurx5xtjwcu2",
            "sql_text": "SELECT /*+ OPT_PARAM('_parallel_syspls_obey_force' 'false') */ KSPPCV.KSPPSTVL FROM X$KSPPCV KSPPCV, X$KSPPI KSPPI WHERE KSPPI.INDX = KSPPCV.INDX AND KSPPI.KSPPINM = :B1 ",
            "elapsed_s": 1,
            "disk_reads": 0,
            "executions": 11604,
            "buffer_gets": 86,
            "parsing_schema": "SYS",
            "rows_processed": 11604
          },
          {
            "cpu_s": 0.33,
            "avg_ms": 38.05,
            "sql_id": "b7wvutrbhf7jg",
            "sql_text": "MERGE INTO SYS.SQLOBJ$BV sbv USING (SELECT 1 FROM SYS.DUAL)  ON (1 = 1)  WHEN MATCHED THEN  UPDATE SET sbv.multi_plans_bv_seg_count = :1,  sbv.plan_existence_bv_seg_count = :2,  sbv.multi_plans_bv = :3,  sbv.plan_existence_bv = :4  WHEN NOT MATCHED THEN  INSERT (multi_plans_bv_seg_count, plan_existence_bv_seg_count,  multi_plans_bv, plan_existence_bv) VALUES  (:5, :6, :7, :8)",
            "elapsed_s": 0.99,
            "disk_reads": 0,
            "executions": 26,
            "buffer_gets": 53553,
            "parsing_schema": "SYS",
            "rows_processed": 26
          }
        ],
        "top_sql_executions": [
          {
            "cpu_s": 0.47,
            "avg_ms": 0.01,
            "sql_id": "62yyzw3309d6a",
            "sql_text": "SELECT VALUE FROM V$SESSION_FIX_CONTROL WHERE BUGNO = :B1 AND SESSION_ID = USERENV('SID')",
            "elapsed_s": 0.5,
            "disk_reads": 5,
            "executions": 47074,
            "buffer_gets": 149,
            "parsing_schema": "SYS",
            "rows_processed": 47074
          },
          {
            "cpu_s": 0.29,
            "avg_ms": 0.03,
            "sql_id": "g3jx9qzg4mz0t",
            "sql_text": "SELECT idx_objn, nvl(idx_objd, 0), idx_base_table_objn, idx_spare1, nvl(json_value(idx_spare2, '$.build_scn'), 0) FROM vecsys.vector$index WHERE JSON_VALUE(idx_params, '$.type') = :1",
            "elapsed_s": 0.33,
            "disk_reads": 7,
            "executions": 11799,
            "buffer_gets": 827,
            "parsing_schema": "SYS",
            "rows_processed": 0
          },
          {
            "cpu_s": 0.06,
            "avg_ms": 0.01,
            "sql_id": "6h19at4ub9n15",
            "sql_text": "SELECT /*+ OPT_PARAM('_parallel_syspls_obey_force' 'false') */ COUNT(*) FROM COL$ C WHERE C.OBJ# = :B2 AND C.NAME = :B1 AND (BITAND(PROPERTY, 8796093022208) > 0 OR (EXISTS (SELECT * FROM OBJ$ O WHERE O.OBJ# = :B2 AND O.OWNER# = :B3 AND O.NAME = 'USER$') AND :B1 IN ('SPARE4', 'PASSWORD')))",
            "elapsed_s": 0.06,
            "disk_reads": 0,
            "executions": 11750,
            "buffer_gets": 23502,
            "parsing_schema": "SYS",
            "rows_processed": 11750
          },
          {
            "cpu_s": 0.95,
            "avg_ms": 0.09,
            "sql_id": "5rurx5xtjwcu2",
            "sql_text": "SELECT /*+ OPT_PARAM('_parallel_syspls_obey_force' 'false') */ KSPPCV.KSPPSTVL FROM X$KSPPCV KSPPCV, X$KSPPI KSPPI WHERE KSPPI.INDX = KSPPCV.INDX AND KSPPI.KSPPINM = :B1 ",
            "elapsed_s": 1,
            "disk_reads": 0,
            "executions": 11604,
            "buffer_gets": 86,
            "parsing_schema": "SYS",
            "rows_processed": 11604
          },
          {
            "cpu_s": 0.04,
            "avg_ms": 0,
            "sql_id": "f6rzrh96swb4h",
            "sql_text": "SELECT :B1 ",
            "elapsed_s": 0.05,
            "disk_reads": 0,
            "executions": 11176,
            "buffer_gets": 4,
            "parsing_schema": "SYS",
            "rows_processed": 11176
          },
          {
            "cpu_s": 0.07,
            "avg_ms": 0.01,
            "sql_id": "4rg3vr6z5yw7m",
            "sql_text": "select /* KSXM:FIND OWNER */ owner# from sys.obj$ where obj# = :objn",
            "elapsed_s": 0.08,
            "disk_reads": 0,
            "executions": 10554,
            "buffer_gets": 21117,
            "parsing_schema": "SYS",
            "rows_processed": 10554
          },
          {
            "cpu_s": 0.09,
            "avg_ms": 0.04,
            "sql_id": "cd5hruubgjzm4",
            "sql_text": "SELECT using_tableobjn, retention, manual_purgescn,                u.name as owner_name, o.name as table_name           FROM directive$ d                                           JOIN obj$ o ON d.using_tableobjn = o.obj#                   JOIN user$ u ON o.owner# = u.user#                          WHERE d.TYPE# = :1 ",
            "elapsed_s": 0.24,
            "disk_reads": 0,
            "executions": 5588,
            "buffer_gets": 22,
            "parsing_schema": "SYS",
            "rows_processed": 0
          },
          {
            "cpu_s": 0.05,
            "avg_ms": 0.02,
            "sql_id": "53saa2zkr6wc3",
            "sql_text": "select intcol#,nvl(pos#,0),col#,nvl(spare1,0) from ccol$ where con#=:1",
            "elapsed_s": 0.13,
            "disk_reads": 21,
            "executions": 5580,
            "buffer_gets": 26413,
            "parsing_schema": "SYS",
            "rows_processed": 7610
          },
          {
            "cpu_s": 0.13,
            "avg_ms": 0.03,
            "sql_id": "aqt2vfxb5b5ad",
            "sql_text": "SELECT idx_objn, idx_base_table_objn, idx_spare1, json_value(IDX_SPARE2, '$.counter') FROM vecsys.vector$index WHERE JSON_VALUE(idx_params, '$.type') = :1 AND JSON_VALUE(idx_params, '$.vector_dimension') != 0 AND JSON_VALUE(idx_params, '$.vector_type') != 'FLEXIBLE' AND (NOT JSON_EXISTS(idx_params, '$.duplicate') OR  JSON_VALUE(idx_params, '$.duplicate') != 'NONE')",
            "elapsed_s": 0.14,
            "disk_reads": 0,
            "executions": 5516,
            "buffer_gets": 90,
            "parsing_schema": "SYS",
            "rows_processed": 0
          },
          {
            "cpu_s": 0.07,
            "avg_ms": 0.01,
            "sql_id": "5c4sr912n136n",
            "sql_text": "SELECT /*+ OPT_PARAM('_parallel_syspls_obey_force' 'false') */ SPARE4, SVAL1 FROM SYS.OPTSTAT_HIST_CONTROL$ WHERE SNAME = :B1 ",
            "elapsed_s": 0.07,
            "disk_reads": 0,
            "executions": 5343,
            "buffer_gets": 10693,
            "parsing_schema": "SYS",
            "rows_processed": 5343
          }
        ],
        "top_segments": [
          {
            "owner": "SYS",
            "segment_name": "C_TOID_VERSION#",
            "segment_type": "CLUSTER",
            "total_size_bytes": 48234496
          },
          {
            "owner": "MDSYS",
            "segment_name": "SYS_LOB0000063838C00006$$",
            "segment_type": "LOBSEGMENT",
            "total_size_bytes": 41222144
          },
          {
            "owner": "AUDSYS",
            "segment_name": "SYS_LOB0000023103C00030$$",
            "segment_type": "LOB PARTITION",
            "total_size_bytes": 25427968
          },
          {
            "owner": "SYS",
            "segment_name": "SYS_LOB0000062967C00004$$",
            "segment_type": "LOBSEGMENT",
            "total_size_bytes": 22282240
          },
          {
            "owner": "SYS",
            "segment_name": "IDL_UB2$",
            "segment_type": "TABLE",
            "total_size_bytes": 17825792
          },
          {
            "owner": "SYS",
            "segment_name": "C_OBJ#",
            "segment_type": "CLUSTER",
            "total_size_bytes": 16777216
          },
          {
            "owner": "SYS",
            "segment_name": "IDL_UB1$",
            "segment_type": "TABLE",
            "total_size_bytes": 13631488
          },
          {
            "owner": "SYS",
            "segment_name": "I_OBJ2",
            "segment_type": "INDEX",
            "total_size_bytes": 12582912
          },
          {
            "owner": "SYS",
            "segment_name": "I_OBJ5",
            "segment_type": "INDEX",
            "total_size_bytes": 12582912
          },
          {
            "owner": "SYS",
            "segment_name": "OBJ$",
            "segment_type": "TABLE",
            "total_size_bytes": 11534336
          },
          {
            "owner": "AUDSYS",
            "segment_name": "AUD$UNIFIED",
            "segment_type": "TABLE PARTITION",
            "total_size_bytes": 11534336
          },
          {
            "owner": "SYS",
            "segment_name": "C_OBJ#_INTCOL#",
            "segment_type": "CLUSTER",
            "total_size_bytes": 10485760
          },
          {
            "owner": "MDSYS",
            "segment_name": "SDO_CS_SRS",
            "segment_type": "TABLE",
            "total_size_bytes": 9437184
          },
          {
            "owner": "SYS",
            "segment_name": "SYS_LOB0000062952C00004$$",
            "segment_type": "LOBSEGMENT",
            "total_size_bytes": 8650752
          },
          {
            "owner": "SYS",
            "segment_name": "I_COL1",
            "segment_type": "INDEX",
            "total_size_bytes": 8388608
          },
          {
            "owner": "MDSYS",
            "segment_name": "SYS_LOB0000066648C00002$$",
            "segment_type": "LOBSEGMENT",
            "total_size_bytes": 7602176
          },
          {
            "owner": "SYS",
            "segment_name": "KOTAD$",
            "segment_type": "TABLE",
            "total_size_bytes": 6291456
          },
          {
            "owner": "SYS",
            "segment_name": "SYS_LOB0000009177C00004$$",
            "segment_type": "LOBSEGMENT",
            "total_size_bytes": 5570560
          },
          {
            "owner": "SYS",
            "segment_name": "SYS_LOB0000014530C00038$$",
            "segment_type": "LOB PARTITION",
            "total_size_bytes": 5570560
          },
          {
            "owner": "SYS",
            "segment_name": "SYS_LOB0000000475C00004$$",
            "segment_type": "LOBSEGMENT",
            "total_size_bytes": 5505024
          }
        ],
        "table_bloat": [
          {
            "relname": "IDL_UB2$",
            "schemaname": "SYS",
            "tablespace": "SYSTEM",
            "segment_type": "TABLE",
            "total_size_bytes": 17825792
          },
          {
            "relname": "IDL_UB1$",
            "schemaname": "SYS",
            "tablespace": "SYSTEM",
            "segment_type": "TABLE",
            "total_size_bytes": 13631488
          },
          {
            "relname": "OBJ$",
            "schemaname": "SYS",
            "tablespace": "SYSTEM",
            "segment_type": "TABLE",
            "total_size_bytes": 11534336
          },
          {
            "relname": "SDO_CS_SRS",
            "schemaname": "MDSYS",
            "tablespace": "SYSAUX",
            "segment_type": "TABLE",
            "total_size_bytes": 9437184
          },
          {
            "relname": "KOTAD$",
            "schemaname": "SYS",
            "tablespace": "SYSTEM",
            "segment_type": "TABLE",
            "total_size_bytes": 6291456
          },
          {
            "relname": "DEPENDENCY$",
            "schemaname": "SYS",
            "tablespace": "SYSTEM",
            "segment_type": "TABLE",
            "total_size_bytes": 5242880
          },
          {
            "relname": "SOURCE$",
            "schemaname": "SYS",
            "tablespace": "SYSTEM",
            "segment_type": "TABLE",
            "total_size_bytes": 5242880
          },
          {
            "relname": "IDL_CHAR$",
            "schemaname": "SYS",
            "tablespace": "SYSTEM",
            "segment_type": "TABLE",
            "total_size_bytes": 4194304
          },
          {
            "relname": "HIST_HEAD$",
            "schemaname": "SYS",
            "tablespace": "SYSTEM",
            "segment_type": "TABLE",
            "total_size_bytes": 3145728
          },
          {
            "relname": "IDL_SB4$",
            "schemaname": "SYS",
            "tablespace": "SYSTEM",
            "segment_type": "TABLE",
            "total_size_bytes": 3145728
          },
          {
            "relname": "ACCESS$",
            "schemaname": "SYS",
            "tablespace": "SYSTEM",
            "segment_type": "TABLE",
            "total_size_bytes": 3145728
          },
          {
            "relname": "OBJAUTH$",
            "schemaname": "SYS",
            "tablespace": "SYSTEM",
            "segment_type": "TABLE",
            "total_size_bytes": 2097152
          },
          {
            "relname": "EXT_TAB_REF_SYS_1",
            "schemaname": "MDSYS",
            "tablespace": "SYSAUX",
            "segment_type": "TABLE",
            "total_size_bytes": 2097152
          },
          {
            "relname": "SDO_COORD_REF_SYS",
            "schemaname": "MDSYS",
            "tablespace": "SYSAUX",
            "segment_type": "TABLE",
            "total_size_bytes": 2097152
          },
          {
            "relname": "KOTTB$",
            "schemaname": "SYS",
            "tablespace": "SYSTEM",
            "segment_type": "TABLE",
            "total_size_bytes": 2097152
          },
          {
            "relname": "KOTTD$",
            "schemaname": "SYS",
            "tablespace": "SYSTEM",
            "segment_type": "TABLE",
            "total_size_bytes": 2097152
          },
          {
            "relname": "WRI$_OPTSTAT_OPR_TASKS",
            "schemaname": "SYS",
            "tablespace": "SYSAUX",
            "segment_type": "TABLE",
            "total_size_bytes": 2097152
          },
          {
            "relname": "SMON_SCN_TIME",
            "schemaname": "SYS",
            "tablespace": "SYSAUX",
            "segment_type": "TABLE",
            "total_size_bytes": 2097152
          },
          {
            "relname": "KOTMD$",
            "schemaname": "SYS",
            "tablespace": "SYSTEM",
            "segment_type": "TABLE",
            "total_size_bytes": 1048576
          },
          {
            "relname": "SYS$SERVICE_METRICS_TAB",
            "schemaname": "SYS",
            "tablespace": "SYSAUX",
            "segment_type": "TABLE",
            "total_size_bytes": 1048576
          }
        ],
        "index_usage": {
          "monitoring_note": "per-index usage needs ALTER INDEX ... MONITORING USAGE",
          "unusable_indexes": []
        },
        "dead_tuples_vacuum": {
          "reason": "Oracle uses undo/redo, not vacuum",
          "stale_stats": [
            {
              "owner": "SYS",
              "table_name": "CLU$"
            },
            {
              "owner": "SYS",
              "table_name": "SEG$"
            },
            {
              "owner": "SYS",
              "table_name": "HISTGRM$"
            },
            {
              "owner": "SYS",
              "table_name": "SEQ$"
            },
            {
              "owner": "SYS",
              "table_name": "SQLOBJ$BV"
            },
            {
              "owner": "SYS",
              "table_name": "STATS_TARGET$"
            },
            {
              "owner": "SYS",
              "table_name": "COL_USAGE$"
            },
            {
              "owner": "SYS",
              "table_name": "MON_MODS_ALL$"
            },
            {
              "owner": "SYS",
              "table_name": "WRI$_OPTSTAT_TAB_HISTORY"
            },
            {
              "owner": "SYS",
              "table_name": "WRI$_OPTSTAT_IND_HISTORY"
            },
            {
              "owner": "SYS",
              "table_name": "WRI$_OPTSTAT_AUX_HISTORY"
            },
            {
              "owner": "SYS",
              "table_name": "WRI$_OPTSTAT_OPR"
            },
            {
              "owner": "SYS",
              "table_name": "WRI$_OPTSTAT_OPR_TASKS"
            },
            {
              "owner": "SYS",
              "table_name": "OPTSTAT_HIST_CONTROL$"
            },
            {
              "owner": "SYS",
              "table_name": "OPT_DIRECTIVE_OWN$"
            },
            {
              "owner": "SYS",
              "table_name": "OPT_DIRECTIVE$"
            },
            {
              "owner": "SYS",
              "table_name": "OPTSTAT_SNAPSHOT$"
            },
            {
              "owner": "SYS",
              "table_name": "EXP_HEAD$"
            },
            {
              "owner": "SYS",
              "table_name": "OPT_SQLSTAT$"
            },
            {
              "owner": "SYS",
              "table_name": "TABPART$"
            }
          ],
          "not_applicable": True
        },
        "wal_checkpoint": [
          {
            "actual_redo_blks": 107,
            "target_redo_blks": 27714,
            "recovery_estimated_ios": 40
          }
        ],
        "wraparound_risk": "not applicable to Oracle",
        "replication_primary": "no Data Guard configured",
        "replication_delay": "no Data Guard / standby",
        "standby_destinations": "null",
        "alert_log_errors": "null",
        "modified_parameters": [
          {
            "name": "_instance_recovery_bloom_filter_size",
            "value": "1048576",
            "is_default": "FALSE",
            "is_modified": "FALSE"
          },
          {
            "name": "compatible",
            "value": "23.6.0",
            "is_default": "FALSE",
            "is_modified": "FALSE"
          },
          {
            "name": "control_files",
            "value": "/opt/oracle/oradata/FREE/control01.ctl, /opt/oracle/oradata/FREE/control02.ctl",
            "is_default": "FALSE",
            "is_modified": "FALSE"
          },
          {
            "name": "db_block_size",
            "value": "8192",
            "is_default": "FALSE",
            "is_modified": "FALSE"
          },
          {
            "name": "db_name",
            "value": "FREE",
            "is_default": "FALSE",
            "is_modified": "FALSE"
          },
          {
            "name": "diagnostic_dest",
            "value": "/opt/oracle",
            "is_default": "FALSE",
            "is_modified": "FALSE"
          },
          {
            "name": "dispatchers",
            "value": "(PROTOCOL=TCP) (SERVICE=FREEXDB)",
            "is_default": "FALSE",
            "is_modified": "FALSE"
          },
          {
            "name": "enable_pluggable_database",
            "value": "TRUE",
            "is_default": "FALSE",
            "is_modified": "FALSE"
          },
          {
            "name": "fast_start_parallel_rollback",
            "value": "LOW",
            "is_default": "FALSE",
            "is_modified": "FALSE"
          },
          {
            "name": "nls_language",
            "value": "AMERICAN",
            "is_default": "FALSE",
            "is_modified": "FALSE"
          },
          {
            "name": "nls_territory",
            "value": "AMERICA",
            "is_default": "FALSE",
            "is_modified": "FALSE"
          },
          {
            "name": "open_cursors",
            "value": "300",
            "is_default": "FALSE",
            "is_modified": "FALSE"
          },
          {
            "name": "pga_aggregate_target",
            "value": "536870912",
            "is_default": "FALSE",
            "is_modified": "FALSE"
          },
          {
            "name": "processes",
            "value": "200",
            "is_default": "FALSE",
            "is_modified": "FALSE"
          },
          {
            "name": "remote_login_passwordfile",
            "value": "EXCLUSIVE",
            "is_default": "FALSE",
            "is_modified": "FALSE"
          },
          {
            "name": "sga_target",
            "value": "0",
            "is_default": "FALSE",
            "is_modified": "FALSE"
          },
          {
            "name": "spatial_vector_acceleration",
            "value": "TRUE",
            "is_default": "FALSE",
            "is_modified": "FALSE"
          },
          {
            "name": "undo_tablespace",
            "value": "UNDOTBS1",
            "is_default": "FALSE",
            "is_modified": "FALSE"
          }
        ],
        "rman_backups": "no RMAN backup jobs in last 7 days",
        "system_resources": "null",
        "health_summary": {
          "total_sessions": 1,
          "active_sessions": 1,
          "blocked_sessions": 0,
          "total_size_bytes": 993001472
        },
        "fast_recovery_area": "no FRA configured",
        "top_temp_sessions": [],
        "redo_log_switches": [],
        "archive_log_daily": [
          {
            "day": "2026-09-14",
            "size_gb": 0.19,
            "size_mb": 194,
            "archives": 1,
            "day_name": "MON"
          },
          {
            "day": "2026-09-18",
            "size_gb": 0.35,
            "size_mb": 362.31,
            "archives": 2,
            "day_name": "FRI"
          },
          {
            "day": "2026-09-25",
            "size_gb": 0.18,
            "size_mb": 182.31,
            "archives": 1,
            "day_name": "FRI"
          },
          {
            "day": "2026-09-29",
            "size_gb": 0.19,
            "size_mb": 197.65,
            "archives": 1,
            "day_name": "TUE"
          }
        ],
        "datafiles_offline": [],
        "failed_scheduler_jobs": [],
        "user_accounts": [
          {
            "created": "2026-04-29T01:35:46",
            "profile": "DEFAULT",
            "username": "PDBADMIN",
            "lock_date": "null",
            "last_login": "null",
            "expiry_date": "2026-10-26T01:35:46",
            "pwd_life_time": "180",
            "account_status": "OPEN",
            "days_to_expire": 27,
            "default_tablespace": "USERS",
            "temporary_tablespace": "TEMP"
          }
        ],
        "id": 2,
        "agent_name": "agent1",
        "service_name": "freepdb1",
        "engine": "oracle",
        "action": "db_health",
        "outcome": "success",
        "severity": "info",
        "collector": "db_discovery",
        "tags": [
          "database",
          "inspect",
          "oracle"
        ],
        "notes": "null",
        "inspected": True,
        "health_status": "healthy",
        "target_name": "oracle@141.148.220.11",
        "db_host": "141.148.220.11",
        "db_port": 1521,
        "db_version": "23.26.2.0.0",
        "current_database": "null",
        "database_count": 1,
        "table_count": 2522,
        "total_size_bytes": 993001472,
        "databases": [
          {
            "name": "FREEPDB1",
            "open_mode": "READ WRITE"
          }
        ],
        "issues": [],
        "details": "null",
        "timestamp": "2026-09-29T12:20:24.333240+00:00",
        "ingested_at": "2026-09-29T12:20:50.020342+00:00"
      }
    ]
  }
}   
    return standard_success_response(
        data={"engine": _canon(engine), "service_name": service_name,
              "matched_on": svc.key, "count": len(data),"rows": data},
        message="stored database data")
