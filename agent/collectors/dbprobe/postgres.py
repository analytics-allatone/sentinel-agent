"""postgres.py - the 14 health points for PostgreSQL (psycopg2), each its own field."""
from typing import Dict, Any
from collectors.dbprobe._util import rows, one, safe
DRIVER = "psycopg2"


def inspect(params: Dict[str, Any]) -> Dict[str, Any]:
    import psycopg2
    conn = psycopg2.connect(
        host=params.get("host") or None, port=int(params.get("port", 5432)),
        user=params.get("user"), password=params.get("password"),
        dbname=params.get("dbname", "postgres"),
        connect_timeout=int(params.get("connect_timeout", 8)),
        application_name="sentinel_db_discovery")
    conn.autocommit = True
    out: Dict[str, Any] = {}
    try:
        cur = conn.cursor()

        # 1. Basic Connectivity & Version
        ver = one(cur, "SELECT version() AS version")
        conn_info = one(cur, """SELECT current_database() AS current_database,
                                       current_user AS current_user,
                                       inet_server_addr()::text AS server_addr,
                                       inet_server_port() AS server_port""")
        out["basic_connectivity"] = {**ver, **conn_info}

        # 2. Database Size
        out["database_size"] = {
            "current_db_size": (one(cur, "SELECT pg_size_pretty(pg_database_size(current_database())) AS current_db_size")
                                .get("current_db_size")),
            "databases": rows(cur, """SELECT datname,
                                             pg_size_pretty(pg_database_size(datname)) AS size,
                                             pg_database_size(datname) AS size_bytes
                                      FROM pg_database ORDER BY pg_database_size(datname) DESC"""),
        }

        # 3. Active Connections (+ long-running queries)
        out["active_connections"] = {
            "by_state": rows(cur, """SELECT state, count(*) AS connections
                                     FROM pg_stat_activity GROUP BY state ORDER BY connections DESC"""),
            "long_running": rows(cur, """SELECT pid, EXTRACT(EPOCH FROM now()-query_start) AS duration_seconds,
                                                state, wait_event_type, wait_event
                                         FROM pg_stat_activity
                                         WHERE state != 'idle'
                                         ORDER BY duration_seconds DESC NULLS LAST LIMIT 10"""),
        }

        # 4. Locks / Blocking Sessions
        out["locks_blocking"] = {"blocking": rows(cur, """
            SELECT blocked.pid AS blocked_pid, blocked.query AS blocked_query,
                   blocking.pid AS blocking_pid, blocking.query AS blocking_query
            FROM pg_stat_activity blocked
            JOIN pg_locks blocked_locks ON blocked.pid = blocked_locks.pid
            JOIN pg_locks blocking_locks
              ON blocking_locks.locktype = blocked_locks.locktype
             AND blocking_locks.database IS NOT DISTINCT FROM blocked_locks.database
             AND blocking_locks.relation IS NOT DISTINCT FROM blocked_locks.relation
             AND blocking_locks.page IS NOT DISTINCT FROM blocked_locks.page
             AND blocking_locks.tuple IS NOT DISTINCT FROM blocked_locks.tuple
             AND blocking_locks.pid != blocked_locks.pid
            JOIN pg_stat_activity blocking ON blocking.pid = blocking_locks.pid
            WHERE NOT blocked_locks.granted""")}

        # 5. Replication Status (Primary)
        out["replication_primary"] = {"standbys": rows(cur, """
            SELECT client_addr::text AS client_addr, state, sync_state,
                   EXTRACT(EPOCH FROM write_lag) AS write_lag_s,
                   EXTRACT(EPOCH FROM flush_lag) AS flush_lag_s,
                   EXTRACT(EPOCH FROM replay_lag) AS replay_lag_s
            FROM pg_stat_replication""")}

        # 6. Replication Delay (Replica)
        out["replication_delay"] = one(cur, """SELECT pg_is_in_recovery() AS in_recovery,
            EXTRACT(EPOCH FROM (now()-pg_last_xact_replay_timestamp())) AS replication_delay_seconds""")

        # 7. Cache Hit Ratio
        out["cache_hit_ratio"] = {"per_database": rows(cur, """
            SELECT datname, round(blks_hit*100.0/NULLIF(blks_hit+blks_read,0),2) AS cache_hit_ratio
            FROM pg_stat_database WHERE datname IS NOT NULL ORDER BY cache_hit_ratio NULLS LAST""")}

        # 8. Dead Tuples / Vacuum Health
        out["dead_tuples_vacuum"] = {"tables": rows(cur, """
            SELECT schemaname, relname, n_live_tup, n_dead_tup, last_vacuum, last_autovacuum
            FROM pg_stat_user_tables ORDER BY n_dead_tup DESC LIMIT 20""")}

        # 9. Index Usage
        out["index_usage"] = {"least_used": rows(cur, """
            SELECT schemaname, relname, indexrelname, idx_scan
            FROM pg_stat_user_indexes ORDER BY idx_scan ASC LIMIT 20""")}

        # 10. Transaction Wraparound Risk
        out["transaction_wraparound"] = {"databases": rows(cur, """
            SELECT datname, age(datfrozenxid) AS xid_age
            FROM pg_database ORDER BY xid_age DESC""")}

        # 11. WAL / Checkpoint Health (PG<17 bgwriter; PG17+ checkpointer fallback)
        wal = safe(lambda: one(cur, """SELECT checkpoints_timed, checkpoints_req, buffers_checkpoint,
                                              buffers_clean, maxwritten_clean FROM pg_stat_bgwriter"""))
        if not wal:
            wal = safe(lambda: one(cur, """SELECT num_timed AS checkpoints_timed, num_requested AS checkpoints_req,
                                                  buffers_written AS buffers_checkpoint FROM pg_stat_checkpointer"""), {})
        out["wal_checkpoint"] = wal or {}

        # 12. Table Bloat / Size
        out["table_bloat"] = {"tables": rows(cur, """
            SELECT schemaname, relname,
                   pg_size_pretty(pg_total_relation_size(relid)) AS total_size,
                   pg_total_relation_size(relid) AS total_size_bytes
            FROM pg_catalog.pg_statio_user_tables
            ORDER BY pg_total_relation_size(relid) DESC LIMIT 20""")}

        # 14. One-Line Health Summary
        out["health_summary"] = one(cur, """SELECT now() AS check_time,
            (SELECT count(*) FROM pg_stat_activity) AS total_connections,
            (SELECT count(*) FROM pg_stat_activity WHERE state='active') AS active_queries,
            (SELECT pg_size_pretty(pg_database_size(current_database()))) AS db_size""")

        cur.close()
    finally:
        conn.close()

    bc = out.get("basic_connectivity", {})
    return {"db_version": bc.get("version"), "current_database": bc.get("current_database"), "points": out}
