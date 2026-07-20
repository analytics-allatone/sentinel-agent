"""mysql.py - the 14 health points for MySQL/MariaDB (PyMySQL). Points that do not
apply to MySQL (8,10) are returned with an explicit not_applicable note."""
from typing import Dict, Any
from collectors.dbprobe._util import jsonify, safe
DRIVER = "pymysql"
SYS = ("mysql", "information_schema", "performance_schema", "sys")


def inspect(params: Dict[str, Any]) -> Dict[str, Any]:
    import pymysql
    from pymysql.cursors import DictCursor
    
    kw = dict(host=params.get("host", "127.0.0.1"), port=int(params.get("port", 3306)),
              user=params.get("user"), password=params.get("password") or "",
              connect_timeout=int(params.get("connect_timeout", 8)), read_timeout=10,
              cursorclass=DictCursor)
    if params.get("unix_socket"):
        kw["unix_socket"] = params["unix_socket"]
    conn = pymysql.connect(**kw)
    
    def q(sql, args=None):
        with conn.cursor() as c:
            
            c.execute(sql, args or ())
            return [{k: jsonify(v) for k, v in row.items()} for row in c.fetchall()]

    def q1(sql, args=None):
        r = q(sql, args)
        return r[0] if r else {}

    out: Dict[str, Any] = {}
    try:
        # Pick the most recently created user database -> current_database
        recent = q1("""SELECT TABLE_SCHEMA AS db, MAX(CREATE_TIME) AS created
                       FROM information_schema.tables
                       WHERE TABLE_SCHEMA NOT IN %s
                       GROUP BY TABLE_SCHEMA ORDER BY created DESC LIMIT 1""", (SYS,))
        cur_db = recent.get("db")
        
        if not cur_db:
            anyschema = q1("""SELECT SCHEMA_NAME AS db FROM information_schema.schemata
                              WHERE SCHEMA_NAME NOT IN %s LIMIT 1""", (SYS,))
            cur_db = anyschema.get("db")
        if cur_db:
            with conn.cursor() as c:
                c.execute(f"USE `{cur_db}`")
                

        # 1. Basic connectivity & version
        out["basic_connectivity"] = q1("""SELECT VERSION() AS version, DATABASE() AS current_database,
                                                  CURRENT_USER() AS currentuser, @@hostname AS server_host,
                                                  @@port AS server_port""")
        
        # 2. Database size (per schema + current db)
        sizes = q("""SELECT table_schema AS datname,
                            SUM(data_length+index_length) AS size_bytes,
                            COUNT(*) AS tables
                     FROM information_schema.tables GROUP BY table_schema
                     ORDER BY size_bytes DESC""")
        cur_size = next((s["size_bytes"] for s in sizes if s["datname"] == cur_db), None)
        out["database_size"] = {"current_database": cur_db, "current_db_size_bytes": cur_size, "databases": sizes}

        # 3. Active connections + long-running
        out["active_connections"] = {
            "by_command": q("""SELECT command, COUNT(*) AS connections
                               FROM information_schema.processlist GROUP BY command ORDER BY connections DESC"""),
            "long_running": q("""SELECT id AS pid, time AS duration_seconds, state, command
                                 FROM information_schema.processlist WHERE command NOT IN ('Sleep','Daemon')
                                 ORDER BY time DESC LIMIT 10"""),
        }

        # 4. Locks / blocking (MySQL 8 performance_schema; best-effort)
        out["locks_blocking"] = {"blocking": safe(lambda: q("""
            SELECT w.blocking_pid AS blocking_pid, bt.processlist_info AS blocking_query,
                   w.requesting_pid AS blocked_pid, rt.processlist_info AS blocked_query
            FROM performance_schema.data_lock_waits w
            JOIN performance_schema.threads bt ON bt.thread_id = w.blocking_thread_id
            JOIN performance_schema.threads rt ON rt.thread_id = w.requesting_thread_id"""), []) or []}

        # 5/6. Replication (best-effort; needs REPLICATION CLIENT)
        out["replication_primary"] = {"replicas": safe(lambda: q("SHOW REPLICAS"),
                                       safe(lambda: q("SHOW SLAVE HOSTS"), [])) or []}
        rep = safe(lambda: q1("SHOW REPLICA STATUS"), safe(lambda: q1("SHOW SLAVE STATUS"), {})) or {}
        out["replication_delay"] = {"seconds_behind": rep.get("Seconds_Behind_Source",
                                    rep.get("Seconds_Behind_Master")), "role": "replica" if rep else "primary"}

        # 7. Cache hit (InnoDB buffer pool)
        st = {r["Variable_name"]: r["Value"] for r in q("SHOW GLOBAL STATUS")}
        
        def num(k):
            try: return float(st.get(k, 0))
            except (TypeError, ValueError): return 0.0
        rr, rd = num("Innodb_buffer_pool_read_requests"), num("Innodb_buffer_pool_reads")
        out["cache_hit_ratio"] = {"buffer_pool_hit_pct": round((rr-rd)/rr*100, 2) if rr else None,
                                  "read_requests": rr, "disk_reads": rd}

        # 8. Dead tuples / vacuum -> not applicable; nearest is fragmentation (DATA_FREE)
        out["dead_tuples_vacuum"] = {"not_applicable": "MySQL/InnoDB has no dead-tuple/vacuum model",
            "fragmentation_top": q("""SELECT table_schema, table_name, data_free
                                      FROM information_schema.tables WHERE data_free > 0
                                      ORDER BY data_free DESC LIMIT 20""")}

        # 9. Index usage (unused indexes; needs sys schema)
        out["index_usage"] = {"unused_indexes": safe(lambda: q("""
            SELECT object_schema, object_name, index_name FROM sys.schema_unused_indexes LIMIT 20"""), []) or []}

        # 10. Transaction wraparound -> not applicable
        out["transaction_wraparound"] = {"not_applicable": "No XID wraparound concept in MySQL/InnoDB"}

        # 11. WAL/checkpoint (InnoDB redo log analogs)
        out["wal_checkpoint"] = {"innodb_os_log_written": num("Innodb_os_log_written"),
                                 "buffer_pool_pages_dirty": num("Innodb_buffer_pool_pages_dirty"),
                                 "log_waits": num("Innodb_log_waits")}

        # 12. Table size / bloat
        out["table_bloat"] = {"tables": q("""SELECT table_schema, table_name,
                                                    (data_length+index_length) AS total_size_bytes, data_free
                                             FROM information_schema.tables
                                             ORDER BY total_size_bytes DESC LIMIT 20""")}

        # 14. Health summary
        out["health_summary"] = {"check_time": None, "total_connections": int(num("Threads_connected")),
                                 "active_queries": int(num("Threads_running")),
                                 "current_database": cur_db, "db_size_bytes": cur_size,
                                 "uptime_seconds": int(num("Uptime"))}
    finally:
        conn.close()
    
    bc = out.get("basic_connectivity", {})

    return {"db_version": bc.get("version"), "current_database": bc.get("current_database"), "points": out}
