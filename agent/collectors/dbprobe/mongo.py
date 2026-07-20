"""mongo.py - the 14 health points for MongoDB (pymongo). Default local installs need no auth."""
from typing import Dict, Any
DRIVER = "pymongo"
NA = lambda why: {"not_applicable": why}


def inspect(params: Dict[str, Any]) -> Dict[str, Any]:
    import pymongo
    kw = dict(serverSelectionTimeoutMS=8000)
    if params.get("user"):
        kw["username"] = params["user"]; kw["password"] = params.get("password") or ""
    cli = pymongo.MongoClient(host=params.get("host", "127.0.0.1"), port=int(params.get("port", 27017)), **kw)

    def cmd(db, c, default=None):
        try: return cli[db].command(c)
        except Exception: return default if default is not None else {}
    try:
        ss = cmd("admin", "serverStatus")
        listing = cmd("admin", "listDatabases")
        rs = cmd("admin", "replSetGetStatus", default={})
        databases = []
        for d in listing.get("databases", []):
            name = d["name"]; stats = cmd(name, "dbStats")
            databases.append({"name": name, "size_bytes": int(stats.get("storageSize", d.get("sizeOnDisk", 0)) or 0),
                              "data_size": int(stats.get("dataSize", 0) or 0),
                              "collections": int(stats.get("collections", 0) or 0),
                              "objects": int(stats.get("objects", 0) or 0)})
        cur_db = next((d["name"] for d in databases if d["name"] not in ("admin", "local", "config")), "admin")
    finally:
        cli.close()

    conns = ss.get("connections", {}); mem = ss.get("mem", {}); gl = ss.get("globalLock", {})
    wt = ss.get("wiredTiger", {}); cache = wt.get("cache", {}); log = wt.get("log", {})
    members = rs.get("members", [])
    primary_optime = next((m.get("optimeDate") for m in members if m.get("stateStr") == "PRIMARY"), None)
    lags = [{"name": m.get("name"), "state": m.get("stateStr"),
             "lag_seconds": (primary_optime - m["optimeDate"]).total_seconds()
                            if primary_optime and m.get("optimeDate") and m.get("stateStr") == "SECONDARY" else None}
            for m in members]
    out = {
        "basic_connectivity": {"version": ss.get("version"), "current_database": cur_db,
                               "server_host": ss.get("host"), "server_port": params.get("port", 27017),
                               "process": ss.get("process")},
        "database_size": {"current_database": cur_db, "databases": sorted(databases, key=lambda d: d["size_bytes"], reverse=True),
                          "total_size_bytes": sum(d["size_bytes"] for d in databases)},
        "active_connections": {"current": conns.get("current"), "available": conns.get("available"),
                               "active": conns.get("active"), "queue": gl.get("currentQueue", {})},
        "locks_blocking": {"global_lock_queue": gl.get("currentQueue", {}), "locks": ss.get("locks", {})},
        "replication_primary": {"set": rs.get("set"), "members": [{"name": m.get("name"), "state": m.get("stateStr"),
                                "health": m.get("health")} for m in members]},
        "replication_delay": {"member_lag": lags},
        "cache_hit_ratio": {"bytes_in_cache": cache.get("bytes currently in the cache"),
                            "pages_read_into_cache": cache.get("pages read into cache"),
                            "pages_requested_from_cache": cache.get("pages requested from the cache"),
                            "max_bytes_configured": cache.get("maximum bytes configured")},
        "dead_tuples_vacuum": NA("MongoDB/WiredTiger has no vacuum; storage is reclaimed automatically."),
        "index_usage": NA("Per-index usage requires $indexStats per collection; not collected by default."),
        "transaction_wraparound": NA("No XID wraparound in MongoDB."),
        "wal_checkpoint": {"log": {k: log.get(k) for k in ("log sync operations", "log write operations") if k in log},
                           "transaction_checkpoints": wt.get("transaction", {}).get("transaction checkpoints")},
        "table_bloat": {"databases": [{"name": d["name"], "data_size": d["data_size"],
                        "storage_size": d["size_bytes"]} for d in databases]},
        "health_summary": {"connections_current": conns.get("current"), "databases": len(databases),
                           "total_size_bytes": sum(d["size_bytes"] for d in databases),
                           "uptime_seconds": int(ss.get("uptime", 0))},
    }
    return {"db_version": ss.get("version"), "current_database": cur_db, "points": out}
