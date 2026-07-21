"""redis.py - the 14 health points for Redis (redis-py). Default local installs need no auth."""
from typing import Dict, Any
DRIVER = "redis"
NA = lambda why: {"not_applicable": why}


def inspect(params: Dict[str, Any]) -> Dict[str, Any]:
    import redis
    r = redis.Redis(host=params.get("host", "127.0.0.1"), port=int(params.get("port", 6379)),
                    password=params.get("password") or None, socket_timeout=8,
                    socket_connect_timeout=8, decode_responses=True)
    info = r.info()
    try: slow = r.slowlog_get(10)
    except Exception: slow = []
    try: r.close()
    except Exception: pass
    g = info.get
    keyspace = [{"db": k, "keys": v.get("keys", 0), "expires": v.get("expires", 0)}
                for k, v in info.items() if k.startswith("db") and isinstance(v, dict)]
    total_keys = sum(d["keys"] for d in keyspace)
    hits, misses = g("keyspace_hits", 0), g("keyspace_misses", 0)
    out = {
        "basic_connectivity": {"version": g("redis_version"), "current_database": "db0",
                               "server_host": params.get("host", "127.0.0.1"), "server_port": g("tcp_port"),
                               "mode": g("redis_mode"), "os": g("os")},
        "database_size": {"used_memory_bytes": g("used_memory"), "used_memory_human": g("used_memory_human"),
                          "keyspace": keyspace, "total_keys": total_keys},
        "active_connections": {"connected_clients": g("connected_clients"), "blocked_clients": g("blocked_clients"),
                               "slowlog_recent": [{"id": s.get("id"), "duration_us": s.get("duration"),
                                                   "command": " ".join(map(str, s.get("command", [])))} for s in slow]},
        "locks_blocking": NA("Redis is single-threaded; no row/table locks. blocked_clients shown.") |
                          {"blocked_clients": g("blocked_clients")},
        "replication_primary": {"role": g("role"), "connected_slaves": g("connected_slaves"),
                                "slaves": [v for k, v in info.items() if k.startswith("slave") and isinstance(v, dict)]},
        "replication_delay": {"master_link_status": g("master_link_status"),
                              "master_last_io_seconds_ago": g("master_last_io_seconds_ago"),
                              "master_repl_offset": g("master_repl_offset")},
        "cache_hit_ratio": {"keyspace_hits": hits, "keyspace_misses": misses,
                            "hit_ratio_pct": round(hits/(hits+misses)*100, 2) if (hits+misses) else None},
        "dead_tuples_vacuum": NA("No dead tuples/vacuum. expired/evicted keys are the memory-reclaim analog.") |
                              {"expired_keys": g("expired_keys"), "evicted_keys": g("evicted_keys")},
        "index_usage": NA("Redis has no secondary indexes."),
        "transaction_wraparound": NA("No transaction-ID wraparound in Redis."),
        "wal_checkpoint": {"rdb_last_save_time": g("rdb_last_save_time"),
                           "rdb_changes_since_last_save": g("rdb_changes_since_last_save"),
                           "aof_enabled": g("aof_enabled"), "rdb_last_bgsave_status": g("rdb_last_bgsave_status")},
        "table_bloat": {"mem_fragmentation_ratio": g("mem_fragmentation_ratio"),
                        "used_memory_rss_bytes": g("used_memory_rss"), "maxmemory_bytes": g("maxmemory")},
        "health_summary": {"connected_clients": g("connected_clients"), "total_keys": total_keys,
                           "used_memory_bytes": g("used_memory"), "uptime_seconds": g("uptime_in_seconds")},
    }
    return {"db_version": g("redis_version"), "current_database": "db0", "points": out}
