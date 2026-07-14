"""schema/redis_db_event.py — Redis health event -> redis_db_events table."""
from dataclasses import dataclass
from typing import Optional, Any, ClassVar, List
from schema.db_event_base import BaseDbEvent

REDIS_SECTIONS = [
    "connectivity_version", "database_sizes", "active_connections", "long_running_queries",
    "locks_blocking", "replication_primary", "replication_delay", "cache_hit_ratio",
    "dead_tuples_vacuum", "index_usage", "wraparound_risk", "wal_checkpoint",
    "table_bloat", "system_resources", "health_summary",
]


@dataclass
class RedisDbEvent(BaseDbEvent):
    engine: str = "redis"
    category: str = "redis_health"

    # promoted scalar metrics
    uptime_seconds: Optional[int] = None
    connected_clients: Optional[int] = None
    used_memory_bytes: Optional[int] = None
    hit_ratio_pct: Optional[float] = None
    role: Optional[str] = None
    connected_slaves: Optional[int] = None

    # sections
    connectivity_version: Optional[Any] = None
    database_sizes: Optional[Any] = None
    active_connections: Optional[Any] = None
    long_running_queries: Optional[Any] = None
    locks_blocking: Optional[Any] = None
    replication_primary: Optional[Any] = None
    replication_delay: Optional[Any] = None
    cache_hit_ratio: Optional[Any] = None
    dead_tuples_vacuum: Optional[Any] = None
    index_usage: Optional[Any] = None
    wraparound_risk: Optional[Any] = None
    wal_checkpoint: Optional[Any] = None
    table_bloat: Optional[Any] = None
    system_resources: Optional[Any] = None
    health_summary: Optional[Any] = None

    SECTIONS: ClassVar[List[str]] = REDIS_SECTIONS
    METRICS: ClassVar[List[tuple]] = [
        ("uptime_seconds", "uptime_seconds"), ("connected_clients", "connected_clients"),
        ("used_memory_bytes", "used_memory_bytes"), ("hit_ratio_pct", "hit_ratio_pct"),
        ("role", "role"), ("connected_slaves", "connected_slaves"),
    ]
