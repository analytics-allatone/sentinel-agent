"""schema/mongo_db_event.py — MongoDB health event -> mongo_db_events table."""
from dataclasses import dataclass
from typing import Optional, Any, ClassVar, List
from schema.db_event_base import BaseDbEvent

# NB: "databases" is carried by the shared base field, so it is not repeated here.
MONGO_SECTIONS = [
     "basic_connectivity", "database_size", "active_connections", "locks_blocking",
        "replication_primary", "replication_delay", "cache_hit_ratio", "dead_tuples_vacuum",
        "index_usage", "transaction_wraparound", "wal_checkpoint", "table_bloat",
        "system_resources", "health_summary"]


@dataclass
class MongoDbEvent(BaseDbEvent):
    engine: str = "mongodb"
    category: str = "mongodb_health"

    basic_connectivity: Optional[Any] = None
    database_size: Optional[Any] = None
    active_connections: Optional[Any] = None
    locks_blocking: Optional[Any] = None
    replication_primary: Optional[Any] = None
    replication_delay: Optional[Any] = None
    cache_hit_ratio: Optional[Any] = None
    dead_tuples_vacuum: Optional[Any] = None
    index_usage: Optional[Any] = None
    transaction_wraparound: Optional[Any] = None
    wal_checkpoint: Optional[Any] = None
    table_bloat: Optional[Any] = None
    system_resources: Optional[Any] = None
    health_summary: Optional[Any] = None

    SECTIONS: ClassVar[List[str]] = MONGO_SECTIONS
    METRICS: ClassVar[List[tuple]] = [
        ("uptime_seconds", "uptime_seconds"), ("connections_current", "connections_current"),
        ("connections_available", "connections_available"),
        ("connections_used_pct", "connections_used_pct"),
        ("resident_mb", "resident_mb"), ("virtual_mb", "virtual_mb"),
    ]
