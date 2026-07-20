"""schema/mongo_db_event.py — MongoDB health event -> mongo_db_events table."""
from dataclasses import dataclass
from typing import Optional, Any, ClassVar, List
from schema.db_event_base import BaseDbEvent

# NB: "databases" is carried by the shared base field, so it is not repeated here.
MONGO_SECTIONS = [
    "connections", "memory_mb", "opcounters", "network",
    "largest_tables", "connection_summary",
]


@dataclass
class MongoDbEvent(BaseDbEvent):
    engine: str = "mongodb"
    category: str = "mongodb_health"

    # promoted scalar metrics
    uptime_seconds: Optional[int] = None
    connections_current: Optional[int] = None
    connections_available: Optional[int] = None
    connections_used_pct: Optional[float] = None
    resident_mb: Optional[int] = None
    virtual_mb: Optional[int] = None

    # sections
    connections: Optional[Any] = None
    memory_mb: Optional[Any] = None
    opcounters: Optional[Any] = None
    network: Optional[Any] = None
    largest_tables: Optional[Any] = None
    connection_summary: Optional[Any] = None

    SECTIONS: ClassVar[List[str]] = MONGO_SECTIONS
    METRICS: ClassVar[List[tuple]] = [
        ("uptime_seconds", "uptime_seconds"), ("connections_current", "connections_current"),
        ("connections_available", "connections_available"),
        ("connections_used_pct", "connections_used_pct"),
        ("resident_mb", "resident_mb"), ("virtual_mb", "virtual_mb"),
    ]
