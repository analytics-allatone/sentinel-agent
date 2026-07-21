"""schema/oracle_db_event.py — Oracle health event -> oracle_db_events table."""
from dataclasses import dataclass
from typing import Optional, Any, ClassVar, List
from schema.db_event_base import BaseDbEvent

ORACLE_SECTIONS = [
    "connectivity_version", "database_sizes", "active_connections", "session_summary",
    "sessions_by_user", "idle_sessions", "long_running_queries", "locks_blocking",
    "cache_hit_ratio", "memory", "resource_limits", "top_sql_elapsed", "top_sql_executions",
    "top_segments", "table_bloat", "index_usage", "dead_tuples_vacuum", "wal_checkpoint",
    "wraparound_risk", "replication_primary", "replication_delay", "standby_destinations",
    "alert_log_errors", "modified_parameters", "rman_backups", "system_resources", "health_summary",
]


@dataclass
class OracleDbEvent(BaseDbEvent):
    engine: str = "oracle"
    category: str = "oracle_health"

    # promoted scalar metrics
    sessions_current: Optional[int] = None
    sessions_active: Optional[int] = None
    sessions_blocked: Optional[int] = None
    is_cdb: Optional[bool] = None
    uptime_seconds: Optional[int] = None
    database_role: Optional[str] = None
    open_mode: Optional[str] = None
    cache_hit_pct: Optional[float] = None
    library_hit_pct: Optional[float] = None
    dict_hit_pct: Optional[float] = None

    # sections (one JSONB column each)
    connectivity_version: Optional[Any] = None
    database_sizes: Optional[Any] = None
    active_connections: Optional[Any] = None
    session_summary: Optional[Any] = None
    sessions_by_user: Optional[Any] = None
    idle_sessions: Optional[Any] = None
    long_running_queries: Optional[Any] = None
    locks_blocking: Optional[Any] = None
    cache_hit_ratio: Optional[Any] = None
    memory: Optional[Any] = None
    resource_limits: Optional[Any] = None
    top_sql_elapsed: Optional[Any] = None
    top_sql_executions: Optional[Any] = None
    top_segments: Optional[Any] = None
    table_bloat: Optional[Any] = None
    index_usage: Optional[Any] = None
    dead_tuples_vacuum: Optional[Any] = None
    wal_checkpoint: Optional[Any] = None
    wraparound_risk: Optional[Any] = None
    replication_primary: Optional[Any] = None
    replication_delay: Optional[Any] = None
    standby_destinations: Optional[Any] = None
    alert_log_errors: Optional[Any] = None
    modified_parameters: Optional[Any] = None
    rman_backups: Optional[Any] = None
    system_resources: Optional[Any] = None
    health_summary: Optional[Any] = None

    SECTIONS: ClassVar[List[str]] = ORACLE_SECTIONS
    METRICS: ClassVar[List[tuple]] = [
        ("sessions_current", "sessions_current"), ("sessions_active", "sessions_active"),
        ("sessions_blocked", "sessions_blocked"), ("is_cdb", "is_cdb"),
        ("uptime_seconds", "uptime_seconds"), ("database_role", "database_role"),
        ("open_mode", "open_mode"), ("cache_hit_pct", "cache_hit_pct"),
        ("library_hit_pct", "library_hit_pct"), ("dict_hit_pct", "dict_hit_pct"),
    ]
