"""schema/db_events.py — engine -> per-engine event class registry.

The controller (db_discovery_collector) uses this in its INSPECT portion to build
the right event for each detected engine and route it to that engine's own table.
Detection stays in the controller; inspection is emitted per engine.
"""
from schema.postgres_db_event import PostgresDbEvent
from schema.mysql_db_event import MysqlDbEvent
from schema.oracle_db_event import OracleDbEvent
from schema.redis_db_event import RedisDbEvent
from schema.mongo_db_event import MongoDbEvent

EVENT_FOR_ENGINE = {
    "postgresql": PostgresDbEvent,
    "postgres":   PostgresDbEvent,
    "mysql":      MysqlDbEvent,
    "mariadb":    MysqlDbEvent,
    "oracle":     OracleDbEvent,
    "redis":      RedisDbEvent,
    "mongodb":    MongoDbEvent,
    "mongo":      MongoDbEvent,
}

__all__ = ["EVENT_FOR_ENGINE", "PostgresDbEvent", "MysqlDbEvent",
           "OracleDbEvent", "RedisDbEvent", "MongoDbEvent"]
