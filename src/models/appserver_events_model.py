from sqlalchemy import Column, Integer, BigInteger, String, Boolean, Float, TIMESTAMP
from sqlalchemy.dialects.postgresql import JSONB
from datetime import datetime, timezone

try:
    from db.base import Base
    try:
        from models.event_model import ForceDateTime
    except Exception:
        ForceDateTime = TIMESTAMP(timezone=True)
except Exception:
    from sqlalchemy.orm import declarative_base
    Base = declarative_base()
    ForceDateTime = TIMESTAMP(timezone=True)


class AppServerEvents(Base):
    __tablename__ = "appserver_events"

    id = Column(BigInteger, primary_key=True, autoincrement=True, index=True)
    agent_name = Column(String, nullable=False, index=True)

    category = Column(String)
    engine = Column(String)                 # "appserver"
    server = Column(String, index=True)     # wildfly | jboss | tomcat
    backend = Column(String, index=True)    # api | cli
    action = Column(String, nullable=False)
    outcome = Column(String)
    severity = Column(String, index=True)
    collector = Column(String)
    tags = Column(JSONB)
    notes = Column(String)
    inspected = Column(Boolean)
    health_status = Column(String, index=True)

    detected = Column(Boolean)
    running = Column(Boolean)
    process_pid = Column(Integer)
    exe_path = Column(String)
    auth_method = Column(String)
    inspect_error = Column(String)
    system_resources = Column(JSONB)

    target_name = Column(String, index=True)
    app_host = Column(String)
    app_port = Column(Integer)
    app_version = Column(String)
    server_state = Column(String, index=True)

    heap_pct = Column(Float)
    heap_used = Column(BigInteger)
    gc_time_ms = Column(BigInteger)
    thread_count = Column(Integer)
    datasource_wait_total = Column(BigInteger)
    deployments_ok = Column(Integer)
    deployments_total = Column(Integer)
    uptime_ms = Column(BigInteger)

    connectivity_version = Column(JSONB)
    jvm = Column(JSONB)
    threads = Column(JSONB)
    thread_pools = Column(JSONB)
    datasources = Column(JSONB)
    deployments = Column(JSONB)
    health_summary = Column(JSONB)

    issues = Column(JSONB)
    details = Column(JSONB)

    timestamp = Column(ForceDateTime)
    ingested_at = Column(TIMESTAMP(timezone=True), nullable=False,
                         default=lambda: datetime.now(timezone.utc))
