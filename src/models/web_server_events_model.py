
from sqlalchemy import Column, Integer, BigInteger, String, Boolean, Float, TIMESTAMP,ForeignKey
from sqlalchemy.dialects.postgresql import JSONB
from datetime import datetime, timezone

try:
    from db.base import Base                       # <- the real shared Base
    try:
        from models.event_model import ForceDateTime
    except Exception:
        ForceDateTime = TIMESTAMP(timezone=True)
except Exception:
    from sqlalchemy.orm import declarative_base
    Base = declarative_base()
    ForceDateTime = TIMESTAMP(timezone=True)


class WebServerEvents(Base):
    __tablename__ = "web_server_events"

    id = Column(BigInteger, primary_key=True, autoincrement=True, index=True)

    agent_id = Column(Integer, nullable=True, index=True)

    engine = Column(String)                        # "webserver"
    server = Column(String, index=True)            # nginx | apache
    category = Column(String)
    action = Column(String, nullable=False)
    outcome = Column(String)
    severity = Column(String, index=True)
    collector = Column(String)
    tags = Column(JSONB)
    notes = Column(String)
    inspected = Column(Boolean)
    health_status = Column(String, index=True)

    # detect fields
    detected = Column(Boolean)
    running = Column(Boolean)
    process_pid = Column(Integer)
    exe_path = Column(String)
    service_name = Column(String)
    auth_method = Column(String)
    inspect_error = Column(String)
    system_resources = Column(JSONB)

    # identity
    target_name = Column(String, index=True)
    db_host = Column(String)                        # host (reused name from base)
    db_port = Column(Integer)                       # listening port
    db_version = Column(String)                     # server version

    # promoted scalar metrics
    active_connections = Column(Integer)
    requests_total = Column(BigInteger)
    req_per_sec = Column(Float)
    busy_workers = Column(Integer)
    idle_workers = Column(Integer)
    uptime_seconds = Column(BigInteger)
    error_rate_pct = Column(Float)
    config_ok = Column(Boolean)

    # sections
    connectivity_version = Column(JSONB)
    live_status = Column(JSONB)
    vhosts_tls = Column(JSONB)
    access_log = Column(JSONB)
    error_log = Column(JSONB)
    health_summary = Column(JSONB)

    issues = Column(JSONB)
    details = Column(JSONB)

    timestamp = Column(ForceDateTime)
    ingested_at = Column(TIMESTAMP(timezone=True), nullable=False,
                         default=lambda: datetime.now(timezone.utc))
