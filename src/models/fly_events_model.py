from sqlalchemy import Column, Integer, BigInteger, String, Boolean, TIMESTAMP
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


class FlyEvents(Base):
    __tablename__ = "fly_events"

    id = Column(BigInteger, primary_key=True, autoincrement=True, index=True)
    agent_name = Column(String, nullable=False, index=True)

    engine = Column(String)                 # "fly"
    server = Column(String)                 # "fly"
    backend = Column(String, index=True)    # cli | api
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
    exe_path = Column(String)               # flyctl path (cli backend)
    service_name = Column(String)
    auth_method = Column(String)
    inspect_error = Column(String)
    system_resources = Column(JSONB)

    # identity
    target_name = Column(String, index=True)
    db_host = Column(String)
    db_port = Column(Integer)
    db_version = Column(String)             # flyctl version / "machines-api"

    # promoted metrics
    apps_total = Column(Integer)
    machines_up = Column(Integer)
    machines_down = Column(Integer)
    regions = Column(Integer)

    # sections
    connectivity_version = Column(JSONB)
    apps = Column(JSONB)
    machines = Column(JSONB)
    releases = Column(JSONB)
    volumes_ips = Column(JSONB)
    metrics_section = Column(JSONB)
    health_summary = Column(JSONB)

    issues = Column(JSONB)
    details = Column(JSONB)

    timestamp = Column(ForceDateTime)
    ingested_at = Column(TIMESTAMP(timezone=True), nullable=False,
                         default=lambda: datetime.now(timezone.utc))
