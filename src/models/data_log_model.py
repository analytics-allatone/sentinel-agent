from db.base import Base
import uuid
from sqlalchemy import ( Column, Integer, BigInteger, String,
                         Text, Boolean, DateTime, Float, func,
)

from sqlalchemy.dialects.postgresql import UUID, JSONB, ARRAY




class MachineLogs(Base):
    __tablename__ = "machine_logs"

    id = Column(BigInteger, primary_key=True, autoincrement=True, index=True)

    machine_id = Column( Integer, nullable=False, index=True)

    event_id = Column(UUID(as_uuid=True), default=uuid.uuid4, unique=True, nullable=False)

    timestamp = Column(DateTime(timezone=True), nullable=False)

    ingested_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())


    category = Column(String(32), nullable=False, index=True)

    action = Column(String(64), nullable=False)

    outcome = Column(String(32), nullable=False)

    severity = Column(String(16), nullable=False, index=True)

    tags = Column(ARRAY(String), nullable=True)


    collector = Column(String(128),nullable=True)

    raw_log = Column(Text, nullable=True)


    host = Column(JSONB,nullable=False)

    file = Column(JSONB,nullable=True)

    user = Column(JSONB,nullable=True)

    process = Column(JSONB,nullable=True)

    network = Column(JSONB,nullable=True)

    auth = Column(JSONB,nullable=True)


    file_path = Column(String, nullable=True)

    file_sha256 = Column(String(64),nullable=True,index=True)

    process_name = Column( String(256), nullable=True)

    process_pid = Column(Integer,nullable=True,index=True)

    process_sha256 = Column(String(64),nullable=True)

    username = Column(String(128),nullable=True,index=True)


    net_src_ip = Column(String(64),nullable=True,index=True)

    net_src_port = Column(Integer,nullable=True)

    net_dst_ip = Column(String(64),nullable=True,index=True)

    net_dst_port = Column(Integer,nullable=True)

    net_protocol = Column(String(32),nullable=True)


    risk_score = Column(Float,nullable=True)

    anomaly = Column(Boolean,default = False)

    ioc_match = Column(String,nullable=True)

    mitre_tactic = Column(String(128),nullable=True)

    mitre_technique = Column(String(64),nullable=True)

    notes = Column(Text,nullable=True)