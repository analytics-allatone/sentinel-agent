from sqlalchemy import Column, Integer, BigInteger, String, DateTime, func
from db.base import Base   

class SecurityAlerts(Base):
    __tablename__ = "security_alerts"

    id          = Column(BigInteger, primary_key=True, autoincrement=True)
    rule_id     = Column(String)
    severity    = Column(Integer)
    agent_name  = Column(String)
    entity      = Column(String)
    event_count = Column(BigInteger)
    first_seen  = Column(DateTime(timezone=True))
    last_seen   = Column(DateTime(timezone=True))
    detail      = Column(String)
    technique   = Column(String)
    phase       = Column(String)
    status      = Column(String)
    created_at  = Column(DateTime(timezone=True), server_default=func.now())
