from sqlalchemy import Column, Integer, String, Text, Boolean, DateTime, func,UniqueConstraint

from db.base import Base


class CredentialStorage(Base):
    __tablename__ = "credential_storage"

    id = Column(Integer, primary_key=True, autoincrement=True)
    agent_name = Column(String(255), nullable=True, index=True)
    engine = Column(String(32), nullable=False, index=True)

    host = Column(String(255), nullable=False, default="127.0.0.1")
    port = Column(Integer, nullable=True)

    user_name = Column(String(255), nullable=True)
    password_enc = Column(Text, nullable=True)          # encrypted, never plaintext

    service_name = Column(String(255), nullable=True)   # oracle
    dbname = Column(String(255), nullable=True)         # mysql / postgres / mongo

    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())

     # one credential per agent + engine + host + service
    __table_args__ = (
        UniqueConstraint("agent_name", "engine", "host", "service_name",
                         name="uq_cred_agent_engine_host_service"),
    )
