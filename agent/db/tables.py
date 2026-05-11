from sqlalchemy import (
    Column, String, Integer, Float, DateTime
)

from .base import Base



class Users(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, autoincrement=True , index = True)
    email = Column(String , unique=True , index = True)
    password = Column(String , nullable = False)






class Events(Base):
    __tablename__ = "events"

    id = Column(Integer, primary_key=True, autoincrement=True , index = True)
    user = Column(Integer , nullable = False)
    event_id  = Column(String)
    timestamp = Column(DateTime(timezone=True) , index = True)
    category = Column(String , index = True)
    action = Column(String)
    outcome = Column(String)
    severity = Column(String , index = True)
    collector = Column(String)
    host_hostname = Column(String)
    host_os = Column(String)
    user_name = Column(String , index = True)
    file_path = Column(String , index = True)
    file_sha256 = Column(String , index = True)
    process_name = Column(String , index = True)
    process_pid = Column(Integer)
    net_src_ip = Column(String)
    net_dst_ip = Column(String)
    net_dst_port = Column(Integer)
    risk_score = Column(Float)
    mitre_technique = Column(String)
    raw_log = Column(String)
    payload = Column(String)