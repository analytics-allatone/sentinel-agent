from sqlalchemy import Boolean, Column,Integer, String, TIMESTAMP , Text
from datetime import datetime , timezone
from db.base import Base




class Machines(Base):
    __tablename__ = "machines"


    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String , nullable = False)
    host = Column(String , nullable = False , unique = True)
    port = Column(Integer , default = 22)
    username = Column(String , nullable = False)

    auth_type = Column(String , nullable = False)
    private_key = Column(Text, nullable=True)
    password = Column(Text, nullable=True) 

    cloud_provider = Column(String, nullable=True)
    region = Column(String, nullable=True)
    os_type = Column(String, nullable=True)

    status = Column(String, default="active")

    created_at = Column(TIMESTAMP, nullable=False, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))
    last_updated_at = Column(TIMESTAMP, nullable=False, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None), onupdate=lambda: datetime.now(timezone.utc).replace(tzinfo=None))
