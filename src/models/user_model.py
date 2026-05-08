from sqlalchemy import Boolean, Column,Integer, String, TIMESTAMP
from datetime import datetime , timezone
from db.base import Base




class Users(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, autoincrement=True)
    first_name = Column(String)
    last_name = Column(String)
    email = Column(String , nullable = False , index = True)
    country_code = Column(String , nullable = False)
    phone_number = Column(String , nullable = False)
    password = Column(String , nullable = False)
    created_at = Column(TIMESTAMP, nullable=False, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))
    last_updated_at = Column(TIMESTAMP, nullable=False, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None), onupdate=lambda: datetime.now(timezone.utc).replace(tzinfo=None))


