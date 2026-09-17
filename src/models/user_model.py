from sqlalchemy import Boolean, Column,Integer, String
from db.base import Base
from sqlalchemy.dialects.postgresql import JSONB



class Users(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String)
    email = Column(String , unique = True , nullable = False)
    password = Column(String , nullable = False)
    role = Column(String , nullable = False)
    two_fa_enabled = Column(Boolean , default = False)
    two_fa_secret = Column(String)
    is_active = Column(Boolean , default = True)



class CommunicationChannel(Base):
    __tablename__="communication_channels"
    id = Column(Integer, primary_key=True, autoincrement=True)
    name=Column(String , unique = True)
    type=Column(String,nullable=False)
    value=Column(String,nullable=False)
