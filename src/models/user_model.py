from sqlalchemy import Boolean, Column,Integer, String
from db.base import Base




class Users(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String)
    email = Column(String , unique = True , nullable = False)
    password = Column(String , nullable = False)
    role = Column(String , nullable = False)
    is_active = Column(Boolean , default = True)