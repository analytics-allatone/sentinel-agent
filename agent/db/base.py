from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.ext.asyncio import AsyncAttrs

class Base(AsyncAttrs, DeclarativeBase):
    """
    Base class for all SQLAlchemy ORM models with asynchronous capabilities.

    This class combines SQLAlchemy's `DeclarativeBase` for model declaration and `AsyncAttrs` 
    to enable support for asynchronous attribute access in an async context.

    All ORM models should inherit from this class to ensure consistency and compatibility
    with SQLAlchemy's async ORM features.

    Example:
        class User(Base):
            __tablename__ = "users"
            id = Column(Integer, primary_key=True)
            name = Column(String)

    Inherits:
        AsyncAttrs: Provides support for asynchronous operations.
        DeclarativeBase: Enables declarative model definitions.
    """
    pass 