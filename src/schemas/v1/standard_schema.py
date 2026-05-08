from typing import Any, Generic, TypeVar, Optional
from pydantic import BaseModel

T = TypeVar("T")

class standard_success_response(BaseModel, Generic[T]):
    status: Optional[str] = "success"
    message: str
    data: Optional[T] = None
    
    

class standard_error_response(BaseModel):
    status : Optional[str] = "error"
    message : str
    data : Optional[Any] = None