from fastapi import APIRouter
from .auth_api import auth_router

v1_api_router = APIRouter()


v1_api_router.include_router(auth_router, tags = ["Auth router"])