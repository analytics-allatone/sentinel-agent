from fastapi import APIRouter
from .auth_api import auth_router
from .machine_management_api import machine_management_router

v1_api_router = APIRouter()


v1_api_router.include_router(auth_router, tags = ["Auth router"])
v1_api_router.include_router(machine_management_router, tags = ["Machine Management router"])