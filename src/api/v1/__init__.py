from fastapi import APIRouter
from .auth_api import auth_router
from .agent_management_api import agent_management_router
from .agent_visualisation_api import agent_visualisation_router

v1_api_router = APIRouter(prefix = "/v1")


v1_api_router.include_router(auth_router, tags = ["Auth router"])
v1_api_router.include_router(agent_management_router, tags = ["Agent Management router"])
v1_api_router.include_router(agent_visualisation_router, tags = ["Agent Visualisation router"])