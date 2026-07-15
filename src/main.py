from contextlib import asynccontextmanager
import asyncio

import os
from fastapi import FastAPI, HTTPException, Query , Request , APIRouter , Depends
from fastapi.responses import PlainTextResponse , FileResponse
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from api.v1 import v1_api_router
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from db.db import create_db_and_tables , get_async_db
import sys
from bots.mqtt_consumer import mqtt_background_consumer
from models.agent_model import AgentGroups, Agents


worker_task = None


@asynccontextmanager
async def lifespan(app: FastAPI):

    global worker_task

    # DATABASE STARTUP
    await create_db_and_tables()


    worker_task = asyncio.create_task(mqtt_background_consumer())

    print("Application Started")

    yield

    # SHUTDOWN LOGIC
    print("Application Shutting Down...")
    worker_task.cancel()


app = FastAPI(
    lifespan=lifespan
)


HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPTS_DIR = os.path.join(HERE, "scripts")
BINARIES_DIR = os.path.join(HERE, "binaries")
DOWNLOADABLES_DIR = os.path.join(HERE , "downloadables")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


app.include_router(v1_api_router , prefix="/api")



@app.get("/api/v1/scripts/{name}", response_class=PlainTextResponse)
def install_ps1(name:str , request : Request , db: AsyncSession = Depends(get_async_db)):
    text = open(os.path.join(SCRIPTS_DIR, name), encoding="utf-8").read()
    base = str(request.base_url).rstrip("/")          # e.g. https://agents.example.com
    return text.replace("https://YOUR_HOST", base)



@app.get("/api/v1/binaries/{name}", response_class=FileResponse)
async def get_binary(
    name: str,
    agent_name: str = Query(...),                    # required
    group_name: str = Query(default=None),           # optional
    db: AsyncSession = Depends(get_async_db)
):
    safe = os.path.basename(name)
    path = os.path.join(BINARIES_DIR, safe)
    if not os.path.isfile(path):
        raise HTTPException(status_code=404, detail=f"Binary '{safe}' not found")
    group_id = None
    if group_name:
        group_result = await db.execute(select(AgentGroups).where(AgentGroups.group_name == group_name))
        existing_groups = group_result.scalars().first()
        if existing_groups:
            group_id = existing_groups.id
        else:
            new_group = AgentGroups(group_name = group_name)
            db.add(new_group)
            await db.commit()
            await db.refresh(new_group)
            group_id = new_group.id
    agent_exist_result = await db.execute(select(Agents).where(Agents.agent_name == agent_name))
    existing_agent = agent_exist_result.scalars().first()
    if existing_agent:
        if existing_agent.mac_address:
            raise HTTPException(status_code=409, detail=f"Agent already installed with this name , use another name")
    this_agent = Agents(agent_name = agent_name)
    if group_id :
        this_agent.group_id = group_id
    db.add(this_agent)
    await db.commit()
    return FileResponse(path, media_type="application/octet-stream", filename=safe)





@app.get("/api/v1/nssm" , response_class=FileResponse)
async def getNssm():
    print("here")
    safe = os.path.basename("nssm-2.24.zip")
    path = os.path.join(DOWNLOADABLES_DIR, safe)
    print(path)
    if not os.path.isfile(path):
        raise HTTPException(status_code=404, detail=f"NSSM '{safe}' not found")

    return FileResponse(path, media_type="application/octet-stream", filename=safe)




@app.get("/healthCheck")
def health_check():
    return {
        "status": "Success"
    }




def resource_path(rel):
    if getattr(sys, "frozen", False):
        base = sys._MEIPASS          # PyInstaller's bundled-files location
    else:
        base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, rel)

FRONTEND_DIR = resource_path(os.path.join("frontend", "build"))
STATIC_DIR = os.path.join(FRONTEND_DIR, "static")

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# FRONTEND_DIR = os.path.join(BASE_DIR, "frontend", "build")   # CRA -> build
# STATIC_DIR = os.path.join(FRONTEND_DIR, "static")            # CRA -> static

if os.path.isdir(STATIC_DIR):
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
else:
    print(f"WARNING: frontend build not found at {FRONTEND_DIR}. Run `npm run build`.")

@app.get("/{full_path:path}")
async def serve_spa(full_path: str):
    # Serve real root-level files (favicon.ico, manifest.json, logo192.png, etc.)
    candidate = os.path.normpath(os.path.join(FRONTEND_DIR, full_path))
    if full_path and candidate.startswith(FRONTEND_DIR) and os.path.isfile(candidate):
        return FileResponse(candidate)
    # Fall back to index.html for client-side routing
    index_file = os.path.join(FRONTEND_DIR, "index.html")
    if os.path.isfile(index_file):
        return FileResponse(index_file)
    return {"detail": "Frontend not built yet. Run `npm run build` in the frontend folder."}