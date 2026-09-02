import re
from io import BytesIO

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from db.db import get_async_db
from auth.jwt_auth import verify_token
from models.agent_model import Agents
from schemas.v1.soc2_fleet_schema import SOC2FleetPdfRequest
from schemas.v1.soc2_pdf_report import build_fleet_soc2_pdf

from api.v1.agent_report_api import (
    soc2_auth_report, soc2_file_report, soc2_network_report,
    soc2_process_report, soc2_usb_report,
)

soc2_fleet_pdf_router = APIRouter()

_REPORT_FNS = (
    ("auth", soc2_auth_report), ("file", soc2_file_report),
    ("network", soc2_network_report), ("process", soc2_process_report),
    ("usb", soc2_usb_report),
)


async def _select_agents(db: AsyncSession, req: SOC2FleetPdfRequest):
    q = select(Agents)
    conds = []
    if req.agent_ids:
        conds.append(Agents.id.in_(req.agent_ids))
    if req.agent_names:
        conds.append(Agents.agent_name.in_([n.strip() for n in req.agent_names]))
    if conds:
        # match either list (union) if both provided
        from sqlalchemy import or_
        q = q.where(or_(*conds))
    q = q.order_by(Agents.agent_name.asc())
    agents = (await db.execute(q)).scalars().all()
    if not agents:
        raise HTTPException(status_code=404, detail="No matching agents found.")
    return agents


@soc2_fleet_pdf_router.post("/fleet-pdf")
async def generate_fleet_soc2_pdf(
    req: SOC2FleetPdfRequest,
    db: AsyncSession = Depends(get_async_db),
    claims: dict = Depends(verify_token),
):
    agents = await _select_agents(db, req)
    a, b, bucket = req.from_dt, req.to_dt, req.bucket

    agents_data = []
    # print(agents)
    for agent in agents:
        common = dict(from_dt=a, to_dt=b, agent_name=agent.agent_name, bucket=bucket, db=db , _claims=claims)
        reports = {}
        for key, fn in _REPORT_FNS:
            try:
                result = await fn(**common)
                reports[key] = getattr(result, "data", None)
            except Exception as e:
                reports[key] = None
                print(f"[FLEET PDF] agent {agent.id} {key} failed: {e}")
        agents_data.append({
            "agent": {c.name: getattr(agent, c.name) for c in agent.__table__.columns},
            "reports": reports,
        })

    window = {"start": a.strftime("%Y-%m-%d %H:%M"), "end": b.strftime("%Y-%m-%d %H:%M")}
    pdf_bytes = build_fleet_soc2_pdf(
        agents_data=agents_data,
        window=window,
        # generated_by= #claims.get("email", "system"),
    )

    filename = f"soc2_fleet_{a:%Y%m%d}_{b:%Y%m%d}.pdf"
    return StreamingResponse(
        BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
