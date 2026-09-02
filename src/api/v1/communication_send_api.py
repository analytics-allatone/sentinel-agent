"""
communication_send_api.py
=========================
Routes each CommunicationChannel row to the matching sender in notifier.py.

  type -> kind -> notifier function
  email    -> send_gmail          (recipient = value)
  outlook  -> send_outlook        (recipient = value)
  whatsapp -> send_whatsapp       (phone = value)
  sms      -> send_sms            (phone = value)
  slack    -> send_slack          (webhook url = value)
  discord  -> send_discord        (webhook url = value)
  teams    -> send_teams          (webhook url = value)
  telegram -> send_telegram       (bot:chat = value)

Endpoints:
  GET  /communication/test-config
  POST /communication/send
"""

from typing import Optional, List

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.future import select
from sqlalchemy.ext.asyncio import AsyncSession

from db.db import get_async_db
from models.user_model import CommunicationChannel
from schemas.v1.standard_schema import standard_success_response

import notifier

communication_send_router = APIRouter()

# EDIT the left side to match EXACTLY what your DB `type` column stores.
TYPE_MAP = {
    "email": "email", "Email": "email", "gmail": "email", "Gmail": "email",
    "outlook": "outlook", "Outlook": "outlook",
    "whatsapp": "whatsapp", "WhatsApp": "whatsapp",
    "sms": "sms", "SMS": "sms",
    "slack": "slack", "Slack": "slack",
    "discord": "discord", "Discord": "discord",
    "teams": "teams", "Microsoft Teams": "teams", "MicrosoftTeams": "teams",
    "telegram": "telegram", "Telegram": "telegram",
}

# kind -> (readiness check, is it an email-style subject+body sender?)
EMAIL_KINDS = {"email", "outlook"}
WEBHOOK_KINDS = {"slack", "discord", "teams", "telegram"}   # need no sender creds

READY_CHECK = {
    "email": notifier.gmail_ready,
    "outlook": notifier.outlook_ready,
    "whatsapp": notifier.whatsapp_ready,
    "sms": notifier.sms_ready,
}


class SendRequest(BaseModel):
    title: str
    message: str
    severity: str = "high"
    types: Optional[List[str]] = None   # restrict to these DB `type` values; omit = all


def _text(title, severity, message) -> str:
    return f"[{severity.upper()}] {title}\n\n{message}"


def _ready(kind: str) -> bool:
    if kind in WEBHOOK_KINDS:
        return True
    check = READY_CHECK.get(kind)
    return bool(check and check())


@communication_send_router.get("/test-config")
async def test_config(db: AsyncSession = Depends(get_async_db)):
    rows = (await db.execute(select(CommunicationChannel))).scalars().all()
    out = []
    for ch in rows:
        kind = TYPE_MAP.get(ch.type, "unknown")
        ready = _ready(kind)
        note = ""
        if not ready:
            note = ("type not mapped in TYPE_MAP" if kind == "unknown"
                    else f"{kind} sender not configured in .env")
        out.append({"id": ch.id, "name": ch.name, "type": ch.type,
                    "kind": kind, "ready": ready, "note": note})
    return standard_success_response(data={"channels": out},
                                     message="Channel send-readiness")


@communication_send_router.post("/send")
async def send(req: SendRequest, db: AsyncSession = Depends(get_async_db)):
    rows = (await db.execute(select(CommunicationChannel))).scalars().all()
    if req.types:
        wanted = set(req.types)
        rows = [r for r in rows if r.type in wanted]

    text = _text(req.title, req.severity, req.message)
    subject = f"[{req.severity.upper()}] {req.title}"
    results = []

    for ch in rows:
        kind = TYPE_MAP.get(ch.type, "unknown")
        try:
            if kind == "email":
                await notifier.send_gmail(ch.value, subject, text)
            elif kind == "outlook":
                await notifier.send_outlook(ch.value, subject, text)
            elif kind == "whatsapp":
                await notifier.send_whatsapp(ch.value, text)
            elif kind == "sms":
                await notifier.send_sms(ch.value, text)
            elif kind == "slack":
                await notifier.send_slack(ch.value, text)
            elif kind == "discord":
                await notifier.send_discord(ch.value, text)
            # elif kind == "teams":
            #     await notifier.send_teams(ch.value, text)
            
            elif kind == "teams":
                await notifier.send_teams_graph(ch.value, text)
            elif kind == "telegram":
                await notifier.send_telegram(ch.value, text)
            else:
                results.append({"id": ch.id, "name": ch.name, "type": ch.type,
                                "status": "not_mapped"})
                continue
            status = "ok"
        except Exception as e:
            status = f"error: {e}"
        results.append({"id": ch.id, "name": ch.name, "type": ch.type, "status": status})

    delivered = [r for r in results if r["status"] == "ok"]
    return standard_success_response(
        data={"sent": len(delivered), "total": len(results), "results": results},
        message="Send attempted")