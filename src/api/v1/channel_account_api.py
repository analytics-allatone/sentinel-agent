import os
import json
from typing import Optional
import httpx
import time

from cryptography.fernet import Fernet
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form
from pydantic import BaseModel
from sqlalchemy.future import select
from sqlalchemy.ext.asyncio import AsyncSession

from db.db import get_async_db
from models.channel_account_model import ChannelAccount
from models.user_model import CommunicationChannel   # your existing table (recipients + webhooks)
import channel_providers as providers

channel_account_router = APIRouter()
static_key=b"3ro6WjqwAl5LUvZSJ06fh9y2Po0pltR8Z-_8xzKQTGc="
_fernet = Fernet(static_key)
# _fernet = Fernet(os.environ["CHANNEL_ENC_KEY"].encode())


def _encrypt(d: dict) -> str:
    return _fernet.encrypt(json.dumps(d).encode()).decode()


def _decrypt(s: str) -> dict:
    return json.loads(_fernet.decrypt(s.encode()).decode())


class AddAccountRequest(BaseModel):
    label: str
    channel_type: str          # gmail | outlook365 | teams | telegram | whatsapp | sms | jira
    credentials: dict


class SendRequest(BaseModel):
    recipient: Optional[str] = None                # raw destination value
    communication_channel_id: Optional[int] = None  # OR: pick a saved recipient by id
    subject: str = ""
    body: str = "message"


def _check_fields(channel_type: str, creds: dict):
    required = providers.REQUIRED_FIELDS.get(channel_type)
    if required is None:
        raise HTTPException(status_code=400,
                            detail=f"Unknown channel_type. Use one of {list(providers.REQUIRED_FIELDS)}")
    missing = [f for f in required if not creds.get(f)]
    if missing:
        raise HTTPException(status_code=400, detail=f"Missing credential fields: {missing}")


# ═══════════════════════ ACCOUNT-BASED CHANNELS ═════════════════════════

@channel_account_router.post("/channel-accounts")
async def add_channel_account(req: AddAccountRequest, db: AsyncSession = Depends(get_async_db)):
    _check_fields(req.channel_type, req.credentials)

    verify_fn = providers.VERIFY[req.channel_type]
    try:
        identifier = await verify_fn(req.credentials)   # real live check
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"Credential verification failed: {e}")

    row = ChannelAccount(
        label=req.label, channel_type=req.channel_type, identifier=identifier,
        credentials_enc=_encrypt(req.credentials), is_verified=True, is_active=True,
    )
    db.add(row)
    await db.commit()
    await db.refresh(row)
    return {"id": row.id, "label": row.label, "channel_type": row.channel_type,
            "identifier": row.identifier, "is_verified": row.is_verified}


@channel_account_router.get("/channel-accounts")
async def list_channel_accounts(db: AsyncSession = Depends(get_async_db)):
    rows = (await db.execute(select(ChannelAccount))).scalars().all()
    return {"accounts": [
        {"id": r.id, "label": r.label, "channel_type": r.channel_type,
         "identifier": r.identifier, "is_verified": r.is_verified, "is_active": r.is_active}
        for r in rows
    ]}


@channel_account_router.delete("/channel-accounts/{account_id}")
async def delete_channel_account(account_id: int, db: AsyncSession = Depends(get_async_db)):
    row = await db.get(ChannelAccount, account_id)
    if not row:
        raise HTTPException(status_code=404, detail="Account not found.")
    await db.delete(row)
    await db.commit()
    return {"id": account_id, "deleted": True}


async def _resolve_recipient(db, req_recipient, communication_channel_id):
    dest = req_recipient
    if not dest and communication_channel_id:
        ch = await db.get(CommunicationChannel, communication_channel_id)
        if not ch:
            raise HTTPException(status_code=404, detail="Recipient channel not found.")
        dest = ch.value
    if not dest:
        raise HTTPException(status_code=400,
                            detail="Provide either 'recipient' or 'communication_channel_id'.")
    return dest


@channel_account_router.post("/channel-accounts/{account_id}/send")
async def send_via_account(account_id: int, req: SendRequest,
                           db: AsyncSession = Depends(get_async_db)):
    account = await db.get(ChannelAccount, account_id)
    if not account or not account.is_active:
        raise HTTPException(status_code=404, detail="Account not found or inactive.")

    recipient = await _resolve_recipient(db, req.recipient, req.communication_channel_id)
    creds = _decrypt(account.credentials_enc)
    send_fn = providers.SEND[account.channel_type]
    try:
        await send_fn(creds, recipient, req.subject, req.body)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Send failed: {e}")

    return {"sent_from": account.identifier, "sent_to": recipient,
            "channel_type": account.channel_type, "status": "ok"}


@channel_account_router.post("/channel-accounts/{account_id}/send-file")
async def send_file_via_account(
    account_id: int,
    subject: str = Form(""),
    body: str = Form("message"),
    recipient: Optional[str] = Form(None),
    communication_channel_id: Optional[int] = Form(None),
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_async_db),
):
    account = await db.get(ChannelAccount, account_id)
    if not account or not account.is_active:
        raise HTTPException(status_code=404, detail="Account not found or inactive.")

    send_fn = providers.SEND_WITH_ATTACHMENT.get(account.channel_type)
    if not send_fn:
        raise HTTPException(
            status_code=400,
            detail=f"'{account.channel_type}' does not support file attachments. "
                   f"Supported: {list(providers.SEND_WITH_ATTACHMENT)}")

    dest = await _resolve_recipient(db, recipient, communication_channel_id)
    file_bytes = await file.read()
    creds = _decrypt(account.credentials_enc)
    try:
        await send_fn(creds, dest, subject, body, file_bytes, file.filename)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Send failed: {e}")

    return {"sent_from": account.identifier, "sent_to": dest,
            "channel_type": account.channel_type, "attachment": file.filename, "status": "ok"}


# # ═══════════════════ WEBHOOK-ONLY CHANNELS: Slack / Discord ═════════════
# No ChannelAccount needed — the CommunicationChannel row's `value` (the
# webhook URL) is the entire credential. Hit directly by that row's id.

class WebhookSendRequest(BaseModel):
    subject: str = ""
    body: str = "message"


@channel_account_router.post("/communication-channels/{channel_id}/send-webhook")
async def send_via_webhook(channel_id: int, req: WebhookSendRequest,
                           db: AsyncSession = Depends(get_async_db)):
    ch = await db.get(CommunicationChannel, channel_id)
    if not ch:
        raise HTTPException(status_code=404, detail="Channel not found.")

    text = f"{req.subject}\n\n{req.body}" if req.subject else req.body
    ch_type = (ch.type or "").lower()

    try:
        if ch_type in ("slack",):
            await providers.send_slack_webhook(ch.value, text)
        elif ch_type in ("discord",):
            await providers.send_discord_webhook(ch.value, text)
        else:
            raise HTTPException(status_code=400,
                                detail=f"Channel type '{ch.type}' is not a webhook channel. "
                                       f"Use /channel-accounts for account-based channels.")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Send failed: {e}")

    return {"sent_to": ch.name, "channel_type": ch.type, "status": "ok"}
# ═══════════ TEAMS LOGIN — IN-APP, no separate script to run ════════════

_pending_logins: dict = {}   # login_id -> {tenant_id, client_id, label, device_code, interval, expires_at}
 
 
class StartTeamsLoginRequest(BaseModel):
    label: str
    tenant_id: str
    client_id: str
 
 
class CompleteTeamsLoginRequest(BaseModel):
    login_id: str
 
 
@channel_account_router.post("/teams-login/start")
async def start_teams_login(req: StartTeamsLoginRequest):
    url = f"https://login.microsoftonline.com/{req.tenant_id}/oauth2/v2.0/devicecode"
    async with httpx.AsyncClient(timeout=20) as c:
        r = await c.post(url, data={
            "client_id": req.client_id,
            "scope": "offline_access ChannelMessage.Send",
        })
    if r.status_code != 200:
        raise HTTPException(status_code=400, detail=f"Could not start login: {r.text[:200]}")
    j = r.json()
 
    login_id = f"tl_{int(time.time()*1000)}"
    _pending_logins[login_id] = {
        "tenant_id": req.tenant_id, "client_id": req.client_id, "label": req.label,
        "device_code": j["device_code"],
        "interval": j.get("interval", 5),
        "expires_at": time.time() + j.get("expires_in", 900),
    }
    return {
        "login_id": login_id,
        "verification_url": j["verification_uri"],   # e.g. https://microsoft.com/devicelogin
        "user_code": j["user_code"],                  # the code the admin types there
        "message": j.get("message", f"Go to {j['verification_uri']} and enter {j['user_code']}"),
        "expires_in": j.get("expires_in", 900),
        "poll_interval": j.get("interval", 5),
    }
 
 
@channel_account_router.post("/teams-login/complete")
async def complete_teams_login(req: CompleteTeamsLoginRequest, db: AsyncSession = Depends(get_async_db)):
    pending = _pending_logins.get(req.login_id)
    if not pending:
        raise HTTPException(status_code=404, detail="Unknown or expired login_id. Call /teams-login/start again.")
    if time.time() > pending["expires_at"]:
        del _pending_logins[req.login_id]
        raise HTTPException(status_code=408, detail="Login expired before the admin signed in. Start again.")
 
    url = f"https://login.microsoftonline.com/{pending['tenant_id']}/oauth2/v2.0/token"
    data = {
        "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
        "client_id": pending["client_id"],
        "device_code": pending["device_code"],
    }
    async with httpx.AsyncClient(timeout=20) as c:
        r = await c.post(url, data=data)
    j = r.json()
 
    if r.status_code != 200:
        err = j.get("error")
        if err == "authorization_pending":
            return {"status": "pending", "detail": "Admin hasn't finished signing in yet — keep polling."}
        if err == "authorization_declined":
            del _pending_logins[req.login_id]
            raise HTTPException(status_code=400, detail="Sign-in was declined.")
        if err == "expired_token":
            del _pending_logins[req.login_id]
            raise HTTPException(status_code=408, detail="Login expired. Start again.")
        raise HTTPException(status_code=400, detail=j.get("error_description", "Login failed"))
 
    # Success — save the ChannelAccount right here, automatically.
    creds = {"tenant_id": pending["tenant_id"], "client_id": pending["client_id"],
            "refresh_token": j["refresh_token"]}
    try:
        identifier = await providers.verify_teams(creds)
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"Login succeeded but verification failed: {e}")
 
    row = ChannelAccount(label=pending["label"], channel_type="teams", identifier=identifier,
                         credentials_enc=_encrypt(creds), is_verified=True, is_active=True)
    db.add(row)
    await db.commit()
    await db.refresh(row)
    del _pending_logins[req.login_id]
 
    return {"status": "ok", "id": row.id, "label": row.label,
            "identifier": row.identifier, "is_verified": True} 