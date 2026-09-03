
import os
import ssl
import asyncio
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
from typing import Optional
from urllib.parse import urlparse, parse_qs, unquote

import httpx


# ─────────────────────────── EMAIL: Gmail (SMTP) ───────────────────────────
def gmail_ready() -> bool:
    return bool(os.getenv("GMAIL_USER") and os.getenv("GMAIL_APP_PASSWORD"))


def _smtp_send(host, port, user, password, sender, recipient, subject, body,
               pdf_bytes: Optional[bytes] = None, pdf_filename: str = "report.pdf"):
    if pdf_bytes:
        msg = MIMEMultipart()
        msg.attach(MIMEText(body, "plain", "utf-8"))
        part = MIMEApplication(pdf_bytes, _subtype="pdf")
        part.add_header("Content-Disposition", "attachment", filename=pdf_filename)
        msg.attach(part)
    else:
        msg = MIMEText(body, "plain", "utf-8")
    msg["Subject"] = subject
    msg["From"] = sender
    msg["To"] = recipient
    with smtplib.SMTP(host, port, timeout=20) as s:
        s.starttls(context=ssl.create_default_context())
        s.login(user, password)
        s.send_message(msg)


async def send_gmail(recipient: str, subject: str, body: str,
                     pdf_bytes: Optional[bytes] = None, pdf_filename: str = "report.pdf") -> None:
    if not gmail_ready():
        raise RuntimeError("Gmail not configured (GMAIL_USER / GMAIL_APP_PASSWORD)")
    await asyncio.to_thread(_smtp_send, "smtp.gmail.com", 587,
                            os.getenv("GMAIL_USER"), os.getenv("GMAIL_APP_PASSWORD"),
                            os.getenv("GMAIL_FROM", os.getenv("GMAIL_USER")),
                            recipient, subject, body, pdf_bytes, pdf_filename)


# ────────────────── EMAIL: Outlook (company M365, SMTP user+password) ──────

def outlook_ready() -> bool:
    return bool(os.getenv("OUTLOOK_USER") and os.getenv("OUTLOOK_PASSWORD"))


async def send_outlook(recipient: str, subject: str, body: str,
                       pdf_bytes: Optional[bytes] = None, pdf_filename: str = "report.pdf") -> None:
    if not outlook_ready():
        raise RuntimeError("Outlook not configured (OUTLOOK_USER / OUTLOOK_PASSWORD)")
    await asyncio.to_thread(
        _smtp_send, "smtp.office365.com", 587,
        os.getenv("OUTLOOK_USER"), os.getenv("OUTLOOK_PASSWORD"),
        os.getenv("OUTLOOK_FROM", os.getenv("OUTLOOK_USER")),
        recipient, subject, body, pdf_bytes, pdf_filename,
    )


async def _twilio_post(sid: str, token: str, data: dict):
    """POST to Twilio and raise its ACTUAL error message (not just 'HTTP 422'),
    so failures are debuggable without opening the Twilio console."""
    url = f"https://api.twilio.com/2010-04-01/Accounts/{sid}/Messages.json"
    async with httpx.AsyncClient(timeout=20) as c:
        r = await c.post(url, data=data, auth=(sid, token))
        if r.status_code >= 400:
            try:
                j = r.json()
                raise RuntimeError(f"Twilio {r.status_code}: {j.get('message')} "
                                   f"(code {j.get('code')}) — {j.get('more_info')}")
            except ValueError:
                r.raise_for_status()


# ─────────────────────── WhatsApp via Twilio Sandbox ───────────────────────
# # def whatsapp_ready() -> bool:
# #     return bool(os.getenv("WA_TOKEN") and os.getenv("WA_PHONE_NUMBER_ID"))
 
 
# # def _wa_payload(to: str, text: str) -> dict:
# #     template = os.getenv("WA_TEMPLATE_NAME")
# #     if template:
# #         # business-initiated / outside 24h window -> approved template required
# #         return {"messaging_product": "whatsapp", "to": to, "type": "template",
# #                 "template": {"name": template,
# #                              "language": {"code": os.getenv("WA_LANG", "en_US")},
# #                              "components": [{"type": "body",
# #                                              "parameters": [{"type": "text", "text": text[:1000]}]}]}}
# #     # free-form text (only delivers inside the 24h customer-service window)
# #     return {"messaging_product": "whatsapp", "to": to, "type": "text",
# #             "text": {"body": text[:4000]}}
 
 
# # async def send_whatsapp(recipient: str, text: str) -> None:
# #     if not whatsapp_ready():
# #         raise RuntimeError("WhatsApp not configured (WA_TOKEN / WA_PHONE_NUMBER_ID)")
# #     ver = os.getenv("WA_GRAPH_VERSION", "v22.0")
# #     url = f"https://graph.facebook.com/{ver}/{os.getenv('WA_PHONE_NUMBER_ID')}/messages"
# #     headers = {"Authorization": f"Bearer {os.getenv('WA_TOKEN')}"}
# #     async with httpx.AsyncClient(timeout=20) as c:
# #         r = await c.post(url, headers=headers, json=_wa_payload(recipient, text))
# #         r.raise_for_status()


def whatsapp_ready() -> bool:
    return bool(os.getenv("TWILIO_ACCOUNT_SID") and os.getenv("TWILIO_AUTH_TOKEN")
                and os.getenv("TWILIO_WHATSAPP_FROM"))


async def send_whatsapp(recipient: str, text: str, *, title: str = None, severity: str = None) -> None:
    if not whatsapp_ready():
        raise RuntimeError("WhatsApp not configured (TWILIO_ACCOUNT_SID / TWILIO_AUTH_TOKEN / TWILIO_WHATSAPP_FROM)")
    sid = os.getenv("TWILIO_ACCOUNT_SID")
    from_num = os.getenv("TWILIO_WHATSAPP_FROM")
    content_sid = os.getenv("TWILIO_WA_CONTENT_SID")

    data = {
        "From": f"whatsapp:{from_num}" if not from_num.startswith("whatsapp:") else from_num,
        "To": f"whatsapp:{recipient}" if not recipient.startswith("whatsapp:") else recipient,
    }
    if content_sid:
        # Template mode. Fill {{1}}, {{2}}, ... via ContentVariables to match
        # YOUR template's body (e.g. "Security Alert: {{1}} / Severity: {{2}}").
        data["ContentSid"] = content_sid
        import json as _json
        variables = {}
        if title is not None:
            variables["1"] = str(title)[:250]
        if severity is not None:
            variables["2"] = str(severity)[:250]
        if not variables:
            # fallback: single-variable template, whole text goes into {{1}}
            variables = {"1": text[:250]}
        data["ContentVariables"] = _json.dumps(variables)
    else:
        # Plain free-form text — only works if your account still allows it.
        data["Body"] = text[:1500]

    await _twilio_post(sid, os.getenv("TWILIO_AUTH_TOKEN"), data)


# ───────────────────────────── SMS (Fast2SMS) ──────────────────────────────

# # def sms_ready() -> bool:
# #     return bool(os.getenv("TWILIO_ACCOUNT_SID") and os.getenv("TWILIO_AUTH_TOKEN")
# #                 and os.getenv("TWILIO_FROM"))
 
 
# # async def send_sms(recipient: str, text: str) -> None:
# #     # Twilio. To use MSG91 instead, swap this function's URL/payload/auth.
# #     if not sms_ready():
# #         raise RuntimeError("SMS not configured (TWILIO_ACCOUNT_SID / TWILIO_AUTH_TOKEN / TWILIO_FROM)")
# #     sid = os.getenv("TWILIO_ACCOUNT_SID")
# #     url = f"https://api.twilio.com/2010-04-01/Accounts/{sid}/Messages.json"
# #     data = {"From": os.getenv("TWILIO_FROM"), "To": recipient, "Body": text[:1500]}
# #     async with httpx.AsyncClient(timeout=20) as c:
# #         r = await c.post(url, data=data, auth=(sid, os.getenv("TWILIO_AUTH_TOKEN")))
# #         r.raise_for_status()
#
# #
# # No verified-recipient restriction like Twilio trial — sends to any Indian
# # number once the account + Sender ID are approved.
# # def sms_ready() -> bool:
# #     return bool(os.getenv("MSG91_AUTH_KEY") and os.getenv("MSG91_SENDER_ID"))
 
 
# # async def send_sms(recipient: str, text: str) -> None:
# #     if not sms_ready():
# #         raise RuntimeError("SMS not configured (MSG91_AUTH_KEY / MSG91_SENDER_ID)")
# #     # MSG91 expects a bare 10-digit number (or with country code, no '+').
# #     number = recipient.lstrip("+")
# #     url = "https://api.msg91.com/api/v5/flow/"  # legacy simple-SMS endpoint below is easier for plain text:
# #     url = "https://api.msg91.com/api/v2/sendsms"
# #     headers = {"authkey": os.getenv("MSG91_AUTH_KEY"), "Content-Type": "application/json"}
# #     payload = {
# #         "sender": os.getenv("MSG91_SENDER_ID"),
# #         "route": os.getenv("MSG91_ROUTE", "4"),
# #         "country": "91",
# #         "sms": [{"message": text[:1500], "to": [number]}],
# #     }
# #     async with httpx.AsyncClient(timeout=20) as c:
# #         r = await c.post(url, headers=headers, json=payload)
# #         if r.status_code >= 400:
# #             raise RuntimeError(f"MSG91 error {r.status_code}: {r.text[:300]}")

def sms_ready() -> bool:
    return bool(os.getenv("FAST2SMS_API_KEY"))


async def send_sms(recipient: str, text: str, *, title: str = None, severity: str = None) -> None:
    if not sms_ready():
        raise RuntimeError("SMS not configured (FAST2SMS_API_KEY)")
    number = recipient.lstrip("+")
    if number.startswith("91") and len(number) == 12:
        number = number[2:]   # Fast2SMS wants the bare 10-digit Indian number

    url = "https://www.fast2sms.com/dev/bulkV2"
    headers = {"authorization": os.getenv("FAST2SMS_API_KEY"),
              "Content-Type": "application/json"}
    payload = {
        "route": "q",                 # Quick SMS: no DLT template required
        "message": text[:900],
        "language": "english",
        "flash": 0,
        "numbers": number,
    }
    async with httpx.AsyncClient(timeout=20) as c:
        r = await c.post(url, headers=headers, json=payload)
        j = {}
        try:
            j = r.json()
        except Exception:
            pass
        if r.status_code >= 400 or j.get("return") is False:
            raise RuntimeError(f"Fast2SMS error {r.status_code}: {r.text[:300]}")



# ──────────────────────── Webhooks (no credentials) ────────────────────────
async def send_slack(webhook_url: str, text: str) -> None:
    async with httpx.AsyncClient(timeout=15) as c:
        r = await c.post(webhook_url, json={"text": text})   # Slack: "text"
        r.raise_for_status()


async def send_discord(webhook_url: str, text: str,
                       pdf_bytes: Optional[bytes] = None, pdf_filename: str = "report.pdf") -> None:
    # Discord incoming webhooks support multipart file upload (Slack's do not).
    async with httpx.AsyncClient(timeout=30) as c:
        if pdf_bytes:
            files = {"file": (pdf_filename, pdf_bytes, "application/pdf")}
            r = await c.post(webhook_url, data={"content": text}, files=files)
        else:
            r = await c.post(webhook_url, json={"content": text})
        r.raise_for_status()


async def send_teams(webhook_url: str, text: str) -> None:
    payload = {
        "type": "message",
        "attachments": [
            {
                "contentType": "application/vnd.microsoft.card.adaptive",
                "content": {
                    "type": "AdaptiveCard",
                    "version": "1.4",
                    "$schema": "http://adaptivecards.io",
                    "body": [
                        {
                            "type": "TextBlock",
                            "text": "🚨 Sentinel Agent System Alert",
                            "weight": "Bolder",
                            "size": "Medium",
                            "color": "Attention"
                        },
                        {
                            "type": "TextBlock",
                            "text": text, 
                            "wrap": True
                        }
                    ]
                }
            }
        ]
    }

    async with httpx.AsyncClient(timeout=15) as c:
        r = await c.post(webhook_url, json=payload)
        r.raise_for_status()


_teams_tok = {"val": None, "exp": 0.0}


def teams_graph_ready() -> bool:
    return bool(os.getenv("MS_TEAMS_CLIENT_ID") and os.getenv("MS_TEAMS_REFRESH_TOKEN"))


def _parse_teams_link(value: str):
    """Return (team_id, channel_id) from a Teams deep-link OR from
    'team_id|channel_id'. Raises if it can't."""
    if value and value.strip().startswith("http"):
        p = urlparse(value)
        parts = p.path.split("/")
        channel_id = unquote(parts[parts.index("team") + 1]) if "team" in parts else None
        team_id = parse_qs(p.query).get("groupId", [None])[0]
    elif "|" in (value or ""):
        team_id, channel_id = value.split("|", 1)
    else:
        team_id = channel_id = None
    if not (team_id and channel_id):
        raise RuntimeError("Could not extract team-id/channel-id from the Teams value")
    return team_id, channel_id


async def _teams_token() -> str:
    import time
    if _teams_tok["val"] and time.time() < _teams_tok["exp"] - 60:
        return _teams_tok["val"]
    tenant = os.getenv("MS_TEAMS_TENANT_ID", "common")
    url = f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
    data = {
        "client_id": os.getenv("MS_TEAMS_CLIENT_ID"),
        "grant_type": "refresh_token",
        "refresh_token": os.getenv("MS_TEAMS_REFRESH_TOKEN"),
        "scope": "offline_access ChannelMessage.Send",
    }
    if os.getenv("MS_TEAMS_CLIENT_SECRET"):
        data["client_secret"] = os.getenv("MS_TEAMS_CLIENT_SECRET")
    async with httpx.AsyncClient(timeout=20) as c:
        r = await c.post(url, data=data)
        r.raise_for_status()
        j = r.json()
    _teams_tok["val"] = j["access_token"]
    _teams_tok["exp"] = time.time() + int(j.get("expires_in", 3600))
    return _teams_tok["val"]


async def send_teams_graph(value: str, text: str) -> None:
    if not teams_graph_ready():
        raise RuntimeError("Teams Graph not configured (MS_TEAMS_CLIENT_ID / MS_TEAMS_REFRESH_TOKEN)")
    team_id, channel_id = _parse_teams_link(value)
    token = await _teams_token()
    url = f"https://graph.microsoft.com/v1.0/teams/{team_id}/channels/{channel_id}/messages"
    body = {"body": {"content": text}}
    async with httpx.AsyncClient(timeout=20) as c:
        r = await c.post(url, headers={"Authorization": f"Bearer {token}"}, json=body)
        r.raise_for_status()   # 201 Created on success


async def send_telegram(value: str, text: str,
                        pdf_bytes: Optional[bytes] = None, pdf_filename: str = "report.pdf") -> None:
    # value = "<bot_token>:<chat_id>"  (bot token itself contains ':')
    token, chat_id = value.rsplit(":", 1)
    async with httpx.AsyncClient(timeout=30) as c:
        if pdf_bytes:
            # sendDocument: file + caption in one call (Telegram caption limit ~1024 chars)
            url = f"https://api.telegram.org/bot{token}/sendDocument"
            files = {"document": (pdf_filename, pdf_bytes, "application/pdf")}
            data = {"chat_id": chat_id, "caption": text[:1024]}
            r = await c.post(url, data=data, files=files)
        else:
            url = f"https://api.telegram.org/bot{token}/sendMessage"
            r = await c.post(url, json={"chat_id": chat_id, "text": text})
        r.raise_for_status() 