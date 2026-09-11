# import ssl
# import time
# import base64
# import asyncio
# import smtplib
# from email.mime.text import MIMEText
# from email.mime.multipart import MIMEMultipart
# from email.mime.application import MIMEApplication

# import httpx


# # ─────────────────────────────── Gmail ──────────────────────────────────
# def _smtp_login_sync(host, port, user, password):
#     with smtplib.SMTP(host, port, timeout=15) as s:
#         s.starttls(context=ssl.create_default_context())
#         s.login(user, password)


# def _smtp_send_sync(host, port, user, password, sender, recipient, subject, body):
#     msg = MIMEText(body, "plain", "utf-8")
#     msg["Subject"] = subject
#     msg["From"] = sender
#     msg["To"] = recipient
#     with smtplib.SMTP(host, port, timeout=20) as s:
#         s.starttls(context=ssl.create_default_context())
#         s.login(user, password)
#         s.send_message(msg)


# def _smtp_send_with_attachment_sync(host, port, user, password, sender, recipient,
#                                     subject, body, attachment_bytes, attachment_filename):
#     msg = MIMEMultipart()
#     msg["Subject"] = subject
#     msg["From"] = sender
#     msg["To"] = recipient
#     msg.attach(MIMEText(body, "plain", "utf-8"))

#     part = MIMEApplication(attachment_bytes, _subtype="pdf")
#     part.add_header("Content-Disposition", "attachment", filename=attachment_filename)
#     msg.attach(part)

#     with smtplib.SMTP(host, port, timeout=30) as s:
#         s.starttls(context=ssl.create_default_context())
#         s.login(user, password)
#         s.send_message(msg)


# async def verify_gmail(creds: dict) -> str:
#     await asyncio.to_thread(_smtp_login_sync, "smtp.gmail.com", 587,
#                             creds["email"], creds["password"])
#     return creds["email"]


# async def send_gmail(creds: dict, recipient: str, subject: str, body: str) -> None:
#     await asyncio.to_thread(_smtp_send_sync, "smtp.gmail.com", 587,
#                             creds["email"], creds["password"], creds["email"],
#                             recipient, subject, body)


# async def send_gmail_with_attachment(creds: dict, recipient: str, subject: str, body: str,
#                                      attachment_bytes: bytes, attachment_filename: str) -> None:
#     await asyncio.to_thread(_smtp_send_with_attachment_sync, "smtp.gmail.com", 587,
#                             creds["email"], creds["password"], creds["email"], recipient,
#                             subject, body, attachment_bytes, attachment_filename)


# # ───────────────────────── Outlook / 365 (SMTP) ─────────────────────────
# # async def verify_outlook365(creds: dict) -> str:
# #     await asyncio.to_thread(_smtp_login_sync, "smtp.office365.com", 587,
# #                             creds["email"], creds["password"])
# #     return creds["email"]


# # async def send_outlook365(creds: dict, recipient: str, subject: str, body: str) -> None:
# #     await asyncio.to_thread(_smtp_send_sync, "smtp.office365.com", 587,
# #                             creds["email"], creds["password"], creds["email"],
# #                             recipient, subject, body)


# # async def send_outlook365_with_attachment(creds: dict, recipient: str, subject: str, body: str,
# #                                           attachment_bytes: bytes, attachment_filename: str) -> None:
# #     await asyncio.to_thread(_smtp_send_with_attachment_sync, "smtp.office365.com", 587,
# #                             creds["email"], creds["password"], creds["email"], recipient,
# #                             subject, body, attachment_bytes, attachment_filename)
# # creds = {"tenant_id", "client_id", "client_secret", "sender_email"}
# _graph_token_cache: dict = {}   # keyed by client_id, so multiple accounts don't clash
 
 
# async def _graph_token(creds: dict) -> str:
#     key = creds["client_id"]
#     cached = _graph_token_cache.get(key)
#     if cached and time.time() < cached["exp"] - 60:
#         return cached["val"]
 
#     url = f"https://login.microsoftonline.com/{creds['tenant_id']}/oauth2/v2.0/token"
#     data = {
#         "client_id": creds["client_id"],
#         "client_secret": creds["client_secret"],
#         "scope": "https://graph.microsoft.com/.default",
#         "grant_type": "client_credentials",
#     }
#     async with httpx.AsyncClient(timeout=20) as c:
#         r = await c.post(url, data=data)
#         if r.status_code != 200:
#             raise RuntimeError(f"Graph auth failed: {r.text[:200]}")
#         j = r.json()
#     _graph_token_cache[key] = {"val": j["access_token"],
#                                "exp": time.time() + int(j.get("expires_in", 3600))}
#     return j["access_token"]
 
 
# async def verify_outlook365(creds: dict) -> str:
#     """Confirms tenant/client/secret work AND the sender mailbox is reachable."""
#     for f in ("tenant_id", "client_id", "client_secret", "sender_email"):
#         if not creds.get(f):
#             raise RuntimeError(f"Missing field: {f}")
#     token = await _graph_token(creds)
#     url = f"https://graph.microsoft.com/v1.0/users/{creds['sender_email']}"
#     async with httpx.AsyncClient(timeout=20) as c:
#         r = await c.get(url, headers={"Authorization": f"Bearer {token}"})
#     if r.status_code == 403:
#         raise RuntimeError("Mail.Send application permission not granted (admin consent missing)")
#     if r.status_code == 404:
#         raise RuntimeError(f"Sender mailbox '{creds['sender_email']}' not found in this tenant")
#     r.raise_for_status()
#     return creds["sender_email"]
 
 
# def _graph_mail_payload(sender_email, recipient, subject, body, attachment_bytes=None,
#                         attachment_filename=None):
#     msg = {
#         "subject": subject,
#         "body": {"contentType": "Text", "content": body},
#         "toRecipients": [{"emailAddress": {"address": recipient}}],
#     }
#     if attachment_bytes is not None:
#         msg["attachments"] = [{
#             "@odata.type": "#microsoft.graph.fileAttachment",
#             "name": attachment_filename,
#             "contentType": "application/pdf",
#             "contentBytes": base64.b64encode(attachment_bytes).decode(),
#         }]
#     return {"message": msg, "saveToSentItems": False}
 
 
# async def send_outlook365(creds: dict, recipient: str, subject: str, body: str) -> None:
#     token = await _graph_token(creds)
#     url = f"https://graph.microsoft.com/v1.0/users/{creds['sender_email']}/sendMail"
#     payload = _graph_mail_payload(creds["sender_email"], recipient, subject, body)
#     async with httpx.AsyncClient(timeout=30) as c:
#         r = await c.post(url, headers={"Authorization": f"Bearer {token}"}, json=payload)
#         r.raise_for_status()   # 202 Accepted on success
 
 
# async def send_outlook365_with_attachment(creds: dict, recipient: str, subject: str, body: str,
#                                           attachment_bytes: bytes, attachment_filename: str) -> None:
#     token = await _graph_token(creds)
#     url = f"https://graph.microsoft.com/v1.0/users/{creds['sender_email']}/sendMail"
#     payload = _graph_mail_payload(creds["sender_email"], recipient, subject, body,
#                                   attachment_bytes, attachment_filename)
#     async with httpx.AsyncClient(timeout=60) as c:
#         r = await c.post(url, headers={"Authorization": f"Bearer {token}"}, json=payload)
#         r.raise_for_status()
 

# # ──────────────────────────────── Telegram ──────────────────────────────
# async def verify_telegram(creds: dict) -> str:
#     """Calls Telegram's getMe — proves the bot token is real and returns its username."""
#     token = creds["bot_token"]
#     async with httpx.AsyncClient(timeout=15) as c:
#         r = await c.get(f"https://api.telegram.org/bot{token}/getMe")
#     j = r.json()
#     if not j.get("ok"):
#         raise RuntimeError(j.get("description", "Invalid bot token"))
#     return "@" + j["result"]["username"]


# async def send_telegram(creds: dict, recipient: str, subject: str, body: str) -> None:
#     # recipient here is the chat_id (from CommunicationChannel.value)
#     token = creds["bot_token"]
#     text = f"{subject}\n\n{body}" if subject else body
#     async with httpx.AsyncClient(timeout=15) as c:
#         r = await c.post(f"https://api.telegram.org/bot{token}/sendMessage",
#                          json={"chat_id": recipient, "text": text})
#         r.raise_for_status()


# async def send_telegram_with_attachment(creds: dict, recipient: str, subject: str, body: str,
#                                         attachment_bytes: bytes, attachment_filename: str) -> None:
#     token = creds["bot_token"]
#     caption = f"{subject}\n\n{body}" if subject else body
#     files = {"document": (attachment_filename, attachment_bytes, "application/pdf")}
#     data = {"chat_id": recipient, "caption": caption[:1024]}   # Telegram caption limit
#     async with httpx.AsyncClient(timeout=60) as c:
#         r = await c.post(f"https://api.telegram.org/bot{token}/sendDocument",
#                          data=data, files=files)
#         r.raise_for_status()


# # ───────────────────────── WhatsApp (Twilio) ────────────────────────────
# async def verify_whatsapp(creds: dict) -> str:
#     """Checks the Twilio account itself is real (fetches account info)."""
#     sid, token = creds["account_sid"], creds["auth_token"]
#     url = f"https://api.twilio.com/2010-04-01/Accounts/{sid}.json"
#     async with httpx.AsyncClient(timeout=15) as c:
#         r = await c.get(url, auth=(sid, token))
#     if r.status_code != 200:
#         raise RuntimeError("Invalid Twilio Account SID / Auth Token")
#     return creds.get("from_number", sid)


# async def send_whatsapp(creds: dict, recipient: str, subject: str, body: str) -> None:
#     sid, token = creds["account_sid"], creds["auth_token"]
#     from_num = creds["from_number"]
#     url = f"https://api.twilio.com/2010-04-01/Accounts/{sid}/Messages.json"
#     data = {
#         "From": from_num if from_num.startswith("whatsapp:") else f"whatsapp:{from_num}",
#         "To": recipient if recipient.startswith("whatsapp:") else f"whatsapp:{recipient}",
#         "Body": body[:1500],
#     }
#     async with httpx.AsyncClient(timeout=20) as c:
#         r = await c.post(url, data=data, auth=(sid, token))
#         r.raise_for_status()


# # ──────────────────────────── SMS (Twilio) ──────────────────────────────
# async def verify_sms(creds: dict) -> str:
#     return await verify_whatsapp(creds)   # same Twilio account check


# async def send_sms(creds: dict, recipient: str, subject: str, body: str) -> None:
#     sid, token = creds["account_sid"], creds["auth_token"]
#     url = f"https://api.twilio.com/2010-04-01/Accounts/{sid}/Messages.json"
#     data = {"From": creds["from_number"], "To": recipient, "Body": body[:1500]}
#     async with httpx.AsyncClient(timeout=20) as c:
#         r = await c.post(url, data=data, auth=(sid, token))
#         r.raise_for_status()


# # ────────────────────────────── Jira ─────────────────────────────────
# # creds = {"base_url": "https://company.atlassian.net", "email": "...",
# #          "api_token": "...", "project_key": "SEC"}
# def _jira_auth(creds: dict):
#     return (creds["email"], creds["api_token"])


# async def verify_jira(creds: dict) -> str:
#     """Confirms the base_url/email/api_token are valid AND the project_key exists."""
#     base = creds["base_url"].rstrip("/")
#     async with httpx.AsyncClient(timeout=15) as c:
#         r = await c.get(f"{base}/rest/api/3/myself", auth=_jira_auth(creds))
#         if r.status_code == 401:
#             raise RuntimeError("Invalid Jira email / API token")
#         r.raise_for_status()
#         who = r.json().get("displayName", creds["email"])

#         pr = await c.get(f"{base}/rest/api/3/project/{creds['project_key']}",
#                          auth=_jira_auth(creds))
#         if pr.status_code == 404:
#             raise RuntimeError(f"Project key '{creds['project_key']}' not found")
#         pr.raise_for_status()
#     return f"{who} @ {creds['project_key']}"


# async def send_jira(creds: dict, recipient: str, subject: str, body: str) -> None:
#     """'Send' for Jira = create an issue. `recipient` is ignored (Jira has no
#     recipient concept) — kept only so the call shape matches every other
#     channel's send_fn(creds, recipient, subject, body)."""
#     base = creds["base_url"].rstrip("/")
#     payload = {
#         "fields": {
#             "project": {"key": creds["project_key"]},
#             "summary": subject or "Security Alert",
#             "description": {
#                 "type": "doc", "version": 1,
#                 "content": [{"type": "paragraph",
#                             "content": [{"type": "text", "text": body}]}],
#             },
#             "issuetype": {"name": "Task"},
#         }
#     }
#     async with httpx.AsyncClient(timeout=20) as c:
#         r = await c.post(f"{base}/rest/api/3/issue", json=payload, auth=_jira_auth(creds))
#         r.raise_for_status()   # 201 Created; response has the new issue key (e.g. "SEC-123")


# # ═══════════════════ Teams — Graph API (delegated, refresh token) ═════════
# # creds = {"tenant_id": "...", "client_id": "...", "refresh_token": "...",
# #          "client_secret": ""}  # client_secret optional, only if app is confidential
# # Get the refresh_token ONCE via device-code login (a user who is a member of
# # the target team). Message goes out as that user.
# # Azure setup: Authentication -> "Allow public client flows" = Yes
# #              API permissions -> Graph -> DELEGATED -> ChannelMessage.Send
# _teams_token_cache: dict = {}
 
 
# async def _teams_token(creds: dict) -> str:
#     key = creds["client_id"]
#     cached = _teams_token_cache.get(key)
#     if cached and time.time() < cached["exp"] - 60:
#         return cached["val"]
 
#     url = f"https://login.microsoftonline.com/{creds['tenant_id']}/oauth2/v2.0/token"
#     data = {
#         "client_id": creds["client_id"],
#         "grant_type": "refresh_token",
#         "refresh_token": creds["refresh_token"],
#         "scope": "offline_access ChannelMessage.Send",
#     }
#     if creds.get("client_secret"):
#         data["client_secret"] = creds["client_secret"]
#     async with httpx.AsyncClient(timeout=20) as c:
#         r = await c.post(url, data=data)
#         if r.status_code != 200:
#             raise RuntimeError(f"Teams token refresh failed: {r.text[:200]}")
#         j = r.json()
#     _teams_token_cache[key] = {"val": j["access_token"],
#                               "exp": time.time() + int(j.get("expires_in", 3600))}
#     # Microsoft may rotate the refresh_token — keep the latest one in creds for
#     # the caller to persist back to the DB if it changed.
#     if j.get("refresh_token"):
#         creds["refresh_token"] = j["refresh_token"]
#     return j["access_token"]
 
 
# def parse_teams_link(value: str):
#     """Extract (team_id, channel_id) from a Teams deep-link, or from
#     'team_id|channel_id'."""
#     if value and value.strip().startswith("http"):
#         p = urlparse(value)
#         parts = p.path.split("/")
#         channel_id = unquote(parts[parts.index("team") + 1]) if "team" in parts else None
#         team_id = parse_qs(p.query).get("groupId", [None])[0]
#     elif "|" in (value or ""):
#         team_id, channel_id = value.split("|", 1)
#     else:
#         team_id = channel_id = None
#     if not (team_id and channel_id):
#         raise RuntimeError("Could not extract team-id/channel-id from the Teams value")
#     return team_id, channel_id
 
 
# async def verify_teams(creds: dict) -> str:
#     for f in ("tenant_id", "client_id", "refresh_token"):
#         if not creds.get(f):
#             raise RuntimeError(f"Missing field: {f}")
#     token = await _teams_token(creds)
#     async with httpx.AsyncClient(timeout=20) as c:
#         r = await c.get("https://graph.microsoft.com/v1.0/me",
#                         headers={"Authorization": f"Bearer {token}"})
#     if r.status_code == 401:
#         raise RuntimeError("Refresh token invalid/expired — re-run the device-code login")
#     r.raise_for_status()
#     who = r.json().get("userPrincipalName", "unknown user")
#     return who
 
 
# async def send_teams(creds: dict, recipient: str, subject: str, body: str) -> None:
#     """`recipient` = the Teams deep-link (or 'team_id|channel_id') identifying
#     WHICH channel to post into — this is the CommunicationChannel row's value."""
#     team_id, channel_id = parse_teams_link(recipient)
#     token = await _teams_token(creds)
#     url = f"https://graph.microsoft.com/v1.0/teams/{team_id}/channels/{channel_id}/messages"
#     text = f"{subject}\n\n{body}" if subject else body
#     async with httpx.AsyncClient(timeout=20) as c:
#         r = await c.post(url, headers={"Authorization": f"Bearer {token}"},
#                          json={"body": {"content": text}})
#         r.raise_for_status()   # 201 Created
# # ─────────────────── Webhooks: Slack / Discord (no account) ────────────
# # These need no ChannelAccount at all — the webhook URL in CommunicationChannel
# # IS the credential. Kept here for a consistent call shape from the send API.
# async def send_slack_webhook(webhook_url: str, text: str) -> None:
#     async with httpx.AsyncClient(timeout=15) as c:
#         r = await c.post(webhook_url, json={"text": text})
#         r.raise_for_status()


# async def send_discord_webhook(webhook_url: str, text: str) -> None:
#     async with httpx.AsyncClient(timeout=15) as c:
#         r = await c.post(webhook_url, json={"content": text})
#         r.raise_for_status()


# # ── registries the API layer uses ────────────────────────────────────
# VERIFY = {
#     "gmail": verify_gmail, "outlook365": verify_outlook365,
#     "telegram": verify_telegram, "whatsapp": verify_whatsapp, "sms": verify_sms,
#     "jira": verify_jira,
# }

# SEND = {
#     "gmail": send_gmail, "outlook365": send_outlook365,
#     "telegram": send_telegram, "whatsapp": send_whatsapp, "sms": send_sms,
#     "jira": send_jira,
# }

# REQUIRED_FIELDS = {
#     "gmail": ["email", "password"],
#     "outlook365": ["tenant_id", "client_id", "client_secret", "sender_email"],
#     "telegram": ["bot_token"],
#     "whatsapp": ["account_sid", "auth_token", "from_number"],
#     "sms": ["account_sid", "auth_token", "from_number"],
#     "jira": ["base_url", "email", "api_token", "project_key"],
# }

# # Channels that can send a PDF/file directly (function signature:
# # fn(creds, recipient, subject, body, attachment_bytes, attachment_filename)).
# # WhatsApp/SMS need a public media URL instead of raw bytes (Twilio can't take
# # an upload directly) — not included here; ask if you need that variant.
# # Slack/Discord webhooks cannot upload files at all — only a bot-token API can.
# SEND_WITH_ATTACHMENT = {
#     "gmail": send_gmail_with_attachment,
#     "outlook365": send_outlook365_with_attachment,
#     "telegram": send_telegram_with_attachment,
# }
"""
channel_providers.py
=====================
One consistent shape for every channel:

    verify_<channel>(creds: dict) -> str        # returns a display identifier, raises on failure
    send_<channel>(creds: dict, recipient, subject, body) -> None
    send_<channel>_with_attachment(creds, recipient, subject, body, bytes, filename) -> None  (where supported)

`creds` is the decrypted dict pulled from ChannelAccount.credentials_enc.
No provider credentials are hardcoded anywhere in this file — everything
comes from `creds`, which the API layer loads from the database.

Outlook (company M365) uses GRAPH API + OAuth client-credentials — NOT a
password. This avoids the "Authentication unsuccessful" IP/location block that
SMTP basic-auth hits when sent from a cloud deploy server outside the
company's trusted network; Graph uses a token, not a location-checked login.
    creds = {"tenant_id": "...", "client_id": "...", "client_secret": "...",
             "sender_email": "alerts@company.com"}
Azure setup: App registration -> API permissions -> Microsoft Graph ->
APPLICATION permission `Mail.Send` -> Grant admin consent.
"""

import time
import base64
import json
import ssl
import asyncio
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication

from urllib.parse import urlparse, parse_qs, unquote

import httpx


# ═══════════════════════════════ Gmail (SMTP) ═══════════════════════════════
def _smtp_login_sync(host, port, user, password):
    with smtplib.SMTP(host, port, timeout=15) as s:
        s.starttls(context=ssl.create_default_context())
        s.login(user, password)


def _smtp_send_sync(host, port, user, password, sender, recipient, subject, body):
    msg = MIMEText(body, "plain", "utf-8")
    msg["Subject"] = subject
    msg["From"] = sender
    msg["To"] = recipient
    with smtplib.SMTP(host, port, timeout=20) as s:
        s.starttls(context=ssl.create_default_context())
        s.login(user, password)
        s.send_message(msg)


def _smtp_send_with_attachment_sync(host, port, user, password, sender, recipient,
                                    subject, body, attachment_bytes, attachment_filename):
    msg = MIMEMultipart()
    msg["Subject"] = subject
    msg["From"] = sender
    msg["To"] = recipient
    msg.attach(MIMEText(body, "plain", "utf-8"))
    part = MIMEApplication(attachment_bytes, _subtype="pdf")
    part.add_header("Content-Disposition", "attachment", filename=attachment_filename)
    msg.attach(part)
    with smtplib.SMTP(host, port, timeout=30) as s:
        s.starttls(context=ssl.create_default_context())
        s.login(user, password)
        s.send_message(msg)


async def verify_gmail(creds: dict) -> str:
    await asyncio.to_thread(_smtp_login_sync, "smtp.gmail.com", 587,
                            creds["email"], creds["password"])
    return creds["email"]


async def send_gmail(creds: dict, recipient: str, subject: str, body: str) -> None:
    await asyncio.to_thread(_smtp_send_sync, "smtp.gmail.com", 587,
                            creds["email"], creds["password"], creds["email"],
                            recipient, subject, body)


async def send_gmail_with_attachment(creds: dict, recipient: str, subject: str, body: str,
                                     attachment_bytes: bytes, attachment_filename: str) -> None:
    await asyncio.to_thread(_smtp_send_with_attachment_sync, "smtp.gmail.com", 587,
                            creds["email"], creds["password"], creds["email"], recipient,
                            subject, body, attachment_bytes, attachment_filename)


# ═══════════════════ Outlook / Microsoft 365 — GRAPH API (OAuth) ═══════════
# creds = {"tenant_id", "client_id", "client_secret", "sender_email"}
_graph_token_cache: dict = {}   # keyed by client_id, so multiple accounts don't clash
 
 
async def _graph_token(creds: dict) -> str:
    key = creds["client_id"]
    cached = _graph_token_cache.get(key)
    if cached and time.time() < cached["exp"] - 60:
        return cached["val"]
 
    url = f"https://login.microsoftonline.com/{creds['tenant_id']}/oauth2/v2.0/token"
    data = {
        "client_id": creds["client_id"],
        "client_secret": creds["client_secret"],
        "scope": "https://graph.microsoft.com/.default",
        "grant_type": "client_credentials",
    }
    async with httpx.AsyncClient(timeout=20) as c:
        r = await c.post(url, data=data)
        if r.status_code != 200:
            raise RuntimeError(f"Graph auth failed: {r.text[:200]}")
        j = r.json()
    _graph_token_cache[key] = {"val": j["access_token"],
                               "exp": time.time() + int(j.get("expires_in", 3600))}
    return j["access_token"]
 
 
async def verify_outlook365(creds: dict) -> str:
    """Confirms tenant/client/secret produce a valid OAuth token.
    NOTE: we deliberately do NOT call GET /v1.0/users/{email} here — that
    endpoint needs its OWN separate permission (User.Read.All, Application),
    which has nothing to do with sending mail and is not something you should
    need to grant. Mail.Send is the only permission required to send; the real
    proof that it works is a successful sendMail call, so verification here
    only confirms the app registration + credentials are valid (token issued).
    """
    for f in ("tenant_id", "client_id", "client_secret", "sender_email"):
        if not creds.get(f):
            raise RuntimeError(f"Missing field: {f}")
    try:
        await _graph_token(creds)   # raises RuntimeError itself if auth fails
    except RuntimeError:
        raise
    except Exception as e:
        raise RuntimeError(f"Could not obtain Graph token: {e}")
    return creds["sender_email"]
 
 
def _graph_mail_payload(sender_email, recipient, subject, body, attachment_bytes=None,
                        attachment_filename=None):
    msg = {
        "subject": subject,
        "body": {"contentType": "Text", "content": body},
        "toRecipients": [{"emailAddress": {"address": recipient}}],
    }
    if attachment_bytes is not None:
        msg["attachments"] = [{
            "@odata.type": "#microsoft.graph.fileAttachment",
            "name": attachment_filename,
            "contentType": "application/pdf",
            "contentBytes": base64.b64encode(attachment_bytes).decode(),
        }]
    return {"message": msg, "saveToSentItems": False}
 
 
async def send_outlook365(creds: dict, recipient: str, subject: str, body: str) -> None:
    token = await _graph_token(creds)
    url = f"https://graph.microsoft.com/v1.0/users/{creds['sender_email']}/sendMail"
    payload = _graph_mail_payload(creds["sender_email"], recipient, subject, body)
    async with httpx.AsyncClient(timeout=30) as c:
        r = await c.post(url, headers={"Authorization": f"Bearer {token}"}, json=payload)
        r.raise_for_status()   # 202 Accepted on success
 
 
async def send_outlook365_with_attachment(creds: dict, recipient: str, subject: str, body: str,
                                          attachment_bytes: bytes, attachment_filename: str) -> None:
    token = await _graph_token(creds)
    url = f"https://graph.microsoft.com/v1.0/users/{creds['sender_email']}/sendMail"
    payload = _graph_mail_payload(creds["sender_email"], recipient, subject, body,
                                  attachment_bytes, attachment_filename)
    async with httpx.AsyncClient(timeout=60) as c:
        r = await c.post(url, headers={"Authorization": f"Bearer {token}"}, json=payload)
        r.raise_for_status()
 
# # creds = {"tenant_id", "client_id", "client_secret", "sender_email"}
# _graph_token_cache: dict = {}   # keyed by client_id, so multiple accounts don't clash


# async def _graph_token(creds: dict) -> str:
#     key = creds["client_id"]
#     cached = _graph_token_cache.get(key)
#     if cached and time.time() < cached["exp"] - 60:
#         return cached["val"]

#     url = f"https://login.microsoftonline.com/{creds['tenant_id']}/oauth2/v2.0/token"
#     data = {
#         "client_id": creds["client_id"],
#         "client_secret": creds["client_secret"],
#         "scope": "https://graph.microsoft.com/.default",
#         "grant_type": "client_credentials",
#     }
#     async with httpx.AsyncClient(timeout=20) as c:
#         r = await c.post(url, data=data)
#         if r.status_code != 200:
#             raise RuntimeError(f"Graph auth failed: {r.text[:200]}")
#         j = r.json()
#     _graph_token_cache[key] = {"val": j["access_token"],
#                                "exp": time.time() + int(j.get("expires_in", 3600))}
#     return j["access_token"]


# async def verify_outlook365(creds: dict) -> str:
#     """Confirms tenant/client/secret work AND the sender mailbox is reachable."""
#     for f in ("tenant_id", "client_id", "client_secret", "sender_email"):
#         if not creds.get(f):
#             raise RuntimeError(f"Missing field: {f}")
#     token = await _graph_token(creds)
#     url = f"https://graph.microsoft.com/v1.0/users/{creds['sender_email']}"
#     async with httpx.AsyncClient(timeout=20) as c:
#         r = await c.get(url, headers={"Authorization": f"Bearer {token}"})
#     if r.status_code == 403:
#         raise RuntimeError("Mail.Send application permission not granted (admin consent missing)")
#     if r.status_code == 404:
#         raise RuntimeError(f"Sender mailbox '{creds['sender_email']}' not found in this tenant")
#     r.raise_for_status()
#     return creds["sender_email"]


# def _graph_mail_payload(sender_email, recipient, subject, body, attachment_bytes=None,
#                         attachment_filename=None):
#     msg = {
#         "subject": subject,
#         "body": {"contentType": "Text", "content": body},
#         "toRecipients": [{"emailAddress": {"address": recipient}}],
#     }
#     if attachment_bytes is not None:
#         msg["attachments"] = [{
#             "@odata.type": "#microsoft.graph.fileAttachment",
#             "name": attachment_filename,
#             "contentType": "application/pdf",
#             "contentBytes": base64.b64encode(attachment_bytes).decode(),
#         }]
#     return {"message": msg, "saveToSentItems": False}


# async def send_outlook365(creds: dict, recipient: str, subject: str, body: str) -> None:
#     token = await _graph_token(creds)
#     url = f"https://graph.microsoft.com/v1.0/users/{creds['sender_email']}/sendMail"
#     payload = _graph_mail_payload(creds["sender_email"], recipient, subject, body)
#     async with httpx.AsyncClient(timeout=30) as c:
#         r = await c.post(url, headers={"Authorization": f"Bearer {token}"}, json=payload)
#         r.raise_for_status()   # 202 Accepted on success


# async def send_outlook365_with_attachment(creds: dict, recipient: str, subject: str, body: str,
#                                           attachment_bytes: bytes, attachment_filename: str) -> None:
#     token = await _graph_token(creds)
#     url = f"https://graph.microsoft.com/v1.0/users/{creds['sender_email']}/sendMail"
#     payload = _graph_mail_payload(creds["sender_email"], recipient, subject, body,
#                                   attachment_bytes, attachment_filename)
#     async with httpx.AsyncClient(timeout=60) as c:
#         r = await c.post(url, headers={"Authorization": f"Bearer {token}"}, json=payload)
#         r.raise_for_status()


# ═══════════════════════════════ Telegram ═══════════════════════════════════
async def verify_telegram(creds: dict) -> str:
    token = creds["bot_token"]
    async with httpx.AsyncClient(timeout=15) as c:
        r = await c.get(f"https://api.telegram.org/bot{token}/getMe")
    j = r.json()
    if not j.get("ok"):
        raise RuntimeError(j.get("description", "Invalid bot token"))
    return "@" + j["result"]["username"]


async def send_telegram(creds: dict, recipient: str, subject: str, body: str) -> None:
    token = creds["bot_token"]
    text = f"{subject}\n\n{body}" if subject else body
    async with httpx.AsyncClient(timeout=15) as c:
        r = await c.post(f"https://api.telegram.org/bot{token}/sendMessage",
                         json={"chat_id": recipient, "text": text})
        r.raise_for_status()


async def send_telegram_with_attachment(creds: dict, recipient: str, subject: str, body: str,
                                        attachment_bytes: bytes, attachment_filename: str) -> None:
    token = creds["bot_token"]
    caption = f"{subject}\n\n{body}" if subject else body
    files = {"document": (attachment_filename, attachment_bytes, "application/pdf")}
    data = {"chat_id": recipient, "caption": caption[:1024]}
    async with httpx.AsyncClient(timeout=60) as c:
        r = await c.post(f"https://api.telegram.org/bot{token}/sendDocument",
                         data=data, files=files)
        r.raise_for_status()


# ═══════════════════════════ WhatsApp (Twilio) ═══════════════════════════════
async def verify_whatsapp(creds: dict) -> str:
    sid, token = creds["account_sid"], creds["auth_token"]
    url = f"https://api.twilio.com/2010-04-01/Accounts/{sid}.json"
    async with httpx.AsyncClient(timeout=15) as c:
        r = await c.get(url, auth=(sid, token))
    if r.status_code != 200:
        raise RuntimeError("Invalid Twilio Account SID / Auth Token")
    return creds.get("from_number", sid)


async def send_whatsapp(creds: dict, recipient: str, subject: str, body: str) -> None:
    sid, token = creds["account_sid"], creds["auth_token"]
    from_num = creds["from_number"]
    url = f"https://api.twilio.com/2010-04-01/Accounts/{sid}/Messages.json"
    data = {
        "From": from_num if from_num.startswith("whatsapp:") else f"whatsapp:{from_num}",
        "To": recipient if recipient.startswith("whatsapp:") else f"whatsapp:{recipient}",
        "Body": body[:1500],
    }
    async with httpx.AsyncClient(timeout=20) as c:
        r = await c.post(url, data=data, auth=(sid, token))
        r.raise_for_status()


# ═══════════════════════════════ SMS (Twilio) ════════════════════════════════
async def verify_sms(creds: dict) -> str:
    return await verify_whatsapp(creds)


async def send_sms(creds: dict, recipient: str, subject: str, body: str) -> None:
    sid, token = creds["account_sid"], creds["auth_token"]
    url = f"https://api.twilio.com/2010-04-01/Accounts/{sid}/Messages.json"
    data = {"From": creds["from_number"], "To": recipient, "Body": body[:1500]}
    async with httpx.AsyncClient(timeout=20) as c:
        r = await c.post(url, data=data, auth=(sid, token))
        r.raise_for_status()


# ═══════════════════ Teams — Graph API (delegated, refresh token) ═════════
# creds = {"tenant_id": "...", "client_id": "...", "refresh_token": "...",
#          "client_secret": ""}  # client_secret optional, only if app is confidential
# Get the refresh_token ONCE via device-code login (a user who is a member of
# the target team). Message goes out as that user.
# Azure setup: Authentication -> "Allow public client flows" = Yes
#              API permissions -> Graph -> DELEGATED -> ChannelMessage.Send
_teams_token_cache: dict = {}


async def _teams_token(creds: dict) -> str:
    key = creds["client_id"]
    cached = _teams_token_cache.get(key)
    if cached and time.time() < cached["exp"] - 60:
        return cached["val"]

    url = f"https://login.microsoftonline.com/{creds['tenant_id']}/oauth2/v2.0/token"
    data = {
        "client_id": creds["client_id"],
        "grant_type": "refresh_token",
        "refresh_token": creds["refresh_token"],
        "scope": "offline_access ChannelMessage.Send",
    }
    if creds.get("client_secret"):
        data["client_secret"] = creds["client_secret"]
    async with httpx.AsyncClient(timeout=20) as c:
        r = await c.post(url, data=data)
        if r.status_code != 200:
            raise RuntimeError(f"Teams token refresh failed: {r.text[:200]}")
        j = r.json()
    _teams_token_cache[key] = {"val": j["access_token"],
                              "exp": time.time() + int(j.get("expires_in", 3600))}
    # Microsoft may rotate the refresh_token — keep the latest one in creds for
    # the caller to persist back to the DB if it changed.
    if j.get("refresh_token"):
        creds["refresh_token"] = j["refresh_token"]
    return j["access_token"]


def parse_teams_link(value: str):
    """Extract (team_id, channel_id) from a Teams deep-link, or from
    'team_id|channel_id'."""
    if value and value.strip().startswith("http"):
        p = urlparse(value)
        parts = p.path.split("/")
        channel_id = unquote(parts[parts.index("channel") + 1]) if "channel" in parts else None
        team_id = parse_qs(p.query).get("groupId", [None])[0]
    elif "|" in (value or ""):
        team_id, channel_id = value.split("|", 1)
    else:
        team_id = channel_id = None
    if not (team_id and channel_id):
        raise RuntimeError("Could not extract team-id/channel-id from the Teams value")
    return team_id, channel_id


async def verify_teams(creds: dict) -> str:
    for f in ("tenant_id", "client_id", "refresh_token"):
        if not creds.get(f):
            raise RuntimeError(f"Missing field: {f}")
    token = await _teams_token(creds)
    # Don't call /v1.0/me — it needs User.Read/profile scope which we never
    # request (we only ask for ChannelMessage.Send). Instead decode the JWT's
    # own payload locally to confirm it's a real token and show who it's for.
    try:
        payload_b64 = token.split(".")[1]
        padded = payload_b64 + "=" * (-len(payload_b64) % 4)
        claims = json.loads(base64.urlsafe_b64decode(padded))
        who = claims.get("upn") or claims.get("unique_name") or claims.get("preferred_username")
    except Exception:
        who = None
    if not who:
        raise RuntimeError("Got a token but could not read identity from it — token may be malformed")
    return who

# async def verify_teams(creds: dict) -> str:
#     for f in ("tenant_id", "client_id", "refresh_token"):
#         if not creds.get(f):
#             raise RuntimeError(f"Missing field: {f}")
#     token = await _teams_token(creds)
#     print(token)
#     async with httpx.AsyncClient(timeout=20) as c:
#         r = await c.get("https://graph.microsoft.com/v1.0/me",
#                         headers={"Authorization": f"Bearer {token}"})
#         print(r)
#     if r.status_code == 401:
#         raise RuntimeError("Refresh token invalid/expired — re-run the device-code login")
#     r.raise_for_status()
#     who = r.json().get("userPrincipalName", "unknown user")
#     return who


async def send_teams(creds: dict, recipient: str, subject: str, body: str) -> None:
    """`recipient` = the Teams deep-link (or 'team_id|channel_id') identifying
    WHICH channel to post into — this is the CommunicationChannel row's value."""
    team_id, channel_id = parse_teams_link(recipient)
    token = await _teams_token(creds)
    url = f"https://graph.microsoft.com/v1.0/teams/{team_id}/channels/{channel_id}/messages"
    text = f"{subject}\n\n{body}" if subject else body
    async with httpx.AsyncClient(timeout=20) as c:
        r = await c.post(url, headers={"Authorization": f"Bearer {token}"},
                         json={"body": {"content": text}})
        r.raise_for_status()   # 201 Created


# ═══════════════════════════════ Jira ════════════════════════════════════════
def _jira_auth(creds: dict):
    return (creds["email"], creds["api_token"])


async def verify_jira(creds: dict) -> str:
    base = creds["base_url"].rstrip("/")
    async with httpx.AsyncClient(timeout=15) as c:
        r = await c.get(f"{base}/rest/api/3/myself", auth=_jira_auth(creds))
        if r.status_code == 401:
            raise RuntimeError("Invalid Jira email / API token")
        r.raise_for_status()
        who = r.json().get("displayName", creds["email"])
        pr = await c.get(f"{base}/rest/api/3/project/{creds['project_key']}", auth=_jira_auth(creds))
        if pr.status_code == 404:
            raise RuntimeError(f"Project key '{creds['project_key']}' not found")
        pr.raise_for_status()
    return f"{who} @ {creds['project_key']}"


async def send_jira(creds: dict, recipient: str, subject: str, body: str) -> None:
    base = creds["base_url"].rstrip("/")
    payload = {"fields": {
        "project": {"key": creds["project_key"]},
        "summary": subject or "Security Alert",
        "description": {"type": "doc", "version": 1,
                        "content": [{"type": "paragraph",
                                    "content": [{"type": "text", "text": body}]}]},
        "issuetype": {"name": "Task"},
    }}
    async with httpx.AsyncClient(timeout=20) as c:
        r = await c.post(f"{base}/rest/api/3/issue", json=payload, auth=_jira_auth(creds))
        r.raise_for_status()


# ═══════════════ Webhooks: Slack / Discord (no account needed) ══════════════
async def send_slack_webhook(webhook_url: str, text: str) -> None:
    async with httpx.AsyncClient(timeout=15) as c:
        r = await c.post(webhook_url, json={"text": text})
        r.raise_for_status()


async def send_discord_webhook(webhook_url: str, text: str) -> None:
    async with httpx.AsyncClient(timeout=15) as c:
        r = await c.post(webhook_url, json={"content": text})
        r.raise_for_status()


# ═══════════════════════════ registries ═════════════════════════════════════
VERIFY = {
    "gmail": verify_gmail, "outlook365": verify_outlook365,
    "telegram": verify_telegram, "whatsapp": verify_whatsapp, "sms": verify_sms,
    "jira": verify_jira, "teams": verify_teams,
}

SEND = {
    "gmail": send_gmail, "outlook365": send_outlook365,
    "telegram": send_telegram, "whatsapp": send_whatsapp, "sms": send_sms,
    "jira": send_jira, "teams": send_teams,
}

REQUIRED_FIELDS = {
    "gmail": ["email", "password"],
    "outlook365": ["tenant_id", "client_id", "client_secret", "sender_email"],
    "telegram": ["bot_token"],
    "whatsapp": ["account_sid", "auth_token", "from_number"],
    "sms": ["account_sid", "auth_token", "from_number"],
    "jira": ["base_url", "email", "api_token", "project_key"],
    "teams": ["tenant_id", "client_id", "refresh_token"],
}

# Channels that can send a file directly: fn(creds, recipient, subject, body, bytes, filename)
SEND_WITH_ATTACHMENT = {
    "gmail": send_gmail_with_attachment,
    "outlook365": send_outlook365_with_attachment,
    "telegram": send_telegram_with_attachment,
}