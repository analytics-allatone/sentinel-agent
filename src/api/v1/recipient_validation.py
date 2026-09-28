import re
from fastapi import HTTPException

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

# Which channel_types are email-shaped and should get this check.
EMAIL_LIKE_CHANNELS = {"gmail", "outlook365"}


def is_valid_email_format(addr: str) -> bool:
    return bool(addr and _EMAIL_RE.match(addr.strip()))


def validate_recipient_for_channel(channel_type: str, recipient: str) -> None:
    if channel_type in EMAIL_LIKE_CHANNELS:
        if not is_valid_email_format(recipient):
            raise HTTPException(
                status_code=422,
                detail=f"'{recipient}' doesn't look like a valid email address "
                       f"(expected something like name@domain.com).")
