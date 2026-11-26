"""Quota rules (v5 section 4.2).

One file converted = one conversion. PDF-to-images = one conversion
regardless of page count. A conversion is counted when the job is
accepted and refunded automatically if the job fails or is cancelled
before it starts. The daily quota resets at 00:00 in ``QUOTA_TZ``
(default Asia/Karachi).

Signed-in owner key = the user id. Anonymous owner key combines a
signed device cookie with ``HMAC(salt, ip)``; the stricter of the two
counters applies. Never IP alone (shared mobile/CGNAT networks are
common in Pakistan).
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import date, datetime, timedelta, timezone
from zoneinfo import ZoneInfo

from fastapi import Request
from sqlalchemy import select

from .deps import DEVICE_COOKIE, get_settings
from .models import Quota
from .security import sign_value, unsign_value

ANONYMOUS_DAILY_LIMIT = 5


def quota_day(tz_name: str | None = None) -> date:
    """Today's quota day in QUOTA_TZ."""
    name = tz_name or get_settings().quota_tz
    try:
        tz = ZoneInfo(name)
    except Exception:
        tz = timezone.utc
    return datetime.now(tz).date()


def resets_at(tz_name: str | None = None) -> datetime:
    """Next 00:00 in QUOTA_TZ, as an aware UTC datetime."""
    name = tz_name or get_settings().quota_tz
    try:
        tz = ZoneInfo(name)
    except Exception:
        tz = timezone.utc
    now = datetime.now(tz)
    nxt = (now + timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
    return nxt.astimezone(timezone.utc)


def user_owner_key(user_id: str) -> str:
    return f"user:{user_id}"


def device_owner_key(device_id: str) -> str:
    return f"device:{device_id}"


def ip_owner_key(ip: str) -> str:
    """HMAC(salt, ip) owner key — the salt is the app secret, so the
    stored key cannot be reversed to an IP address."""
    secret = get_settings().secret
    digest = hmac.new(secret.encode("utf-8"), f"ip:{ip}".encode("utf-8"), hashlib.sha256).hexdigest()
    return f"ip:{digest[:32]}"


def get_or_create_device_id(request: Request) -> tuple[str, bool]:
    """Return (device_id, is_new). Reads the signed ``qic_device``
    cookie; a fresh id is generated when absent or tampered with."""
    signed = request.cookies.get(DEVICE_COOKIE, "")
    device_id = unsign_value(get_settings().secret, signed) if signed else None
    if device_id:
        return device_id, False
    return secrets.token_hex(16), True


def anonymous_owner_keys(request: Request, ip: str) -> list[str]:
    """Both anonymous counters: [device key, ip-HMAC key]."""
    device_id, _ = get_or_create_device_id(request)
    return [device_owner_key(device_id), ip_owner_key(ip)]


def signed_device_cookie(device_id: str) -> str:
    return sign_value(get_settings().secret, device_id)


async def get_used(db, owner_key: str, day: date | None = None) -> int:
    day = day or quota_day()
    row = await db.get(Quota, (owner_key, day))
    return row.used if row else 0


async def consume(db, owner_key: str, day: date | None = None) -> int:
    """Count one conversion. Returns the new ``used`` value."""
    day = day or quota_day()
    row = await db.get(Quota, (owner_key, day))
    if row is None:
        row = Quota(owner_key=owner_key, day=day, used=1)
        db.add(row)
    else:
        row.used += 1
    await db.commit()
    return row.used


async def refund(db, owner_key: str, day: date | None = None) -> int:
    """Refund one conversion (job failed / cancelled before start).
    Never goes below zero. Returns the new ``used`` value."""
    day = day or quota_day()
    row = await db.get(Quota, (owner_key, day))
    if row is None or row.used <= 0:
        return 0
    row.used -= 1
    await db.commit()
    return row.used


async def usage_for(db, owner_keys: list[str], limit: int) -> dict:
    """Usage summary for one or more owner keys (anonymous: stricter
    counter applies, i.e. the max)."""
    day = quota_day()
    used = 0
    for key in owner_keys:
        used = max(used, await get_used(db, key, day))
    return {
        "used": used,
        "limit": limit,
        "remaining": max(0, limit - used),
        "resets_at": resets_at().isoformat(),
    }


async def check_and_consume(db, owner_keys: list[str], limit: int) -> dict:
    """Raise 403 when the quota is exhausted, else count one conversion
    on EVERY supplied key and return the usage summary."""
    from .deps import api_error

    summary = await usage_for(db, owner_keys, limit)
    if summary["used"] >= limit:
        raise api_error(
            403, "quota_exceeded",
            f"You have used all {limit} free conversions for today.",
            "Your quota resets at midnight. Upgrade for a higher daily limit.",
        )
    for key in owner_keys:
        await consume(db, key)
    return await usage_for(db, owner_keys, limit)


async def refund_all(db, owner_keys: list[str]) -> None:
    for key in owner_keys:
        await refund(db, key)
