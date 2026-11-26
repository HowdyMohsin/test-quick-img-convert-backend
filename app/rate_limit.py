"""Rate limits (v5 sections 8.4 and 11).

In-memory sliding-window counters for per-IP / per-email limits, plus
DB-backed login-failure lockout via ``auth_attempts`` (spec 8.3):
5 failures per account+IP in 15 minutes locks that pair for 15
minutes; 20 failures per IP in 15 minutes blocks the IP.

All limits return 429 with a ``Retry-After`` header and a plain
sentence (the error shape is applied by the caller / handler).
"""

from __future__ import annotations

import time
from collections import deque
from datetime import datetime, timedelta, timezone

from fastapi import Request
from sqlalchemy import func, select

from .deps import api_error, client_ip
from .models import AuthAttempt
from .security import hash_email


class RateLimiter:
    """Sliding-window limiter keyed by an arbitrary string."""

    def __init__(self) -> None:
        self._buckets: dict[str, deque[float]] = {}

    def check(self, key: str, limit: int, window_seconds: int) -> int | None:
        """Return seconds to wait when over the limit, else None.

        Callers raise the 429 themselves so the message can name the
        action.
        """
        now = time.monotonic()
        bucket = self._buckets.setdefault(key, deque())
        while bucket and bucket[0] <= now - window_seconds:
            bucket.popleft()
        if len(bucket) >= limit:
            return int(bucket[0] + window_seconds - now) + 1
        bucket.append(now)
        return None

    def reset(self) -> None:
        self._buckets.clear()


limiter = RateLimiter()


def reset_rate_limits() -> None:
    limiter.reset()


def rate_limit_or_429(key: str, limit: int, window_seconds: int, what: str) -> None:
    wait = limiter.check(key, limit, window_seconds)
    if wait is not None:
        raise api_error(
            429, "rate_limited",
            f"Too many {what} attempts. Please try again in {wait} seconds.",
            f"Wait {wait} seconds and try again.",
        )


def ip_key(request: Request, scope: str) -> str:
    return f"{scope}:{client_ip(request)}"


# ---------------------------------------------------------------- login lockout

LOCKOUT_WINDOW = timedelta(minutes=15)
PAIR_FAILURE_LIMIT = 5
IP_FAILURE_LIMIT = 20


async def record_auth_attempt(db, kind: str, email: str | None, ip: str, success: bool) -> None:
    db.add(AuthAttempt(
        kind=kind,
        email_hash=hash_email(email) if email else None,
        ip=ip,
        success=success,
    ))
    await db.commit()


async def login_locked(db, email: str, ip: str) -> int | None:
    """Seconds remaining on a login lockout for this account+IP or IP,
    else None."""
    since = datetime.now(timezone.utc) - LOCKOUT_WINDOW
    email_hash = hash_email(email)
    pair = await db.execute(
        select(func.count()).select_from(AuthAttempt).where(
            AuthAttempt.kind == "login",
            AuthAttempt.success.is_(False),
            AuthAttempt.email_hash == email_hash,
            AuthAttempt.ip == ip,
            AuthAttempt.ts >= since,
        )
    )
    if (pair.scalar() or 0) >= PAIR_FAILURE_LIMIT:
        return _remaining_lockout(db, email_hash, ip, since)
    ip_count = await db.execute(
        select(func.count()).select_from(AuthAttempt).where(
            AuthAttempt.kind == "login",
            AuthAttempt.success.is_(False),
            AuthAttempt.ip == ip,
            AuthAttempt.ts >= since,
        )
    )
    if (ip_count.scalar() or 0) >= IP_FAILURE_LIMIT:
        return _remaining_lockout(db, None, ip, since)
    return None


async def _remaining_lockout(db, email_hash: str | None, ip: str, since: datetime) -> int:
    conds = [
        AuthAttempt.kind == "login",
        AuthAttempt.success.is_(False),
        AuthAttempt.ip == ip,
        AuthAttempt.ts >= since,
    ]
    if email_hash:
        conds.append(AuthAttempt.email_hash == email_hash)
    latest = await db.execute(
        select(func.max(AuthAttempt.ts)).select_from(AuthAttempt).where(*conds)
    )
    last = latest.scalar()
    if last is None:
        return 15 * 60
    if last.tzinfo is None:
        last = last.replace(tzinfo=timezone.utc)
    remaining = int((last + LOCKOUT_WINDOW - datetime.now(timezone.utc)).total_seconds())
    return max(1, remaining)
