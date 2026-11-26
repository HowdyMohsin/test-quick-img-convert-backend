"""Shared dependencies: settings, async engine/session, auth + CSRF.

Settings are read from the environment (see ``.env.example`` for every
variable). One runtime behaviour: secure cookies / HTTPS handling is
derived from the ``SITE_URL`` scheme, never from a separate toggle.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import AsyncGenerator

from fastapi import Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from . import models


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default)


@dataclass
class Settings:
    database_url: str = field(default_factory=lambda: _env(
        "DATABASE_URL", "sqlite+aiosqlite:///./dev.db"))
    secret_key: str = field(default_factory=lambda: _env("SECRET_KEY", ""))
    app_secret: str = field(default_factory=lambda: _env("APP_SECRET", ""))
    site_url: str = field(default_factory=lambda: _env("SITE_URL", "http://localhost:3000"))
    quota_tz: str = field(default_factory=lambda: _env("QUOTA_TZ", "Asia/Karachi"))
    data_dir: str = field(default_factory=lambda: _env("DATA_DIR", "./data"))
    retention_hours: int = field(default_factory=lambda: int(_env("RETENTION_HOURS", "24")))
    env: str = field(default_factory=lambda: _env("ENV", "development"))
    api_docs: bool = field(default_factory=lambda: _env("API_DOCS", "false").lower() == "true")
    smtp_host: str = field(default_factory=lambda: _env("SMTP_HOST", ""))
    smtp_port: int = field(default_factory=lambda: int(_env("SMTP_PORT", "587")))
    smtp_user: str = field(default_factory=lambda: _env("SMTP_USER", ""))
    smtp_password: str = field(default_factory=lambda: _env("SMTP_PASSWORD", ""))
    smtp_from: str = field(default_factory=lambda: _env("SMTP_FROM", ""))
    google_client_id: str = field(default_factory=lambda: _env("GOOGLE_CLIENT_ID", ""))
    pkr_per_usd: float = field(default_factory=lambda: float(_env("PKR_PER_USD", "280")))
    approval_window_hours: int = field(default_factory=lambda: int(_env("APPROVAL_WINDOW_HOURS", "24")))

    @property
    def is_https(self) -> bool:
        return self.site_url.lower().startswith("https://")

    @property
    def secret(self) -> str:
        """Signing secret: SECRET_KEY, falling back to APP_SECRET."""
        return self.secret_key or self.app_secret


_settings: Settings | None = None


def get_settings() -> Settings:
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings


def reset_settings() -> None:
    global _settings
    _settings = None


# ---------------------------------------------------------------- engine

_engine = None
_engine_url: str | None = None
_SessionLocal: async_sessionmaker[AsyncSession] | None = None


def get_engine():
    global _engine, _engine_url, _SessionLocal
    settings = get_settings()
    url = settings.database_url
    if _engine is None or _engine_url != url:
        kwargs: dict = {}
        if url.startswith("sqlite"):
            kwargs["connect_args"] = {"check_same_thread": False}
        else:
            # Small, explicit pool for small PostgreSQL instances (Render
            # free tier, and the compose box with max_connections=50):
            # one single-worker API may hold at most 5 + 2 connections
            # here; the sync DbStore (app/pipeline.py) holds at most
            # 3 + 2. pool_pre_ping survives idle connections the server
            # has dropped, and pool_recycle bounds connection lifetime.
            # Without this, SQLAlchemy defaults are pool_size=5,
            # max_overflow=10 per engine, which across the async engine,
            # the sync store and the worker could approach the 50 limit.
            kwargs["pool_size"] = 5
            kwargs["max_overflow"] = 2
            kwargs["pool_pre_ping"] = True
            kwargs["pool_recycle"] = 300
        _engine = create_async_engine(url, **kwargs)
        _engine_url = url
        _SessionLocal = async_sessionmaker(_engine, expire_on_commit=False, class_=AsyncSession)
    return _engine


def reset_engine() -> None:
    global _engine, _engine_url, _SessionLocal
    _engine = None
    _engine_url = None
    _SessionLocal = None


def get_sessionmaker() -> async_sessionmaker[AsyncSession]:
    get_engine()
    assert _SessionLocal is not None
    return _SessionLocal


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    session = get_sessionmaker()()
    try:
        yield session
    finally:
        await session.close()


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def ensure_aware(dt: datetime | None) -> datetime | None:
    """Make a DB datetime timezone-aware (assume UTC when naive).

    SQLite returns naive datetimes even for DateTime(timezone=True)
    columns; PostgreSQL returns aware ones. Normalising at the
    comparison point keeps the same code correct on both.
    """
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


# ---------------------------------------------------------------- errors

def api_error(status: int, code: str, message: str, hint: str = "") -> HTTPException:
    """The single error shape: {"error": {code, message, hint}}.

    FastAPI's HTTPException detail carries the dict; main.py's handler
    renders it verbatim.
    """
    return HTTPException(
        status_code=status,
        detail={"error": {"code": code, "message": message, "hint": hint or message}},
    )


# ---------------------------------------------------------------- sessions

SESSION_COOKIE = "qic_session"
DEVICE_COOKIE = "qic_device"
CSRF_COOKIE = "qic_csrf_secret"
CSRF_HEADER = "X-CSRF-Token"

SESSION_SLIDING_DAYS = 30
SESSION_ABSOLUTE_DAYS = 90
SESSION_BROWSER_HOURS = 24


def hash_session_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def new_session_token() -> str:
    return secrets.token_urlsafe(32)  # 256-bit


def csrf_token_for(secret_value: str) -> str:
    """CSRF token bound to a session/anonymous secret."""
    settings = get_settings()
    return hmac.new(
        settings.secret.encode("utf-8"),
        f"csrf:{secret_value}".encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


async def get_session_and_user(
    request: Request, db: AsyncSession
) -> tuple[models.Session | None, models.User | None]:
    """Resolve the ``qic_session`` cookie to (session, user) or (None, None)."""
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        return None, None
    from sqlalchemy import select

    token_hash = hash_session_token(token)
    result = await db.execute(
        select(models.Session).where(models.Session.token_hash == token_hash)
    )
    session = result.scalar_one_or_none()
    if session is None or session.revoked_at is not None:
        return None, None
    now = datetime.now(timezone.utc)
    if session.expires_at is not None and ensure_aware(session.expires_at) <= now:
        return None, None
    result = await db.execute(select(models.User).where(models.User.id == session.user_id))
    user = result.scalar_one_or_none()
    if user is None or user.deleted_at is not None:
        return None, None
    # Sliding expiry for "remember me" sessions, capped at the absolute cap.
    if session.remember:
        absolute_cap = ensure_aware(session.created_at) + timedelta(days=SESSION_ABSOLUTE_DAYS)
        new_exp = min(now + timedelta(days=SESSION_SLIDING_DAYS), absolute_cap)
        if new_exp > session.expires_at:
            session.expires_at = new_exp
    session.last_seen_at = now
    user.last_seen_at = now
    await db.commit()
    return session, user


async def get_current_user(
    request: Request, db: AsyncSession = Depends(get_db)
) -> models.User:
    _, user = await get_session_and_user(request, db)
    if user is None:
        raise api_error(401, "unauthenticated", "You need to sign in to do that.",
                        "Sign in and try again.")
    if user.banned:
        raise api_error(403, "account_banned",
                        f"Your account is banned. {user.ban_reason or ''}".strip(),
                        "Contact support if you think this is a mistake.")
    return user


async def get_optional_user(
    request: Request, db: AsyncSession = Depends(get_db)
) -> models.User | None:
    _, user = await get_session_and_user(request, db)
    if user is not None and user.banned:
        raise api_error(403, "account_banned",
                        f"Your account is banned. {user.ban_reason or ''}".strip(),
                        "Contact support if you think this is a mistake.")
    return user


async def get_current_session(
    request: Request, db: AsyncSession = Depends(get_db)
) -> models.Session:
    session, user = await get_session_and_user(request, db)
    if session is None or user is None:
        raise api_error(401, "unauthenticated", "You need to sign in to do that.",
                        "Sign in and try again.")
    if user.banned:
        raise api_error(403, "account_banned",
                        f"Your account is banned. {user.ban_reason or ''}".strip(),
                        "Contact support if you think this is a mistake.")
    return session


def require_csrf(request: Request, session: models.Session | None) -> None:
    """Verify the X-CSRF-Token header against the session (or the
    anonymous CSRF secret cookie for signed-out mutations)."""
    supplied = request.headers.get(CSRF_HEADER, "")
    if not supplied:
        raise api_error(403, "csrf_required",
                        "This request needs a valid CSRF token.",
                        "Fetch a token from GET /v1/auth/csrf and send it as X-CSRF-Token.")
    if session is not None:
        expected = csrf_token_for(session.csrf_secret)
    else:
        secret = request.cookies.get(CSRF_COOKIE, "")
        if not secret:
            raise api_error(403, "csrf_required",
                            "This request needs a valid CSRF token.",
                            "Fetch a token from GET /v1/auth/csrf and send it as X-CSRF-Token.")
        expected = csrf_token_for(secret)
    if not hmac.compare_digest(supplied, expected):
        raise api_error(403, "csrf_invalid",
                        "The CSRF token is invalid or has expired.",
                        "Fetch a fresh token from GET /v1/auth/csrf and try again.")


def client_ip(request: Request) -> str:
    """Client IP: honour X-Forwarded-For only as the leftmost entry
    (reverse proxy in front), else the direct peer."""
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def parse_user_agent(request: Request) -> tuple[str, str]:
    """Best-effort (device, browser) labels from a User-Agent string."""
    ua = request.headers.get("user-agent", "")
    ua_low = ua.lower()
    if "iphone" in ua_low or "ipad" in ua_low:
        device = "iPhone" if "iphone" in ua_low else "iPad"
    elif "android" in ua_low:
        device = "Android device"
    elif "macintosh" in ua_low or "mac os" in ua_low:
        device = "Mac"
    elif "windows" in ua_low:
        device = "Windows PC"
    elif "linux" in ua_low:
        device = "Linux PC"
    else:
        device = "Unknown device"
    if "edg/" in ua_low:
        browser = "Edge"
    elif "chrome/" in ua_low:
        browser = "Chrome"
    elif "firefox/" in ua_low:
        browser = "Firefox"
    elif "safari/" in ua_low and "chrome" not in ua_low:
        browser = "Safari"
    else:
        browser = "Unknown browser"
    return device, browser
