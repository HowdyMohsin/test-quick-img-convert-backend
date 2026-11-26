"""Admin authentication for Quick IMG Convert v5 (spec §13.2).

Rules implemented here (admin-only, do NOT apply to user accounts):

* Argon2id passwords, same parameters as the user validator in
  ``app.passwords`` (~64 MiB, 3 iterations, 1 lane). Imported from
  ``app.passwords`` when it exists; a local implementation with identical
  parameters is used as a fallback until the core agent lands it.
* Login: 8 failed attempts per 5 minutes (per email + IP) then lockout,
  with the remaining lockout time returned in the error.
* Session: random 256-bit token, only its SHA-256 hash stored in
  ``admin_sessions``; cookie ``qic_admin`` (HttpOnly, Secure when
  ``SITE_URL`` is https, SameSite=Lax, Path=/, 7 days).
* CSRF: token bound to the admin session via HMAC (no extra column needed
  — ``admin_sessions`` has no ``csrf_secret`` column in spec §10), issued
  by ``GET /admin/auth/csrf`` and required as ``X-CSRF-Token`` on every
  mutation.
* Forced password change at first login (``must_change_password``); the
  admin minimum is **12 characters** (spec §13.2). This 12-char rule is
  ADMIN-ONLY; user accounts keep the v5 §8.1 rule (10-128 chars) owned by
  ``app.passwords``.
* Optional TOTP (RFC 6238, 30 s step, ±1 window) with recovery codes.
  The TOTP secret is encrypted with AES-GCM (key derived from
  ``APP_SECRET`` via ``app.security`` when available, local AES-GCM
  fallback otherwise).
* Session invalidation on password change (all sessions revoked).
* Optional IP allow-list read from ``site_settings`` key
  ``admin_ip_allowlist`` (JSON list of IPs / CIDR ranges; empty = allow all).
* Server-side role checks: roles ``super_admin`` / ``staff``; per-sidebar-
  section read/write permissions stored as JSONB on ``admin_users``.
  ``super_admin`` has every permission.
* Every mutation is written to ``audit_log`` (see ``app.audit``).

The first admin exists ONLY through the CLI ``create-admin`` (owned by the
core agent). There are no default credentials anywhere in this module.
A user session (``qic_session``) never grants admin access: separate
cookie, separate table, separate port.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import struct
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    JSON,
    String,
    Text,
    func,
    select,
)
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ADMIN_COOKIE = "qic_admin"
SESSION_DAYS = 7
MAX_LOGIN_ATTEMPTS = 8
LOCKOUT_WINDOW_SECONDS = 5 * 60
ADMIN_MIN_PASSWORD_LEN = 12
ADMIN_MAX_PASSWORD_LEN = 128
TOTP_STEP_SECONDS = 30
TOTP_WINDOW = 1
RESET_TOKEN_TTL_SECONDS = 3600

# Sidebar sections from spec §13.1. Permissions are keyed by these names.
SIDEBAR_SECTIONS = (
    "dashboard",
    "users",
    "payments",
    "plans",
    "formats",
    "ads",
    "popups",
    "jobs",
    "reports",
    "team",
    "settings",
    "audit",
)

# ---------------------------------------------------------------------------
# Standard error shape (contract §0 / §11): {"error": {code, message, hint}}
# ---------------------------------------------------------------------------

def admin_error(
    status: int, code: str, message: str, hint: str = "", **extra: Any
) -> HTTPException:
    detail: dict[str, Any] = {
        "error": {"code": code, "message": message, "hint": hint}
    }
    if extra:
        detail["error"].update(extra)
    return HTTPException(status_code=status, detail=detail)


async def _http_exception_handler(request: Request, exc: HTTPException):
    """Render HTTPException in the standard {"error": {...}} shape.

    FastAPI's default handler wraps ``detail`` in ``{"detail": ...}``; the
    v5 contract requires the error object at the top level. The core agent
    (``api/app/main.py``) should install this same handler globally; it is
    provided here so the admin routers behave correctly standalone too.
    """
    if isinstance(exc.detail, dict) and "error" in exc.detail:
        return JSONResponse(status_code=exc.status_code, content=exc.detail)
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": {
                "code": "http_error",
                "message": str(exc.detail),
                "hint": "",
            }
        },
    )


def install_admin_error_handlers(app) -> None:
    app.add_exception_handler(HTTPException, _http_exception_handler)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _env_secret() -> str:
    return os.environ.get("APP_SECRET") or os.environ.get("SECRET_KEY") or ""


def _site_url() -> str:
    return os.environ.get("SITE_URL", "http://localhost:3001")


def _secure_cookie() -> bool:
    return _site_url().lower().startswith("https://")


# ---------------------------------------------------------------------------
# Passwords: prefer app.passwords (core agent), local Argon2id fallback
# ---------------------------------------------------------------------------

_core_hash = None
_core_verify = None
try:  # pragma: no cover - depends on whether core agent has landed
    from app.passwords import (  # type: ignore
        hash_password as _core_hash,
        verify_password as _core_verify,
    )
except Exception:
    _core_hash = None
    _core_verify = None


def hash_password(password: str) -> str:
    if _core_hash is not None:
        return _core_hash(password)
    from argon2.low_level import Type, hash_secret_raw

    salt = secrets.token_bytes(16)
    raw = hash_secret_raw(
        password.encode("utf-8"),
        salt,
        time_cost=3,
        memory_cost=65536,  # ~64 MiB
        parallelism=1,
        hash_len=32,
        type=Type.ID,
    )
    params = "m=65536,t=3,p=1"
    return (
        "$argon2id$v=19$" + params + "$"
        + base64.b64encode(salt).decode().rstrip("=")
        + "$" + base64.b64encode(raw).decode().rstrip("=")
    )


def _argon2_verify(stored: str, password: str) -> bool:
    from argon2.low_level import Type, verify_secret

    try:
        return verify_secret(stored.encode("utf-8"), password.encode("utf-8"), Type.ID)
    except Exception:
        return False


def verify_password(stored: Optional[str], password: str) -> bool:
    """Constant-time-ish verify; False (never raises) for missing/bad hashes."""
    if not stored or not password:
        return False
    if _core_verify is not None:
        try:
            return bool(_core_verify(stored, password))
        except Exception:
            return False
    return _argon2_verify(stored, password)


def validate_admin_password(password: str) -> Optional[str]:
    """Admin-only password rule (spec §13.2): minimum 12 characters.

    Returns an error string, or None when the password is acceptable.
    No composition rules, no maximum below the 128-char v5 cap.
    """
    if not isinstance(password, str) or len(password) < ADMIN_MIN_PASSWORD_LEN:
        return (
            f"Password must be at least {ADMIN_MIN_PASSWORD_LEN} characters long."
        )
    if len(password) > ADMIN_MAX_PASSWORD_LEN:
        return "Password must be at most 128 characters long."
    return None


# ---------------------------------------------------------------------------
# AES-GCM encryption for the TOTP secret: app.security first, local fallback
# ---------------------------------------------------------------------------

_encrypt_fn = None
_decrypt_fn = None
try:  # pragma: no cover - depends on core agent's app.security API
    import app.security as _security  # type: ignore

    for _enc_name, _dec_name in (
        ("encrypt_str", "decrypt_str"),
        ("encrypt_text", "decrypt_text"),
        ("encrypt", "decrypt"),
    ):
        if hasattr(_security, _enc_name) and hasattr(_security, _dec_name):
            _encrypt_fn = getattr(_security, _enc_name)
            _decrypt_fn = getattr(_security, _dec_name)
            break
    if _encrypt_fn is None and hasattr(_security, "encrypt_config") and hasattr(
        _security, "decrypt_config"
    ):
        # Core API: encrypt_config(app_secret, plaintext) — bind APP_SECRET.
        import functools as _functools

        _app_secret = os.environ.get("APP_SECRET") or ""
        _encrypt_fn = _functools.partial(_security.encrypt_config, _app_secret)
        _decrypt_fn = _functools.partial(_security.decrypt_config, _app_secret)
except Exception:
    _encrypt_fn = None
    _decrypt_fn = None


def _local_key() -> bytes:
    return hashlib.sha256(_env_secret().encode("utf-8")).digest()


def encrypt_secret(plaintext: str) -> str:
    """Encrypt a short secret with AES-GCM; returns urlsafe-base64 blob."""
    if _encrypt_fn is not None:
        return str(_encrypt_fn(plaintext))
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    nonce = secrets.token_bytes(12)
    ct = AESGCM(_local_key()).encrypt(nonce, plaintext.encode("utf-8"), None)
    return base64.urlsafe_b64encode(nonce + ct).decode("utf-8")


def decrypt_secret(blob: str) -> str:
    if _decrypt_fn is not None:
        return str(_decrypt_fn(blob))
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    raw = base64.urlsafe_b64decode(blob.encode("utf-8"))
    nonce, ct = raw[:12], raw[12:]
    return AESGCM(_local_key()).decrypt(nonce, ct, None).decode("utf-8")


# ---------------------------------------------------------------------------
# Fallback ORM models (used only while app.models does not exist yet).
# The core agent owns app.models; when it lands, these definitions are
# skipped entirely and the imported models are used instead.
# ---------------------------------------------------------------------------

class Base(DeclarativeBase):
    pass


try:
    from app.models import AdminSession as AdminSession  # type: ignore
    from app.models import AdminUser as AdminUser  # type: ignore

    _MODELS_FROM_CORE = True
except Exception:  # pragma: no cover - core models not present yet
    _MODELS_FROM_CORE = False

    class AdminUser(Base):
        __tablename__ = "admin_users"

        id: Mapped[str] = mapped_column(
            String(36), primary_key=True, default=lambda: str(__import__("uuid").uuid4())
        )
        email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
        password_hash: Mapped[str] = mapped_column(Text, nullable=False)
        role: Mapped[str] = mapped_column(String(32), nullable=False, default="staff")
        permissions: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
        active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
        must_change_password: Mapped[bool] = mapped_column(
            Boolean, nullable=False, default=True
        )
        totp_secret: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
        last_login_at: Mapped[Optional[datetime]] = mapped_column(
            DateTime(timezone=True), nullable=True
        )
        created_at: Mapped[datetime] = mapped_column(
            DateTime(timezone=True), nullable=False, default=_utcnow
        )

    class AdminSession(Base):
        __tablename__ = "admin_sessions"

        id: Mapped[str] = mapped_column(
            String(36), primary_key=True, default=lambda: str(__import__("uuid").uuid4())
        )
        admin_id: Mapped[str] = mapped_column(
            String(36), ForeignKey("admin_users.id"), nullable=False
        )
        token_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
        ip: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
        user_agent: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
        created_at: Mapped[datetime] = mapped_column(
            DateTime(timezone=True), nullable=False, default=_utcnow
        )
        expires_at: Mapped[datetime] = mapped_column(
            DateTime(timezone=True), nullable=False
        )
        revoked_at: Mapped[Optional[datetime]] = mapped_column(
            DateTime(timezone=True), nullable=True
        )


# ---------------------------------------------------------------------------
# Database session: prefer core app.deps.get_db, local fallback otherwise
# ---------------------------------------------------------------------------

_core_get_db = None
try:  # pragma: no cover - depends on core agent
    from app.deps import get_db as _core_get_db  # type: ignore
except Exception:
    _core_get_db = None

_engine = None
_session_factory = None


def _fallback_engine():
    global _engine
    if _engine is None:
        url = os.environ.get(
            "DATABASE_URL", "sqlite+aiosqlite:///./quick-img-convert.db"
        )
        if "+asyncpg" in url:  # pragma: no cover - asyncpg URL kept as-is
            pass
        kwargs: dict = {}
        if not url.startswith("sqlite"):
            # Small pool for small PostgreSQL instances (see app/deps.py).
            # This fallback engine only exists when core app.deps cannot
            # be imported; in the real app get_db() from deps is used.
            kwargs["pool_size"] = 5
            kwargs["max_overflow"] = 2
            kwargs["pool_pre_ping"] = True
            kwargs["pool_recycle"] = 300
        _engine = create_async_engine(url, future=True, **kwargs)
    return _engine


def _fallback_session_factory():
    global _session_factory
    if _session_factory is None:
        _session_factory = async_sessionmaker(
            bind=_fallback_engine(), expire_on_commit=False
        )
    return _session_factory


async def get_db():
    """Yield an AsyncSession. Core ``app.deps.get_db`` when available."""
    if _core_get_db is not None:
        async for session in _core_get_db():
            yield session
        return
    session = _fallback_session_factory()()
    try:
        yield session
    finally:
        await session.close()


# ---------------------------------------------------------------------------
# Login attempt tracking: 8 failures / 5 min per (email, IP), then lockout
# ---------------------------------------------------------------------------

_LOGIN_FAILURES: dict[str, deque] = defaultdict(deque)
_LOGIN_LOCKED_UNTIL: dict[str, float] = {}


def _attempt_key(email: str, ip: str) -> str:
    return f"{email.strip().lower()}|{ip or ''}"


def _lockout_remaining_seconds(email: str, ip: str) -> float:
    key = _attempt_key(email, ip)
    now = time.time()
    locked_until = _LOGIN_LOCKED_UNTIL.get(key, 0.0)
    if locked_until > now:
        return locked_until - now
    window_start = now - LOCKOUT_WINDOW_SECONDS
    failures = _LOGIN_FAILURES.get(key)
    if failures is not None:
        while failures and failures[0] < window_start:
            failures.popleft()
        if len(failures) >= MAX_LOGIN_ATTEMPTS:
            _LOGIN_LOCKED_UNTIL[key] = now + LOCKOUT_WINDOW_SECONDS
            return float(LOCKOUT_WINDOW_SECONDS)
    return 0.0


def _record_login_failure(email: str, ip: str) -> float:
    """Record a failure; returns remaining lockout seconds (0 if not locked)."""
    key = _attempt_key(email, ip)
    now = time.time()
    _LOGIN_FAILURES[key].append(now)
    return _lockout_remaining_seconds(email, ip)


def _clear_login_failures(email: str, ip: str) -> None:
    key = _attempt_key(email, ip)
    _LOGIN_FAILURES.pop(key, None)
    _LOGIN_LOCKED_UNTIL.pop(key, None)


def reset_admin_login_attempts() -> None:
    """Test/support helper: clear all in-memory admin login attempt state."""
    _LOGIN_FAILURES.clear()
    _LOGIN_LOCKED_UNTIL.clear()

# ---------------------------------------------------------------------------
# Session tokens, CSRF tokens, signed reset tokens
# ---------------------------------------------------------------------------

def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def make_csrf_token(session_token_hash: str) -> str:
    """CSRF token bound to the admin session (HMAC, no DB column needed)."""
    secret = _env_secret()
    return hmac.new(
        secret.encode("utf-8"),
        f"admin-csrf:{session_token_hash}".encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def check_csrf_token(token: Optional[str], session_token_hash: str) -> bool:
    if not token:
        return False
    return hmac.compare_digest(token, make_csrf_token(session_token_hash))


def make_admin_reset_token(admin_id: str, ttl: int = RESET_TOKEN_TTL_SECONDS) -> str:
    """One-time admin password-reset token (HMAC-signed, 1 h expiry).

    No DB row is needed: the signature covers admin id + expiry. Used by
    POST /admin/team/{id}/reset-link; consumed by POST /admin/auth/reset-password.
    """
    payload = json.dumps(
        {"admin_id": admin_id, "exp": int(time.time()) + ttl},
        separators=(",", ":"),
    ).encode("utf-8")
    payload_b64 = base64.urlsafe_b64encode(payload).decode("utf-8").rstrip("=")
    sig = hmac.new(
        _env_secret().encode("utf-8"), payload_b64.encode("utf-8"), hashlib.sha256
    ).hexdigest()
    return f"{payload_b64}.{sig}"


def verify_admin_reset_token(token: str) -> Optional[str]:
    """Return the admin id for a valid, unexpired reset token, else None."""
    try:
        payload_b64, sig = token.rsplit(".", 1)
        expected = hmac.new(
            _env_secret().encode("utf-8"),
            payload_b64.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(sig, expected):
            return None
        payload = json.loads(
            base64.urlsafe_b64decode(payload_b64 + "=" * (-len(payload_b64) % 4))
        )
        if int(payload["exp"]) < int(time.time()):
            return None
        return str(payload["admin_id"])
    except Exception:
        return None


def set_admin_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        ADMIN_COOKIE,
        token,
        max_age=SESSION_DAYS * 24 * 3600,
        expires=SESSION_DAYS * 24 * 3600,
        path="/",
        httponly=True,
        secure=_secure_cookie(),
        samesite="lax",
    )


def clear_admin_cookie(response: Response) -> None:
    response.delete_cookie(ADMIN_COOKIE, path="/")


def _client_ip(request: Request) -> Optional[str]:
    if request.client is not None:
        return request.client.host
    return None


# ---------------------------------------------------------------------------
# TOTP (RFC 6238)
# ---------------------------------------------------------------------------

def _totp_code(secret_b32: str, at: Optional[float] = None) -> str:
    key = base64.b32decode(secret_b32.upper())
    counter = int((time.time() if at is None else at) // TOTP_STEP_SECONDS)
    digest = hmac.new(
        key, struct.pack(">Q", counter), hashlib.sha1
    ).digest()
    offset = digest[-1] & 0x0F
    code = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(code % 1_000_000).zfill(6)


def verify_totp_code(secret_b32: str, code: str) -> bool:
    if not code or not re.fullmatch(r"\d{6}", code.strip()):
        return False
    code = code.strip()
    now = time.time()
    for step_offset in range(-TOTP_WINDOW, TOTP_WINDOW + 1):
        if hmac.compare_digest(
            _totp_code(secret_b32, now + step_offset * TOTP_STEP_SECONDS), code
        ):
            return True
    return False


def _load_totp_blob(admin) -> dict:
    """Decode the (encrypted) totp_secret blob; {} when TOTP is not set up."""
    blob = getattr(admin, "totp_secret", None)
    if not blob:
        return {}
    try:
        return json.loads(decrypt_secret(blob))
    except Exception:
        # Legacy shape: the blob was a bare encrypted base32 secret.
        try:
            return {"secret": decrypt_secret(blob), "verified": False}
        except Exception:
            return {}


def _store_totp_blob(db: AsyncSession, admin, data: dict) -> None:
    admin.totp_secret = encrypt_secret(json.dumps(data))
    db.add(admin)


def _totp_is_verified(admin) -> bool:
    data = _load_totp_blob(admin)
    return bool(data.get("secret")) and bool(data.get("verified"))


def _generate_recovery_codes(count: int = 10) -> list[str]:
    return ["-".join(secrets.token_hex(2) for _ in range(2)).upper() for _ in range(count)]


def _hash_recovery_code(code: str) -> str:
    return hashlib.sha256(code.replace("-", "").upper().encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Permissions / roles
# ---------------------------------------------------------------------------

def _permission_levels(admin, section: str) -> list[str]:
    perms = getattr(admin, "permissions", None) or {}
    if not isinstance(perms, dict):
        return []
    value = perms.get(section)
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple)):
        return [str(v) for v in value]
    if isinstance(value, dict):
        return [k for k, v in value.items() if v]
    return []


def has_permission(admin, section: str, level: str = "read") -> bool:
    """super_admin has every permission; staff need the section entry."""
    if getattr(admin, "role", None) == "super_admin":
        return True
    levels = _permission_levels(admin, section)
    if "write" in levels:
        return True
    return level == "read" and "read" in levels


def admin_public_dict(admin) -> dict:
    return {
        "id": str(admin.id),
        "email": admin.email,
        "role": admin.role,
        "permissions": getattr(admin, "permissions", None) or {},
        "active": bool(getattr(admin, "active", True)),
        "must_change_password": bool(getattr(admin, "must_change_password", False)),
        "totp_enabled": _totp_is_verified(admin),
        "last_login_at": (
            admin.last_login_at.isoformat() if getattr(admin, "last_login_at", None) else None
        ),
    }


# ---------------------------------------------------------------------------
# IP allow-list (site_settings key "admin_ip_allowlist")
# ---------------------------------------------------------------------------

async def _ip_allowed(db: AsyncSession, ip: Optional[str]) -> bool:
    if not ip:
        return True
    raw = None
    try:
        from app.models import SiteSetting  # type: ignore

        setting = (
            await db.execute(
                select(SiteSetting).where(SiteSetting.key == "admin_ip_allowlist")
            )
        ).scalar_one_or_none()
        raw = setting.value if setting is not None else None
    except Exception:
        # Core models not present yet: read the row with plain SQL.
        try:
            from sqlalchemy import text as _text

            row = (
                await db.execute(
                    _text("SELECT value FROM site_settings WHERE key = :key"),
                    {"key": "admin_ip_allowlist"},
                )
            ).first()
            raw = row[0] if row else None
        except Exception:
            raw = None
    if raw is None:
        return True
    try:
        allowed = json.loads(raw) if isinstance(raw, str) else raw
    except Exception:
        return True
    if not allowed:
        return True
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for entry in allowed:
        try:
            network = ipaddress.ip_network(str(entry), strict=False)
            if addr in network:
                return True
        except ValueError:
            if str(entry) == ip:
                return True
    return False


# ---------------------------------------------------------------------------
# Auth dependencies
# ---------------------------------------------------------------------------

async def get_current_admin(
    request: Request, db: AsyncSession = Depends(get_db)
):
    """Resolve the admin from the ``qic_admin`` cookie.

    A user session (``qic_session``) is never accepted here: separate
    cookie, separate table, separate port.
    """
    token = request.cookies.get(ADMIN_COOKIE)
    if not token:
        raise admin_error(
            401,
            "admin_auth_required",
            "Sign in to the admin panel to continue.",
            "Open the admin sign-in page and log in with an admin account.",
        )
    token_hash = _hash_token(token)
    session = (
        await db.execute(
            select(AdminSession).where(AdminSession.token_hash == token_hash)
        )
    ).scalar_one_or_none()
    if session is None or getattr(session, "revoked_at", None) is not None:
        raise admin_error(
            401,
            "admin_auth_required",
            "Your admin session is no longer valid. Sign in again.",
            "Sign in again with your admin account.",
        )
    expires_at = getattr(session, "expires_at", None)
    if expires_at is not None:
        exp = expires_at if expires_at.tzinfo else expires_at.replace(tzinfo=timezone.utc)
        if exp <= _utcnow():
            raise admin_error(
                401,
                "admin_auth_required",
                "Your admin session has expired. Sign in again.",
                "Sign in again with your admin account.",
            )
    admin = await db.get(AdminUser, session.admin_id)
    if admin is None or not getattr(admin, "active", True):
        raise admin_error(
            403,
            "admin_inactive",
            "This admin account is disabled.",
            "Ask another admin to re-enable the account.",
        )
    if not await _ip_allowed(db, _client_ip(request)):
        raise admin_error(
            403,
            "admin_ip_not_allowed",
            "This IP address is not allowed to access the admin panel.",
            "Ask an admin to add this IP to the admin IP allow-list.",
        )
    request.state.admin_session = session
    request.state.admin_session_token_hash = token_hash
    return admin


async def get_current_admin_no_password_gate(
    request: Request, db: AsyncSession = Depends(get_db)
):
    """Like ``get_current_admin``; used by /me, /csrf, /logout, /change-password."""
    return await get_current_admin(request, db)


def require_admin(section: Optional[str] = None, level: str = "read"):
    """Dependency: valid admin session + (optional) section permission.

    Admins with ``must_change_password`` set cannot use any protected
    section until they change their password (spec §13.2 forced change).
    """

    async def _dep(request: Request, admin=Depends(get_current_admin)):
        if getattr(admin, "must_change_password", False):
            raise admin_error(
                403,
                "password_change_required",
                "You must change your password before using the admin panel.",
                "Change your password, then sign in again.",
            )
        if section is not None and not has_permission(admin, section, level):
            raise admin_error(
                403,
                "admin_forbidden",
                "You do not have permission for this section.",
                "Ask a super admin to grant access to this section.",
            )
        return admin

    return _dep


def require_csrf(request: Request):
    """Dependency: valid ``X-CSRF-Token`` for the current admin session.

    Must be used together with ``get_current_admin`` (which stores the
    session token hash on ``request.state``).
    """
    token_hash = getattr(request.state, "admin_session_token_hash", None)
    if token_hash is None:
        raise admin_error(
            401,
            "admin_auth_required",
            "Sign in to the admin panel to continue.",
            "Open the admin sign-in page and log in with an admin account.",
        )
    header = request.headers.get("X-CSRF-Token")
    if not check_csrf_token(header, token_hash):
        raise admin_error(
            403,
            "csrf_required",
            "This request is missing a valid CSRF token.",
            "Fetch a token from GET /admin/auth/csrf and send it as X-CSRF-Token.",
        )
    return True


def _audit_ip(request: Request) -> Optional[str]:
    return _client_ip(request)

# ---------------------------------------------------------------------------
# Request bodies
# ---------------------------------------------------------------------------

class LoginBody(BaseModel):
    email: str
    password: str
    totp_code: Optional[str] = None


class ChangePasswordBody(BaseModel):
    current_password: str
    new_password: str


class TotpVerifyBody(BaseModel):
    code: str


class TotpDisableBody(BaseModel):
    password: str
    code: Optional[str] = None


class ResetPasswordBody(BaseModel):
    token: str
    new_password: str


# ---------------------------------------------------------------------------
# Router: /admin/auth/*
# ---------------------------------------------------------------------------

router = APIRouter(prefix="/admin/auth", tags=["admin-auth"])


async def _audit_login(db, admin, request, action: str, before=None, after=None):
    try:
        from app.audit import audit as _audit

        await _audit(
            db, admin.email, action, str(admin.id), before, after, _audit_ip(request)
        )
    except Exception:
        pass


@router.post("/login")
async def login(
    body: LoginBody, request: Request, response: Response, db: AsyncSession = Depends(get_db)
):
    """Admin sign-in. 8 failures / 5 min per email+IP then lockout (§13.2)."""
    email = body.email.strip().lower()
    ip = _client_ip(request)
    remaining = _lockout_remaining_seconds(email, ip or "")
    if remaining > 0:
        raise admin_error(
            429,
            "admin_locked_out",
            f"Too many failed sign-in attempts. Try again in {int(remaining // 60)} minutes {int(remaining % 60)} seconds.",
            "Wait for the lockout to end, then try again.",
            retry_after_seconds=int(remaining),
        )
    admin = (
        await db.execute(
            select(AdminUser).where(func.lower(AdminUser.email) == email)
        )
    ).scalar_one_or_none()

    # Always run a verify (even for unknown emails) so timing does not leak
    # whether the account exists. The error message never says which failed.
    password_ok = verify_password(
        getattr(admin, "password_hash", None) if admin else None, body.password
    )
    if admin is None or not password_ok:
        locked_for = _record_login_failure(email, ip or "")
        if locked_for > 0:
            raise admin_error(
                429,
                "admin_locked_out",
                f"Too many failed sign-in attempts. Try again in {int(locked_for // 60)} minutes {int(locked_for % 60)} seconds.",
                "Wait for the lockout to end, then try again.",
                retry_after_seconds=int(locked_for),
            )
        raise admin_error(
            401,
            "admin_invalid_credentials",
            "Email or password is incorrect.",
            "Check the email and password and try again.",
        )
    if not getattr(admin, "active", True):
        raise admin_error(
            403,
            "admin_inactive",
            "This admin account is disabled.",
            "Ask another admin to re-enable the account.",
        )
    if not await _ip_allowed(db, ip):
        raise admin_error(
            403,
            "admin_ip_not_allowed",
            "This IP address is not allowed to access the admin panel.",
            "Ask an admin to add this IP to the admin IP allow-list.",
        )

    # Optional TOTP: when enabled, a valid code (or recovery code) is required.
    totp_data = _load_totp_blob(admin)
    if _totp_is_verified(admin):
        code = (body.totp_code or "").strip()
        recovery_hashes = list(totp_data.get("recovery_hashes") or [])
        used_recovery = bool(code) and _hash_recovery_code(code) in recovery_hashes
        if not used_recovery and not verify_totp_code(totp_data["secret"], code):
            _record_login_failure(email, ip or "")
            raise admin_error(
                401,
                "admin_totp_required",
                "Enter the 6-digit code from your authenticator app.",
                "Open your authenticator app and enter the current code.",
            )
        if used_recovery:
            totp_data["recovery_hashes"] = [
                h for h in recovery_hashes if h != _hash_recovery_code(code)
            ]
            _store_totp_blob(db, admin, totp_data)

    _clear_login_failures(email, ip or "")
    token = secrets.token_urlsafe(32)
    now = _utcnow()
    db.add(
        AdminSession(
            admin_id=admin.id,
            token_hash=_hash_token(token),
            ip=ip,
            user_agent=request.headers.get("user-agent"),
            created_at=now,
            expires_at=now + timedelta(days=SESSION_DAYS),
        )
    )
    admin.last_login_at = now
    db.add(admin)
    await _audit_login(db, admin, request, "admin.login")
    await db.commit()
    set_admin_cookie(response, token)
    return {
        "email": admin.email,
        "role": admin.role,
        "must_change_password": bool(getattr(admin, "must_change_password", False)),
        "totp_enabled": _totp_is_verified(admin),
    }


@router.post("/logout")
async def logout(
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
    admin=Depends(get_current_admin_no_password_gate),
):
    session = getattr(request.state, "admin_session", None)
    if session is not None:
        session.revoked_at = _utcnow()
        db.add(session)
    await _audit_login(db, admin, request, "admin.logout")
    await db.commit()
    clear_admin_cookie(response)
    return {"signed_out": True}


@router.get("/me")
async def me(admin=Depends(get_current_admin_no_password_gate)):
    return admin_public_dict(admin)


@router.get("/csrf")
async def csrf(
    request: Request, admin=Depends(get_current_admin_no_password_gate)
):
    token_hash = getattr(request.state, "admin_session_token_hash", None)
    if token_hash is None:
        raise admin_error(
            401,
            "admin_auth_required",
            "Sign in to the admin panel to continue.",
            "Open the admin sign-in page and log in with an admin account.",
        )
    return {"csrf_token": make_csrf_token(token_hash)}


@router.post("/change-password")
async def change_password(
    body: ChangePasswordBody,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
    admin=Depends(get_current_admin_no_password_gate),
):
    """Change the admin password. Revokes ALL admin sessions (§13.2)."""
    if not verify_password(admin.password_hash, body.current_password):
        raise admin_error(
            401,
            "admin_invalid_credentials",
            "The current password is incorrect.",
            "Enter your current admin password.",
        )
    error = validate_admin_password(body.new_password)
    if error:
        raise admin_error(422, "admin_password_too_short", error,
                          "Use a password of at least 12 characters.")
    before = {"must_change_password": bool(admin.must_change_password)}
    admin.password_hash = hash_password(body.new_password)
    admin.must_change_password = False
    db.add(admin)
    # Session invalidation on password change: revoke every session,
    # including the one making this request.
    sessions = (
        await db.execute(
            select(AdminSession).where(
                AdminSession.admin_id == admin.id,
                AdminSession.revoked_at.is_(None),
            )
        )
    ).scalars().all()
    for session in sessions:
        session.revoked_at = _utcnow()
        db.add(session)
    await _audit_login(
        db, admin, request, "admin.change_password",
        before, {"must_change_password": False},
    )
    await db.commit()
    clear_admin_cookie(response)
    return {
        "changed": True,
        "message": "Password changed. Sign in again with your new password.",
    }


@router.post("/totp/setup")
async def totp_setup(
    request: Request,
    db: AsyncSession = Depends(get_db),
    admin=Depends(get_current_admin_no_password_gate),
):
    """Step 1 of TOTP enrolment: generate a secret and store it unverified."""
    if _totp_is_verified(admin):
        raise admin_error(
            409,
            "admin_totp_already_enabled",
            "Two-factor authentication is already enabled for this account.",
            "Disable it first if you want to set it up again.",
        )
    secret = base64.b32encode(secrets.token_bytes(20)).decode("utf-8").rstrip("=")
    _store_totp_blob(db, admin, {"secret": secret, "verified": False})
    await db.commit()
    issuer = "Quick IMG Convert Admin"
    otpauth_url = (
        "otpauth://totp/"
        f"{issuer}:{admin.email}?secret={secret}&issuer={issuer}&digits=6&period=30"
    )
    return {"secret": secret, "otpauth_url": otpauth_url}


@router.post("/totp/verify")
async def totp_verify(
    body: TotpVerifyBody,
    request: Request,
    db: AsyncSession = Depends(get_db),
    admin=Depends(get_current_admin_no_password_gate),
):
    """Step 2: confirm the TOTP code, enable TOTP, issue recovery codes."""
    data = _load_totp_blob(admin)
    if not data.get("secret"):
        raise admin_error(
            409,
            "admin_totp_not_setup",
            "Two-factor authentication has not been set up yet.",
            "Call POST /admin/auth/totp/setup first.",
        )
    if _totp_is_verified(admin):
        raise admin_error(
            409,
            "admin_totp_already_enabled",
            "Two-factor authentication is already enabled for this account.",
            "Disable it first if you want to set it up again.",
        )
    if not verify_totp_code(data["secret"], body.code):
        raise admin_error(
            401,
            "admin_totp_invalid",
            "That code is not correct. Try the current code from your app.",
            "Check the time on your device and enter the current code.",
        )
    recovery_codes = _generate_recovery_codes()
    data["verified"] = True
    data["recovery_hashes"] = [_hash_recovery_code(c) for c in recovery_codes]
    _store_totp_blob(db, admin, data)
    await _audit_login(db, admin, request, "admin.totp_enabled")
    await db.commit()
    # Recovery codes are shown exactly once, here.
    return {"enabled": True, "recovery_codes": recovery_codes}


@router.post("/totp/disable")
async def totp_disable(
    body: TotpDisableBody,
    request: Request,
    db: AsyncSession = Depends(get_db),
    admin=Depends(get_current_admin_no_password_gate),
):
    if not _totp_is_verified(admin):
        raise admin_error(
            409,
            "admin_totp_not_enabled",
            "Two-factor authentication is not enabled for this account.",
            "Nothing to disable.",
        )
    if not verify_password(admin.password_hash, body.password):
        raise admin_error(
            401,
            "admin_invalid_credentials",
            "The password is incorrect.",
            "Enter your current admin password.",
        )
    data = _load_totp_blob(admin)
    if body.code and not verify_totp_code(data["secret"], body.code):
        raise admin_error(
            401,
            "admin_totp_invalid",
            "That code is not correct.",
            "Enter the current code from your authenticator app.",
        )
    admin.totp_secret = None
    db.add(admin)
    await _audit_login(db, admin, request, "admin.totp_disabled")
    await db.commit()
    return {"disabled": True}


@router.post("/reset-password")
async def reset_password(body: ResetPasswordBody, db: AsyncSession = Depends(get_db)):
    """Consume a one-time reset link created by POST /admin/team/{id}/reset-link."""
    admin_id = verify_admin_reset_token(body.token)
    if admin_id is None:
        raise admin_error(
            401,
            "admin_reset_token_invalid",
            "This password reset link is invalid or has expired.",
            "Ask an admin to generate a new reset link.",
        )
    error = validate_admin_password(body.new_password)
    if error:
        raise admin_error(422, "admin_password_too_short", error,
                          "Use a password of at least 12 characters.")
    admin = await db.get(AdminUser, admin_id)
    if admin is None or not getattr(admin, "active", True):
        raise admin_error(
            404, "admin_not_found", "This admin account no longer exists.",
            "Ask an admin to create a new account.",
        )
    admin.password_hash = hash_password(body.new_password)
    admin.must_change_password = False
    db.add(admin)
    sessions = (
        await db.execute(
            select(AdminSession).where(
                AdminSession.admin_id == admin.id,
                AdminSession.revoked_at.is_(None),
            )
        )
    ).scalars().all()
    for session in sessions:
        session.revoked_at = _utcnow()
        db.add(session)
    await db.commit()
    return {"changed": True, "message": "Password reset. Sign in with your new password."}
