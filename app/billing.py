"""Billing core for Quick IMG Convert v5.

Owns: the shared error shape, rate limiting, coupon maths, PKR rounding,
subscription lifecycle, grace sweep, webhook event application, and the
fallback data models used until the core agent lands ``app.models``.

Model resolution: :func:`resolve_models` prefers the core agent's
``app.models`` when it exists and exposes every name we need; otherwise it
falls back to the models defined here (same table names and columns, per
spec section 3). Routers must resolve models lazily per request,
never at import time, so this package imports cleanly before ``app.models``
exists.
"""
from __future__ import annotations

import hashlib
import hmac as hmac_mod
import json
import logging
import math
import os
import re
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from types import SimpleNamespace
from typing import Any, Optional

from fastapi import Request
from fastapi.responses import JSONResponse
from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    Date,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
    select,
)
from sqlalchemy.orm import declarative_base

log = logging.getLogger("qic.billing")

BRAND_NAME = "Quick IMG Convert"
GRACE_DAYS = 7
WEBHOOK_IDEMPOTENCY_DAYS = 30
DEFAULT_PKR_PER_USD = 280.0  # fallback only; admin sets PKR_PER_USD / site setting
DEFAULT_APPROVAL_WINDOW_HOURS = 24


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------- errors
class ApiError(Exception):
    """Error in the standard shape {"error": {"code", "message", "hint"}}."""

    def __init__(self, status: int, code: str, message: str, hint: str = ""):
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message
        self.hint = hint


def error_payload(code: str, message: str, hint: str = "") -> dict:
    return {"error": {"code": code, "message": message, "hint": hint or ""}}


async def api_error_handler(_request: Request, exc: ApiError) -> JSONResponse:
    return JSONResponse(
        status_code=exc.status,
        content=error_payload(exc.code, exc.message, exc.hint),
    )


def err(status: int, code: str, message: str, hint: str = "") -> ApiError:
    return ApiError(status, code, message, hint)


# ------------------------------------------------------- fallback models
# Same table/column names as spec section 3. The core agent's
# app.models (Alembic 0001_initial) is authoritative in production; these
# exist so this package and its tests run before it lands.
FallbackBase = declarative_base()


class User(FallbackBase):
    __tablename__ = "users"
    __table_args__ = {"extend_existing": True}
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    email = Column(String, unique=True, nullable=False)
    email_verified_at = Column(DateTime(timezone=True), nullable=True)
    password_hash = Column(String, nullable=True)
    display_name = Column(String, nullable=True)
    plan = Column(String, nullable=False, default="free")
    banned = Column(Boolean, nullable=False, default=False)
    ban_reason = Column(String, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow)
    last_login_at = Column(DateTime(timezone=True), nullable=True)
    deleted_at = Column(DateTime(timezone=True), nullable=True)


class Plan(FallbackBase):
    __tablename__ = "plans"
    __table_args__ = {"extend_existing": True}
    id = Column(String, primary_key=True)  # slug: anonymous/free/basic/pro
    name = Column(String, nullable=False)
    price_cents = Column(Integer, nullable=False, default=0)
    price_yearly_cents = Column(Integer, nullable=False, default=0)
    currency = Column(String, nullable=False, default="USD")
    trial_days = Column(Integer, nullable=False, default=0)
    limits = Column(JSON, nullable=False, default=dict)
    featured = Column(Integer, nullable=False, default=0)
    active = Column(Boolean, nullable=False, default=True)
    archived = Column(Boolean, nullable=False, default=False)
    sort = Column(Integer, nullable=False, default=0)


class PlanPrice(FallbackBase):
    __tablename__ = "plan_prices"
    __table_args__ = {"extend_existing": True}
    plan_id = Column(String, ForeignKey("plans.id"), primary_key=True)
    provider_key = Column(String, primary_key=True)
    interval = Column(String, primary_key=True)
    provider_price_id = Column(String, nullable=False)


class Coupon(FallbackBase):
    __tablename__ = "coupons"
    __table_args__ = {"extend_existing": True}
    code = Column(String, primary_key=True)
    type = Column(String, nullable=False)  # percent | fixed
    value = Column(Integer, nullable=False)  # percent 0-100, or fixed USD cents
    plans = Column(JSON, nullable=True)  # list of plan ids, null = all
    intervals = Column(JSON, nullable=True)  # monthly/yearly/both
    recurring = Column(Boolean, nullable=False, default=False)
    max_uses = Column(Integer, nullable=True)
    used = Column(Integer, nullable=False, default=0)
    per_user_limit = Column(Integer, nullable=False, default=1)
    expires_at = Column(DateTime(timezone=True), nullable=True)
    active = Column(Boolean, nullable=False, default=True)


class Subscription(FallbackBase):
    __tablename__ = "subscriptions"
    __table_args__ = {"extend_existing": True}
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, ForeignKey("users.id"), nullable=False)
    plan_id = Column(String, ForeignKey("plans.id"), nullable=False)
    provider_key = Column(String, nullable=False)
    provider_sub_id = Column(String, nullable=True)
    interval = Column(String, nullable=False, default="monthly")
    coupon_code = Column(String, nullable=True)
    status = Column(String, nullable=False, default="active")
    cancel_at_period_end = Column(Boolean, nullable=False, default=False)
    current_period_end = Column(DateTime(timezone=True), nullable=True)
    grace_ends_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow)
    updated_at = Column(DateTime(timezone=True), default=utcnow)


class PaymentProviderRow(FallbackBase):
    __tablename__ = "payment_providers"
    __table_args__ = {"extend_existing": True}
    key = Column(String, primary_key=True)
    label = Column(String, nullable=False)
    flow = Column(String, nullable=False)  # manual | link | auto
    enabled = Column(Boolean, nullable=False, default=False)
    config = Column(Text, nullable=True)  # encrypted JSON, write-only
    sort = Column(Integer, nullable=False, default=0)


class PaymentRequest(FallbackBase):
    __tablename__ = "payment_requests"
    __table_args__ = {"extend_existing": True}
    __table_args__ = (
        UniqueConstraint("provider_key", "reference", name="uq_provider_reference"),
        {"extend_existing": True},
    )
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, ForeignKey("users.id"), nullable=False)
    plan_id = Column(String, ForeignKey("plans.id"), nullable=False)
    interval = Column(String, nullable=False, default="monthly")
    provider_key = Column(String, nullable=False)
    coupon_code = Column(String, nullable=True)
    amount_cents = Column(Integer, nullable=False)
    currency = Column(String, nullable=False, default="USD")
    display_amount = Column(Integer, nullable=True)  # PKR (whole) or USDT cents
    fx_rate = Column(Float, nullable=True)
    reference = Column(String, nullable=False)
    note = Column(Text, nullable=True)
    proof_path = Column(String, nullable=True)
    status = Column(String, nullable=False, default="pending")
    admin_note = Column(Text, nullable=True)
    receipt_no = Column(String, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow)
    resolved_at = Column(DateTime(timezone=True), nullable=True)
    resolved_by = Column(String, nullable=True)


class WebhookEvent(FallbackBase):
    __tablename__ = "webhook_events"
    __table_args__ = {"extend_existing": True}
    provider_key = Column(String, primary_key=True)
    event_id = Column(String, primary_key=True)
    received_at = Column(DateTime(timezone=True), default=utcnow)
    type = Column(String, nullable=False)
    payload = Column(JSON, nullable=False, default=dict)
    status = Column(String, nullable=False, default="received")
    error = Column(Text, nullable=True)


class AdSlot(FallbackBase):
    __tablename__ = "ad_slots"
    __table_args__ = {"extend_existing": True}
    # Canonical columns (v5 section 10): key is the primary key.
    key = Column(String, primary_key=True)
    label = Column(String, nullable=False, default="")
    placement = Column(String, nullable=False, default="")
    network = Column(String, nullable=False)  # adsense | adsterra | custom | house
    unit_id = Column(String, nullable=True)
    code = Column(Text, nullable=True)  # custom HTML
    size = Column(String, nullable=False, default="responsive")
    device = Column(String, nullable=False, default="all")
    freq_cap = Column(Integer, nullable=False, default=0)
    enabled = Column(Boolean, nullable=False, default=True)
    sort = Column(Integer, nullable=False, default=0)


class AdEvent(FallbackBase):
    __tablename__ = "ad_events"
    __table_args__ = {"extend_existing": True}
    id = Column(Integer, primary_key=True, autoincrement=True)
    # Canonical columns (v5 section 10): no page_view_id — dedup is
    # within a beacon batch, in app.ads.record_impressions.
    slot = Column(String, nullable=True)
    plan = Column(String, nullable=True)
    page = Column(String, nullable=True)
    device = Column(String, nullable=True)
    ts = Column(DateTime(timezone=True), default=utcnow)


class AdRevenue(FallbackBase):
    __tablename__ = "ad_revenue"
    __table_args__ = {"extend_existing": True}
    id = Column(Integer, primary_key=True, autoincrement=True)
    network = Column(String, nullable=False)
    day = Column(Date, nullable=False)
    amount_cents = Column(Integer, nullable=False, default=0)


class Popup(FallbackBase):
    __tablename__ = "popups"
    __table_args__ = {"extend_existing": True}
    key = Column(String, primary_key=True)
    enabled = Column(Boolean, nullable=False, default=True)
    title = Column(String, nullable=True)
    body = Column(Text, nullable=True)
    cta_text = Column(String, nullable=True)
    cta_href = Column(String, nullable=True)
    frequency = Column(String, nullable=True)
    schedule_start = Column(DateTime(timezone=True), nullable=True)
    schedule_end = Column(DateTime(timezone=True), nullable=True)
    pages = Column(JSON, nullable=True)
    sort = Column(Integer, nullable=False, default=0)


class Announcement(FallbackBase):
    __tablename__ = "announcements"
    __table_args__ = {"extend_existing": True}
    id = Column(Integer, primary_key=True, autoincrement=True)
    title = Column(String, nullable=True)
    body = Column(Text, nullable=True)
    enabled = Column(Boolean, nullable=False, default=True)
    starts_at = Column(DateTime(timezone=True), nullable=True)
    ends_at = Column(DateTime(timezone=True), nullable=True)
    dismissible = Column(Boolean, nullable=False, default=True)


class Notification(FallbackBase):
    __tablename__ = "notifications"
    __table_args__ = {"extend_existing": True}
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, ForeignKey("users.id"), nullable=False)
    kind = Column(String, nullable=False)
    title = Column(String, nullable=False)
    body = Column(Text, nullable=True)
    # Canonical column names (v5 section 10): href + boolean read.
    href = Column(String, nullable=True)
    read = Column(Boolean, nullable=False, default=False)
    created_at = Column(DateTime(timezone=True), default=utcnow)


class SiteSetting(FallbackBase):
    __tablename__ = "site_settings"
    __table_args__ = {"extend_existing": True}
    key = Column(String, primary_key=True)
    value = Column(JSON, nullable=True)


class AuditLog(FallbackBase):
    __tablename__ = "audit_log"
    __table_args__ = {"extend_existing": True}
    id = Column(Integer, primary_key=True, autoincrement=True)
    ts = Column(DateTime(timezone=True), default=utcnow)
    admin_email = Column(String, nullable=True)
    action = Column(String, nullable=False)
    target = Column(String, nullable=True)
    before = Column(JSON, nullable=True)
    after = Column(JSON, nullable=True)
    ip = Column(String, nullable=True)


_FALLBACK = SimpleNamespace(
    User=User, Plan=Plan, PlanPrice=PlanPrice, Coupon=Coupon, Subscription=Subscription,
    PaymentProvider=PaymentProviderRow, PaymentRequest=PaymentRequest,
    WebhookEvent=WebhookEvent, AdSlot=AdSlot, AdEvent=AdEvent,
    AdRevenue=AdRevenue, Popup=Popup, Announcement=Announcement,
    Notification=Notification, SiteSetting=SiteSetting, AuditLog=AuditLog,
)
_MODEL_NAMES = [
    "User", "Plan", "PlanPrice", "Coupon", "Subscription", "PaymentProvider",
    "PaymentRequest", "WebhookEvent", "AdSlot", "AdEvent", "AdRevenue",
    "Popup", "Announcement", "Notification", "SiteSetting", "AuditLog",
]

# Integration: when the canonical ``app.models`` exists and is complete,
# rebind the module-level model names (including ``FallbackBase``) to it,
# so anything importing these names — notably the payment/webhook tests,
# which build their database from ``FallbackBase.metadata`` — uses the
# canonical tables (e.g. ``users.marketing_opt_in``) instead of the
# fallback copies. ``_FALLBACK`` above keeps the true fallback set for
# ``resolve_models()`` when core models are incomplete.
try:
    import app.models as _core_models  # type: ignore

    _missing = [n for n in _MODEL_NAMES if not hasattr(_core_models, n)]
    if not _missing:
        FallbackBase = _core_models.Base
        User = _core_models.User
        Plan = _core_models.Plan
        PlanPrice = _core_models.PlanPrice
        Coupon = _core_models.Coupon
        Subscription = _core_models.Subscription
        PaymentProviderRow = _core_models.PaymentProvider
        PaymentRequest = _core_models.PaymentRequest
        WebhookEvent = _core_models.WebhookEvent
        AdSlot = _core_models.AdSlot
        AdEvent = _core_models.AdEvent
        AdRevenue = _core_models.AdRevenue
        Popup = _core_models.Popup
        Announcement = _core_models.Announcement
        Notification = _core_models.Notification
        SiteSetting = _core_models.SiteSetting
        AuditLog = _core_models.AuditLog
except Exception:  # pragma: no cover - core models not present yet
    pass


def resolve_models():
    """Return the core agent's models if complete, else the fallback models.

    Never mixes the two: if ``app.models`` is missing or lacks any name we
    need, the whole fallback set is used.
    """
    try:
        import app.models as core  # type: ignore
    except Exception:
        return _FALLBACK
    missing = [n for n in _MODEL_NAMES if not hasattr(core, n)]
    if missing:
        log.info("app.models missing %s; using fallback billing models", missing)
        return _FALLBACK
    return SimpleNamespace(**{n: getattr(core, n) for n in _MODEL_NAMES})


# ------------------------------------------------------------- dependencies
async def get_db():
    """Database session dependency, wired to the core session factory.

    Routers depend on this exact callable, so tests can override it via
    ``app.dependency_overrides[get_db]``. Delegates to ``app.deps.get_db``
    (async generator); the import is lazy so this module still imports
    cleanly before ``app.deps`` exists.
    """
    from app.deps import get_db as core_get_db

    async for session in core_get_db():
        yield session


async def _unused_placeholder():
    raise NotImplementedError


# The two dependency callables below delegate to the core agent's auth
# helpers when they exist (imported lazily, at call time). Tests override
# these exact callables via app.dependency_overrides.
from fastapi import Depends as _Depends  # noqa: E402


async def get_current_user(request: Request, db: Any = _Depends(get_db)):  # type: ignore[no-redef]
    try:
        from app.deps import get_current_user as core_user  # type: ignore
    except Exception:
        raise err(401, "unauthorized", "Sign in to continue.",
                  "Use the sign-in page, then try again.")
    try:
        return await core_user(request, db)
    except TypeError:
        try:
            return await core_user(request)
        except ApiError:
            raise
        except Exception:
            raise err(401, "unauthorized", "Sign in to continue.",
                      "Use the sign-in page, then try again.")
    except ApiError:
        raise


async def get_current_admin(request: Request, db: Any = _Depends(get_db)):  # type: ignore[no-redef]
    for mod, fn in (("app.deps", "get_current_admin"),
                    ("app.admin_auth", "get_current_admin")):
        try:
            module = __import__(mod, fromlist=[fn])
            core_admin = getattr(module, fn)
        except Exception:
            continue
        try:
            return await core_admin(request, db)
        except TypeError:
            try:
                return await core_admin(request)
            except ApiError:
                raise
            except Exception:
                continue
        except ApiError:
            raise
    raise err(401, "unauthorized", "Admin sign-in is required.",
              "Sign in to the admin panel, then try again.")


async def get_optional_user(request: Request, db: Any = _Depends(get_db)):  # type: ignore[no-redef]
    """Best-effort current user for public endpoints (ads): None when anon."""
    try:
        return await get_current_user(request, db)
    except Exception:
        return None


# -------------------------------------------------------------- rate limit
_RATE_BUCKETS: dict[str, list[float]] = {}


def check_rate_limit(key: str, limit: int, window_seconds: int) -> Optional[int]:
    """Sliding-window limiter. Returns retry-after seconds when limited."""
    now = time.time()
    bucket = [t for t in _RATE_BUCKETS.get(key, []) if t > now - window_seconds]
    if len(bucket) >= limit:
        retry = int(math.ceil(bucket[0] + window_seconds - now))
        return max(retry, 1)
    bucket.append(now)
    _RATE_BUCKETS[key] = bucket
    return None


def enforce_rate_limit(key: str, limit: int, window_seconds: int) -> None:
    retry = check_rate_limit(key, limit, window_seconds)
    if retry is not None:
        raise err(429, "rate_limited",
                  "Too many requests. Please wait a moment and try again.",
                  f"Retry after {retry} seconds.")
    return None


def client_ip(request: Request) -> str:
    return (request.headers.get("x-forwarded-for") or request.client.host
            if request.client else "unknown").split(",")[0].strip()


# ------------------------------------------------------------------ money
def pkr_amount(usd_cents: int, pkr_per_usd: float) -> int:
    """PKR display: ceil(USD x rate / 10) x 10 (spec 4.4)."""
    usd = Decimal(usd_cents) / Decimal(100)
    raw = usd * Decimal(str(pkr_per_usd))
    return int(math.ceil(float(raw) / 10.0) * 10)


def price_for_plan(plan: Any, interval: str) -> int:
    if interval == "yearly":
        return int(plan.price_yearly_cents or 0)
    if interval == "monthly":
        return int(plan.price_cents or 0)
    raise err(400, "invalid_interval", "Interval must be monthly or yearly.",
              "Choose monthly or yearly billing.")


def apply_coupon_to_amount(amount_cents: int, coupon: Any) -> int:
    if coupon is None:
        return amount_cents
    if coupon.type == "percent":
        discount = amount_cents * int(coupon.value) // 100
    elif coupon.type == "fixed":
        discount = int(coupon.value)
    else:
        raise err(400, "invalid_coupon", "This coupon has an unknown type.",
                  "Contact support about this coupon.")
    return max(amount_cents - discount, 0)


async def get_pkr_rate(db, models) -> float:
    """Admin-set PKR rate: site_settings pkr_per_usd, else env, else fallback."""
    try:
        row = (await db.execute(
            select(models.SiteSetting).where(models.SiteSetting.key == "pkr_per_usd")
        )).scalar_one_or_none()
        if row is not None and row.value:
            return float(row.value if not isinstance(row.value, dict)
                         else row.value.get("value"))
    except Exception:
        pass
    env = os.environ.get("PKR_PER_USD")
    if env:
        try:
            return float(env)
        except ValueError:
            pass
    return DEFAULT_PKR_PER_USD


async def get_site_setting(db, models, key: str, default=None):
    try:
        row = (await db.execute(
            select(models.SiteSetting).where(models.SiteSetting.key == key)
        )).scalar_one_or_none()
        return row.value if row is not None else default
    except Exception:
        return default


# ----------------------------------------------------------------- coupons
async def validate_coupon(db, models, code: str, plan_id: str,
                          interval: str, user_id: Optional[str] = None):
    """Validate a coupon. Returns (coupon, discount_cents, amount_after).

    Raises ApiError with a plain message on any failure. ``amount_after``
    needs the plan price; callers that only validate pass amount_cents=0
    and get discount 0 — use :func:`coupon_discount` for pricing.
    """
    code = (code or "").strip().upper()
    if not code:
        raise err(400, "coupon_required", "Enter a coupon code.",
                  "Coupon codes are shown on the pricing page when available.")
    coupon = (await db.execute(
        select(models.Coupon).where(models.Coupon.code == code)
    )).scalar_one_or_none()
    if coupon is None or not coupon.active:
        raise err(400, "coupon_invalid", "This coupon code is not valid.",
                  "Check the code and try again.")
    if coupon.expires_at is not None:
        exp = coupon.expires_at
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        if exp <= utcnow():
            raise err(400, "coupon_expired", "This coupon has expired.",
                      "Try a different coupon.")
    if coupon.plans:
        if plan_id not in list(coupon.plans):
            raise err(400, "coupon_wrong_plan",
                      "This coupon does not apply to the selected plan.",
                      "Choose a plan this coupon covers, or remove the coupon.")
    if coupon.intervals:
        scopes = [str(i).lower() for i in coupon.intervals]
        if "both" not in scopes and interval.lower() not in scopes:
            raise err(400, "coupon_wrong_interval",
                      "This coupon does not apply to the selected billing interval.",
                      "Choose a different billing interval, or remove the coupon.")
    if coupon.max_uses is not None and int(coupon.used or 0) >= int(coupon.max_uses):
        raise err(400, "coupon_used_up", "This coupon has reached its use limit.",
                  "Try a different coupon.")
    if user_id is not None and coupon.per_user_limit is not None:
        used_by_user = 0
        for model, col in ((models.Subscription, "coupon_code"),
                           (models.PaymentRequest, "coupon_code")):
            rows = (await db.execute(
                select(func.count()).select_from(model).where(
                    model.user_id == user_id,
                    getattr(model, col) == code,
                ))).scalar_one()
            used_by_user += int(rows or 0)
        if used_by_user >= int(coupon.per_user_limit):
            raise err(400, "coupon_already_used",
                      "You have already used this coupon.",
                      "Each coupon can only be used once per account.")
    return coupon


def coupon_discount(amount_cents: int, coupon: Any) -> int:
    if coupon is None:
        return 0
    return amount_cents - apply_coupon_to_amount(amount_cents, coupon)


async def record_coupon_use(db, coupon) -> None:
    coupon.used = int(coupon.used or 0) + 1
    db.add(coupon)


# ------------------------------------------------------- provider config
def _derive_key() -> bytes:
    secret = os.environ.get("APP_SECRET") or os.environ.get("SECRET_KEY") or ""
    if not secret:
        raise err(500, "config_error",
                  "The server is missing its encryption secret.",
                  "Set APP_SECRET in the environment.")
    return hashlib.pbkdf2_hmac("sha256", secret.encode(), b"qic-provider-config",
                               200_000, dklen=32)


def encrypt_config(config: dict) -> str:
    """AES-GCM encrypt a provider config dict. Prefers app.security."""
    try:
        from app.security import encrypt_config as core_encrypt  # type: ignore
        return core_encrypt(config)
    except Exception:
        pass
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        nonce = os.urandom(12)
        ct = AESGCM(_derive_key()).encrypt(
            nonce, json.dumps(config).encode(), None)
        return "aesgcm1:" + (nonce + ct).hex()
    except ImportError:
        raise err(500, "config_error",
                  "Encryption support is not available for provider config.",
                  "Install the cryptography package on the server.")


def decrypt_config(blob: Optional[str]) -> dict:
    """Decrypt a provider config blob. Returns {} for empty/missing."""
    if not blob:
        return {}
    try:
        from app.security import decrypt_config as core_decrypt  # type: ignore
        out = core_decrypt(blob)
        return out if isinstance(out, dict) else {}
    except Exception:
        pass
    if blob.startswith("aesgcm1:"):
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            raw = bytes.fromhex(blob[len("aesgcm1:"):])
            plain = AESGCM(_derive_key()).decrypt(raw[:12], raw[12:], None)
            data = json.loads(plain.decode())
            return data if isinstance(data, dict) else {}
        except Exception:
            log.warning("provider config decrypt failed")
            return {}
    # Legacy plain JSON (never written by this code; tolerated on read only).
    try:
        data = json.loads(blob)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def mask_value(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    s = str(value)
    if len(s) <= 4:
        return "••••"
    return "•" * max(len(s) - 4, 4) + s[-4:]


def mask_config(config: dict, secret_fields: set[str]) -> dict:
    """Presence + masked values only; never returns a real secret."""
    out = {}
    for k, v in (config or {}).items():
        if k in secret_fields:
            out[k] = mask_value(v) if v else None
            out[f"{k}_set"] = bool(v)
        else:
            out[k] = v
    return out


async def load_provider_config(db, models, key: str) -> dict:
    """Merged provider config: DB row (decrypted) over env-var defaults."""
    from app.payments.providers import env_config_for  # local import: no cycle at runtime
    merged = dict(env_config_for(key))
    if db is None:
        return merged
    try:
        row = (await db.execute(
            select(models.PaymentProvider).where(models.PaymentProvider.key == key)
        )).scalar_one_or_none()
        if row is not None and row.config:
            for k, v in decrypt_config(row.config).items():
                if v not in (None, ""):
                    merged[k] = v
    except Exception:
        log.exception("load_provider_config failed for %s", key)
    return merged


async def provider_row(db, models, key: str):
    return (await db.execute(
        select(models.PaymentProvider).where(models.PaymentProvider.key == key)
    )).scalar_one_or_none()


# ------------------------------------------------------------------- mail
def send_mail(to: str, subject: str, body: str, html: Optional[str] = None,
              attachment: Optional[tuple[str, bytes]] = None) -> bool:
    """Send transactional mail via app.mail when present. Never raises.

    Returns True when a mail helper accepted the message. The core agent
    owns app.mail; its exact function name is probed defensively.
    """
    try:
        from app import mail as mail_mod  # type: ignore
    except Exception:
        log.info("mail not configured; skipping email to %s (%s)",
                 _mask_email(to), subject)
        return False
    for name in ("send_email", "send_mail", "send"):
        fn = getattr(mail_mod, name, None)
        if fn is None:
            continue
        try:
            kwargs: dict[str, Any] = {"to": to, "subject": subject, "body": body}
            if html is not None:
                kwargs["html"] = html
            if attachment is not None:
                kwargs["attachment"] = attachment
            fn(**kwargs)
            return True
        except TypeError:
            try:
                fn(to, subject, body)
                return True
            except Exception:
                log.exception("mail send failed")
                return False
        except Exception:
            log.exception("mail send failed")
            return False
    return False


def _mask_email(email: str) -> str:
    if "@" not in email:
        return "***"
    local, domain = email.split("@", 1)
    return (local[:2] + "***@" + domain) if local else "***@" + domain


# ------------------------------------------------------------------ audit
async def record_audit(db, models, admin_email: str, action: str, target: str,
                       before: Any, after: Any, ip: Optional[str] = None) -> None:
    """Write an audit row; prefers app.audit.audit when it exists."""
    try:
        from app.audit import audit as core_audit  # type: ignore
        try:
            await core_audit(db, admin_email, action, target, before, after, ip)
            return
        except TypeError:
            core_audit(admin_email, action, target, before, after, ip)
            return
    except Exception:
        pass
    try:
        db.add(models.AuditLog(
            admin_email=admin_email, action=action, target=target,
            before=before, after=after, ip=ip))
    except Exception:
        log.exception("audit write failed for %s %s", action, target)


# ------------------------------------------------------- subscription life
def period_end_for(interval: str, start: Optional[datetime] = None) -> datetime:
    start = start or utcnow()
    return start + timedelta(days=365 if interval == "yearly" else 30)


async def activate_subscription(db, models, user, plan, provider_key: str,
                                interval: str, provider_sub_id: Optional[str] = None,
                                coupon_code: Optional[str] = None,
                                period_end: Optional[datetime] = None,
                                extend_from_current: bool = False):
    """Activate (or renew) a subscription; extends from the current period
    end when renewing (manual approval rule, spec section 7)."""
    now = utcnow()
    existing = None
    if provider_sub_id:
        existing = (await db.execute(
            select(models.Subscription).where(
                models.Subscription.provider_sub_id == provider_sub_id)
        )).scalar_one_or_none()
    if existing is None:
        rows = (await db.execute(
            select(models.Subscription).where(
                models.Subscription.user_id == user.id,
                models.Subscription.plan_id == plan.id,
            ).order_by(models.Subscription.created_at.desc())
        )).scalars().all()
        for row in rows:
            if row.status in ("active", "past_due", "canceled"):
                existing = row
                break
    if existing is not None and existing.status in ("active", "past_due", "canceled"):
        current_end = existing.current_period_end
        if current_end is not None and current_end.tzinfo is None:
            current_end = current_end.replace(tzinfo=timezone.utc)
        base = current_end if (
            extend_from_current and current_end is not None
            and current_end > now) else now
        existing.status = "active"
        existing.provider_key = provider_key
        existing.interval = interval
        if provider_sub_id:
            existing.provider_sub_id = provider_sub_id
        if coupon_code:
            existing.coupon_code = coupon_code
        existing.cancel_at_period_end = False
        existing.grace_ends_at = None
        existing.current_period_end = period_end or period_end_for(interval, base)
        existing.updated_at = now
        sub = existing
    else:
        sub = models.Subscription(
            user_id=user.id, plan_id=plan.id, provider_key=provider_key,
            provider_sub_id=provider_sub_id, interval=interval,
            coupon_code=coupon_code, status="active",
            current_period_end=period_end or period_end_for(interval, now))
        db.add(sub)
    user.plan = plan.id
    db.add(user)
    await db.flush()
    return sub


async def renew_subscription(db, models, sub, period_end: Optional[datetime] = None):
    sub.status = "active"
    sub.cancel_at_period_end = False
    sub.grace_ends_at = None
    sub.current_period_end = period_end or period_end_for(
        sub.interval, sub.current_period_end or utcnow())
    sub.updated_at = utcnow()
    db.add(sub)
    await db.flush()
    return sub


async def mark_past_due(db, models, sub, notify: bool = True):
    from app.notifications import create_notification  # local, no cycle at runtime
    sub.status = "past_due"
    sub.grace_ends_at = utcnow() + timedelta(days=GRACE_DAYS)
    sub.updated_at = utcnow()
    db.add(sub)
    await db.flush()
    if notify:
        user = (await db.execute(
            select(models.User).where(models.User.id == sub.user_id)
        )).scalar_one_or_none()
        if user is not None:
            await create_notification(
                db, models, user.id, "past_due",
                "Your payment failed — 7 days to fix it",
                "Your subscription payment did not go through. Update your "
                "payment details within 7 days to keep your plan.",
                link="/account?tab=plan")
            if user.email:
                send_mail(user.email, "Payment failed — 7 days to fix it",
                          "Your Quick IMG Convert subscription payment did not "
                          "go through. Please update your payment details "
                          "within 7 days to keep your plan.")
    return sub


async def cancel_subscription(db, models, sub, at_period_end: bool = True):
    """Cancel: stays on the plan until period end, then free (spec 7)."""
    sub.cancel_at_period_end = True
    if not at_period_end:
        sub.status = "canceled"
    sub.updated_at = utcnow()
    db.add(sub)
    await db.flush()
    return sub


async def expire_subscription(db, models, sub, reason: str = "expired"):
    """Downgrade the user to free and close the subscription."""
    sub.status = "expired"
    sub.updated_at = utcnow()
    db.add(sub)
    user = (await db.execute(
        select(models.User).where(models.User.id == sub.user_id)
    )).scalar_one_or_none()
    if user is not None:
        user.plan = "free"
        db.add(user)
        from app.notifications import create_notification
        await create_notification(
            db, models, user.id, "subscription_ended",
            "Your subscription has ended",
            "Your paid plan has ended and your account is now on the free plan.",
            link="/pricing")
        if user.email:
            send_mail(user.email, "Your subscription has ended",
                      "Your Quick IMG Convert subscription has ended. Your "
                      "account is now on the free plan.")
    await db.flush()
    return sub


async def find_subscription_for_provider(db, models, provider_key: str,
                                         provider_sub_id: Optional[str]):
    if not provider_sub_id:
        return None
    return (await db.execute(
        select(models.Subscription).where(
            models.Subscription.provider_key == provider_key,
            models.Subscription.provider_sub_id == provider_sub_id)
    )).scalar_one_or_none()


# ------------------------------------------------------------ webhook apply
@dataclass
class NormalizedEvent:
    kind: str  # activated | renewed | past_due | canceled | expired | ignored
    provider_key: str
    event_id: str
    event_type: str
    user_id: Optional[str] = None
    email: Optional[str] = None
    plan_id: Optional[str] = None
    interval: str = "monthly"
    provider_sub_id: Optional[str] = None
    provider_customer_id: Optional[str] = None
    period_end: Optional[datetime] = None
    amount_cents: Optional[int] = None
    coupon_code: Optional[str] = None
    raw: dict = field(default_factory=dict)


async def apply_event(db, models, event: NormalizedEvent) -> dict:
    """Apply a normalized webhook event. Returns a small outcome dict."""
    if event.kind == "ignored":
        return {"status": "ignored", "kind": event.kind}
    sub = await find_subscription_for_provider(
        db, models, event.provider_key, event.provider_sub_id)
    user = None
    if event.user_id:
        user = (await db.execute(
            select(models.User).where(models.User.id == event.user_id)
        )).scalar_one_or_none()
    if user is None and sub is not None:
        user = (await db.execute(
            select(models.User).where(models.User.id == sub.user_id)
        )).scalar_one_or_none()
    if user is None and event.email:
        user = (await db.execute(
            select(models.User).where(models.User.email == event.email)
        )).scalar_one_or_none()
    if user is None:
        return {"status": "unresolved",
                "detail": "no user or subscription matched this event"}
    plan = None
    if event.plan_id:
        plan = (await db.execute(
            select(models.Plan).where(models.Plan.id == event.plan_id)
        )).scalar_one_or_none()
    if plan is None and sub is not None:
        plan = (await db.execute(
            select(models.Plan).where(models.Plan.id == sub.plan_id)
        )).scalar_one_or_none()
    if plan is None:
        return {"status": "unresolved", "detail": "plan could not be resolved"}
    from app.notifications import create_notification
    if event.kind in ("activated", "renewed"):
        if sub is not None and event.kind == "renewed":
            await renew_subscription(db, models, sub, event.period_end)
            await create_notification(
                db, models, user.id, "subscription_renewed",
                "Your subscription was renewed",
                f"Your {plan.name} plan was renewed.",
                link="/account?tab=plan")
        else:
            await activate_subscription(
                db, models, user, plan, event.provider_key, event.interval,
                provider_sub_id=event.provider_sub_id,
                coupon_code=event.coupon_code, period_end=event.period_end)
            await create_notification(
                db, models, user.id, "subscription_activated",
                "Your subscription is active",
                f"Your {plan.name} plan is now active. Enjoy ad-free converting.",
                link="/account?tab=plan")
        return {"status": "applied", "kind": event.kind}
    if event.kind == "past_due":
        target = sub
        if target is None:
            target = models.Subscription(
                user_id=user.id, plan_id=plan.id,
                provider_key=event.provider_key,
                provider_sub_id=event.provider_sub_id,
                interval=event.interval, status="active")
            db.add(target)
            await db.flush()
        await mark_past_due(db, models, target)
        return {"status": "applied", "kind": event.kind}
    if event.kind == "canceled":
        if sub is not None:
            await cancel_subscription(db, models, sub, at_period_end=True)
            await create_notification(
                db, models, user.id, "subscription_canceled",
                "Your subscription was canceled",
                f"Your {plan.name} plan stays active until "
                f"{sub.current_period_end.date() if sub.current_period_end else 'the end of the billing period'}, "
                "then moves to the free plan.",
                link="/account?tab=plan")
        return {"status": "applied", "kind": event.kind}
    if event.kind == "expired":
        if sub is not None:
            await expire_subscription(db, models, sub)
        return {"status": "applied", "kind": event.kind}
    return {"status": "ignored", "kind": event.kind}


# ------------------------------------------------------------- grace sweep
async def run_grace_sweep(db, models, now: Optional[datetime] = None) -> dict:
    """Hourly job (called by the worker): enforce grace and downgrades.

    - past_due subscriptions whose grace elapsed -> expired (downgrade,
      email + in-app notification at every step).
    - past_due subscriptions still in grace -> daily reminder email +
      notification, at most once per 24h per user.
    - canceled subscriptions whose period ended -> expired (downgrade).
    Returns counts so the worker can log them.
    """
    from app.notifications import create_notification
    now = now or utcnow()
    expired = reminded = downgraded = 0
    subs = (await db.execute(
        select(models.Subscription).where(
            models.Subscription.status.in_(("past_due", "canceled")))
    )).scalars().all()
    for sub in subs:
        if sub.status == "past_due" and sub.grace_ends_at is not None:
            end = sub.grace_ends_at
            if end.tzinfo is None:
                end = end.replace(tzinfo=timezone.utc)
            if end <= now:
                await expire_subscription(db, models, sub, reason="grace elapsed")
                expired += 1
                continue
            # Daily reminder, at most once per 24h (checked via notifications).
            since = now - timedelta(hours=24)
            recent = (await db.execute(
                select(func.count()).select_from(models.Notification).where(
                    models.Notification.user_id == sub.user_id,
                    models.Notification.kind == "past_due",
                    models.Notification.created_at >= since)
            )).scalar_one()
            if not recent:
                user = (await db.execute(
                    select(models.User).where(models.User.id == sub.user_id)
                )).scalar_one_or_none()
                if user is not None:
                    await create_notification(
                        db, models, user.id, "past_due",
                        "Reminder: your payment is past due",
                        "Your subscription payment is still past due. Fix it "
                        "before your grace period ends to keep your plan.",
                        link="/account?tab=plan")
                    if user.email:
                        send_mail(user.email,
                                  "Reminder: your payment is past due",
                                  "Your Quick IMG Convert subscription payment "
                                  "is still past due. Please update your "
                                  "payment details before your grace period "
                                  "ends.")
                    reminded += 1
        if sub.status == "canceled" and sub.current_period_end is not None:
            end = sub.current_period_end
            if end.tzinfo is None:
                end = end.replace(tzinfo=timezone.utc)
            if end <= now:
                await expire_subscription(db, models, sub, reason="period ended")
                downgraded += 1
    await db.commit()
    return {"expired": expired, "reminded": reminded, "downgraded": downgraded}


# ------------------------------------------------------- receipt numbering
async def next_receipt_no(db, models, year: Optional[int] = None) -> str:
    year = year or utcnow().year
    prefix = f"QIC-{year}-"
    rows = (await db.execute(
        select(models.PaymentRequest.receipt_no).where(
            models.PaymentRequest.receipt_no.like(prefix + "%"))
    )).scalars().all()
    taken = 0
    for r in rows:
        try:
            taken = max(taken, int(str(r).rsplit("-", 1)[-1]))
        except (ValueError, IndexError):
            continue
    return f"{prefix}{taken + 1:06d}"


# ------------------------------------------------------------- misc utils
def new_uuid() -> str:
    return str(uuid.uuid4())


def constant_time_compare(a: str, b: str) -> bool:
    return hmac_mod.compare_digest(a.encode(), b.encode())


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
