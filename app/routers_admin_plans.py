"""Admin plans & coupons (v5 sections 4.1-4.4).

Admin guard comes from ``app.admin_auth`` (shared with every other
admin router): the ``qic_admin`` cookie against ``admin_sessions``,
and mutations require the CSRF header with the token issued by
``GET /admin/auth/csrf``. (An earlier local guard used a different
CSRF scheme — ``csrf_token_for`` — that the admin frontend never
issues, so plan/coupon saves always failed with 403 csrf_invalid;
that guard is gone.)

Also holds the shared coupon / currency helpers used by the payments
flow: coupon validation, first-payment discount, and the PKR display
rounding (``ceil(USD x rate / 10) x 10``, snapshotted per request).
"""

from __future__ import annotations

import math
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from .admin_auth import get_current_admin, require_csrf
from .deps import api_error, get_db
from .models import AdminUser, Coupon, PaymentRequest, Plan, SiteSetting
from .seed import ANONYMOUS_LIMITS

router = APIRouter(prefix="/admin", tags=["admin-plans"])

PLAN_ORDER = ["anonymous", "free", "basic", "pro"]
ORDERED_LIMIT_KEYS = ["daily", "batch", "img_mb", "aud_mb", "vid_mb", "vid_min", "parallel"]


# ---------------------------------------------------------------- currency / coupons

def pkr_display(usd_cents: int, pkr_per_usd: float) -> int:
    """PKR display amount: ceil(USD x rate / 10) x 10 (spec 4.4)."""
    usd = usd_cents / 100
    return int(math.ceil(usd * pkr_per_usd / 10) * 10)


def apply_coupon(amount_cents: int, coupon: Coupon) -> int:
    """Discounted amount for the first payment (unless recurring)."""
    if coupon.type == "percent":
        discount = amount_cents * coupon.value // 100
    else:  # fixed cents off
        discount = coupon.value
    return max(0, amount_cents - discount)


async def validate_coupon(
    db: AsyncSession, code: str, plan_id: str, interval: str,
    user_id: str | None = None,
) -> dict:
    """Validate a coupon for a plan + interval. Raises api_error on
    any failure; returns the coupon row + discounted info on success."""
    code = (code or "").strip().upper()
    coupon = await db.get(Coupon, code)
    if coupon is None or not coupon.active:
        raise api_error(404, "coupon_not_found",
                        "That coupon code is not valid.",
                        "Check the code and try again.")
    now = datetime.now(timezone.utc)
    if coupon.expires_at is not None:
        exp = coupon.expires_at
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        if exp <= now:
            raise api_error(400, "coupon_expired",
                            "That coupon has expired.",
                            "Try a different coupon.")
    if coupon.max_uses is not None and coupon.used >= coupon.max_uses:
        raise api_error(400, "coupon_exhausted",
                        "That coupon has already been used up.",
                        "Try a different coupon.")
    if coupon.plans and plan_id not in coupon.plans:
        raise api_error(400, "coupon_plan_mismatch",
                        "That coupon does not apply to this plan.",
                        "Choose a plan the coupon covers, or try a different coupon.")
    if coupon.intervals and interval not in coupon.intervals and "both" not in coupon.intervals:
        raise api_error(400, "coupon_interval_mismatch",
                        "That coupon does not apply to this billing interval.",
                        "Try the other billing interval, or a different coupon.")
    if user_id is not None and coupon.per_user_limit is not None:
        used_by_user = await db.execute(
            select(func.count()).select_from(PaymentRequest).where(
                PaymentRequest.user_id == user_id,
                PaymentRequest.coupon_code == code,
            )
        )
        if (used_by_user.scalar() or 0) >= coupon.per_user_limit:
            raise api_error(400, "coupon_already_used",
                            "You have already used this coupon.",
                            "Try a different coupon.")
    return {
        "code": coupon.code, "type": coupon.type, "value": coupon.value,
        "recurring": coupon.recurring,
        "coupon": coupon,
    }


# Admin guard (session + CSRF) is imported from app.admin_auth, shared
# with every other admin router — see the module docstring.


async def _write_audit(db: AsyncSession, request: Request, admin: AdminUser,
                       action: str, target: str,
                       before: dict | None, after: dict | None) -> None:
    """Write an audit_log row for an admin mutation. The audit helper
    module is owned by the admin-backend agent; this direct insert
    keeps the same table contract until that module lands."""
    from .deps import client_ip
    from .models import AuditLog

    db.add(AuditLog(admin_email=admin.email, action=action, target=target,
                    before=before, after=after, ip=client_ip(request)))


# ---------------------------------------------------------------- plan helpers

def _plan_out(plan: Plan) -> dict:
    return {
        "id": plan.id, "name": plan.name,
        "price_cents": plan.price_cents, "price_yearly_cents": plan.price_yearly_cents,
        "currency": plan.currency, "trial_days": plan.trial_days,
        "limits": plan.limits or {}, "featured": plan.featured,
        "active": plan.active, "archived": plan.archived, "sort": plan.sort,
    }


async def _limits_by_plan(db: AsyncSession) -> dict[str, dict]:
    limits: dict[str, dict] = {"anonymous": dict(ANONYMOUS_LIMITS)}
    anon_setting = await db.get(SiteSetting, "anonymous_limits")
    if anon_setting is not None and isinstance(anon_setting.value, dict):
        limits["anonymous"] = {**ANONYMOUS_LIMITS, **anon_setting.value}
    result = await db.execute(select(Plan).order_by(Plan.sort))
    for plan in result.scalars().all():
        limits[plan.id] = plan.limits or {}
    return limits


def ordering_warning(limits: dict[str, dict]) -> str | None:
    """Warn when numeric limits are not ordered anonymous <= free <=
    basic <= pro (spec 4.1). Priority/ads are booleans and are excluded."""
    for key in ORDERED_LIMIT_KEYS:
        values = []
        for plan_id in PLAN_ORDER:
            v = (limits.get(plan_id) or {}).get(key)
            if v is None:
                break
            values.append(v)
        else:
            if values != sorted(values):
                return (
                    f"Limits are not ordered for '{key}': "
                    + " <= ".join(f"{p}={v}" for p, v in zip(PLAN_ORDER, values))
                    + ". Expected anonymous <= free <= basic <= pro."
                )
    return None


# ---------------------------------------------------------------- schemas

class PlanCreate(BaseModel):
    id: str = Field(min_length=1, max_length=50)
    name: str = Field(min_length=1, max_length=100)
    price_cents: int = Field(ge=0)
    price_yearly_cents: int = Field(ge=0)
    currency: str = "USD"
    trial_days: int = Field(default=0, ge=0)
    limits: dict = Field(default_factory=dict)
    featured: int = 0
    sort: int = 0


class PlanUpdate(BaseModel):
    name: str | None = None
    price_cents: int | None = Field(default=None, ge=0)
    price_yearly_cents: int | None = Field(default=None, ge=0)
    currency: str | None = None
    trial_days: int | None = Field(default=None, ge=0)
    limits: dict | None = None
    featured: int | None = None
    active: bool | None = None
    sort: int | None = None


class CouponCreate(BaseModel):
    code: str = Field(min_length=1, max_length=50)
    type: str = Field(pattern="^(percent|fixed)$")
    value: int = Field(ge=1)
    plans: list[str] | None = None
    intervals: list[str] | None = None
    recurring: bool = False
    max_uses: int | None = Field(default=None, ge=1)
    per_user_limit: int = Field(default=1, ge=1)
    expires_at: datetime | None = None
    active: bool = True


class CouponUpdate(BaseModel):
    type: str | None = Field(default=None, pattern="^(percent|fixed)$")
    value: int | None = Field(default=None, ge=1)
    plans: list[str] | None = None
    intervals: list[str] | None = None
    recurring: bool | None = None
    max_uses: int | None = None
    per_user_limit: int | None = Field(default=None, ge=1)
    expires_at: datetime | None = None
    active: bool | None = None


# ---------------------------------------------------------------- plans CRUD

@router.get("/plans")
async def list_plans(db: AsyncSession = Depends(get_db),
                     admin: AdminUser = Depends(get_current_admin)):
    result = await db.execute(select(Plan).order_by(Plan.sort))
    return {"plans": [_plan_out(p) for p in result.scalars().all()]}


@router.post("/plans")
async def create_plan(body: PlanCreate, request: Request,
                      db: AsyncSession = Depends(get_db),
                      admin: AdminUser = Depends(get_current_admin)):
    require_csrf(request)
    if await db.get(Plan, body.id) is not None:
        raise api_error(409, "plan_exists", "A plan with this id already exists.",
                        "Choose a different plan id.")
    plan = Plan(id=body.id, name=body.name, price_cents=body.price_cents,
                price_yearly_cents=body.price_yearly_cents, currency=body.currency,
                trial_days=body.trial_days, limits=body.limits,
                featured=body.featured, sort=body.sort)
    db.add(plan)
    await db.commit()
    await _write_audit(db, request, admin, "plan.create", f"plan:{plan.id}", None, _plan_out(plan))
    await db.commit()
    limits = await _limits_by_plan(db)
    warning = ordering_warning(limits)
    return {"plan": _plan_out(plan), "warning": warning}


@router.patch("/plans/{plan_id}")
async def update_plan(plan_id: str, body: PlanUpdate, request: Request,
                      db: AsyncSession = Depends(get_db),
                      admin: AdminUser = Depends(get_current_admin)):
    require_csrf(request)
    plan = await db.get(Plan, plan_id)
    if plan is None:
        raise api_error(404, "not_found", "That plan was not found.", "Check the plan id.")
    before = _plan_out(plan)
    for field_name, value in body.model_dump(exclude_unset=True).items():
        setattr(plan, field_name, value)
    await db.commit()
    await _write_audit(db, request, admin, "plan.update", f"plan:{plan.id}", before, _plan_out(plan))
    await db.commit()
    limits = await _limits_by_plan(db)
    warning = ordering_warning(limits)
    return {"plan": _plan_out(plan), "warning": warning}


@router.post("/plans/{plan_id}/archive")
async def archive_plan(plan_id: str, request: Request,
                       db: AsyncSession = Depends(get_db),
                       admin: AdminUser = Depends(get_current_admin)):
    require_csrf(request)
    plan = await db.get(Plan, plan_id)
    if plan is None:
        raise api_error(404, "not_found", "That plan was not found.", "Check the plan id.")
    before = _plan_out(plan)
    plan.archived = True
    plan.active = False
    await db.commit()
    await _write_audit(db, request, admin, "plan.archive", f"plan:{plan.id}", before, _plan_out(plan))
    await db.commit()
    # Existing subscribers keep the archived plan (grandfathering):
    # subscriptions keep pointing at plan_id; only new signups and
    # checkout hide archived plans.
    return {"plan": _plan_out(plan),
            "message": "Plan archived. Existing subscribers keep it."}


@router.get("/plans/order-warning")
async def get_order_warning(db: AsyncSession = Depends(get_db),
                            admin: AdminUser = Depends(get_current_admin)):
    limits = await _limits_by_plan(db)
    return {"warning": ordering_warning(limits)}


# ---------------------------------------------------------------- coupons CRUD

def _coupon_out(c: Coupon) -> dict:
    return {
        "code": c.code, "type": c.type, "value": c.value,
        "plans": c.plans, "intervals": c.intervals, "recurring": c.recurring,
        "max_uses": c.max_uses, "used": c.used,
        "per_user_limit": c.per_user_limit,
        "expires_at": c.expires_at.isoformat() if c.expires_at else None,
        "active": c.active,
    }


@router.get("/coupons")
async def list_coupons(db: AsyncSession = Depends(get_db),
                       admin: AdminUser = Depends(get_current_admin)):
    result = await db.execute(select(Coupon).order_by(Coupon.code))
    return {"coupons": [_coupon_out(c) for c in result.scalars().all()]}


@router.post("/coupons")
async def create_coupon(body: CouponCreate, request: Request,
                        db: AsyncSession = Depends(get_db),
                        admin: AdminUser = Depends(get_current_admin)):
    require_csrf(request)
    code = body.code.strip().upper()
    if await db.get(Coupon, code) is not None:
        raise api_error(409, "coupon_exists", "A coupon with this code already exists.",
                        "Choose a different code.")
    if body.type == "percent" and not (1 <= body.value <= 100):
        raise api_error(400, "invalid_coupon_value",
                        "A percent coupon must be between 1 and 100.",
                        "Use a value from 1 to 100 for percent coupons.")
    coupon = Coupon(code=code, type=body.type, value=body.value, plans=body.plans,
                    intervals=body.intervals, recurring=body.recurring,
                    max_uses=body.max_uses, per_user_limit=body.per_user_limit,
                    expires_at=body.expires_at, active=body.active)
    db.add(coupon)
    await db.commit()
    await _write_audit(db, request, admin, "coupon.create", f"coupon:{coupon.code}", None, _coupon_out(coupon))
    await db.commit()
    return {"coupon": _coupon_out(coupon)}


@router.patch("/coupons/{code}")
async def update_coupon(code: str, body: CouponUpdate, request: Request,
                        db: AsyncSession = Depends(get_db),
                        admin: AdminUser = Depends(get_current_admin)):
    require_csrf(request)
    coupon = await db.get(Coupon, code.strip().upper())
    if coupon is None:
        raise api_error(404, "not_found", "That coupon was not found.", "Check the code.")
    before = _coupon_out(coupon)
    for field_name, value in body.model_dump(exclude_unset=True).items():
        setattr(coupon, field_name, value)
    if coupon.type == "percent" and not (1 <= coupon.value <= 100):
        raise api_error(400, "invalid_coupon_value",
                        "A percent coupon must be between 1 and 100.",
                        "Use a value from 1 to 100 for percent coupons.")
    await db.commit()
    await _write_audit(db, request, admin, "coupon.update", f"coupon:{coupon.code}", before, _coupon_out(coupon))
    await db.commit()
    return {"coupon": _coupon_out(coupon)}


@router.post("/coupons/{code}/deactivate")
async def deactivate_coupon(code: str, request: Request,
                            db: AsyncSession = Depends(get_db),
                            admin: AdminUser = Depends(get_current_admin)):
    require_csrf(request)
    coupon = await db.get(Coupon, code.strip().upper())
    if coupon is None:
        raise api_error(404, "not_found", "That coupon was not found.", "Check the code.")
    before = _coupon_out(coupon)
    coupon.active = False
    await db.commit()
    await _write_audit(db, request, admin, "coupon.deactivate", f"coupon:{coupon.code}", before, _coupon_out(coupon))
    await db.commit()
    return {"coupon": _coupon_out(coupon)}
