"""Admin API for Quick IMG Convert v5 (spec §13.3).

All routes live under ``/admin`` and require:

* a valid admin session (``qic_admin`` cookie, see ``app.admin_auth``),
* the sidebar-section permission for the section (``super_admin`` has all),
* the ``X-CSRF-Token`` header on every mutation (``require_csrf``).

Sections: dashboard, users, team, settings (general / legal / email /
limits / danger), reports, audit log. Every mutation writes an
``audit_log`` row with a before/after diff via ``app.audit``.

All errors use the standard shape ``{"error": {code, message, hint}}``.
All list endpoints support pagination (``page`` / ``per_page``) and sorting
(``sort`` / ``order``).

Note on models: the core agent owns ``app.models``. Until it lands, the
minimal fallback models below (only the columns this router reads or
writes, matching spec §10) are used; once ``app.models`` exists the
imports win and the fallbacks are skipped.
"""

from __future__ import annotations

import csv
import io
import json
import math
import os
import re
import smtplib
from datetime import date, datetime, time, timedelta, timezone
from email.message import EmailMessage
from typing import Any, Optional
from zoneinfo import ZoneInfo

from fastapi import APIRouter, Depends, Query, Request, Response
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import (
    Boolean,
    case,
    Date,
    DateTime,
    ForeignKey,
    Integer,
    JSON,
    String,
    Text,
    and_,
    func,
    or_,
    select,
)
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from app.admin_auth import (
    SIDEBAR_SECTIONS,
    _client_ip,
    _utcnow,
    admin_error,
    admin_public_dict,
    get_current_admin,
    get_db,
    hash_password,
    has_permission,
    make_admin_reset_token,
    require_admin,
    require_csrf,
    validate_admin_password,
)
from app.audit import audit as audit_log_write, diff_dicts

router = APIRouter(prefix="/admin", tags=["admin"])

# ---------------------------------------------------------------------------
# Fallback models (skipped when app.models exists)
# ---------------------------------------------------------------------------

class _Base(DeclarativeBase):
    pass


def _try_models(*names: str):
    try:
        import app.models as _m  # type: ignore

        return {name: getattr(_m, name) for name in names}
    except Exception:
        return None


def _uuid_default() -> str:
    import uuid

    return str(uuid.uuid4())


_imported = _try_models(
    "User", "Session", "Subscription", "PaymentRequest", "Job", "Event",
    "PairHealth", "AdEvent", "AdRevenue", "SiteSetting", "EmailTemplate",
    "Plan", "AuditLog",
)

if _imported is not None:
    User = _imported["User"]
    # Core models call the user-session table model "Session" (spec §10
    # table name is "sessions"); alias it to the local name used below.
    UserSession = _imported["Session"]
    Subscription = _imported["Subscription"]
    PaymentRequest = _imported["PaymentRequest"]
    Job = _imported["Job"]
    Event = _imported["Event"]
    PairHealth = _imported["PairHealth"]
    AdEvent = _imported["AdEvent"]
    AdRevenue = _imported["AdRevenue"]
    SiteSetting = _imported["SiteSetting"]
    EmailTemplate = _imported["EmailTemplate"]
    Plan = _imported["Plan"]
    AuditLog = _imported["AuditLog"]
    Base = _Base  # no fallback tables to create
else:  # pragma: no cover - core models not present yet
    Base = _Base

    class User(Base):
        __tablename__ = "users"
        id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid_default)
        email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
        email_verified_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
        password_hash: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
        display_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
        plan: Mapped[str] = mapped_column(String(32), nullable=False, default="free")
        banned: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
        ban_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
        created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)
        last_login_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
        last_seen_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
        deleted_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    class UserSession(Base):
        __tablename__ = "sessions"
        id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid_default)
        user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id"), nullable=False)
        token_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
        csrf_secret: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
        ip: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
        user_agent: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
        remember: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
        created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)
        last_seen_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
        expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
        revoked_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    class Subscription(Base):
        __tablename__ = "subscriptions"
        id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid_default)
        user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id"), nullable=False)
        plan_id: Mapped[str] = mapped_column(String(64), nullable=False)
        provider_key: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
        provider_sub_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
        interval: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)
        coupon_code: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
        status: Mapped[str] = mapped_column(String(32), nullable=False, default="active")
        cancel_at_period_end: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
        current_period_end: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
        grace_ends_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
        created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)
        updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)

    class PaymentRequest(Base):
        __tablename__ = "payment_requests"
        id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid_default)
        user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id"), nullable=False)
        plan_id: Mapped[str] = mapped_column(String(64), nullable=False)
        interval: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)
        provider_key: Mapped[str] = mapped_column(String(64), nullable=False)
        coupon_code: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
        amount_cents: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
        currency: Mapped[str] = mapped_column(String(8), nullable=False, default="USD")
        display_amount: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
        fx_rate: Mapped[Optional[float]] = mapped_column(JSON, nullable=True)
        reference: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
        note: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
        proof_path: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
        status: Mapped[str] = mapped_column(String(32), nullable=False, default="pending")
        admin_note: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
        receipt_no: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
        created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)
        resolved_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
        resolved_by: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    class Job(Base):
        __tablename__ = "jobs"
        id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid_default)
        batch_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
        owner_key: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
        user_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("users.id"), nullable=True)
        upload_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
        pair_slug: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
        from_slug: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
        to_slug: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
        category: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
        route: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
        settings: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
        plan: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
        status: Mapped[str] = mapped_column(String(32), nullable=False, default="queued")
        progress: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
        error_code: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
        error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
        out_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
        out_path: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
        out_size: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
        in_size: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
        out_info: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
        created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)
        started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
        finished_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
        expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    class Event(Base):
        __tablename__ = "events"
        id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
        ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)
        owner_type: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
        plan: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
        pair_slug: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
        category: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
        status: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
        bytes_in: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
        bytes_out: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
        duration_ms: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)

    class PairHealth(Base):
        __tablename__ = "pair_health"
        pair_slug: Mapped[str] = mapped_column(String(64), primary_key=True)
        status: Mapped[str] = mapped_column(String(32), nullable=False, default="healthy")
        last_checked_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
        last_error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    class AdEvent(Base):
        __tablename__ = "ad_events"
        id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
        ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)
        slot: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
        plan: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
        page: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
        device: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)

    class AdRevenue(Base):
        __tablename__ = "ad_revenue"
        day: Mapped[date] = mapped_column(Date, primary_key=True)
        network: Mapped[str] = mapped_column(String(64), primary_key=True)
        amount_cents: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
        currency: Mapped[str] = mapped_column(String(8), nullable=False, default="USD")

    class SiteSetting(Base):
        __tablename__ = "site_settings"
        key: Mapped[str] = mapped_column(String(128), primary_key=True)
        value: Mapped[Optional[Any]] = mapped_column(JSON, nullable=True)

    class EmailTemplate(Base):
        __tablename__ = "email_templates"
        key: Mapped[str] = mapped_column(String(128), primary_key=True)
        subject: Mapped[str] = mapped_column(String(255), nullable=False, default="")
        body: Mapped[str] = mapped_column(Text, nullable=False, default="")

    class Plan(Base):
        __tablename__ = "plans"
        id: Mapped[str] = mapped_column(String(64), primary_key=True)
        name: Mapped[str] = mapped_column(String(64), nullable=False)
        price_cents: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
        price_yearly_cents: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
        currency: Mapped[str] = mapped_column(String(8), nullable=False, default="USD")
        trial_days: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
        limits: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
        featured: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
        active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
        archived: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
        sort: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    class AuditLog(Base):
        __tablename__ = "audit_log"
        id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
        ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)
        admin_email: Mapped[str] = mapped_column(String(255), nullable=False)
        action: Mapped[str] = mapped_column(String(128), nullable=False)
        target: Mapped[str] = mapped_column(String(255), nullable=False, default="")
        before: Mapped[Optional[Any]] = mapped_column(JSON, nullable=True)
        after: Mapped[Optional[Any]] = mapped_column(JSON, nullable=True)
        ip: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)


# AdminUser / AdminSession live in app.admin_auth (fallback or core models).
from app.admin_auth import AdminSession, AdminUser  # noqa: E402


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _quota_tz() -> ZoneInfo:
    return ZoneInfo(os.environ.get("QUOTA_TZ", "Asia/Karachi"))


def _day_bounds_utc(day: date, tz: ZoneInfo) -> tuple[datetime, datetime]:
    start = datetime.combine(day, time.min, tzinfo=tz).astimezone(timezone.utc)
    end = datetime.combine(day + timedelta(days=1), time.min, tzinfo=tz).astimezone(timezone.utc)
    return start, end


def _parse_date(value: Optional[str], name: str) -> Optional[date]:
    if not value:
        return None
    try:
        return date.fromisoformat(value)
    except ValueError:
        raise admin_error(
            422, "invalid_date", f"{name} must be a date like 2026-11-24.",
            "Use the YYYY-MM-DD format.",
        )


def _page_params(page: int, per_page: int) -> tuple[int, int]:
    page = max(1, page)
    per_page = min(max(1, per_page), 100)
    return page, per_page


async def _paginate(db: AsyncSession, stmt, page: int, per_page: int):
    """Return (items, total, page, per_page) for a select statement."""
    count_stmt = select(func.count()).select_from(stmt.subquery())
    total = (await db.execute(count_stmt)).scalar_one()
    rows = (await db.execute(stmt.offset((page - 1) * per_page).limit(per_page))).scalars().all()
    return list(rows), int(total), page, per_page


def _page_response(items, total: int, page: int, per_page: int) -> dict:
    return {
        "items": items,
        "total": total,
        "page": page,
        "per_page": per_page,
        "pages": max(1, math.ceil(total / per_page)),
    }


def _sort_column(model, sort: Optional[str], allowed: dict, default: str):
    name = (sort or default) if (sort or default) in allowed else default
    return allowed[name]


async def _get_setting(db: AsyncSession, key: str, default: Any = None) -> Any:
    row = await db.get(SiteSetting, key)
    return default if row is None else row.value


async def _set_setting(db: AsyncSession, key: str, value: Any) -> None:
    row = await db.get(SiteSetting, key)
    if row is None:
        db.add(SiteSetting(key=key, value=value))
    else:
        row.value = value
        db.add(row)


def _user_dict(user) -> dict:
    return {
        "id": str(user.id),
        "email": user.email,
        "display_name": getattr(user, "display_name", None),
        "plan": getattr(user, "plan", "free"),
        "banned": bool(getattr(user, "banned", False)),
        "ban_reason": getattr(user, "ban_reason", None),
        "email_verified": bool(getattr(user, "email_verified_at", None)),
        "created_at": user.created_at.isoformat() if getattr(user, "created_at", None) else None,
        "last_login_at": user.last_login_at.isoformat() if getattr(user, "last_login_at", None) else None,
        "last_seen_at": user.last_seen_at.isoformat() if getattr(user, "last_seen_at", None) else None,
    }


def _job_dict(job) -> dict:
    return {
        "id": str(job.id),
        "pair_slug": getattr(job, "pair_slug", None),
        "from_slug": getattr(job, "from_slug", None),
        "to_slug": getattr(job, "to_slug", None),
        "category": getattr(job, "category", None),
        "status": getattr(job, "status", None),
        "error_code": getattr(job, "error_code", None),
        "error_message": getattr(job, "error_message", None),
        "in_size": getattr(job, "in_size", None),
        "out_size": getattr(job, "out_size", None),
        "created_at": job.created_at.isoformat() if getattr(job, "created_at", None) else None,
        "finished_at": job.finished_at.isoformat() if getattr(job, "finished_at", None) else None,
    }


def _payment_request_dict(pr) -> dict:
    return {
        "id": str(pr.id),
        "user_id": str(pr.user_id),
        "plan_id": pr.plan_id,
        "interval": getattr(pr, "interval", None),
        "provider_key": pr.provider_key,
        "coupon_code": getattr(pr, "coupon_code", None),
        "amount_cents": pr.amount_cents,
        "currency": getattr(pr, "currency", "USD"),
        "display_amount": getattr(pr, "display_amount", None),
        "reference": getattr(pr, "reference", None),
        "status": pr.status,
        "receipt_no": getattr(pr, "receipt_no", None),
        "admin_note": getattr(pr, "admin_note", None),
        "created_at": pr.created_at.isoformat() if getattr(pr, "created_at", None) else None,
        "resolved_at": pr.resolved_at.isoformat() if getattr(pr, "resolved_at", None) else None,
        "resolved_by": getattr(pr, "resolved_by", None),
    }


def _subscription_dict(sub, plan=None) -> Optional[dict]:
    if sub is None:
        return None
    return {
        "id": str(sub.id),
        "plan_id": sub.plan_id,
        "plan_name": plan.name if plan is not None else sub.plan_id,
        "provider_key": getattr(sub, "provider_key", None),
        "interval": getattr(sub, "interval", None),
        "status": sub.status,
        "cancel_at_period_end": bool(getattr(sub, "cancel_at_period_end", False)),
        "current_period_end": sub.current_period_end.isoformat() if getattr(sub, "current_period_end", None) else None,
        "grace_ends_at": sub.grace_ends_at.isoformat() if getattr(sub, "grace_ends_at", None) else None,
        "created_at": sub.created_at.isoformat() if getattr(sub, "created_at", None) else None,
    }


async def _get_user_or_404(db: AsyncSession, user_id: str):
    user = await db.get(User, user_id)
    if user is None or getattr(user, "deleted_at", None) is not None:
        raise admin_error(404, "user_not_found", "No user with that id exists.",
                          "Check the user id and try again.")
    return user


async def _get_plan_or_404(db: AsyncSession, plan_id: str):
    plan = await db.get(Plan, plan_id)
    if plan is None:
        # Accept a plan name as well as an id.
        plan = (
            await db.execute(select(Plan).where(func.lower(Plan.name) == plan_id.strip().lower()))
        ).scalar_one_or_none()
    if plan is None:
        raise admin_error(404, "plan_not_found", f"No plan named '{plan_id}' exists.",
                          "Use a plan id from the Plans section.")
    return plan


async def _latest_subscription(db: AsyncSession, user_id: str):
    return (
        await db.execute(
            select(Subscription)
            .where(Subscription.user_id == user_id)
            .order_by(Subscription.created_at.desc())
            .limit(1)
        )
    ).scalar_one_or_none()


async def _user_notes(db: AsyncSession, user_id: str) -> str:
    # Spec §10 has no notes column on users, so internal notes live in
    # site_settings under user_notes:<user_id>.
    value = await _get_setting(db, f"user_notes:{user_id}", "")
    return value if isinstance(value, str) else ""


def _csv_response(filename: str, fieldnames: list[str], rows: list[dict]) -> StreamingResponse:
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=fieldnames)
    writer.writeheader()
    for row in rows:
        writer.writerow({k: row.get(k, "") for k in fieldnames})
    data = buffer.getvalue().encode("utf-8")
    return StreamingResponse(
        io.BytesIO(data),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


def _require_reason(body_reason: Optional[str], what: str) -> str:
    reason = (body_reason or "").strip()
    if not reason:
        raise admin_error(
            422, "reason_required", f"A reason is required to {what}.",
            "Include a non-empty reason in the request.",
        )
    return reason

# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

@router.get("/dashboard")
async def dashboard(
    db: AsyncSession = Depends(get_db),
    admin=Depends(require_admin("dashboard", "read")),
):
    tz = _quota_tz()
    today = datetime.now(tz).date()
    start_utc, end_utc = _day_bounds_utc(today, tz)
    month_start = datetime.combine(today.replace(day=1), time.min, tzinfo=timezone.utc)

    total_users = (await db.execute(select(func.count()).select_from(User))).scalar_one()
    new_users_today = (
        await db.execute(
            select(func.count()).select_from(User).where(User.created_at >= start_utc)
        )
    ).scalar_one()
    conversions_today = (
        await db.execute(
            select(func.count()).select_from(Job).where(Job.created_at >= start_utc)
        )
    ).scalar_one()
    done_today = (
        await db.execute(
            select(func.count()).select_from(Job).where(
                Job.created_at >= start_utc, Job.status.in_(("done", "success", "completed"))
            )
        )
    ).scalar_one()
    failed_today = (
        await db.execute(
            select(func.count()).select_from(Job).where(
                Job.created_at >= start_utc, Job.status.in_(("failed", "error"))
            )
        )
    ).scalar_one()
    success_rate = (
        round(100.0 * done_today / max(1, done_today + failed_today), 1)
        if (done_today + failed_today) > 0
        else 100.0
    )
    active_subs = (
        await db.execute(
            select(func.count()).select_from(Subscription).where(
                Subscription.status.in_(("active", "trialing", "past_due"))
            )
        )
    ).scalar_one()
    pending_approvals = (
        await db.execute(
            select(func.count()).select_from(PaymentRequest).where(
                PaymentRequest.status == "pending"
            )
        )
    ).scalar_one()

    # MRR: monthly price for monthly subs, yearly/12 for yearly subs.
    mrr_cents = 0
    subs = (await db.execute(select(Subscription).where(
        Subscription.status.in_(("active", "trialing", "past_due"))
    ))).scalars().all()
    plans = {p.id: p for p in (await db.execute(select(Plan))).scalars().all()}
    for sub in subs:
        plan = plans.get(sub.plan_id)
        if plan is None:
            continue
        if (getattr(sub, "interval", None) or "monthly") == "yearly":
            mrr_cents += (plan.price_yearly_cents or 0) // 12
        else:
            mrr_cents += plan.price_cents or 0

    # 30-day chart: conversions per day from jobs.
    chart_start = start_utc - timedelta(days=29)
    per_day_rows = (
        await db.execute(
            select(
                func.date(Job.created_at).label("day"),
                func.count().label("total"),
                func.sum(case((Job.status.in_(("done", "success", "completed")), 1), else_=0)).label("done"),
            )
            .where(Job.created_at >= chart_start)
            .group_by(func.date(Job.created_at))
            .order_by(func.date(Job.created_at))
        )
    ).all()
    by_day = {str(r.day): {"conversions": int(r.total), "success": int(r.done or 0)} for r in per_day_rows}
    chart = []
    for offset in range(29, -1, -1):
        d = today - timedelta(days=offset)
        entry = by_day.get(str(d), {"conversions": 0, "success": 0})
        chart.append({"date": d.isoformat(), **entry})

    top_pairs_rows = (
        await db.execute(
            select(Job.pair_slug, func.count().label("total"))
            .where(Job.created_at >= month_start, Job.pair_slug.is_not(None))
            .group_by(Job.pair_slug)
            .order_by(func.count().desc())
            .limit(10)
        )
    ).all()
    top_pairs = [
        {"pair_slug": r.pair_slug, "conversions": int(r.total)} for r in top_pairs_rows
    ]

    recent_errors = (
        await db.execute(
            select(Job)
            .where(Job.status.in_(("failed", "error")))
            .order_by(Job.created_at.desc())
            .limit(10)
        )
    ).scalars().all()

    disabled_pairs = (
        await db.execute(
            select(PairHealth).where(PairHealth.status == "disabled")
        )
    ).scalars().all()

    return {
        "kpis": {
            "users": int(total_users),
            "new_users_today": int(new_users_today),
            "conversions_today": int(conversions_today),
            "success_rate": success_rate,
            "active_subscriptions": int(active_subs),
            "mrr_cents": int(mrr_cents),
            "mrr": round(mrr_cents / 100, 2),
            "pending_approvals": int(pending_approvals),
        },
        "chart_30d": chart,
        "top_pairs": top_pairs,
        "recent_errors": [_job_dict(j) for j in recent_errors],
        "disabled_pair_alerts": [
            {
                "pair_slug": p.pair_slug,
                "last_error": p.last_error,
                "last_checked_at": p.last_checked_at.isoformat() if p.last_checked_at else None,
            }
            for p in disabled_pairs
        ],
    }


# ---------------------------------------------------------------------------
# Users
# ---------------------------------------------------------------------------

class BanBody(BaseModel):
    reason: str = ""


class ChangePlanBody(BaseModel):
    plan: str
    reason: str = ""
    complimentary_days: int = 0


class ExtendPeriodBody(BaseModel):
    days: int = Field(ge=1, le=3650)
    reason: str = ""


class CancelSubscriptionBody(BaseModel):
    reason: str = ""


class NotesBody(BaseModel):
    notes: str = ""


@router.get("/users")
async def list_users(
    q: Optional[str] = Query(None, description="Search email or display name"),
    plan: Optional[str] = Query(None),
    banned: Optional[bool] = Query(None),
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    sort: str = Query("created_at"),
    order: str = Query("desc"),
    db: AsyncSession = Depends(get_db),
    admin=Depends(require_admin("users", "read")),
):
    stmt = select(User).where(User.deleted_at.is_(None))
    if q:
        like = f"%{q.strip().lower()}%"
        stmt = stmt.where(
            or_(
                func.lower(User.email).like(like),
                func.lower(User.display_name).like(like),
            )
        )
    if plan:
        stmt = stmt.where(User.plan == plan)
    if banned is not None:
        stmt = stmt.where(User.banned.is_(banned))
    columns = {
        "created_at": User.created_at,
        "email": User.email,
        "plan": User.plan,
        "last_login_at": User.last_login_at,
    }
    col = _sort_column(User, sort, columns, "created_at")
    stmt = stmt.order_by(col.desc() if order.lower() == "desc" else col.asc())
    page, per_page = _page_params(page, per_page)
    users, total, page, per_page = await _paginate(db, stmt, page, per_page)
    result = _page_response([_user_dict(u) for u in users], total, page, per_page)
    return result


@router.get("/users/{user_id}")
async def user_detail(
    user_id: str,
    db: AsyncSession = Depends(get_db),
    admin=Depends(require_admin("users", "read")),
):
    user = await _get_user_or_404(db, user_id)
    tz = _quota_tz()
    today = datetime.now(tz).date()
    today_start, today_end = _day_bounds_utc(today, tz)
    month_start = datetime.combine(today.replace(day=1), time.min, tzinfo=timezone.utc)

    usage_today = (
        await db.execute(
            select(func.count()).select_from(Job).where(
                Job.user_id == user.id,
                Job.created_at >= today_start,
                Job.created_at < today_end,
            )
        )
    ).scalar_one()
    usage_month = (
        await db.execute(
            select(func.count()).select_from(Job).where(
                Job.user_id == user.id, Job.created_at >= month_start
            )
        )
    ).scalar_one()
    sub = await _latest_subscription(db, user.id)
    plan = await db.get(Plan, sub.plan_id) if sub is not None else None
    requests = (
        await db.execute(
            select(PaymentRequest)
            .where(PaymentRequest.user_id == user.id)
            .order_by(PaymentRequest.created_at.desc())
            .limit(50)
        )
    ).scalars().all()
    jobs = (
        await db.execute(
            select(Job)
            .where(Job.user_id == user.id)
            .order_by(Job.created_at.desc())
            .limit(20)
        )
    ).scalars().all()
    sessions = (
        await db.execute(
            select(UserSession)
            .where(UserSession.user_id == user.id)
            .order_by(UserSession.created_at.desc())
            .limit(20)
        )
    ).scalars().all()
    return {
        "user": _user_dict(user),
        "usage": {"today": int(usage_today), "this_month": int(usage_month)},
        "subscription": _subscription_dict(sub, plan),
        "payment_requests": [_payment_request_dict(r) for r in requests],
        "payments": [
            _payment_request_dict(r) for r in requests if r.status == "approved"
        ],
        "jobs": [_job_dict(j) for j in jobs],
        "sessions": [
            {
                "id": str(s.id),
                "ip": s.ip,
                "user_agent": s.user_agent,
                "created_at": s.created_at.isoformat() if s.created_at else None,
                "last_seen_at": s.last_seen_at.isoformat() if getattr(s, "last_seen_at", None) else None,
                "expires_at": s.expires_at.isoformat() if s.expires_at else None,
                "revoked": bool(getattr(s, "revoked_at", None)),
            }
            for s in sessions
        ],
        "notes": await _user_notes(db, user.id),
    }


@router.post("/users/{user_id}/ban")
async def ban_user(
    user_id: str,
    body: BanBody,
    request: Request,
    db: AsyncSession = Depends(get_db),
    admin=Depends(require_admin("users", "write")),
    _csrf: bool = Depends(require_csrf),
):
    reason = _require_reason(body.reason, "ban a user")
    user = await _get_user_or_404(db, user_id)
    before = {"banned": bool(user.banned), "ban_reason": user.ban_reason}
    user.banned = True
    user.ban_reason = reason
    db.add(user)
    # Banning revokes all user sessions (spec §8.5).
    sessions = (
        await db.execute(
            select(UserSession).where(
                UserSession.user_id == user.id, UserSession.revoked_at.is_(None)
            )
        )
    ).scalars().all()
    for s in sessions:
        s.revoked_at = _utcnow()
        db.add(s)
    after = {"banned": True, "ban_reason": reason, "sessions_revoked": len(sessions)}
    await audit_log_write(db, admin.email, "users.ban", user.id, before, after, _client_ip(request))
    await db.commit()
    return {"user": _user_dict(user), "sessions_revoked": len(sessions)}


@router.post("/users/{user_id}/unban")
async def unban_user(
    user_id: str,
    body: BanBody,
    request: Request,
    db: AsyncSession = Depends(get_db),
    admin=Depends(require_admin("users", "write")),
    _csrf: bool = Depends(require_csrf),
):
    reason = _require_reason(body.reason, "unban a user")
    user = await _get_user_or_404(db, user_id)
    before = {"banned": bool(user.banned), "ban_reason": user.ban_reason}
    user.banned = False
    user.ban_reason = None
    db.add(user)
    after = {"banned": False, "ban_reason": None, "unban_reason": reason}
    await audit_log_write(db, admin.email, "users.unban", user.id, before, after, _client_ip(request))
    await db.commit()
    return {"user": _user_dict(user)}


@router.post("/users/{user_id}/change-plan")
async def change_plan(
    user_id: str,
    body: ChangePlanBody,
    request: Request,
    db: AsyncSession = Depends(get_db),
    admin=Depends(require_admin("users", "write")),
    _csrf: bool = Depends(require_csrf),
):
    reason = _require_reason(body.reason, "change a user's plan")
    user = await _get_user_or_404(db, user_id)
    plan = await _get_plan_or_404(db, body.plan)
    if getattr(plan, "archived", False):
        raise admin_error(
            422, "plan_archived",
            "That plan is archived and cannot be assigned to new subscribers.",
            "Choose an active plan.",
        )
    sub = await _latest_subscription(db, user.id)
    before = {
        "user_plan": user.plan,
        "subscription_plan": sub.plan_id if sub else None,
        "subscription_status": sub.status if sub else None,
        "current_period_end": sub.current_period_end.isoformat() if sub and sub.current_period_end else None,
    }
    user.plan = plan.id
    db.add(user)
    now = _utcnow()
    period_end = now + timedelta(days=30)
    if body.complimentary_days:
        period_end = now + timedelta(days=body.complimentary_days)
    if sub is None:
        sub = Subscription(
            user_id=user.id, plan_id=plan.id, provider_key="manual",
            interval="monthly", status="active", current_period_end=period_end,
        )
    else:
        sub.plan_id = plan.id
        sub.status = "active"
        sub.cancel_at_period_end = False
        if body.complimentary_days:
            base = sub.current_period_end if sub.current_period_end else now
            if base.tzinfo is None:
                base = base.replace(tzinfo=timezone.utc)
            if base < now:
                base = now
            sub.current_period_end = base + timedelta(days=body.complimentary_days)
        elif sub.current_period_end is None:
            sub.current_period_end = period_end
        sub.updated_at = now
    db.add(sub)
    after = {
        "user_plan": plan.id,
        "subscription_plan": plan.id,
        "subscription_status": "active",
        "current_period_end": sub.current_period_end.isoformat() if sub.current_period_end else None,
        "reason": reason,
        "complimentary_days": body.complimentary_days,
    }
    await audit_log_write(db, admin.email, "users.change_plan", user.id, before, after, _client_ip(request))
    await db.commit()
    return {"user": _user_dict(user), "subscription": _subscription_dict(sub, plan)}


@router.post("/users/{user_id}/extend-period")
async def extend_period(
    user_id: str,
    body: ExtendPeriodBody,
    request: Request,
    db: AsyncSession = Depends(get_db),
    admin=Depends(require_admin("users", "write")),
    _csrf: bool = Depends(require_csrf),
):
    user = await _get_user_or_404(db, user_id)
    sub = await _latest_subscription(db, user.id)
    if sub is None:
        raise admin_error(
            404, "subscription_not_found",
            "This user has no subscription to extend.",
            "Change the plan first to create a subscription.",
        )
    now = _utcnow()
    base = sub.current_period_end or now
    if base.tzinfo is None:
        base = base.replace(tzinfo=timezone.utc)
    if base < now:
        base = now
    before = {"current_period_end": sub.current_period_end.isoformat() if sub.current_period_end else None}
    sub.current_period_end = base + timedelta(days=body.days)
    sub.updated_at = now
    db.add(sub)
    after = {
        "current_period_end": sub.current_period_end.isoformat(),
        "extended_days": body.days,
        "reason": (body.reason or "").strip(),
    }
    await audit_log_write(db, admin.email, "users.extend_period", user.id, before, after, _client_ip(request))
    await db.commit()
    plan = await db.get(Plan, sub.plan_id)
    return {"subscription": _subscription_dict(sub, plan)}


@router.post("/users/{user_id}/cancel-subscription")
async def cancel_subscription(
    user_id: str,
    body: CancelSubscriptionBody,
    request: Request,
    db: AsyncSession = Depends(get_db),
    admin=Depends(require_admin("users", "write")),
    _csrf: bool = Depends(require_csrf),
):
    user = await _get_user_or_404(db, user_id)
    sub = await _latest_subscription(db, user.id)
    if sub is None:
        raise admin_error(
            404, "subscription_not_found",
            "This user has no subscription to cancel.",
            "Nothing to cancel.",
        )
    before = {"status": sub.status, "cancel_at_period_end": bool(sub.cancel_at_period_end)}
    # Cancel at period end: access continues until current_period_end.
    sub.cancel_at_period_end = True
    sub.status = "active"
    sub.updated_at = _utcnow()
    db.add(sub)
    after = {
        "status": "active",
        "cancel_at_period_end": True,
        "current_period_end": sub.current_period_end.isoformat() if sub.current_period_end else None,
        "reason": (body.reason or "").strip(),
    }
    await audit_log_write(db, admin.email, "users.cancel_subscription", user.id, before, after, _client_ip(request))
    await db.commit()
    plan = await db.get(Plan, sub.plan_id)
    return {"subscription": _subscription_dict(sub, plan)}


@router.post("/users/{user_id}/force-signout")
async def force_signout(
    user_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    admin=Depends(require_admin("users", "write")),
    _csrf: bool = Depends(require_csrf),
):
    user = await _get_user_or_404(db, user_id)
    sessions = (
        await db.execute(
            select(UserSession).where(
                UserSession.user_id == user.id, UserSession.revoked_at.is_(None)
            )
        )
    ).scalars().all()
    for s in sessions:
        s.revoked_at = _utcnow()
        db.add(s)
    await audit_log_write(
        db, admin.email, "users.force_signout", user.id,
        {"active_sessions": len(sessions)}, {"active_sessions": 0}, _client_ip(request),
    )
    await db.commit()
    return {"signed_out_sessions": len(sessions)}


@router.patch("/users/{user_id}/notes")
async def update_notes(
    user_id: str,
    body: NotesBody,
    request: Request,
    db: AsyncSession = Depends(get_db),
    admin=Depends(require_admin("users", "write")),
    _csrf: bool = Depends(require_csrf),
):
    user = await _get_user_or_404(db, user_id)
    before = {"notes": await _user_notes(db, user.id)}
    await _set_setting(db, f"user_notes:{user.id}", body.notes)
    after = {"notes": body.notes}
    await audit_log_write(db, admin.email, "users.update_notes", user.id, before, after, _client_ip(request))
    await db.commit()
    return {"user_id": str(user.id), "notes": body.notes}

# ---------------------------------------------------------------------------
# Team
# ---------------------------------------------------------------------------

class TeamCreateBody(BaseModel):
    email: str
    password: str
    role: str = "staff"
    permissions: dict = Field(default_factory=dict)


class TeamUpdateBody(BaseModel):
    role: Optional[str] = None
    permissions: Optional[dict] = None
    active: Optional[bool] = None


def _validate_team_permissions(permissions: dict) -> dict:
    if not isinstance(permissions, dict):
        raise admin_error(422, "invalid_permissions", "Permissions must be an object.",
                          "Send an object keyed by sidebar section.")
    cleaned: dict[str, list[str]] = {}
    for section, value in permissions.items():
        if section not in SIDEBAR_SECTIONS:
            raise admin_error(
                422, "invalid_permissions",
                f"'{section}' is not a sidebar section.",
                f"Use one of: {', '.join(SIDEBAR_SECTIONS)}.",
            )
        if isinstance(value, str):
            levels = [value]
        elif isinstance(value, (list, tuple)):
            levels = [str(v) for v in value]
        elif isinstance(value, dict):
            levels = [k for k, v in value.items() if v]
        else:
            raise admin_error(422, "invalid_permissions",
                              f"Permission for '{section}' must be 'read', 'write' or a list.",
                              "Use 'read' and/or 'write'.")
        for level in levels:
            if level not in ("read", "write"):
                raise admin_error(422, "invalid_permissions",
                                  f"Permission level '{level}' is not valid.",
                                  "Use 'read' and/or 'write'.")
        cleaned[section] = sorted(set(levels))
    return cleaned


@router.get("/team")
async def list_team(
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
    admin=Depends(require_admin("team", "read")),
):
    stmt = select(AdminUser).order_by(AdminUser.email.asc())
    page, per_page = _page_params(page, per_page)
    admins, total, page, per_page = await _paginate(db, stmt, page, per_page)
    return _page_response([admin_public_dict(a) for a in admins], total, page, per_page)


@router.post("/team")
async def create_team_member(
    body: TeamCreateBody,
    request: Request,
    db: AsyncSession = Depends(get_db),
    admin=Depends(require_admin("team", "write")),
    _csrf: bool = Depends(require_csrf),
):
    email = body.email.strip().lower()
    if "@" not in email:
        raise admin_error(422, "invalid_email", "Enter a valid email address.",
                          "Check the email and try again.")
    if body.role not in ("super_admin", "staff"):
        raise admin_error(422, "invalid_role", "Role must be super_admin or staff.",
                          "Choose super_admin or staff.")
    error = validate_admin_password(body.password)
    if error:
        raise admin_error(422, "admin_password_too_short", error,
                          "Use a password of at least 12 characters.")
    existing = (
        await db.execute(select(AdminUser).where(func.lower(AdminUser.email) == email))
    ).scalar_one_or_none()
    if existing is not None:
        raise admin_error(409, "admin_exists", "An admin with that email already exists.",
                          "Use a different email address.")
    permissions = _validate_team_permissions(body.permissions or {})
    new_admin = AdminUser(
        email=email,
        password_hash=hash_password(body.password),
        role=body.role,
        permissions=permissions,
        active=True,
        must_change_password=True,  # forced change at first login (§13.2)
    )
    db.add(new_admin)
    await audit_log_write(
        db, admin.email, "team.create", email,
        None, {"email": email, "role": body.role, "permissions": permissions},
        _client_ip(request),
    )
    await db.commit()
    await db.refresh(new_admin)
    return admin_public_dict(new_admin)


@router.patch("/team/{admin_id}")
async def update_team_member(
    admin_id: str,
    body: TeamUpdateBody,
    request: Request,
    db: AsyncSession = Depends(get_db),
    admin=Depends(require_admin("team", "write")),
    _csrf: bool = Depends(require_csrf),
):
    target = await db.get(AdminUser, admin_id)
    if target is None:
        raise admin_error(404, "admin_not_found", "No admin with that id exists.",
                          "Check the admin id and try again.")
    if body.role is not None and body.role not in ("super_admin", "staff"):
        raise admin_error(422, "invalid_role", "Role must be super_admin or staff.",
                          "Choose super_admin or staff.")
    before = {
        "role": target.role,
        "permissions": getattr(target, "permissions", None) or {},
        "active": bool(target.active),
    }
    if body.role is not None:
        target.role = body.role
    if body.permissions is not None:
        target.permissions = _validate_team_permissions(body.permissions)
    if body.active is not None:
        if str(target.id) == str(admin.id) and body.active is False:
            raise admin_error(422, "cannot_disable_self",
                              "You cannot disable your own admin account.",
                              "Ask another super admin to disable it.")
        target.active = body.active
    db.add(target)
    after = {
        "role": target.role,
        "permissions": getattr(target, "permissions", None) or {},
        "active": bool(target.active),
    }
    await audit_log_write(db, admin.email, "team.update", target.email, before, after, _client_ip(request))
    await db.commit()
    return admin_public_dict(target)


@router.delete("/team/{admin_id}")
async def delete_team_member(
    admin_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    admin=Depends(require_admin("team", "write")),
    _csrf: bool = Depends(require_csrf),
):
    target = await db.get(AdminUser, admin_id)
    if target is None:
        raise admin_error(404, "admin_not_found", "No admin with that id exists.",
                          "Check the admin id and try again.")
    if str(target.id) == str(admin.id):
        raise admin_error(422, "cannot_delete_self",
                          "You cannot delete your own admin account.",
                          "Ask another super admin to delete it.")
    super_count = (
        await db.execute(
            select(func.count()).select_from(AdminUser).where(
                AdminUser.role == "super_admin", AdminUser.active.is_(True)
            )
        )
    ).scalar_one()
    if target.role == "super_admin" and super_count <= 1:
        raise admin_error(
            422, "cannot_delete_last_super_admin",
            "You cannot delete the last active super admin.",
            "Create another super admin first.",
        )
    before = admin_public_dict(target)
    sessions = (
        await db.execute(
            select(AdminSession).where(
                AdminSession.admin_id == target.id, AdminSession.revoked_at.is_(None)
            )
        )
    ).scalars().all()
    for s in sessions:
        s.revoked_at = _utcnow()
        db.add(s)
    await db.delete(target)
    await audit_log_write(db, admin.email, "team.delete", target.email, before, None, _client_ip(request))
    await db.commit()
    return {"deleted": True, "email": target.email}


@router.post("/team/{admin_id}/reset-link")
async def team_reset_link(
    admin_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    admin=Depends(require_admin("team", "write")),
    _csrf: bool = Depends(require_csrf),
):
    """Generate a one-time password reset link for a team member.

    The link is returned once and must be handed to the member out of band
    (the admin app shows it with a copy button). It expires after 1 hour
    and is invalidated by use (the password reset revokes all sessions).
    """
    target = await db.get(AdminUser, admin_id)
    if target is None:
        raise admin_error(404, "admin_not_found", "No admin with that id exists.",
                          "Check the admin id and try again.")
    token = make_admin_reset_token(str(target.id))
    base_url = (await _get_setting(db, "site_url", None)) or os.environ.get("SITE_URL", "")
    base_url = str(base_url).rstrip("/") if base_url else ""
    reset_link = f"{base_url}/admin/reset-password?token={token}" if base_url else f"/admin/reset-password?token={token}"
    await audit_log_write(
        db, admin.email, "team.reset_link", target.email,
        None, {"reset_link_issued": True}, _client_ip(request),
    )
    await db.commit()
    return {"email": target.email, "reset_link": reset_link, "expires_in_seconds": 3600}


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------

GENERAL_SETTING_KEYS = (
    "site_name", "site_url", "support_email", "pkr_per_usd", "quota_tz",
    "approval_window_text", "maintenance_mode", "admin_ip_allowlist",
)

LEGAL_SETTING_KEYS = ("legal_privacy", "legal_terms", "legal_owner_name",
                      "legal_contact_email", "legal_address", "legal_governing_law")

LIMITS_SETTING_KEYS = (
    "retention_hours", "upload_rate_per_min", "convert_rate_per_min",
    "max_upload_mb", "max_batch_files",
)

EMAIL_PLACEHOLDERS = ("name", "plan", "reference", "amount", "reason", "date", "link")

SMTP_SETTING_KEYS = ("smtp_host", "smtp_port", "smtp_user", "smtp_password",
                     "smtp_from", "smtp_use_tls")


class GeneralSettingsBody(BaseModel):
    site_name: Optional[str] = None
    site_url: Optional[str] = None
    support_email: Optional[str] = None
    pkr_per_usd: Optional[float] = None
    quota_tz: Optional[str] = None
    approval_window_text: Optional[str] = None
    maintenance_mode: Optional[bool] = None
    admin_ip_allowlist: Optional[list] = None


class LegalSettingsBody(BaseModel):
    legal_privacy: Optional[str] = None
    legal_terms: Optional[str] = None
    legal_owner_name: Optional[str] = None
    legal_contact_email: Optional[str] = None
    legal_address: Optional[str] = None
    legal_governing_law: Optional[str] = None


class LimitsSettingsBody(BaseModel):
    retention_hours: Optional[int] = None
    upload_rate_per_min: Optional[int] = None
    convert_rate_per_min: Optional[int] = None
    max_upload_mb: Optional[int] = None
    max_batch_files: Optional[int] = None


class EmailSettingsBody(BaseModel):
    smtp_host: Optional[str] = None
    smtp_port: Optional[int] = None
    smtp_user: Optional[str] = None
    smtp_password: Optional[str] = None
    smtp_from: Optional[str] = None
    smtp_use_tls: Optional[bool] = None
    templates: Optional[list] = None  # [{key, subject, body}]


def _settings_snapshot(db_values: dict, keys) -> dict:
    return {k: db_values.get(k) for k in keys}


# The admin Settings pages (General, Limits) call the single aggregate
# endpoint GET/PATCH /admin/settings; the section endpoints below
# (/settings/general, /settings/limits, ...) are the same data split by
# section. The aggregate merges the general + limits keys and accepts the
# field names the admin pages send, which differ from the canonical
# storage keys in three places (see _SETTINGS_ALIASES): the pages send
# `quota_timezone` (stored as `quota_tz`), `max_batch` (stored as
# `max_batch_files`) and `max_file_mb` (stored as `max_upload_mb`).
# `approval_window_hours` is stored as its own site_settings row (the
# seed supplies it); the runtime still reads the APPROVAL_WINDOW_HOURS
# env var, so changing it here only affects what the panel shows until
# the runtime is moved to the stored value.
_SETTINGS_ALIASES = {
    "quota_timezone": "quota_tz",
    "max_batch": "max_batch_files",
    "max_file_mb": "max_upload_mb",
}


class AllSettingsBody(BaseModel):
    site_name: Optional[str] = None
    site_url: Optional[str] = None
    support_email: Optional[str] = None
    pkr_per_usd: Optional[float] = None
    quota_tz: Optional[str] = None
    quota_timezone: Optional[str] = None
    approval_window_hours: Optional[int] = None
    approval_window_text: Optional[str] = None
    maintenance_mode: Optional[bool] = None
    admin_ip_allowlist: Optional[list] = None
    retention_hours: Optional[int] = None
    upload_rate_per_min: Optional[int] = None
    convert_rate_per_min: Optional[int] = None
    max_upload_mb: Optional[int] = None
    max_batch_files: Optional[int] = None
    max_batch: Optional[int] = None
    max_file_mb: Optional[int] = None


async def _all_settings(db: AsyncSession) -> dict:
    values: dict = {}
    for key in GENERAL_SETTING_KEYS:
        values[key] = await _get_setting(db, key)
    for key in LIMITS_SETTING_KEYS:
        values[key] = await _get_setting(db, key)
    if values.get("site_name") is None:
        values["site_name"] = "Quick IMG Convert"
    if values.get("pkr_per_usd") is None:
        values["pkr_per_usd"] = float(os.environ.get("PKR_PER_USD", "0") or 0) or None
    if values.get("quota_tz") is None:
        # The seed stores this under `quota_timezone`; accept that row too.
        values["quota_tz"] = await _get_setting(db, "quota_timezone")
    if values.get("quota_tz") is None:
        values["quota_tz"] = os.environ.get("QUOTA_TZ", "Asia/Karachi")
    if values.get("maintenance_mode") is None:
        values["maintenance_mode"] = False
    if values.get("retention_hours") is None:
        values["retention_hours"] = int(os.environ.get("RETENTION_HOURS", "24"))
    # Aliases the admin pages read.
    values["quota_timezone"] = values.get("quota_tz")
    values["max_batch"] = values.get("max_batch_files")
    values["max_file_mb"] = values.get("max_upload_mb")
    approval_hours = await _get_setting(db, "approval_window_hours")
    values["approval_window_hours"] = (
        approval_hours
        if approval_hours is not None
        else int(os.environ.get("APPROVAL_WINDOW_HOURS", "24"))
    )
    return values


@router.get("/settings")
async def get_all_settings(
    db: AsyncSession = Depends(get_db),
    admin=Depends(require_admin("settings", "read")),
):
    return await _all_settings(db)


@router.patch("/settings")
async def patch_all_settings(
    body: AllSettingsBody,
    request: Request,
    db: AsyncSession = Depends(get_db),
    admin=Depends(require_admin("settings", "write")),
    _csrf: bool = Depends(require_csrf),
):
    before = await _all_settings(db)
    data = body.model_dump(exclude_unset=True)
    # Canonicalise the admin pages' field names.
    for alias, canonical in _SETTINGS_ALIASES.items():
        if alias in data:
            if canonical not in data:
                data[canonical] = data.pop(alias)
            else:
                data.pop(alias)
    if "pkr_per_usd" in data and data["pkr_per_usd"] is not None and data["pkr_per_usd"] <= 0:
        raise admin_error(422, "invalid_setting", "pkr_per_usd must be greater than zero.",
                          "Enter a positive exchange rate.")
    if data.get("quota_tz"):
        try:
            ZoneInfo(data["quota_tz"])
        except Exception:
            raise admin_error(422, "invalid_setting",
                              f"'{data['quota_tz']}' is not a valid timezone.",
                              "Use an IANA timezone name such as Asia/Karachi.")
    if "admin_ip_allowlist" in data and data["admin_ip_allowlist"] is not None:
        for entry in data["admin_ip_allowlist"]:
            try:
                import ipaddress as _ip

                _ip.ip_network(str(entry), strict=False)
            except ValueError:
                raise admin_error(422, "invalid_setting",
                                  f"'{entry}' is not a valid IP or CIDR range.",
                                  "Use an IP address or CIDR range.")
    for key in ("retention_hours", "upload_rate_per_min", "convert_rate_per_min",
                "max_upload_mb", "max_batch_files", "approval_window_hours"):
        if key in data and data[key] is not None and data[key] < 0:
            raise admin_error(422, "invalid_setting", f"{key} cannot be negative.",
                              "Enter zero or a positive number.")
    for key, value in data.items():
        await _set_setting(db, key, value)
    after = await _all_settings(db)
    await audit_log_write(db, admin.email, "settings.all", "all",
                          diff_dicts(before, after), after, _client_ip(request))
    await db.commit()
    return after


@router.get("/settings/general")
async def get_general_settings(
    db: AsyncSession = Depends(get_db),
    admin=Depends(require_admin("settings", "read")),
):
    values = {}
    for key in GENERAL_SETTING_KEYS:
        values[key] = await _get_setting(db, key)
    if values.get("site_name") is None:
        values["site_name"] = "Quick IMG Convert"
    if values.get("pkr_per_usd") is None:
        values["pkr_per_usd"] = float(os.environ.get("PKR_PER_USD", "0") or 0) or None
    if values.get("quota_tz") is None:
        values["quota_tz"] = os.environ.get("QUOTA_TZ", "Asia/Karachi")
    if values.get("maintenance_mode") is None:
        values["maintenance_mode"] = False
    return values


@router.patch("/settings/general")
async def patch_general_settings(
    body: GeneralSettingsBody,
    request: Request,
    db: AsyncSession = Depends(get_db),
    admin=Depends(require_admin("settings", "write")),
    _csrf: bool = Depends(require_csrf),
):
    before = {k: await _get_setting(db, k) for k in GENERAL_SETTING_KEYS}
    data = body.model_dump(exclude_unset=True)
    if "pkr_per_usd" in data and data["pkr_per_usd"] is not None and data["pkr_per_usd"] <= 0:
        raise admin_error(422, "invalid_setting", "pkr_per_usd must be greater than zero.",
                          "Enter a positive exchange rate.")
    if "quota_tz" in data and data["quota_tz"]:
        try:
            ZoneInfo(data["quota_tz"])
        except Exception:
            raise admin_error(422, "invalid_setting",
                              f"'{data['quota_tz']}' is not a valid timezone.",
                              "Use an IANA timezone name such as Asia/Karachi.")
    if "admin_ip_allowlist" in data and data["admin_ip_allowlist"] is not None:
        for entry in data["admin_ip_allowlist"]:
            try:
                import ipaddress as _ip

                _ip.ip_network(str(entry), strict=False)
            except ValueError:
                raise admin_error(422, "invalid_setting",
                                  f"'{entry}' is not a valid IP or CIDR range.",
                                  "Use an IP address or CIDR range.")
    # Maintenance mode keeps the admin panel and webhooks reachable: that
    # behaviour is enforced by the web/API middleware reading this flag;
    # this endpoint only stores it.
    for key, value in data.items():
        await _set_setting(db, key, value)
    after = {k: await _get_setting(db, k) for k in GENERAL_SETTING_KEYS}
    await audit_log_write(db, admin.email, "settings.general", "general",
                          diff_dicts(before, after), after, _client_ip(request))
    await db.commit()
    return after


@router.get("/settings/legal")
async def get_legal_settings(
    db: AsyncSession = Depends(get_db),
    admin=Depends(require_admin("settings", "read")),
):
    return {k: await _get_setting(db, k, "") for k in LEGAL_SETTING_KEYS}


@router.patch("/settings/legal")
async def patch_legal_settings(
    body: LegalSettingsBody,
    request: Request,
    db: AsyncSession = Depends(get_db),
    admin=Depends(require_admin("settings", "write")),
    _csrf: bool = Depends(require_csrf),
):
    before = {k: await _get_setting(db, k, "") for k in LEGAL_SETTING_KEYS}
    data = body.model_dump(exclude_unset=True)
    for key, value in data.items():
        await _set_setting(db, key, value)
    after = {k: await _get_setting(db, k, "") for k in LEGAL_SETTING_KEYS}
    await audit_log_write(db, admin.email, "settings.legal", "legal",
                          diff_dicts(before, after), after, _client_ip(request))
    await db.commit()
    return after


def _validate_template_placeholders(body: str, key: str) -> None:
    found = set(re.findall(r"\{([a-z_]+)\}", body or ""))
    unknown = found - set(EMAIL_PLACEHOLDERS)
    if unknown:
        raise admin_error(
            422, "invalid_placeholder",
            f"Template '{key}' uses unknown placeholder(s): {', '.join(sorted(unknown))}.",
            f"Allowed placeholders: {', '.join('{' + p + '}' for p in EMAIL_PLACEHOLDERS)}.",
        )


@router.get("/settings/email")
async def get_email_settings(
    db: AsyncSession = Depends(get_db),
    admin=Depends(require_admin("settings", "read")),
):
    smtp = {}
    for key in SMTP_SETTING_KEYS:
        value = await _get_setting(db, key)
        if value is None:
            value = os.environ.get(key.upper())
        if key == "smtp_password" and value:
            value = "********"  # masked: write-only in practice
        smtp[key] = value
    templates = (await db.execute(select(EmailTemplate))).scalars().all()
    return {
        "smtp": smtp,
        "placeholders": ["{" + p + "}" for p in EMAIL_PLACEHOLDERS],
        "templates": [
            {"key": t.key, "subject": t.subject, "body": t.body} for t in templates
        ],
    }


@router.patch("/settings/email")
async def patch_email_settings(
    body: EmailSettingsBody,
    request: Request,
    db: AsyncSession = Depends(get_db),
    admin=Depends(require_admin("settings", "write")),
    _csrf: bool = Depends(require_csrf),
):
    before_smtp = {k: await _get_setting(db, k) for k in SMTP_SETTING_KEYS}
    data = body.model_dump(exclude_unset=True)
    templates_data = data.pop("templates", None)
    for key, value in data.items():
        if key == "smtp_password" and value in (None, "", "********"):
            continue  # masked value means "keep the stored password"
        await _set_setting(db, key, value)
    if templates_data is not None:
        for item in templates_data:
            key = (item or {}).get("key")
            if not key:
                continue
            _validate_template_placeholders((item or {}).get("body", ""), key)
            row = await db.get(EmailTemplate, key)
            if row is None:
                db.add(EmailTemplate(
                    key=key,
                    subject=(item or {}).get("subject", ""),
                    body=(item or {}).get("body", ""),
                ))
            else:
                if "subject" in (item or {}):
                    row.subject = item["subject"]
                if "body" in (item or {}):
                    row.body = item["body"]
                db.add(row)
    after_smtp = {k: await _get_setting(db, k) for k in SMTP_SETTING_KEYS}
    await audit_log_write(
        db, admin.email, "settings.email", "email",
        {k: ("********" if k == "smtp_password" and v else v) for k, v in before_smtp.items()},
        {k: ("********" if k == "smtp_password" and v else v) for k, v in after_smtp.items()},
        _client_ip(request),
    )
    await db.commit()
    return await get_email_settings(db=db, admin=admin)


@router.post("/settings/email/test")
async def test_email_settings(
    request: Request,
    db: AsyncSession = Depends(get_db),
    admin=Depends(require_admin("settings", "write")),
    _csrf: bool = Depends(require_csrf),
):
    """SMTP check: sends a real message to the signed-in admin's own address."""
    host = await _get_setting(db, "smtp_host") or os.environ.get("SMTP_HOST")
    port = await _get_setting(db, "smtp_port") or os.environ.get("SMTP_PORT")
    user = await _get_setting(db, "smtp_user") or os.environ.get("SMTP_USER")
    password = await _get_setting(db, "smtp_password") or os.environ.get("SMTP_PASSWORD")
    sender = await _get_setting(db, "smtp_from") or os.environ.get("SMTP_FROM") or user
    use_tls = await _get_setting(db, "smtp_use_tls")
    if use_tls is None:
        use_tls = True
    if not host:
        raise admin_error(
            422, "smtp_not_configured",
            "SMTP is not configured yet.",
            "Fill in the SMTP host, port and credentials first.",
        )
    msg = EmailMessage()
    msg["Subject"] = "Quick IMG Convert — SMTP check"
    msg["From"] = sender or "Quick IMG Convert"
    msg["To"] = admin.email
    msg.set_content(
        "This is a check message from the Quick IMG Convert admin panel.\n\n"
        "If you received this email, SMTP is configured correctly."
    )
    try:
        with smtplib.SMTP(str(host), int(port or 587), timeout=15) as server:
            if use_tls:
                server.starttls()
            if user and password:
                server.login(str(user), str(password))
            server.send_message(msg)
    except Exception as exc:  # pragma: no cover - needs a live SMTP server
        raise admin_error(
            502, "smtp_failed",
            f"Could not send the check email: {exc}",
            "Check the SMTP host, port, credentials and firewall rules.",
        )
    return {"sent": True, "to": admin.email}


@router.get("/settings/limits")
async def get_limits_settings(
    db: AsyncSession = Depends(get_db),
    admin=Depends(require_admin("settings", "read")),
):
    values = {}
    for key in LIMITS_SETTING_KEYS:
        values[key] = await _get_setting(db, key)
    if values.get("retention_hours") is None:
        values["retention_hours"] = int(os.environ.get("RETENTION_HOURS", "24"))
    return values


@router.patch("/settings/limits")
async def patch_limits_settings(
    body: LimitsSettingsBody,
    request: Request,
    db: AsyncSession = Depends(get_db),
    admin=Depends(require_admin("settings", "write")),
    _csrf: bool = Depends(require_csrf),
):
    before = {k: await _get_setting(db, k) for k in LIMITS_SETTING_KEYS}
    data = body.model_dump(exclude_unset=True)
    for key, value in data.items():
        if value is not None and value < 0:
            raise admin_error(422, "invalid_setting", f"{key} cannot be negative.",
                              "Enter zero or a positive number.")
    for key, value in data.items():
        await _set_setting(db, key, value)
    after = {k: await _get_setting(db, k) for k in LIMITS_SETTING_KEYS}
    await audit_log_write(db, admin.email, "settings.limits", "limits",
                          diff_dicts(before, after), after, _client_ip(request))
    await db.commit()
    return after


@router.post("/settings/danger/purge")
async def danger_purge(
    request: Request,
    db: AsyncSession = Depends(get_db),
    admin=Depends(require_admin("settings", "write")),
    _csrf: bool = Depends(require_csrf),
):
    """Delete expired conversion data (jobs/events past retention).

    Uploads and output files are deleted by the worker retention job; this
    endpoint purges the matching database rows.
    """
    retention_hours = await _get_setting(db, "retention_hours")
    if retention_hours is None:
        retention_hours = int(os.environ.get("RETENTION_HOURS", "24"))
    cutoff = _utcnow() - timedelta(hours=int(retention_hours))
    expired_jobs = (
        await db.execute(select(Job).where(Job.expires_at.is_not(None), Job.expires_at < cutoff))
    ).scalars().all()
    for job in expired_jobs:
        await db.delete(job)
    old_events = (
        await db.execute(select(Event).where(Event.ts < cutoff))
    ).scalars().all()
    for event in old_events:
        await db.delete(event)
    result = {"jobs_purged": len(expired_jobs), "events_purged": len(old_events)}
    await audit_log_write(db, admin.email, "settings.danger_purge", "danger",
                          None, result, _client_ip(request))
    await db.commit()
    return result


@router.get("/settings/danger/export")
async def danger_export(
    db: AsyncSession = Depends(get_db),
    admin=Depends(require_admin("settings", "read")),
):
    """Full data export (JSON). Password hashes and secrets are excluded."""
    users = (await db.execute(select(User).limit(10000))).scalars().all()
    subs = (await db.execute(select(Subscription).limit(10000))).scalars().all()
    requests = (await db.execute(select(PaymentRequest).limit(10000))).scalars().all()
    plans = (await db.execute(select(Plan))).scalars().all()
    settings = (await db.execute(select(SiteSetting))).scalars().all()
    payload = {
        "exported_at": _utcnow().isoformat(),
        "exported_by": admin.email,
        "users": [
            {**_user_dict(u), "notes": await _user_notes(db, str(u.id))} for u in users
        ],
        "subscriptions": [_subscription_dict(s) for s in subs],
        "payment_requests": [_payment_request_dict(r) for r in requests],
        "plans": [
            {"id": p.id, "name": p.name, "price_cents": p.price_cents,
             "price_yearly_cents": p.price_yearly_cents, "limits": p.limits}
            for p in plans
        ],
        "site_settings": {s.key: s.value for s in settings},
    }
    filename = f"quick-img-convert-export-{_utcnow().date().isoformat()}.json"
    return Response(
        content=json.dumps(payload, indent=2),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )

# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------

_SUCCESS_STATUSES = ("done", "success", "completed")
_FAILED_STATUSES = ("failed", "error")


def _date_range(start: Optional[str], end: Optional[str]) -> tuple[datetime, datetime]:
    end_d = _parse_date(end, "end") or datetime.now(timezone.utc).date()
    start_d = _parse_date(start, "start") or (end_d - timedelta(days=29))
    if start_d > end_d:
        raise admin_error(422, "invalid_date_range", "start must be before end.",
                          "Pick a start date on or before the end date.")
    start_utc = datetime.combine(start_d, time.min, tzinfo=timezone.utc)
    end_utc = datetime.combine(end_d + timedelta(days=1), time.min, tzinfo=timezone.utc)
    return start_utc, end_utc


async def _report_base(db: AsyncSession, start_utc: datetime, end_utc: datetime):
    total = (
        await db.execute(
            select(func.count()).select_from(Job).where(
                Job.created_at >= start_utc, Job.created_at < end_utc
            )
        )
    ).scalar_one()
    done = (
        await db.execute(
            select(func.count()).select_from(Job).where(
                Job.created_at >= start_utc, Job.created_at < end_utc,
                Job.status.in_(_SUCCESS_STATUSES),
            )
        )
    ).scalar_one()
    failed = (
        await db.execute(
            select(func.count()).select_from(Job).where(
                Job.created_at >= start_utc, Job.created_at < end_utc,
                Job.status.in_(_FAILED_STATUSES),
            )
        )
    ).scalar_one()
    bytes_in = (
        await db.execute(
            select(func.coalesce(func.sum(Event.bytes_in), 0)).where(
                Event.ts >= start_utc, Event.ts < end_utc
            )
        )
    ).scalar_one()
    bytes_out = (
        await db.execute(
            select(func.coalesce(func.sum(Event.bytes_out), 0)).where(
                Event.ts >= start_utc, Event.ts < end_utc
            )
        )
    ).scalar_one()
    return {
        "conversions": int(total),
        "successful": int(done),
        "failed": int(failed),
        "success_rate": round(100.0 * done / total, 1) if total else 100.0,
        "bytes_in": int(bytes_in or 0),
        "bytes_out": int(bytes_out or 0),
    }


@router.get("/reports/conversions")
async def report_conversions(
    start: Optional[str] = Query(None),
    end: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
    admin=Depends(require_admin("reports", "read")),
):
    start_utc, end_utc = _date_range(start, end)
    summary = await _report_base(db, start_utc, end_utc)
    rows = (
        await db.execute(
            select(
                func.date(Job.created_at).label("day"),
                func.count().label("total"),
                func.sum(case((Job.status.in_(_SUCCESS_STATUSES), 1), else_=0)).label("done"),
                func.sum(case((Job.status.in_(_FAILED_STATUSES), 1), else_=0)).label("failed"),
                func.coalesce(func.sum(Job.in_size), 0).label("bytes_in"),
                func.coalesce(func.sum(Job.out_size), 0).label("bytes_out"),
            )
            .where(Job.created_at >= start_utc, Job.created_at < end_utc)
            .group_by(func.date(Job.created_at))
            .order_by(func.date(Job.created_at))
        )
    ).all()
    return {
        "start": start_utc.date().isoformat(),
        "end": (end_utc - timedelta(days=1)).date().isoformat(),
        "summary": summary,
        "by_day": [
            {
                "date": str(r.day),
                "conversions": int(r.total),
                "successful": int(r.done or 0),
                "failed": int(r.failed or 0),
                "bytes_in": int(r.bytes_in or 0),
                "bytes_out": int(r.bytes_out or 0),
            }
            for r in rows
        ],
    }


@router.get("/reports/revenue")
async def report_revenue(
    start: Optional[str] = Query(None),
    end: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
    admin=Depends(require_admin("reports", "read")),
):
    start_utc, end_utc = _date_range(start, end)
    by_provider_rows = (
        await db.execute(
            select(
                PaymentRequest.provider_key,
                func.count().label("count"),
                func.coalesce(func.sum(PaymentRequest.amount_cents), 0).label("amount_cents"),
            )
            .where(
                PaymentRequest.status == "approved",
                PaymentRequest.created_at >= start_utc,
                PaymentRequest.created_at < end_utc,
            )
            .group_by(PaymentRequest.provider_key)
            .order_by(func.sum(PaymentRequest.amount_cents).desc())
        )
    ).all()
    by_plan_rows = (
        await db.execute(
            select(
                PaymentRequest.plan_id,
                func.count().label("count"),
                func.coalesce(func.sum(PaymentRequest.amount_cents), 0).label("amount_cents"),
            )
            .where(
                PaymentRequest.status == "approved",
                PaymentRequest.created_at >= start_utc,
                PaymentRequest.created_at < end_utc,
            )
            .group_by(PaymentRequest.plan_id)
            .order_by(func.sum(PaymentRequest.amount_cents).desc())
        )
    ).all()
    total_cents = sum(int(r.amount_cents or 0) for r in by_provider_rows)
    # MRR from currently active subscriptions.
    subs = (await db.execute(select(Subscription).where(
        Subscription.status.in_(("active", "trialing", "past_due"))
    ))).scalars().all()
    plans = {p.id: p for p in (await db.execute(select(Plan))).scalars().all()}
    mrr_cents = 0
    for sub in subs:
        plan = plans.get(sub.plan_id)
        if plan is None:
            continue
        if (getattr(sub, "interval", None) or "monthly") == "yearly":
            mrr_cents += (plan.price_yearly_cents or 0) // 12
        else:
            mrr_cents += plan.price_cents or 0
    # RPM by slot: revenue per 1,000 impressions, from ad_revenue + ad_events.
    revenue_rows = (
        await db.execute(
            select(AdRevenue.network, func.coalesce(func.sum(AdRevenue.amount_cents), 0))
            .where(AdRevenue.day >= start_utc.date(), AdRevenue.day < end_utc.date())
            .group_by(AdRevenue.network)
        )
    ).all()
    impressions_rows = (
        await db.execute(
            select(AdEvent.slot, func.count().label("count"))
            .where(AdEvent.ts >= start_utc, AdEvent.ts < end_utc)
            .group_by(AdEvent.slot)
        )
    ).all()
    total_impressions = sum(int(r.count) for r in impressions_rows)
    total_ad_cents = sum(int(r[1] or 0) for r in revenue_rows)
    rpm = round(total_ad_cents / max(1, total_impressions) * 1000, 2) if total_impressions else 0.0
    return {
        "start": start_utc.date().isoformat(),
        "end": (end_utc - timedelta(days=1)).date().isoformat(),
        "total_revenue_cents": int(total_cents),
        "total_revenue": round(total_cents / 100, 2),
        "by_provider": [
            {"provider_key": r.provider_key, "count": int(r.count), "amount_cents": int(r.amount_cents or 0)}
            for r in by_provider_rows
        ],
        "by_plan": [
            {"plan_id": r.plan_id, "count": int(r.count), "amount_cents": int(r.amount_cents or 0)}
            for r in by_plan_rows
        ],
        "mrr_cents": int(mrr_cents),
        "mrr": round(mrr_cents / 100, 2),
        "ad_revenue_cents": int(total_ad_cents),
        "ad_impressions": int(total_impressions),
        "rpm_cents": rpm,
        "rpm_by_slot": [
            {"slot": r.slot, "impressions": int(r.count)} for r in impressions_rows
        ],
        "revenue_by_network": [
            {"network": r[0], "amount_cents": int(r[1] or 0)} for r in revenue_rows
        ],
    }


@router.get("/reports/funnel")
async def report_funnel(
    start: Optional[str] = Query(None),
    end: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
    admin=Depends(require_admin("reports", "read")),
):
    start_utc, end_utc = _date_range(start, end)
    anon_conversions = (
        await db.execute(
            select(func.count()).select_from(Event).where(
                Event.ts >= start_utc, Event.ts < end_utc,
                Event.owner_type == "anonymous",
            )
        )
    ).scalar_one()
    free_users = (
        await db.execute(
            select(func.count()).select_from(User).where(
                User.plan == "free", User.created_at >= start_utc, User.created_at < end_utc
            )
        )
    ).scalar_one()
    paid_subs = (
        await db.execute(
            select(func.count()).select_from(Subscription).where(
                Subscription.status.in_(("active", "trialing", "past_due")),
                Subscription.created_at >= start_utc,
                Subscription.created_at < end_utc,
            )
        )
    ).scalar_one()
    total_users = (await db.execute(select(func.count()).select_from(User))).scalar_one()
    paid_total = (
        await db.execute(
            select(func.count()).select_from(Subscription).where(
                Subscription.status.in_(("active", "trialing", "past_due"))
            )
        )
    ).scalar_one()
    return {
        "start": start_utc.date().isoformat(),
        "end": (end_utc - timedelta(days=1)).date().isoformat(),
        "anonymous_conversions": int(anon_conversions),
        "free_signups_in_range": int(free_users),
        "paid_subscriptions_in_range": int(paid_subs),
        "total_users": int(total_users),
        "total_paid_subscriptions": int(paid_total),
        "free_to_paid_rate": round(100.0 * paid_total / max(1, total_users), 2),
    }


@router.get("/reports/top-pairs")
async def report_top_pairs(
    start: Optional[str] = Query(None),
    end: Optional[str] = Query(None),
    limit: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
    admin=Depends(require_admin("reports", "read")),
):
    start_utc, end_utc = _date_range(start, end)
    rows = (
        await db.execute(
            select(Job.pair_slug, func.count().label("total"))
            .where(Job.created_at >= start_utc, Job.created_at < end_utc, Job.pair_slug.is_not(None))
            .group_by(Job.pair_slug)
            .order_by(func.count().desc())
            .limit(limit)
        )
    ).all()
    return {
        "start": start_utc.date().isoformat(),
        "end": (end_utc - timedelta(days=1)).date().isoformat(),
        "top_pairs": [
            {"pair_slug": r.pair_slug, "conversions": int(r.total)} for r in rows
        ],
    }


@router.get("/reports/errors")
async def report_errors(
    start: Optional[str] = Query(None),
    end: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
    admin=Depends(require_admin("reports", "read")),
):
    start_utc, end_utc = _date_range(start, end)
    rows = (
        await db.execute(
            select(Job.error_code, func.count().label("total"))
            .where(
                Job.created_at >= start_utc, Job.created_at < end_utc,
                Job.status.in_(_FAILED_STATUSES),
            )
            .group_by(Job.error_code)
            .order_by(func.count().desc())
        )
    ).all()
    recent = (
        await db.execute(
            select(Job)
            .where(Job.created_at >= start_utc, Job.created_at < end_utc,
                   Job.status.in_(_FAILED_STATUSES))
            .order_by(Job.created_at.desc())
            .limit(20)
        )
    ).scalars().all()
    return {
        "start": start_utc.date().isoformat(),
        "end": (end_utc - timedelta(days=1)).date().isoformat(),
        "by_error_code": [
            {"error_code": r.error_code or "unknown", "count": int(r.total)} for r in rows
        ],
        "recent_errors": [_job_dict(j) for j in recent],
    }


@router.get("/reports/export")
async def report_export(
    type: str = Query("conversions"),
    start: Optional[str] = Query(None),
    end: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
    admin=Depends(require_admin("reports", "read")),
):
    start_utc, end_utc = _date_range(start, end)
    if type == "conversions":
        data = await report_conversions(start=start, end=end, db=db, admin=admin)
        rows = data["by_day"]
        return _csv_response(
            "conversions.csv",
            ["date", "conversions", "successful", "failed", "bytes_in", "bytes_out"],
            rows,
        )
    if type == "revenue":
        data = await report_revenue(start=start, end=end, db=db, admin=admin)
        return _csv_response(
            "revenue-by-provider.csv",
            ["provider_key", "count", "amount_cents"],
            data["by_provider"],
        )
    if type == "top-pairs":
        data = await report_top_pairs(start=start, end=end, limit=20, db=db, admin=admin)
        return _csv_response(
            "top-pairs.csv", ["pair_slug", "conversions"], data["top_pairs"]
        )
    if type == "errors":
        data = await report_errors(start=start, end=end, db=db, admin=admin)
        return _csv_response(
            "errors.csv", ["error_code", "count"], data["by_error_code"]
        )
    raise admin_error(
        422, "invalid_export_type",
        "Export type must be conversions, revenue, top-pairs or errors.",
        "Use type=conversions, type=revenue, type=top-pairs or type=errors.",
    )


# ---------------------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------------------

@router.get("/audit")
async def list_audit(
    admin_email: Optional[str] = Query(None),
    action: Optional[str] = Query(None),
    start: Optional[str] = Query(None),
    end: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    sort: str = Query("ts"),
    order: str = Query("desc"),
    db: AsyncSession = Depends(get_db),
    admin=Depends(require_admin("audit", "read")),
):
    stmt = select(AuditLog)
    if admin_email:
        stmt = stmt.where(func.lower(AuditLog.admin_email).like(f"%{admin_email.strip().lower()}%"))
    if action:
        stmt = stmt.where(AuditLog.action.like(f"%{action.strip()}%"))
    if start:
        start_d = _parse_date(start, "start")
        stmt = stmt.where(AuditLog.ts >= datetime.combine(start_d, time.min, tzinfo=timezone.utc))
    if end:
        end_d = _parse_date(end, "end")
        stmt = stmt.where(AuditLog.ts < datetime.combine(end_d + timedelta(days=1), time.min, tzinfo=timezone.utc))
    columns = {"ts": AuditLog.ts, "admin_email": AuditLog.admin_email, "action": AuditLog.action}
    col = _sort_column(AuditLog, sort, columns, "ts")
    stmt = stmt.order_by(col.desc() if order.lower() == "desc" else col.asc())
    page, per_page = _page_params(page, per_page)
    rows, total, page, per_page = await _paginate(db, stmt, page, per_page)
    items = []
    for row in rows:
        before = row.before
        after = row.after
        if isinstance(before, str):
            try:
                before = json.loads(before)
            except Exception:
                pass
        if isinstance(after, str):
            try:
                after = json.loads(after)
            except Exception:
                pass
        items.append(
            {
                "id": row.id,
                "ts": row.ts.isoformat() if row.ts else None,
                "admin_email": row.admin_email,
                "action": row.action,
                "target": row.target,
                "before": before,
                "after": after,
                "diff": diff_dicts(before if isinstance(before, dict) else None,
                                  after if isinstance(after, dict) else None),
                "ip": row.ip,
            }
        )
    return _page_response(items, total, page, per_page)


@router.get("/audit/export")
async def export_audit(
    admin_email: Optional[str] = Query(None),
    action: Optional[str] = Query(None),
    start: Optional[str] = Query(None),
    end: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
    admin=Depends(require_admin("audit", "read")),
):
    stmt = select(AuditLog).order_by(AuditLog.ts.desc()).limit(10000)
    if admin_email:
        stmt = stmt.where(func.lower(AuditLog.admin_email).like(f"%{admin_email.strip().lower()}%"))
    if action:
        stmt = stmt.where(AuditLog.action.like(f"%{action.strip()}%"))
    if start:
        start_d = _parse_date(start, "start")
        stmt = stmt.where(AuditLog.ts >= datetime.combine(start_d, time.min, tzinfo=timezone.utc))
    if end:
        end_d = _parse_date(end, "end")
        stmt = stmt.where(AuditLog.ts < datetime.combine(end_d + timedelta(days=1), time.min, tzinfo=timezone.utc))
    rows = (await db.execute(stmt)).scalars().all()
    return _csv_response(
        "audit-log.csv",
        ["id", "ts", "admin_email", "action", "target", "before", "after", "ip"],
        [
            {
                "id": r.id,
                "ts": r.ts.isoformat() if r.ts else "",
                "admin_email": r.admin_email,
                "action": r.action,
                "target": r.target,
                "before": json.dumps(r.before) if r.before is not None else "",
                "after": json.dumps(r.after) if r.after is not None else "",
                "ip": r.ip or "",
            }
            for r in rows
        ],
    )
