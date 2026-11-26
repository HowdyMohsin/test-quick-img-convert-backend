"""FastAPI application (v5 sections 11 and 15).

Single error shape everywhere: ``{"error": {code, message, hint}}``.
``GET /healthz`` for container health checks. ``/docs`` only when
``API_DOCS=true``. Security headers per section 15; HSTS + secure
cookies derive from the ``SITE_URL`` scheme.

Sibling routers are mounted DEFENSIVELY (try/except ImportError) so
this app boots before the pipeline/payments/ads/admin routers exist;
the coordinator verifies all routers mounted at integration.
"""

from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import Depends, FastAPI, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from . import auth as auth_module
from . import mail, passwords
from .brand import BRAND_NAME, BRAND_TAGLINE
from .deps import (
    SESSION_COOKIE,
    api_error,
    client_ip,
    get_current_user,
    get_db,
    get_optional_user,
    get_session_and_user,
    get_settings,
    require_csrf,
)
from .models import (
    Announcement,
    Base,
    Job,
    Notification,
    PaymentProvider,
    PaymentRequest,
    Plan,
    Popup,
    Session,
    SiteSetting,
    Subscription,
    Upload,
    User,
)
from .quotas import (
    ANONYMOUS_DAILY_LIMIT,
    usage_for,
    user_owner_key,
)
from .rate_limit import ip_key, rate_limit_or_429
from .seed import ANONYMOUS_LIMITS

__all__ = ["app", "create_app"]


# ---------------------------------------------------------------- errors

def _error_payload(code: str, message: str, hint: str = "") -> dict:
    return {"error": {"code": code, "message": message, "hint": hint or message}}


# ---------------------------------------------------------------- app factory

def _startup_health_check_once() -> None:
    """Run the pair health check once, in the background, on first boot.

    Only when the pair_health table is empty (first boot), never blocking
    startup, never in tests (``PYTEST_CURRENT_TEST``), opt-out via
    ``QIC_STARTUP_HEALTH_CHECK=0``. Results land in the shared pipeline
    store (database pair_health table) so the API and admin read the
    same health state. A failure here must never break boot.
    """
    import logging

    if os.environ.get("PYTEST_CURRENT_TEST"):
        return
    if os.environ.get("QIC_STARTUP_HEALTH_CHECK", "1") == "0":
        return
    logger = logging.getLogger("quick-img-convert.health")
    try:
        from .health import SAMPLES_DIR, health_check
        from .pipeline import MemoryStore, get_default_store

        store = get_default_store()
        if isinstance(store, MemoryStore):
            return
        if store.get_pair_health():
            return
        health_check(store, SAMPLES_DIR)
        logger.info("startup pair health check complete")
    except Exception as exc:  # noqa: BLE001 - health check must never break boot
        logger.warning("startup pair health check failed: %s", exc)


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title="Quick IMG Convert API",
        docs_url="/docs" if settings.api_docs else None,
        redoc_url=None,
        openapi_url="/openapi.json" if settings.api_docs else None,
    )

    from fastapi import HTTPException

    # Billing / payments / ads routers raise app.billing.ApiError; without
    # this handler every one of those becomes a 500 instead of the
    # standard {error:{code,message,hint}} shape (spec section 11).
    from .billing import ApiError, api_error_handler

    app.add_exception_handler(ApiError, api_error_handler)

    @app.exception_handler(HTTPException)
    async def _http_exception_handler(request: Request, exc: HTTPException):
        detail = exc.detail
        if isinstance(detail, dict) and "error" in detail:
            return JSONResponse(status_code=exc.status_code, content=detail)
        return JSONResponse(
            status_code=exc.status_code,
            content=_error_payload("error", str(detail), ""),
        )

    @app.exception_handler(Exception)
    async def _unhandled_exception_handler(request: Request, exc: Exception):
        return JSONResponse(
            status_code=500,
            content=_error_payload("internal_error",
                                   "Something went wrong. Please try again.",
                                   "Try again in a moment."),
        )

    @app.exception_handler(RequestValidationError)
    async def _validation_handler(request: Request, exc: RequestValidationError):
        first = exc.errors()[0] if exc.errors() else {}
        field = ".".join(str(p) for p in first.get("loc", []) if p != "body")
        return JSONResponse(
            status_code=422,
            content=_error_payload(
                "validation_error",
                f"Invalid value for {field or 'request'}.",
                "Check the highlighted field and try again.",
            ),
        )

    @app.middleware("http")
    async def _security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        # CSP: self only, plus enabled ad networks (added by the ads
        # router when it exists; the base policy stays locked down).
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; font-src 'self'; frame-ancestors 'none'; "
            "base-uri 'self'; form-action 'self'"
        )
        if settings.is_https:
            response.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains"
            )
        return response

    @app.on_event("startup")
    async def _startup() -> None:
        # SQLite dev convenience: create tables automatically. Production
        # (PostgreSQL) must use Alembic migrations.
        if settings.database_url.startswith("sqlite"):
            from .deps import get_engine

            engine = get_engine()
            async with engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
        # First-boot pair health check, in a daemon thread, never blocking.
        import threading

        threading.Thread(target=_startup_health_check_once, daemon=True).start()

    @app.get("/healthz")
    async def healthz():
        return {"status": "ok", "service": "quick-img-convert-api"}

    # Core routers owned by this agent.
    app.include_router(auth_module.router)
    from .routers_admin_plans import router as plans_router

    app.include_router(plans_router)

    # Sibling routers (other agents) — defensive mounting.
    for _mod, _attr in [
        ("admin_auth", "router"),
        ("routers_pipeline", "router"),
        ("routers_payments", "router"),
        ("routers_payments", "webhook_router"),
        ("routers_ads", "router"),
        ("routers_marketing", "router"),
        ("routers_marketing", "notifications_router"),
        ("routers_admin", "router"),
        ("routers_admin_payments", "router"),
        ("routers_admin_ads", "router"),
        ("routers_admin_ads", "router_admin"),
        ("routers_admin_formats", "router"),
        ("routers_captcha", "router"),
    ]:
        try:
            _imported = __import__(f"app.{_mod}", fromlist=[_attr])
            app.include_router(getattr(_imported, _attr))
        except ImportError:
            pass

    _register_account_routes(app)
    return app


# ---------------------------------------------------------------- account routes

class MePatch(BaseModel):
    display_name: str | None = Field(default=None, min_length=1, max_length=200)
    marketing_opt_in: bool | None = None


class DeleteMeBody(BaseModel):
    password: str | None = None
    confirmation: str = ""


class ContactBody(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    email: str = Field(min_length=3, max_length=255)
    topic: str = Field(min_length=1, max_length=200)
    message: str = Field(min_length=1, max_length=5000)
    website: str = ""  # honeypot: real users leave this empty


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _register_account_routes(app: FastAPI) -> None:

    @app.get("/v1/me")
    async def get_me(request: Request, db: AsyncSession = Depends(get_db),
                     user: User = Depends(get_current_user)):
        plan = await db.get(Plan, user.plan) if user.plan != "anonymous" else None
        limits = dict(plan.limits) if plan else dict(ANONYMOUS_LIMITS)
        limit = int(limits.get("daily", 25))
        usage = await usage_for(db, [user_owner_key(user.id)], limit)
        sub = None
        result = await db.execute(
            select(Subscription).where(
                Subscription.user_id == user.id,
                Subscription.status.in_(["active", "past_due", "trialing"]),
            ).order_by(Subscription.created_at.desc())
        )
        row = result.scalars().first()
        grace_banner = None
        if row is not None:
            sub = {
                "plan_id": row.plan_id, "provider_key": row.provider_key,
                "interval": row.interval, "status": row.status,
                "cancel_at_period_end": row.cancel_at_period_end,
                "current_period_end": row.current_period_end.isoformat() if row.current_period_end else None,
                "grace_ends_at": row.grace_ends_at.isoformat() if row.grace_ends_at else None,
            }
            if row.status == "past_due" and row.grace_ends_at:
                grace_banner = {
                    "message": "Your subscription payment is past due. Update your payment details to keep your plan.",
                    "grace_ends_at": row.grace_ends_at.isoformat(),
                }
        payments_result = await db.execute(
            select(PaymentRequest).where(PaymentRequest.user_id == user.id)
            .order_by(PaymentRequest.created_at.desc()).limit(20)
        )
        payments = [{
            "id": p.id, "plan_id": p.plan_id, "interval": p.interval,
            "provider_key": p.provider_key, "amount_cents": p.amount_cents,
            "currency": p.currency, "display_amount": p.display_amount,
            "reference": p.reference, "status": p.status,
            "receipt_no": p.receipt_no,
            "created_at": p.created_at.isoformat() if p.created_at else None,
        } for p in payments_result.scalars().all()]
        unread = await db.execute(
            select(Notification).where(
                Notification.user_id == user.id, Notification.read.is_(False))
        )
        unread_count = len(unread.scalars().all())
        return {
            "user": auth_module._public_user(user),
            "plan": {"id": user.plan, "limits": limits,
                     "price_cents": plan.price_cents if plan else 0,
                     "price_yearly_cents": plan.price_yearly_cents if plan else 0},
            "usage": usage,
            "limits": limits,
            "subscription": sub,
            "payments": payments,
            "unread_notifications": unread_count,
            "grace_banner": grace_banner,
        }

    @app.patch("/v1/me")
    async def patch_me(body: MePatch, request: Request,
                       db: AsyncSession = Depends(get_db),
                       user: User = Depends(get_current_user)):
        session, _ = await get_session_and_user(request, db)
        require_csrf(request, session)
        if body.display_name is not None:
            user.display_name = body.display_name.strip()
        if body.marketing_opt_in is not None:
            user.marketing_opt_in = body.marketing_opt_in
        await db.commit()
        return {"user": auth_module._public_user(user)}

    @app.get("/v1/me/export")
    async def export_me(request: Request, db: AsyncSession = Depends(get_db),
                        user: User = Depends(get_current_user)):
        jobs_result = await db.execute(
            select(Job).where(Job.user_id == user.id)
            .order_by(Job.created_at.desc()).limit(1000)
        )
        history = [{
            "id": j.id, "pair_slug": j.pair_slug, "status": j.status,
            "in_size": j.in_size, "out_size": j.out_size,
            "created_at": j.created_at.isoformat() if j.created_at else None,
            "finished_at": j.finished_at.isoformat() if j.finished_at else None,
        } for j in jobs_result.scalars().all()]
        payments_result = await db.execute(
            select(PaymentRequest).where(PaymentRequest.user_id == user.id)
            .order_by(PaymentRequest.created_at.desc())
        )
        payments = [{
            "id": p.id, "plan_id": p.plan_id, "provider_key": p.provider_key,
            "amount_cents": p.amount_cents, "currency": p.currency,
            "reference": p.reference, "status": p.status,
            "receipt_no": p.receipt_no,
            "created_at": p.created_at.isoformat() if p.created_at else None,
        } for p in payments_result.scalars().all()]
        payload = {
            "exported_at": _now().isoformat(),
            "profile": auth_module._public_user(user),
            "conversion_history": history,
            "payments": payments,
        }
        return Response(
            content=json.dumps(payload, indent=2),
            media_type="application/json",
            headers={"Content-Disposition": 'attachment; filename="quick-img-convert-export.json"'},
        )

    @app.post("/v1/me/delete")
    async def delete_me(body: DeleteMeBody, request: Request, response: Response,
                        db: AsyncSession = Depends(get_db),
                        user: User = Depends(get_current_user)):
        session, _ = await get_session_and_user(request, db)
        require_csrf(request, session)
        if body.confirmation.strip() != "DELETE":
            raise api_error(400, "confirmation_required",
                            "To delete your account, type DELETE to confirm.",
                            "Type DELETE in the confirmation field.")
        if user.password_hash is not None:
            if not body.password or not passwords.verify_password(user.password_hash, body.password):
                raise api_error(401, "invalid_credentials",
                                "Your password is incorrect.",
                                "Check your password and try again.")
        # Cancel any active subscription.
        result = await db.execute(
            select(Subscription).where(
                Subscription.user_id == user.id,
                Subscription.status.in_(["active", "past_due", "trialing"]),
            )
        )
        for sub in result.scalars().all():
            sub.status = "canceled"
            sub.cancel_at_period_end = False
        # Delete uploads + jobs and their files immediately.
        data_dir = get_settings().data_dir
        jobs_result = await db.execute(select(Job).where(Job.user_id == user.id))
        for job in jobs_result.scalars().all():
            if job.out_path:
                try:
                    os.remove(os.path.join(data_dir, os.path.basename(job.out_path)))
                except OSError:
                    pass
            await db.delete(job)
        uploads_result = await db.execute(
            select(Upload).where(Upload.owner_key == user_owner_key(user.id)))
        for up in uploads_result.scalars().all():
            try:
                os.remove(os.path.join(data_dir, os.path.basename(up.path)))
            except OSError:
                pass
            await db.delete(up)
        await auth_module.revoke_all_sessions(db, user.id)
        # Anonymize the account; payment records are kept anonymized
        # for accounting (they reference the user id only).
        anon = f"deleted-{uuid.uuid4().hex[:12]}@deleted.invalid"
        user.email = anon
        user.display_name = "Deleted user"
        user.password_hash = None
        user.email_verified_at = None
        user.deleted_at = _now()
        user.marketing_opt_in = False
        await db.commit()
        response.delete_cookie(SESSION_COOKIE, path="/")
        return {"message": "Your account has been deleted."}

    @app.get("/v1/site")
    async def get_site(request: Request, db: AsyncSession = Depends(get_db),
                       user: User | None = Depends(get_optional_user)):
        settings_rows = await db.execute(select(SiteSetting))
        site_settings = {row.key: row.value for row in settings_rows.scalars().all()}
        plans_result = await db.execute(
            select(Plan).where(Plan.active.is_(True), Plan.archived.is_(False))
            .order_by(Plan.sort)
        )
        plans = [{
            "id": p.id, "name": p.name, "price_cents": p.price_cents,
            "price_yearly_cents": p.price_yearly_cents, "currency": p.currency,
            "limits": p.limits or {}, "featured": p.featured,
        } for p in plans_result.scalars().all()]
        anonymous_limits = site_settings.get("anonymous_limits") or dict(ANONYMOUS_LIMITS)
        plans.insert(0, {
            "id": "anonymous", "name": "Anonymous", "price_cents": 0,
            "price_yearly_cents": 0, "currency": "USD",
            "limits": anonymous_limits, "featured": 0,
        })
        providers_result = await db.execute(
            select(PaymentProvider).where(PaymentProvider.enabled.is_(True))
            .order_by(PaymentProvider.sort)
        )
        providers = [{
            "key": p.key, "label": p.label, "flow": p.flow,
        } for p in providers_result.scalars().all() if p.config]
        now = _now()
        ann_result = await db.execute(
            select(Announcement).where(Announcement.enabled.is_(True))
            .order_by(Announcement.starts_at)
        )
        announcement = None
        for ann in ann_result.scalars().all():
            starts = ann.starts_at
            ends = ann.ends_at
            if starts is not None and starts.tzinfo is None:
                starts = starts.replace(tzinfo=timezone.utc)
            if ends is not None and ends.tzinfo is None:
                ends = ends.replace(tzinfo=timezone.utc)
            if starts is not None and starts > now:
                continue
            if ends is not None and ends <= now:
                continue
            announcement = {"text": ann.text}
            break
        popups_result = await db.execute(
            select(Popup).where(Popup.enabled.is_(True)))
        popups = [{
            "key": p.key, "title": p.title, "body": p.body,
            "cta_text": p.cta_text, "cta_href": p.cta_href,
            "frequency": p.frequency, "pages": p.pages,
        } for p in popups_result.scalars().all()]
        return {
            "site_name": BRAND_NAME,
            "tagline": BRAND_TAGLINE,
            "support_email": site_settings.get("support_email", "support@quickimgconvert.com"),
            "pkr_per_usd": site_settings.get("pkr_per_usd", get_settings().pkr_per_usd),
            "approval_window_hours": site_settings.get(
                "approval_window_hours", get_settings().approval_window_hours),
            "approval_window_text": site_settings.get(
                "approval_window_text", "Manual payments are reviewed within 24 hours."),
            "maintenance_mode": bool(site_settings.get("maintenance_mode", False)),
            # TEMPORARY (test-only): the frontend reads this to decide
            # whether to show the OTP screen after registration and the
            # "Verify your email first" gate on checkout. Default true.
            "require_email_verification": get_settings().require_email_verification,
            "plans": plans,
            "providers": providers,
            "announcement": announcement,
            "popups": popups,
            "consent": {
                "consent_required": bool(site_settings.get("consent_required", True)),
                "cmp_configured": bool(site_settings.get("cmp_configured", False)),
            },
            "google_sign_in_enabled": bool(get_settings().google_client_id),
            "anonymous_daily_limit": ANONYMOUS_DAILY_LIMIT,
        }

    @app.post("/v1/contact")
    async def contact(body: ContactBody, request: Request,
                      db: AsyncSession = Depends(get_db)):
        session, _ = await get_session_and_user(request, db)
        require_csrf(request, session)
        rate_limit_or_429(ip_key(request, "contact"), 3, 3600, "contact message")
        if body.website.strip():
            # Honeypot filled: pretend success, send nothing.
            return {"message": "Thanks for your message. We will reply soon."}
        settings = get_settings()
        support = settings.smtp_from or "support@quickimgconvert.com"
        site_rows = await db.execute(
            select(SiteSetting).where(SiteSetting.key == "support_email"))
        row = site_rows.scalar_one_or_none()
        if row is not None and isinstance(row.value, str):
            support = row.value
        subject = f"Contact: {body.topic} — {body.name}"
        text = (f"From: {body.name} <{body.email}>\nTopic: {body.topic}\n\n{body.message}")
        await mail.send_mail(support, subject, text)
        return {"message": "Thanks for your message. We will reply soon."}


app = create_app()
