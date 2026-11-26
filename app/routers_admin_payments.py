"""Admin payment endpoints (spec sections 7, 13).

- Requests queue: approve (instant upgrade + PDF receipt emailed +
  in-app notification), reject with a reason, expire.
- Subscriptions: list, cancel, extend.
- Providers: enable switch, flow badge, write-only config fields shown
  masked, "Check configuration" (completeness only — creates no charge
  and makes no network call), webhook URL with copy (frontend renders
  it from the provider key).
- Webhook log: payload viewer + replay.

Every mutation writes an audit_log entry with a before/after diff
(``app.audit.audit`` when present, else the fallback table).
"""
from __future__ import annotations

import logging
from datetime import timedelta
from typing import Any, Optional

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel
from sqlalchemy import select

from app.billing import (
    activate_subscription, apply_event, cancel_subscription, client_ip,
    decrypt_config, encrypt_config, err, get_current_admin, get_db,
    get_site_setting, load_provider_config, mask_config, next_receipt_no,
    record_audit, resolve_models, send_mail, utcnow,
)
from app.admin_auth import require_csrf
from app.notifications import create_notification
from app.payments.providers import get_provider, registry
from app.receipts import generate_receipt_pdf, receipt_data

log = logging.getLogger("qic.admin_payments")
router = APIRouter(prefix="/admin/payments", tags=["admin-payments"])


class ApproveBody(BaseModel):
    admin_note: Optional[str] = None
    amount_cents: Optional[int] = None  # admin may adjust the amount


class RejectBody(BaseModel):
    reason: str
    admin_note: Optional[str] = None


class ProviderUpdateBody(BaseModel):
    enabled: Optional[bool] = None
    config: Optional[dict[str, Any]] = None


class ExtendBody(BaseModel):
    days: int


async def expire_stale_requests(db, models, hours: Optional[int] = None) -> int:
    """Expire pending requests older than the approval window (default 24h,
    admin-editable via site setting ``approval_window_hours``). Called by
    the worker alongside the grace sweep."""
    if hours is None:
        setting = await get_site_setting(db, models, "approval_window_hours", 24)
        try:
            hours = int(setting if not isinstance(setting, dict)
                        else setting.get("value", 24))
        except (TypeError, ValueError):
            hours = 24
    cutoff = utcnow() - timedelta(hours=hours)
    rows = (await db.execute(
        select(models.PaymentRequest).where(
            models.PaymentRequest.status == "pending",
            models.PaymentRequest.created_at < cutoff)
    )).scalars().all()
    for req in rows:
        req.status = "expired"
        req.resolved_at = utcnow()
        db.add(req)
        await create_notification(
            db, models, req.user_id, "payment_expired",
            "Your payment request expired",
            f"Your {req.provider_key} payment request (reference "
            f"{req.reference}) expired before approval. Submit a new one "
            "if you still want to upgrade.",
            link="/pricing")
    await db.commit()
    return len(rows)


def _admin_email(admin: Any) -> str:
    return getattr(admin, "email", "admin") or "admin"


def _request_payload(req: Any, plan_name: Optional[str] = None) -> dict:
    return {
        "id": req.id, "user_id": req.user_id, "plan": req.plan_id,
        "plan_name": plan_name, "interval": req.interval,
        "provider": req.provider_key, "coupon": req.coupon_code,
        "amount_cents": req.amount_cents, "currency": req.currency,
        "display_amount": req.display_amount, "fx_rate": req.fx_rate,
        "reference": req.reference, "note": req.note,
        "proof_path": req.proof_path, "status": req.status,
        "admin_note": req.admin_note, "receipt_no": req.receipt_no,
        "created_at": req.created_at.isoformat() if req.created_at else None,
        "resolved_at": req.resolved_at.isoformat() if req.resolved_at else None,
        "resolved_by": req.resolved_by,
    }


# ---------------------------------------------------------------- requests
@router.get("/requests")
async def list_requests(status: Optional[str] = None,
                        admin=Depends(get_current_admin), db=Depends(get_db)):
    models = resolve_models()
    query = select(models.PaymentRequest).order_by(
        models.PaymentRequest.created_at.desc())
    if status:
        query = query.where(models.PaymentRequest.status == status)
    rows = (await db.execute(query.limit(200))).scalars().all()
    return {"requests": [_request_payload(r) for r in rows],
            "pending_count": sum(1 for r in rows if r.status == "pending")}


@router.get("/requests/{request_id}")
async def get_request(request_id: str, admin=Depends(get_current_admin),
                      db=Depends(get_db)):
    models = resolve_models()
    req = (await db.execute(
        select(models.PaymentRequest).where(models.PaymentRequest.id == request_id)
    )).scalar_one_or_none()
    if req is None:
        raise err(404, "not_found", "That payment request was not found.",
                  "Check the request and try again.")
    return _request_payload(req)


@router.post("/requests/{request_id}/approve")
async def approve_request(request_id: str, body: ApproveBody,
                          http_request: Request,
                          admin=Depends(get_current_admin), _csrf: bool = Depends(require_csrf), db=Depends(get_db)):
    models = resolve_models()
    req = (await db.execute(
        select(models.PaymentRequest).where(models.PaymentRequest.id == request_id)
    )).scalar_one_or_none()
    if req is None:
        raise err(404, "not_found", "That payment request was not found.",
                  "Check the request and try again.")
    if req.status != "pending":
        raise err(400, "not_pending",
                  f"A {req.status} request cannot be approved.",
                  "Only pending requests can be approved.")
    user = (await db.execute(
        select(models.User).where(models.User.id == req.user_id)
    )).scalar_one_or_none()
    plan = (await db.execute(
        select(models.Plan).where(models.Plan.id == req.plan_id)
    )).scalar_one_or_none()
    if user is None or plan is None:
        raise err(400, "invalid_request",
                  "The user or plan for this request no longer exists.",
                  "Reject the request with a note to the user.")
    before = {"status": req.status, "receipt_no": req.receipt_no}
    if body.amount_cents is not None:
        if body.amount_cents < 0:
            raise err(400, "invalid_amount", "The amount cannot be negative.",
                      "Enter a valid amount in cents.")
        req.amount_cents = body.amount_cents
    receipt_no = await next_receipt_no(db, models)
    req.receipt_no = receipt_no
    req.status = "approved"
    req.admin_note = body.admin_note
    req.resolved_at = utcnow()
    req.resolved_by = _admin_email(admin)
    db.add(req)
    # Instant activation; extends from the current period end on renewal.
    await activate_subscription(
        db, models, user, plan, req.provider_key, req.interval,
        coupon_code=req.coupon_code, extend_from_current=True)
    await create_notification(
        db, models, user.id, "payment_approved",
        "Payment approved — your plan is active",
        f"Your {plan.name} plan is now active. Receipt {receipt_no} was "
        "emailed to you.",
        link="/account?tab=plan")
    cls = get_provider(req.provider_key)
    if getattr(user, "email", None):
        data = receipt_data(
            receipt_no=receipt_no, plan_name=plan.name, interval=req.interval,
            amount_cents=req.amount_cents, provider_label=cls.label,
            reference=req.reference, email=user.email,
            customer_name=user.display_name,
            display_text=(f"{req.display_amount} PKR"
                          if req.provider_key != "manual_usdt"
                          else f"{(req.display_amount or 0) / 100:.2f} USDT"))
        pdf_bytes, _renderer = generate_receipt_pdf(data)
        send_mail(user.email,
                  f"Payment approved — receipt {receipt_no}",
                  f"Your {plan.name} plan payment was approved. "
                  f"Receipt {receipt_no} is attached.",
                  attachment=(f"receipt-{receipt_no}.pdf", pdf_bytes))
    await record_audit(db, models, _admin_email(admin), "payment.approve",
                       f"payment_request:{req.id}", before,
                       {"status": "approved", "receipt_no": receipt_no},
                       ip=client_ip(http_request))
    await db.commit()
    return _request_payload(req, plan_name=plan.name)


@router.post("/requests/{request_id}/reject")
async def reject_request(request_id: str, body: RejectBody,
                         http_request: Request,
                         admin=Depends(get_current_admin), _csrf: bool = Depends(require_csrf), db=Depends(get_db)):
    models = resolve_models()
    if not (body.reason or "").strip():
        raise err(400, "reason_required",
                  "A reason is required to reject a payment.",
                  "Tell the user why the payment was rejected.")
    req = (await db.execute(
        select(models.PaymentRequest).where(models.PaymentRequest.id == request_id)
    )).scalar_one_or_none()
    if req is None:
        raise err(404, "not_found", "That payment request was not found.",
                  "Check the request and try again.")
    if req.status != "pending":
        raise err(400, "not_pending",
                  f"A {req.status} request cannot be rejected.",
                  "Only pending requests can be rejected.")
    before = {"status": req.status}
    req.status = "rejected"
    req.admin_note = body.reason
    req.resolved_at = utcnow()
    req.resolved_by = _admin_email(admin)
    db.add(req)
    await create_notification(
        db, models, req.user_id, "payment_rejected",
        "Your payment was not approved",
        f"Your payment (reference {req.reference}) was rejected: "
        f"{body.reason}",
        link="/pricing")
    user = (await db.execute(
        select(models.User).where(models.User.id == req.user_id)
    )).scalar_one_or_none()
    if user is not None and getattr(user, "email", None):
        send_mail(user.email, "Your payment was not approved",
                  f"Your payment (reference {req.reference}) was rejected: "
                  f"{body.reason}")
    await record_audit(db, models, _admin_email(admin), "payment.reject",
                       f"payment_request:{req.id}", before,
                       {"status": "rejected", "reason": body.reason},
                       ip=client_ip(http_request))
    await db.commit()
    return _request_payload(req)


@router.post("/requests/{request_id}/expire")
async def expire_request(request_id: str, http_request: Request,
                         admin=Depends(get_current_admin), _csrf: bool = Depends(require_csrf), db=Depends(get_db)):
    models = resolve_models()
    req = (await db.execute(
        select(models.PaymentRequest).where(models.PaymentRequest.id == request_id)
    )).scalar_one_or_none()
    if req is None:
        raise err(404, "not_found", "That payment request was not found.",
                  "Check the request and try again.")
    if req.status != "pending":
        raise err(400, "not_pending",
                  f"A {req.status} request cannot be expired.",
                  "Only pending requests can be expired.")
    before = {"status": req.status}
    req.status = "expired"
    req.resolved_at = utcnow()
    req.resolved_by = _admin_email(admin)
    db.add(req)
    await record_audit(db, models, _admin_email(admin), "payment.expire",
                       f"payment_request:{req.id}", before,
                       {"status": "expired"}, ip=client_ip(http_request))
    await db.commit()
    return _request_payload(req)


# ------------------------------------------------------------ subscriptions
@router.get("/subscriptions")
async def list_subscriptions(status: Optional[str] = None,
                             admin=Depends(get_current_admin), db=Depends(get_db)):
    models = resolve_models()
    query = select(models.Subscription).order_by(
        models.Subscription.created_at.desc())
    if status:
        query = query.where(models.Subscription.status == status)
    rows = (await db.execute(query.limit(200))).scalars().all()
    return {"subscriptions": [{
        "id": s.id, "user_id": s.user_id, "plan": s.plan_id,
        "provider": s.provider_key, "provider_sub_id": s.provider_sub_id,
        "interval": s.interval, "status": s.status,
        "cancel_at_period_end": s.cancel_at_period_end,
        "current_period_end": s.current_period_end.isoformat()
        if s.current_period_end else None,
        "grace_ends_at": s.grace_ends_at.isoformat() if s.grace_ends_at else None,
    } for s in rows]}


@router.post("/subscriptions/{sub_id}/cancel")
async def admin_cancel_subscription(sub_id: str, http_request: Request,
                                    admin=Depends(get_current_admin), _csrf: bool = Depends(require_csrf),
                                    db=Depends(get_db)):
    models = resolve_models()
    sub = (await db.execute(
        select(models.Subscription).where(models.Subscription.id == sub_id)
    )).scalar_one_or_none()
    if sub is None:
        raise err(404, "not_found", "That subscription was not found.",
                  "Check the subscription and try again.")
    before = {"status": sub.status, "cancel_at_period_end": sub.cancel_at_period_end}
    await cancel_subscription(db, models, sub, at_period_end=True)
    await record_audit(db, models, _admin_email(admin), "subscription.cancel",
                       f"subscription:{sub.id}", before,
                       {"status": sub.status, "cancel_at_period_end": True},
                       ip=client_ip(http_request))
    await db.commit()
    return {"id": sub.id, "status": sub.status,
            "cancel_at_period_end": sub.cancel_at_period_end}


@router.post("/subscriptions/{sub_id}/extend")
async def admin_extend_subscription(sub_id: str, body: ExtendBody,
                                    http_request: Request,
                                    admin=Depends(get_current_admin), _csrf: bool = Depends(require_csrf),
                                    db=Depends(get_db)):
    models = resolve_models()
    sub = (await db.execute(
        select(models.Subscription).where(models.Subscription.id == sub_id)
    )).scalar_one_or_none()
    if sub is None:
        raise err(404, "not_found", "That subscription was not found.",
                  "Check the subscription and try again.")
    before = {"current_period_end": sub.current_period_end.isoformat()
              if sub.current_period_end else None}
    base = sub.current_period_end or utcnow()
    sub.current_period_end = base + timedelta(days=body.days)
    sub.updated_at = utcnow()
    db.add(sub)
    await record_audit(db, models, _admin_email(admin), "subscription.extend",
                       f"subscription:{sub.id}", before,
                       {"current_period_end": sub.current_period_end.isoformat(),
                        "days": body.days}, ip=client_ip(http_request))
    await db.commit()
    return {"id": sub.id,
            "current_period_end": sub.current_period_end.isoformat()}


# ---------------------------------------------------------------- providers
@router.get("/providers")
async def list_providers(admin=Depends(get_current_admin), db=Depends(get_db)):
    models = resolve_models()
    rows = (await db.execute(select(models.PaymentProvider))).scalars().all()
    by_key = {r.key: r for r in rows}
    out = []
    for key, cls in registry().items():
        row = by_key.get(key)
        config = await load_provider_config(db, models, key) if row else {}
        configured = cls.is_configured(config)
        out.append({
            "key": key, "label": cls.label, "flow": cls.flow,
            "reserved": getattr(cls, "reserved", False),
            "enabled": bool(row.enabled) if row else False,
            "configured": configured,
            # Config fields are write-only through the admin API: every
            # value is masked here (full values are shown to the payer
            # only inside checkout instructions, never in admin reads).
            "config": mask_config(config, set(config.keys())),
            "config_fields": cls.config_fields(),
            "webhook_url": f"/webhooks/{key}" if cls.flow == "auto" else None,
        })
    return {"providers": out}


@router.patch("/providers/{key}")
async def update_provider(key: str, body: ProviderUpdateBody,
                          http_request: Request,
                          admin=Depends(get_current_admin), _csrf: bool = Depends(require_csrf), db=Depends(get_db)):
    models = resolve_models()
    cls = get_provider(key)
    row = (await db.execute(
        select(models.PaymentProvider).where(models.PaymentProvider.key == key)
    )).scalar_one_or_none()
    before = {
        "enabled": bool(row.enabled) if row else False,
        "config_keys": sorted(decrypt_config(row.config).keys()) if row and row.config else [],
    }
    if row is None:
        row = models.PaymentProvider(key=key, label=cls.label, flow=cls.flow,
                                     enabled=False, config=None, sort=0)
        db.add(row)
    if body.enabled is not None:
        row.enabled = bool(body.enabled)
    if body.config is not None:
        existing = decrypt_config(row.config)
        merged = dict(existing)
        for field, value in body.config.items():
            if field not in {f["name"] for f in cls.config_fields()}:
                raise err(400, "unknown_config_field",
                          f"Unknown config field '{field}' for {cls.label}.",
                          "Use only the fields shown in the provider form.")
            if value in (None, ""):
                merged.pop(field, None)
            else:
                merged[field] = value
        row.config = encrypt_config(merged) if merged else None
    await db.flush()
    config = await load_provider_config(db, models, key)
    after = {"enabled": bool(row.enabled),
             "config_keys": sorted(config.keys()),
             "configured": cls.is_configured(config)}
    await record_audit(db, models, _admin_email(admin), "provider.update",
                       f"provider:{key}", before, after, ip=client_ip(http_request))
    await db.commit()
    return {
        "key": key, "label": cls.label, "flow": cls.flow,
        "enabled": bool(row.enabled), "configured": cls.is_configured(config),
        "config": mask_config(config, set(config.keys())),
        "webhook_url": f"/webhooks/{key}" if cls.flow == "auto" else None,
    }


@router.post("/providers/{key}/check")
async def check_provider(key: str, admin=Depends(get_current_admin), _csrf: bool = Depends(require_csrf),
                         db=Depends(get_db)):
    """Check configuration: completeness + format only. Creates no charge
    and makes no network call to any payment provider."""
    models = resolve_models()
    cls = get_provider(key)
    config = await load_provider_config(db, models, key)
    missing = [f["name"] for f in cls.config_fields()
               if f.get("required") and not str(config.get(f["name"]) or "").strip()]
    problems = []
    if key == "payoneer_link" and config.get("payment_url"):
        url = str(config["payment_url"])
        if not (url.startswith("http://") or url.startswith("https://")):
            problems.append("payment_url must start with http:// or https://")
    if key == "manual_usdt" and config.get("trc20_address"):
        addr = str(config["trc20_address"]).strip()
        if not (addr.startswith("T") and len(addr) == 34):
            problems.append("trc20_address does not look like a TRON address")
    configured = cls.is_configured(config) and not problems
    return {
        "key": key, "label": cls.label, "configured": configured,
        "missing": missing, "problems": problems,
        "note": "Completeness check only — no charge was created and no "
                "payment provider was contacted.",
    }


# -------------------------------------------------------------- webhook log
@router.get("/webhooks")
async def webhook_log(provider: Optional[str] = None,
                      status: Optional[str] = None,
                      admin=Depends(get_current_admin), db=Depends(get_db)):
    models = resolve_models()
    query = select(models.WebhookEvent).order_by(
        models.WebhookEvent.received_at.desc())
    if provider:
        query = query.where(models.WebhookEvent.provider_key == provider)
    if status:
        query = query.where(models.WebhookEvent.status == status)
    rows = (await db.execute(query.limit(200))).scalars().all()
    return {"events": [{
        "provider": r.provider_key, "event_id": r.event_id, "type": r.type,
        "status": r.status, "error": r.error,
        "received_at": r.received_at.isoformat() if r.received_at else None,
        "payload": r.payload,
    } for r in rows]}


@router.post("/webhooks/{provider}/{event_id}/replay")
async def replay_webhook(provider: str, event_id: str, http_request: Request,
                         admin=Depends(get_current_admin), _csrf: bool = Depends(require_csrf), db=Depends(get_db)):
    models = resolve_models()
    row = (await db.execute(
        select(models.WebhookEvent).where(
            models.WebhookEvent.provider_key == provider,
            models.WebhookEvent.event_id == event_id)
    )).scalar_one_or_none()
    if row is None:
        raise err(404, "not_found", "That webhook event was not found.",
                  "Check the provider and event id.")
    cls = get_provider(provider)
    normalized = cls.normalize_event(row.type, row.payload or {})
    if normalized.plan_id is None:
        price_id = (row.payload or {}).get("_price_id") or (
            normalized.raw or {}).get("_price_id") or (
            normalized.raw or {}).get("_variant_id")
        if price_id:
            price_row = (await db.execute(
                select(models.PlanPrice).where(
                    models.PlanPrice.provider_key == provider,
                    models.PlanPrice.provider_price_id == str(price_id))
            )).scalar_one_or_none()
            if price_row is not None:
                normalized.plan_id = price_row.plan_id
                normalized.interval = price_row.interval
    outcome = await apply_event(db, models, normalized)
    row.status = "processed" if outcome.get("status") == "applied" else row.status
    db.add(row)
    await record_audit(db, models, _admin_email(admin), "webhook.replay",
                       f"webhook:{provider}:{event_id}",
                       {"status": "replayed"}, outcome,
                       ip=client_ip(http_request))
    await db.commit()
    return {"status": "ok", "event_id": event_id, "applied": outcome.get("status")}
