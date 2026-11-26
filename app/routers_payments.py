"""Public payment endpoints + signed webhooks (spec sections 7, 11).

- GET /v1/payments/config — enabled + configured providers, labels and
  flow hints only, never secrets.
- POST /v1/payments/checkout — rate limit 5/min; verified email required
  (unless REQUIRE_EMAIL_VERIFICATION=false, test-only).
- POST /v1/payments/manual/submit — rate limit 3/min; multipart proof.
- POST /v1/payments/cancel, GET /v1/payments/history, receipt download,
  POST /v1/payments/coupons/validate, GET /v1/payments/link.
- POST /webhooks/{key} — signature verified on the RAW body, timestamp
  tolerance, idempotency by (provider_key, event_id) for 30 days.

All errors use the standard shape from app.billing.ApiError.
"""
from __future__ import annotations

import logging
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

from fastapi import APIRouter, Depends, File, Form, Request, UploadFile
from fastapi.responses import JSONResponse, RedirectResponse, Response
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.billing import (
    ApiError, api_error_handler, apply_coupon_to_amount, apply_event,
    client_ip, enforce_rate_limit, err, get_current_user, get_db,
    get_pkr_rate, load_provider_config, next_receipt_no, pkr_amount,
    price_for_plan, record_coupon_use, resolve_models, send_mail, utcnow,
    validate_coupon,
)
from app.deps import get_settings
from app.notifications import create_notification
from app.payments.manual import PROOF_MAX_BYTES, validate_proof
from app.payments.providers import (
    WebhookVerificationError, get_provider, is_link_provider,
    is_manual_provider, registry,
)
from app.receipts import generate_receipt_pdf, receipt_data, receipt_filename

log = logging.getLogger("qic.payments")
router = APIRouter(prefix="/v1/payments", tags=["payments"])
webhook_router = APIRouter(prefix="/webhooks", tags=["webhooks"])


# ------------------------------------------------------------------ models
class CheckoutBody(BaseModel):
    plan: str
    interval: str = "monthly"
    provider: str
    coupon: Optional[str] = None


class CancelBody(BaseModel):
    request_id: str


class CouponValidateBody(BaseModel):
    code: str
    plan: str
    interval: str = "monthly"


def _models():
    return resolve_models()


def _require_verified(user: Any) -> None:
    if getattr(user, "banned", False):
        raise err(403, "account_banned",
                  f"Your account is banned: {getattr(user, 'ban_reason', '') or 'no reason given'}.",
                  "Contact support if you think this is a mistake.")
    # TEMPORARY (test-only): when REQUIRE_EMAIL_VERIFICATION=false this
    # checkout / manual-submit gate is open for unverified users. The
    # default (true) keeps the gate. Re-enable by removing the env var
    # or setting it to "true".
    if not get_settings().require_email_verification:
        return
    if getattr(user, "email_verified_at", None) is None:
        raise err(403, "email_not_verified",
                  "Verify your email before checking out.",
                  "Use the verification link we emailed you, or resend it from your account page.")


async def _get_plan(db, models, plan_id: str):
    plan = (await db.execute(
        select(models.Plan).where(models.Plan.id == plan_id)
    )).scalar_one_or_none()
    if plan is None or not plan.active or plan.archived:
        raise err(400, "plan_unavailable",
                  "That plan is not available for purchase.",
                  "Choose one of the plans on the pricing page.")
    if plan_id in ("anonymous", "free"):
        raise err(400, "plan_unavailable",
                  "The free plan needs no payment.",
                  "Choose Basic or Pro to upgrade.")
    return plan


async def _provider_status(db, models, key: str):
    """(provider class, db row or None, merged config, enabled, configured)."""
    cls = get_provider(key)
    row = (await db.execute(
        select(models.PaymentProvider).where(models.PaymentProvider.key == key)
    )).scalar_one_or_none()
    config = await load_provider_config(db, models, key)
    enabled = bool(row.enabled) if row is not None else False
    configured = cls.is_configured(config)
    return cls, row, config, enabled, configured


def _provider_public(cls, config: dict) -> dict:
    info = {"key": cls.key, "label": cls.label, "flow": cls.flow}
    if cls.flow == "manual":
        info["fields"] = [f["label"] for f in cls.config_fields()
                          if f["name"] != "instructions"]
    if cls.flow == "link":
        info["opens_in_new_tab"] = True
    if cls.flow == "auto":
        info["instant"] = True
    return info


# ------------------------------------------------------------------ config
@router.get("/config")
async def payments_config(db=Depends(get_db)):
    models = _models()
    out = []
    for key, cls in registry().items():
        if getattr(cls, "reserved", False):
            continue
        _cls, _row, config, enabled, configured = await _provider_status(db, models, key)
        if enabled and configured:
            out.append(_provider_public(cls, config))
    return {"providers": out}


# --------------------------------------------------------------- checkout
@router.post("/checkout")
async def checkout(body: CheckoutBody, request: Request,
                   user=Depends(get_current_user), db=Depends(get_db)):
    models = _models()
    _require_verified(user)
    enforce_rate_limit(f"checkout:{user.id}:{client_ip(request)}", 5, 60)
    plan = await _get_plan(db, models, body.plan)
    if body.interval not in ("monthly", "yearly"):
        raise err(400, "invalid_interval", "Interval must be monthly or yearly.",
                  "Choose monthly or yearly billing.")
    cls, _row, config, enabled, configured = await _provider_status(db, models, body.provider)
    if getattr(cls, "reserved", False):
        raise err(400, "provider_reserved",
                  f"{cls.label} is reserved and not available yet.",
                  "Choose another payment method.")
    if not enabled or not configured:
        raise err(400, "provider_unavailable",
                  f"{cls.label} is not available right now.",
                  "Choose another payment method.")
    coupon = None
    if body.coupon:
        coupon = await validate_coupon(db, models, body.coupon, plan.id,
                                       body.interval, user_id=user.id)
        can_apply, reason = cls.supports_coupon(coupon) if cls.flow == "auto" else (True, "")
        if cls.flow == "auto" and not can_apply:
            raise err(400, "coupon_not_supported",
                      f"This coupon cannot be used with {cls.label}. {reason}",
                      "Remove the coupon, or pay with a different method.")
    base_cents = price_for_plan(plan, body.interval)
    total_cents = apply_coupon_to_amount(base_cents, coupon)
    if cls.flow == "manual":
        fx = await get_pkr_rate(db, models)
        return cls.build_instructions(config=config, amount_cents=base_cents,
                                      coupon=coupon, fx_rate=fx,
                                      original_cents=base_cents)
    if cls.flow == "link":
        return cls.build_instructions(config=config, amount_cents=base_cents,
                                      coupon=coupon, original_cents=base_cents)
    # auto
    price_row = (await db.execute(
        select(models.PlanPrice).where(
            models.PlanPrice.plan_id == plan.id,
            models.PlanPrice.provider_key == cls.key,
            models.PlanPrice.interval == body.interval)
    )).scalar_one_or_none()
    provider_price_id = price_row.provider_price_id if price_row else None
    result = cls.create_checkout(
        user=user, plan=plan, interval=body.interval,
        amount_cents=total_cents, coupon=coupon, config=config,
        provider_price_id=provider_price_id)
    result["plan"] = plan.id
    result["interval"] = body.interval
    result["total_cents"] = total_cents
    result["original_cents"] = base_cents
    return result


# ----------------------------------------------------------- manual submit
@router.post("/manual/submit")
async def manual_submit(
        request: Request,
        plan: str = Form(...), interval: str = Form("monthly"),
        provider: str = Form(...), reference: str = Form(...),
        note: Optional[str] = Form(None), coupon: Optional[str] = Form(None),
        proof: Optional[UploadFile] = File(None),
        user=Depends(get_current_user), db=Depends(get_db)):
    models = _models()
    _require_verified(user)
    enforce_rate_limit(f"manual:{user.id}:{client_ip(request)}", 3, 60)
    reference = (reference or "").strip()
    if not reference:
        raise err(400, "reference_required",
                  "A payment reference is required.",
                  "Enter the transaction ID or reference from your payment app.")
    if interval not in ("monthly", "yearly"):
        raise err(400, "invalid_interval", "Interval must be monthly or yearly.",
                  "Choose monthly or yearly billing.")
    plan_obj = await _get_plan(db, models, plan)
    cls, _row, config, enabled, configured = await _provider_status(db, models, provider)
    if cls.flow not in ("manual", "link"):
        raise err(400, "provider_unavailable",
                  f"{cls.label} does not accept manual payment submissions.",
                  "Use the checkout button for automatic providers.")
    if not enabled or not configured:
        raise err(400, "provider_unavailable",
                  f"{cls.label} is not available right now.",
                  "Choose another payment method.")
    coupon_obj = None
    if coupon:
        coupon_obj = await validate_coupon(db, models, coupon, plan_obj.id,
                                           interval, user_id=user.id)
    base_cents = price_for_plan(plan_obj, interval)
    total_cents = apply_coupon_to_amount(base_cents, coupon_obj)
    fx = await get_pkr_rate(db, models)
    if cls.key == "manual_usdt":
        display_amount = total_cents  # USDT cents, USD 1:1
        fx_snapshot = None
    else:
        display_amount = pkr_amount(total_cents, fx)
        fx_snapshot = fx
    proof_path = None
    proof_bytes = None
    proof_name = None
    if proof is not None and proof.filename:
        proof_bytes = await proof.read()
        problem = validate_proof(proof.filename, proof.content_type or "",
                                 len(proof_bytes))
        if problem:
            raise err(400, "invalid_proof", problem,
                      "Upload a JPG, PNG or PDF file up to 5 MB.")
        proof_name = proof.filename
    req = models.PaymentRequest(
        user_id=user.id, plan_id=plan_obj.id, interval=interval,
        provider_key=cls.key, coupon_code=coupon_obj.code if coupon_obj else None,
        amount_cents=total_cents, currency="USD",
        display_amount=display_amount, fx_rate=fx_snapshot,
        reference=reference, note=(note or "").strip() or None,
        status="pending")
    db.add(req)
    try:
        await db.flush()
    except IntegrityError:
        await db.rollback()
        raise err(409, "duplicate_reference",
                  "This payment reference was already submitted for this provider.",
                  "Check the reference, or contact support if you already paid.")
    if proof_bytes is not None:
        data_dir = Path(os.environ.get("DATA_DIR", "data"))
        target_dir = data_dir / "proofs" / req.id
        target_dir.mkdir(parents=True, exist_ok=True)
        safe_name = Path(proof_name or "proof").name
        target = target_dir / safe_name
        target.write_bytes(proof_bytes)
        try:
            target.chmod(0o600)
        except OSError:
            pass
        req.proof_path = str(target)
        db.add(req)
        await db.flush()
    if coupon_obj is not None:
        await record_coupon_use(db, coupon_obj)
    await create_notification(
        db, models, user.id, "payment_submitted",
        "Payment submitted — pending approval",
        f"Your {cls.label} payment for the {plan_obj.name} plan "
        f"(reference {reference}) is pending approval.",
        link="/account?tab=plan")
    if getattr(user, "email", None):
        await send_mail(user.email, "Payment submitted — pending approval",
                        f"Your {cls.label} payment for the {plan_obj.name} plan "
                        f"(reference {reference}) was submitted and is pending "
                        "approval. We will email you once it is reviewed.")
    await db.commit()
    return {
        "id": req.id, "status": req.status, "provider": req.provider_key,
        "plan": req.plan_id, "interval": req.interval,
        "amount_cents": req.amount_cents,
        "display_amount": req.display_amount,
        "display_currency": "USDT" if cls.key == "manual_usdt" else "PKR",
        "fx_rate": req.fx_rate, "reference": req.reference,
        "created_at": req.created_at.isoformat() if req.created_at else None,
    }


# ----------------------------------------------------------------- cancel
@router.post("/cancel")
async def cancel_payment(body: CancelBody, user=Depends(get_current_user),
                         db=Depends(get_db)):
    models = _models()
    req = (await db.execute(
        select(models.PaymentRequest).where(
            models.PaymentRequest.id == body.request_id,
            models.PaymentRequest.user_id == user.id)
    )).scalar_one_or_none()
    if req is None:
        raise err(404, "not_found", "That payment request was not found.",
                  "Check the request and try again.")
    if req.status != "pending":
        raise err(400, "not_pending",
                  f"A {req.status} payment request cannot be canceled.",
                  "Only pending requests can be canceled.")
    req.status = "canceled"
    req.resolved_at = utcnow()
    db.add(req)
    await db.commit()
    return {"id": req.id, "status": req.status}


# ---------------------------------------------------------------- history
@router.get("/history")
async def payment_history(user=Depends(get_current_user), db=Depends(get_db)):
    models = _models()
    requests = (await db.execute(
        select(models.PaymentRequest).where(
            models.PaymentRequest.user_id == user.id
        ).order_by(models.PaymentRequest.created_at.desc()).limit(100)
    )).scalars().all()
    subs = (await db.execute(
        select(models.Subscription).where(
            models.Subscription.user_id == user.id
        ).order_by(models.Subscription.created_at.desc()).limit(20)
    )).scalars().all()
    return {
        "requests": [{
            "id": r.id, "provider": r.provider_key, "plan": r.plan_id,
            "interval": r.interval, "status": r.status,
            "amount_cents": r.amount_cents, "reference": r.reference,
            "receipt_no": r.receipt_no, "admin_note": r.admin_note,
            "created_at": r.created_at.isoformat() if r.created_at else None,
            "resolved_at": r.resolved_at.isoformat() if r.resolved_at else None,
        } for r in requests],
        "subscriptions": [{
            "id": s.id, "plan": s.plan_id, "provider": s.provider_key,
            "interval": s.interval, "status": s.status,
            "cancel_at_period_end": s.cancel_at_period_end,
            "current_period_end": s.current_period_end.isoformat()
            if s.current_period_end else None,
            "grace_ends_at": s.grace_ends_at.isoformat()
            if s.grace_ends_at else None,
        } for s in subs],
    }


# ---------------------------------------------------------------- receipt
@router.get("/receipts/{receipt_no}")
async def download_receipt(receipt_no: str, user=Depends(get_current_user),
                           db=Depends(get_db)):
    models = _models()
    req = (await db.execute(
        select(models.PaymentRequest).where(
            models.PaymentRequest.receipt_no == receipt_no,
            models.PaymentRequest.user_id == user.id)
    )).scalar_one_or_none()
    if req is None:
        raise err(404, "not_found", "That receipt was not found.",
                  "Check the receipt number and try again.")
    plan = (await db.execute(
        select(models.Plan).where(models.Plan.id == req.plan_id)
    )).scalar_one_or_none()
    cls = get_provider(req.provider_key)
    display = (f"{req.display_amount} PKR" if req.provider_key != "manual_usdt"
               else f"{(req.display_amount or 0) / 100:.2f} USDT")
    data = receipt_data(
        receipt_no=req.receipt_no, plan_name=plan.name if plan else req.plan_id,
        interval=req.interval, amount_cents=req.amount_cents,
        provider_label=cls.label, reference=req.reference,
        email=user.email, customer_name=user.display_name,
        display_text=display,
        date=req.resolved_at.strftime("%Y-%m-%d") if req.resolved_at else None)
    pdf_bytes, _renderer = generate_receipt_pdf(data)
    return Response(
        content=pdf_bytes, media_type="application/pdf",
        headers={"Content-Disposition":
                 f'attachment; filename="{receipt_filename(receipt_no)}"'})


# --------------------------------------------------------- coupon validate
@router.post("/coupons/validate")
async def validate_coupon_endpoint(body: CouponValidateBody,
                                   user=Depends(get_current_user),
                                   db=Depends(get_db)):
    models = _models()
    plan = (await db.execute(
        select(models.Plan).where(models.Plan.id == body.plan)
    )).scalar_one_or_none()
    if plan is None:
        raise err(400, "plan_unavailable", "That plan is not available.",
                  "Choose one of the plans on the pricing page.")
    coupon = await validate_coupon(db, models, body.code, plan.id,
                                   body.interval, user_id=user.id)
    base_cents = price_for_plan(plan, body.interval)
    discount = base_cents - apply_coupon_to_amount(base_cents, coupon)
    return {
        "code": coupon.code, "type": coupon.type, "value": coupon.value,
        "recurring": coupon.recurring,
        "discount_cents": discount,
        "total_cents": base_cents - discount,
        "applies_to_first_payment_only": not coupon.recurring,
    }


# ------------------------------------------------------------------- link
@router.get("/link")
async def payment_link(provider: str = "payoneer_link",
                       user=Depends(get_current_user), db=Depends(get_db)):
    models = _models()
    cls, _row, config, enabled, configured = await _provider_status(db, models, provider)
    if cls.flow != "link":
        raise err(400, "not_a_link_provider",
                  "That provider does not use a payment link.",
                  "Choose the Payoneer option at checkout.")
    if not enabled or not configured:
        raise err(400, "provider_unavailable",
                  f"{cls.label} is not available right now.",
                  "Choose another payment method.")
    url = cls.payment_url(config)
    if not url:
        raise err(400, "provider_unavailable",
                  "No payment link is configured for this provider.",
                  "Choose another payment method.")
    log.info("payment link opened: provider=%s user=%s", provider, user.id)
    return RedirectResponse(url=url, status_code=302)


# --------------------------------------------------------------- webhooks
def _verify(provider_cls, raw_body: bytes, headers, config: dict):
    secret = str(config.get("webhook_secret") or "")
    verifier = getattr(provider_cls, "verify_webhook_with_secret", None)
    if verifier is not None:
        return verifier(raw_body, headers, secret)
    return provider_cls.verify_webhook(raw_body, headers)


@webhook_router.post("/{key}")
async def webhook_endpoint(key: str, request: Request, db=Depends(get_db)):
    models = _models()
    raw_body = await request.body()
    try:
        cls = get_provider(key)
    except ApiError:
        raise err(404, "unknown_provider", "That webhook endpoint does not exist.",
                  "Check the webhook URL in the provider dashboard.")
    if getattr(cls, "reserved", False):
        raise err(404, "unknown_provider", "That webhook endpoint does not exist.",
                  "Check the webhook URL in the provider dashboard.")
    config = await load_provider_config(db, models, key)
    if not cls.is_configured(config):
        raise err(401, "webhook_not_configured",
                  "This webhook endpoint is not configured.",
                  "Configure the provider in the admin panel first.")
    try:
        event_id, event_type, payload = _verify(cls, raw_body, request.headers, config)
    except WebhookVerificationError as exc:
        raise err(401, "invalid_signature",
                  "The webhook signature could not be verified.",
                  str(exc) or "Check the webhook secret in the admin panel.")
    # Idempotency: (provider_key, event_id) for 30 days.
    cutoff = utcnow() - timedelta(days=30)
    existing = (await db.execute(
        select(models.WebhookEvent).where(
            models.WebhookEvent.provider_key == key,
            models.WebhookEvent.event_id == event_id)
    )).scalar_one_or_none()
    if existing is not None:
        return {"status": "duplicate", "event_id": event_id}
    event_row = models.WebhookEvent(
        provider_key=key, event_id=event_id, type=event_type,
        payload=payload, status="received")
    db.add(event_row)
    try:
        await db.flush()
    except IntegrityError:
        await db.rollback()
        return {"status": "duplicate", "event_id": event_id}
    try:
        normalized = cls.normalize_event(event_type, payload)
        # Resolve the plan from the provider price/variant id when the
        # event carries no custom plan data.
        if normalized.plan_id is None:
            price_id = (payload.get("_price_id")
                        or (normalized.raw or {}).get("_price_id")
                        or (normalized.raw or {}).get("_variant_id"))
            if price_id:
                price_row = (await db.execute(
                    select(models.PlanPrice).where(
                        models.PlanPrice.provider_key == key,
                        models.PlanPrice.provider_price_id == str(price_id))
                )).scalar_one_or_none()
                if price_row is not None:
                    normalized.plan_id = price_row.plan_id
                    normalized.interval = price_row.interval
        outcome = await apply_event(db, models, normalized)
        event_row.status = "processed" if outcome.get("status") == "applied" else "ignored"
        if outcome.get("status") == "unresolved":
            event_row.status = "ignored"
            event_row.error = str(outcome.get("detail") or "")
        await db.commit()
        return {"status": "ok", "event_id": event_id,
                "applied": outcome.get("status")}
    except Exception as exc:  # never a stack trace to the caller
        await db.rollback()
        log.exception("webhook apply failed: %s %s", key, event_id)
        try:
            row = (await db.execute(
                select(models.WebhookEvent).where(
                    models.WebhookEvent.provider_key == key,
                    models.WebhookEvent.event_id == event_id)
            )).scalar_one_or_none()
            if row is not None:
                row.status = "error"
                row.error = str(exc)[:500]
                await db.commit()
        except Exception:
            await db.rollback()
        raise err(400, "webhook_apply_failed",
                  "The webhook was received but could not be applied.",
                  "The event is stored in the webhook log for replay.")
