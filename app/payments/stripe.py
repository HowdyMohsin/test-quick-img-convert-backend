"""Stripe provider — TEST MODE ONLY (spec section 7, user order 2026-11-26).

Stripe is enabled for TEST payments only: ``is_configured()`` is True
only when the stored keys are Stripe TEST keys (secret ``sk_test_...``,
publishable ``pk_test_...``). LIVE keys (``sk_live_`` / ``pk_live_``)
are refused everywhere — the provider never appears at checkout and
``create_checkout()`` raises — because Stripe does not onboard
Pakistan-based businesses for live payments. There is no live path in
this module at all; the ``reserved`` flag is gone because the test-key
check enforces the same boundary more strongly.

Checkout uses Stripe Checkout Sessions (``mode=subscription``) via the
Stripe HTTPS API with stdlib ``urllib`` (no new dependency — the Render
free tier stays light, matching the captcha module's approach). The
webhook verifies the ``Stripe-Signature`` header (HMAC-SHA256 over
``{timestamp}.{raw body}``, 5-minute tolerance) with the stored webhook
secret. The webhook is the source of truth, as for Paddle/Lemon Squeezy.
"""
from __future__ import annotations

import base64
import hashlib
import hmac as hmac_mod
import json
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Any, Optional

from app.billing import NormalizedEvent, err
from app.deps import get_settings
from app.payments.providers import PaymentProvider, WebhookVerificationError

STRIPE_API_BASE = "https://api.stripe.com/v1"
TIMESTAMP_TOLERANCE_SECONDS = 300  # 5 minutes


def _is_test_secret(secret_key: str) -> bool:
    return secret_key.startswith("sk_test_")


def _is_test_publishable(publishable_key: str) -> bool:
    return publishable_key.startswith("pk_test_")


def _api_post(secret_key: str, path: str, data: dict) -> dict:
    """POST one form-encoded call to the Stripe API. Raises ApiError with
    Stripe's own message on failure (never a raw traceback)."""
    body = urllib.parse.urlencode(data, doseq=True).encode()
    req = urllib.request.Request(
        f"{STRIPE_API_BASE}/{path}", data=body, method="POST",
        headers={
            "Authorization": "Basic " + base64.b64encode(
                f"{secret_key}:".encode()).decode(),
            "Content-Type": "application/x-www-form-urlencoded",
            "Stripe-Version": "2024-06-20",
        })
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        try:
            payload = json.loads(exc.read().decode())
        except Exception:
            payload = {}
        message = ((payload.get("error") or {}).get("message")
                   or f"Stripe request failed ({exc.code}).")
        raise err(400, "stripe_error", message,
                  "Check the Stripe test keys in the admin panel.")


def _parse_signature(header: str) -> tuple[int, list[str]]:
    parts: dict[str, list[str]] = {}
    for item in header.split(","):
        if "=" in item:
            k, v = item.split("=", 1)
            parts.setdefault(k.strip(), []).append(v.strip())
    if "t" not in parts or "v1" not in parts:
        raise WebhookVerificationError("Stripe-Signature header is malformed")
    try:
        ts = int(parts["t"][0])
    except ValueError:
        raise WebhookVerificationError("Stripe-Signature timestamp is invalid")
    return ts, parts["v1"]


def verify_stripe_signature(raw_body: bytes, header: Optional[str],
                            secret: str) -> None:
    if not header:
        raise WebhookVerificationError("Missing Stripe-Signature header")
    if not secret:
        raise WebhookVerificationError("Stripe webhook secret is not configured")
    ts, signatures = _parse_signature(header)
    if abs(int(time.time()) - ts) > TIMESTAMP_TOLERANCE_SECONDS:
        raise WebhookVerificationError("Stripe webhook timestamp is too old")
    expected = hmac_mod.new(
        secret.encode(), f"{ts}.".encode() + raw_body, hashlib.sha256).hexdigest()
    if not any(hmac_mod.compare_digest(expected, sig) for sig in signatures):
        raise WebhookVerificationError("Stripe webhook signature does not match")


class StripeProvider(PaymentProvider):
    key = "stripe"
    label = "Stripe"
    flow = "auto"
    # No `reserved` flag: TEST MODE ONLY is enforced by is_configured()
    # (test keys only) and create_checkout() (live keys refused). A live
    # key can never reach a checkout or a webhook here.

    @classmethod
    def config_fields(cls) -> list[dict[str, Any]]:
        return [
            {"name": "secret_key", "label": "Stripe secret key (TEST only — sk_test_…)",
             "secret": True, "required": True,
             "hint": "Test mode key from the Stripe dashboard (Developers → API keys, test mode). Live keys are refused."},
            {"name": "publishable_key", "label": "Stripe publishable key (TEST only — pk_test_…)",
             "secret": False, "required": True,
             "hint": "Test mode publishable key from the Stripe dashboard."},
            {"name": "webhook_secret", "label": "Stripe webhook secret",
             "secret": True, "required": False,
             "hint": "Signing secret of the test-mode webhook endpoint (Developers → Webhooks)."},
        ]

    @classmethod
    def is_configured(cls, config: Optional[dict]) -> bool:
        """True only with real TEST keys. A live key is never configured."""
        if not super().is_configured(config):
            return False
        cfg = config or {}
        return (_is_test_secret(str(cfg.get("secret_key") or "").strip())
                and _is_test_publishable(str(cfg.get("publishable_key") or "").strip()))

    @classmethod
    def create_checkout(cls, *, user: Any, plan: Any, interval: str,
                        amount_cents: int, coupon: Any = None,
                        config: Optional[dict] = None,
                        provider_price_id: Optional[str] = None) -> dict:
        if coupon is not None:
            # Stripe discounts need a Stripe coupon id, which this build
            # does not store; per spec the coupon is rejected for this
            # provider rather than silently dropped.
            raise err(400, "coupon_not_supported",
                      "This coupon cannot be used with Stripe.",
                      "Remove the coupon, or pay with a different method.")
        cfg = config or {}
        secret_key = str(cfg.get("secret_key") or "").strip()
        if not _is_test_secret(secret_key):
            # Live keys are refused even if they somehow got stored: there
            # is no live Stripe path in this module.
            raise err(400, "provider_unavailable",
                      "Stripe test keys are not configured yet.",
                      "Add the Stripe test keys (sk_test_… / pk_test_…) in the admin panel.")
        site_url = get_settings().site_url.rstrip("/")
        stripe_interval = "year" if interval == "yearly" else "month"
        session = _api_post(secret_key, "checkout/sessions", {
            "mode": "subscription",
            "success_url": f"{site_url}/pricing?success=1&session_id={{CHECKOUT_SESSION_ID}}",
            "cancel_url": f"{site_url}/pricing?cancelled=1",
            "customer_email": str(getattr(user, "email", "") or ""),
            "client_reference_id": str(getattr(user, "id", "")),
            "line_items[0][quantity]": "1",
            "line_items[0][price_data][currency]": "usd",
            "line_items[0][price_data][unit_amount]": str(amount_cents),
            "line_items[0][price_data][recurring][interval]": stripe_interval,
            "line_items[0][price_data][product_data][name]":
                f"{getattr(plan, 'name', 'Plan')} — Quick IMG Convert",
            "metadata[user_id]": str(getattr(user, "id", "")),
            "metadata[plan_id]": str(getattr(plan, "id", "")),
            "metadata[interval]": interval,
        })
        url = session.get("url")
        if not url:
            raise err(400, "stripe_error",
                      "Stripe did not return a checkout URL.",
                      "Check the Stripe test keys in the admin panel.")
        return {
            "provider": cls.key,
            "flow": "auto",
            "mode": "hosted_url",
            "checkout_url": url,
            "amount_cents": amount_cents,
            "currency": "USD",
        }

    @classmethod
    def supports_coupon(cls, coupon: Any) -> tuple[bool, str]:
        return False, ("Stripe discounts need a Stripe coupon id; this "
                       "coupon cannot be applied through Stripe.")

    @classmethod
    def verify_webhook(cls, raw_body: bytes, headers: Any) -> tuple[str, str, dict]:
        raise WebhookVerificationError(
            "Stripe webhook verification needs the stored webhook secret; "
            "use verify_webhook_with_secret().")

    @classmethod
    def verify_webhook_with_secret(cls, raw_body: bytes, headers: Any,
                                   secret: str) -> tuple[str, str, dict]:
        if hasattr(headers, "get"):
            header = headers.get("stripe-signature") or headers.get("Stripe-Signature")
        else:
            header = None
        verify_stripe_signature(raw_body, header, secret)
        try:
            payload = json.loads(raw_body.decode())
        except Exception:
            raise WebhookVerificationError("Stripe webhook body is not valid JSON")
        event_id = str(payload.get("id") or "")
        event_type = str(payload.get("type") or "")
        if not event_id or not event_type:
            raise WebhookVerificationError("Stripe webhook is missing its id or type")
        return event_id, event_type, payload

    @classmethod
    def normalize_event(cls, event_type: str, payload: dict) -> NormalizedEvent:
        obj = (payload.get("data") or {}).get("object") or {}
        meta = obj.get("metadata") or {}
        if not isinstance(meta, dict):
            meta = {}
        details = obj.get("customer_details") or {}
        period_end = None
        lines = ((obj.get("lines") or {}).get("data") or [])
        if lines:
            end_ts = ((lines[0] or {}).get("period") or {}).get("end")
            if end_ts:
                try:
                    period_end = datetime.fromtimestamp(int(end_ts), tz=timezone.utc)
                except (ValueError, TypeError, OverflowError):
                    period_end = None
        base = NormalizedEvent(
            kind="ignored", provider_key=cls.key,
            event_id=str(payload.get("id") or ""),
            event_type=event_type,
            user_id=str(meta.get("user_id")) if meta.get("user_id") else None,
            email=(details.get("email") or obj.get("customer_email")),
            plan_id=str(meta.get("plan_id")) if meta.get("plan_id") else None,
            interval=str(meta.get("interval") or "monthly"),
            provider_sub_id=str(obj.get("subscription") or obj.get("id") or ""),
            provider_customer_id=str(obj.get("customer") or ""),
            period_end=period_end,
            raw=payload)
        mapping = {
            "checkout.session.completed": "activated",
            "invoice.payment_succeeded": "renewed",
            "invoice.payment_failed": "past_due",
            "customer.subscription.deleted": "canceled",
        }
        kind = mapping.get(event_type)
        if kind is None:
            return base
        base.kind = kind
        return base
