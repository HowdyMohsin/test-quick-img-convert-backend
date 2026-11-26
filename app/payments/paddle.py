"""Paddle Billing provider (spec section 7).

Config: API key, client-side token, webhook secret.
Webhook: header ``Paddle-Signature`` (``ts=...;h1=...``), HMAC-SHA256 over
``{ts}:{raw body}``; timestamps older than 5 minutes are rejected.
Mapped events: subscription.activated, transaction.completed,
subscription.past_due, subscription.canceled. Also handled:
subscription.created (first activation), subscription.updated and
subscription.resumed (activation state), transaction.paid (payment
confirmation, no plan change on its own).

Checkout is client-side: the frontend loads Paddle.js with the
client-side token and opens the checkout with the plan's Paddle price
id (stored per plan in ``plan_prices``). This module makes no network
call and creates no charge; the webhook is the source of truth.

Sandbox: Paddle sandbox is selected by the client token — sandbox
tokens start with ``test_``, live tokens with ``live_``. The checkout
response carries ``sandbox: true`` for test tokens and the frontend
loads Paddle.js in sandbox mode. A sandbox price id (from the Paddle
sandbox dashboard) must be stored per plan for test checkouts.

Event names verified against Paddle Billing's public webhook
documentation on 2026-11-24; the spec names match.
"""
from __future__ import annotations

import hashlib
import hmac as hmac_mod
import json
import time
from datetime import datetime, timezone
from typing import Any, Optional

from app.billing import ApiError, NormalizedEvent, err
from app.payments.providers import PaymentProvider, WebhookVerificationError

TIMESTAMP_TOLERANCE_SECONDS = 300  # 5 minutes


def _parse_signature(header: str) -> tuple[int, str]:
    parts: dict[str, str] = {}
    for item in header.split(";"):
        if "=" in item:
            k, v = item.split("=", 1)
            parts[k.strip()] = v.strip()
    if "ts" not in parts or "h1" not in parts:
        raise WebhookVerificationError("Paddle-Signature header is malformed")
    try:
        ts = int(parts["ts"])
    except ValueError:
        raise WebhookVerificationError("Paddle-Signature timestamp is invalid")
    return ts, parts["h1"]


def verify_paddle_signature(raw_body: bytes, header: Optional[str],
                            secret: str) -> None:
    if not header:
        raise WebhookVerificationError("Missing Paddle-Signature header")
    if not secret:
        raise WebhookVerificationError("Paddle webhook secret is not configured")
    ts, signature = _parse_signature(header)
    now = int(time.time())
    if abs(now - ts) > TIMESTAMP_TOLERANCE_SECONDS:
        raise WebhookVerificationError("Paddle webhook timestamp is too old")
    expected = hmac_mod.new(
        secret.encode(), f"{ts}:".encode() + raw_body, hashlib.sha256).hexdigest()
    if not hmac_mod.compare_digest(expected, signature):
        raise WebhookVerificationError("Paddle webhook signature does not match")


class PaddleProvider(PaymentProvider):
    key = "paddle"
    label = "Paddle"
    flow = "auto"

    @classmethod
    def config_fields(cls) -> list[dict[str, Any]]:
        return [
            {"name": "api_key", "label": "Paddle API key",
             "secret": True, "required": True},
            {"name": "client_token", "label": "Paddle client-side token",
             "secret": True, "required": True},
            {"name": "webhook_secret", "label": "Paddle webhook secret",
             "secret": True, "required": True},
        ]

    @classmethod
    def create_checkout(cls, *, user: Any, plan: Any, interval: str,
                        amount_cents: int, coupon: Any = None,
                        config: Optional[dict] = None,
                        provider_price_id: Optional[str] = None) -> dict:
        if coupon is not None:
            # Paddle discounts need a Paddle discount id, which this build
            # does not store; per spec the coupon is rejected for this
            # provider rather than silently dropped.
            raise err(400, "coupon_not_supported",
                      "This coupon cannot be used with Paddle.",
                      "Remove the coupon, or pay with a different method.")
        if not provider_price_id:
            raise err(400, "provider_price_missing",
                      "This plan has no Paddle price configured yet.",
                      "Ask the site owner to add the Paddle price for this plan.")
        token = str((config or {}).get("client_token") or "")
        return {
            "provider": cls.key,
            "flow": "auto",
            "mode": "paddle_js",
            "client_token": token,
            "price_id": provider_price_id,
            "amount_cents": amount_cents,
            "currency": "USD",
            # Paddle sandbox is selected by the client token itself:
            # sandbox tokens start with "test_", live tokens with "live_".
            # The frontend loads Paddle.js in sandbox mode when this is
            # true. No live payment can happen on a sandbox token.
            "sandbox": token.startswith("test_"),
            "custom_data": {
                "user_id": str(getattr(user, "id", "")),
                "plan_id": str(getattr(plan, "id", "")),
                "interval": interval,
            },
        }

    @classmethod
    def supports_coupon(cls, coupon: Any) -> tuple[bool, str]:
        return False, ("Paddle discounts need a Paddle discount id; this "
                       "coupon cannot be applied through Paddle.")

    @classmethod
    def verify_webhook(cls, raw_body: bytes, headers: Any) -> tuple[str, str, dict]:
        header = headers.get("paddle-signature") if hasattr(headers, "get") else None
        if header is None and isinstance(headers, dict):
            header = headers.get("Paddle-Signature")
        secret = ""  # resolved by the router from stored config
        # The router passes the secret via a module-level override when it
        # calls this method through verify_webhook_with_secret; direct calls
        # without a secret always fail closed.
        raise WebhookVerificationError(
            "Paddle webhook verification needs the stored webhook secret; "
            "use verify_webhook_with_secret().")

    @classmethod
    def verify_webhook_with_secret(cls, raw_body: bytes, headers: Any,
                                   secret: str) -> tuple[str, str, dict]:
        if hasattr(headers, "get"):
            header = headers.get("paddle-signature") or headers.get("Paddle-Signature")
        else:
            header = None
        verify_paddle_signature(raw_body, header, secret)
        try:
            payload = json.loads(raw_body.decode())
        except Exception:
            raise WebhookVerificationError("Paddle webhook body is not valid JSON")
        event_id = str(payload.get("event_id") or "")
        event_type = str(payload.get("event_type") or "")
        if not event_id or not event_type:
            raise WebhookVerificationError("Paddle webhook is missing event_id or event_type")
        return event_id, event_type, payload

    @classmethod
    def normalize_event(cls, event_type: str, payload: dict) -> NormalizedEvent:
        data = payload.get("data") or {}
        custom = data.get("custom_data") or {}
        if not isinstance(custom, dict):
            custom = {}
        occurred = payload.get("occurred_at") or data.get("updated_at")
        event_id = str(payload.get("event_id") or "")
        base = NormalizedEvent(
            kind="ignored", provider_key=cls.key, event_id=event_id,
            event_type=event_type,
            user_id=str(custom.get("user_id")) if custom.get("user_id") else None,
            email=(data.get("customer_email") or (data.get("customer") or {}).get("email")),
            plan_id=str(custom.get("plan_id")) if custom.get("plan_id") else None,
            interval=str(custom.get("interval") or "monthly"),
            provider_sub_id=str(data.get("subscription_id") or data.get("id") or ""),
            provider_customer_id=str(data.get("customer_id") or ""),
            raw=payload)
        # Plan resolution also falls back to the Paddle price id, matched
        # against plan_prices by billing.apply_event's caller (webhook
        # router resolves price -> plan before applying).
        items = data.get("items") or []
        if items and isinstance(items, list):
            price = (items[0] or {}).get("price") or {}
            base.raw = dict(payload)
            base.raw["_price_id"] = price.get("id")
        period = (data.get("current_billing_period") or {})
        ends = period.get("ends_at") or data.get("next_billed_at")
        if ends:
            try:
                base.period_end = datetime.fromisoformat(
                    str(ends).replace("Z", "+00:00"))
            except ValueError:
                base.period_end = None
        mapping = {
            "subscription.created": "activated",
            "subscription.activated": "activated",
            "subscription.updated": "activated",
            "subscription.resumed": "activated",
            "transaction.completed": "renewed",
            "transaction.paid": "renewed",
            "subscription.past_due": "past_due",
            "subscription.canceled": "canceled",
        }
        kind = mapping.get(event_type)
        if kind is None:
            return base
        base.kind = kind
        # A bare transaction.completed with no subscription id is a
        # one-time payment, not a subscription renewal.
        if event_type in ("transaction.completed", "transaction.paid") and not (
                data.get("subscription_id")):
            base.kind = "ignored"
        return base
