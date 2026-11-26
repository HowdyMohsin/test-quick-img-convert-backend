"""Lemon Squeezy provider (spec section 7).

Config: API key, store id, webhook signing secret.
Webhook: header ``X-Signature`` = hex HMAC-SHA256 of the raw body with
the signing secret.
Mapped events: subscription_created, subscription_payment_success,
subscription_payment_failed, subscription_cancelled, subscription_expired.
Also handled: subscription_updated (activation state),
subscription_resumed, subscription_payment_recovered (renewal),
order_created (ignored — the subscription event carries the plan).

Checkout is a hosted URL built locally (no network call): the store
checkout URL with the plan's Lemon Squeezy variant id (stored per plan
in ``plan_prices``) and ``checkout[custom][user_id]`` / plan / interval,
plus ``checkout[discount_code]`` when a coupon applies.

Event names verified against Lemon Squeezy's public event-types
documentation on 2026-11-24; the spec names match. Note from those
docs: Lemon Squeezy is no longer accepting new sign-ups and will shut
down on 2027-03-31 — confirm eligibility before enabling it.
"""
from __future__ import annotations

import hashlib
import hmac as hmac_mod
import json
import urllib.parse
from datetime import datetime
from typing import Any, Optional

from app.billing import NormalizedEvent, err
from app.payments.providers import PaymentProvider, WebhookVerificationError


def verify_lemonsqueezy_signature(raw_body: bytes, header: Optional[str],
                                  secret: str) -> None:
    if not header:
        raise WebhookVerificationError("Missing X-Signature header")
    if not secret:
        raise WebhookVerificationError(
            "Lemon Squeezy webhook secret is not configured")
    expected = hmac_mod.new(secret.encode(), raw_body, hashlib.sha256).hexdigest()
    if not hmac_mod.compare_digest(expected, header.strip().lower()):
        raise WebhookVerificationError(
            "Lemon Squeezy webhook signature does not match")


class LemonSqueezyProvider(PaymentProvider):
    key = "lemonsqueezy"
    label = "Lemon Squeezy"
    flow = "auto"

    @classmethod
    def config_fields(cls) -> list[dict[str, Any]]:
        return [
            {"name": "api_key", "label": "Lemon Squeezy API key",
             "secret": True, "required": True},
            {"name": "store_id", "label": "Lemon Squeezy store id",
             "secret": False, "required": True},
            {"name": "webhook_secret", "label": "Lemon Squeezy webhook signing secret",
             "secret": True, "required": True},
        ]

    @classmethod
    def create_checkout(cls, *, user: Any, plan: Any, interval: str,
                        amount_cents: int, coupon: Any = None,
                        config: Optional[dict] = None,
                        provider_price_id: Optional[str] = None) -> dict:
        if not provider_price_id:
            raise err(400, "provider_price_missing",
                      "This plan has no Lemon Squeezy variant configured yet.",
                      "Ask the site owner to add the Lemon Squeezy variant for this plan.")
        store_id = str((config or {}).get("store_id") or "").strip()
        params = {
            "checkout[custom][user_id]": str(getattr(user, "id", "")),
            "checkout[custom][plan_id]": str(getattr(plan, "id", "")),
            "checkout[custom][interval]": interval,
        }
        if coupon is not None:
            params["checkout[discount_code]"] = str(getattr(coupon, "code", ""))
        query = urllib.parse.urlencode(params)
        return {
            "provider": cls.key,
            "flow": "auto",
            "mode": "hosted_url",
            "checkout_url": (
                f"https://app.lemonsqueezy.com/checkout/buy/{provider_price_id}?{query}"),
            "amount_cents": amount_cents,
            "currency": "USD",
            "store_id": store_id or None,
        }

    @classmethod
    def supports_coupon(cls, coupon: Any) -> tuple[bool, str]:
        return True, "Applied as a Lemon Squeezy discount code at checkout."

    @classmethod
    def verify_webhook(cls, raw_body: bytes, headers: Any) -> tuple[str, str, dict]:
        raise WebhookVerificationError(
            "Lemon Squeezy webhook verification needs the stored signing "
            "secret; use verify_webhook_with_secret().")

    @classmethod
    def verify_webhook_with_secret(cls, raw_body: bytes, headers: Any,
                                   secret: str) -> tuple[str, str, dict]:
        if hasattr(headers, "get"):
            header = headers.get("x-signature") or headers.get("X-Signature")
        else:
            header = None
        verify_lemonsqueezy_signature(raw_body, header, secret)
        try:
            payload = json.loads(raw_body.decode())
        except Exception:
            raise WebhookVerificationError(
                "Lemon Squeezy webhook body is not valid JSON")
        meta = payload.get("meta") or {}
        event_name = str(meta.get("event_name") or "")
        data = payload.get("data") or {}
        # Lemon Squeezy sends no unique per-delivery event id; the
        # subscription id alone would collide across event types, so the
        # idempotency key is event_name + resource id. A redelivery of the
        # same event still dedupes; a different event for the same
        # subscription does not.
        resource_id = str(data.get("id") or "")
        event_id = f"{event_name}:{resource_id}"
        if not event_name or not resource_id:
            raise WebhookVerificationError(
                "Lemon Squeezy webhook is missing its event name or id")
        return event_id, event_name, payload

    @classmethod
    def normalize_event(cls, event_type: str, payload: dict) -> NormalizedEvent:
        meta = payload.get("meta") or {}
        data = payload.get("data") or {}
        attrs = data.get("attributes") or {}
        custom = meta.get("custom_data") or {}
        if not isinstance(custom, dict):
            custom = {}
        ends = attrs.get("ends_at") or attrs.get("renews_at")
        period_end = None
        if ends:
            try:
                period_end = datetime.fromisoformat(str(ends).replace("Z", "+00:00"))
            except ValueError:
                period_end = None
        base = NormalizedEvent(
            kind="ignored", provider_key=cls.key,
            event_id=str(data.get("id") or ""),
            event_type=event_type,
            user_id=str(custom.get("user_id")) if custom.get("user_id") else None,
            email=attrs.get("user_email"),
            plan_id=str(custom.get("plan_id")) if custom.get("plan_id") else None,
            interval=str(custom.get("interval") or "monthly"),
            provider_sub_id=str(data.get("id") or ""),
            provider_customer_id=str(attrs.get("customer_id") or ""),
            period_end=period_end,
            raw=payload)
        # Variant id -> plan fallback for the webhook router.
        first_item = (attrs.get("first_subscription_item") or {})
        variant = first_item.get("variant_id")
        if variant:
            base.raw = dict(payload)
            base.raw["_variant_id"] = str(variant)
        mapping = {
            "subscription_created": "activated",
            "subscription_updated": "activated",
            "subscription_resumed": "activated",
            "subscription_payment_success": "renewed",
            "subscription_payment_recovered": "renewed",
            "subscription_payment_failed": "past_due",
            "subscription_cancelled": "canceled",
            "subscription_expired": "expired",
        }
        kind = mapping.get(event_type)
        if kind is None:
            return base
        base.kind = kind
        return base
