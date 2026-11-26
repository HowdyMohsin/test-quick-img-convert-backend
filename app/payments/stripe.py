"""Stripe provider — RESERVED (spec section 7).

Stripe is reserved for a later phase. It is inactive until keys exist:
``is_configured()`` returns False with no keys, and there is no checkout
path — ``create_checkout()`` always raises, even if keys are present,
until the owner deliberately enables Stripe support. Webhooks are not
accepted for Stripe while it is reserved.
"""
from __future__ import annotations

from typing import Any, Optional

from app.billing import err
from app.payments.providers import PaymentProvider, WebhookVerificationError


class StripeProvider(PaymentProvider):
    key = "stripe"
    label = "Stripe"
    flow = "auto"
    reserved = True

    @classmethod
    def config_fields(cls) -> list[dict[str, Any]]:
        return [
            {"name": "secret_key", "label": "Stripe secret key",
             "secret": True, "required": True},
            {"name": "publishable_key", "label": "Stripe publishable key",
             "secret": False, "required": True},
            {"name": "webhook_secret", "label": "Stripe webhook secret",
             "secret": True, "required": False},
        ]

    @classmethod
    def create_checkout(cls, *, user: Any, plan: Any, interval: str,
                        amount_cents: int, coupon: Any = None,
                        config: Optional[dict] = None,
                        provider_price_id: Optional[str] = None) -> dict:
        raise err(400, "provider_reserved",
                  "Stripe is reserved and not available yet.",
                  "Choose another payment method.")

    @classmethod
    def verify_webhook(cls, raw_body: bytes, headers: Any) -> tuple[str, str, dict]:
        raise WebhookVerificationError("Stripe webhooks are not accepted while reserved")
