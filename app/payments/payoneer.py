"""Payoneer LINK provider (spec section 7).

The admin pastes a Payoneer payment-request URL. The user opens it in a
new tab (the click is logged by GET /v1/payments/link), pays there, then
submits a transaction reference — the same manual-submit shape as the
manual providers.
"""
from __future__ import annotations

from typing import Any, Optional

from app.payments.providers import PaymentProvider


class PayoneerProvider(PaymentProvider):
    key = "payoneer_link"
    label = "Payoneer"
    flow = "link"

    @classmethod
    def config_fields(cls) -> list[dict[str, Any]]:
        return [
            {"name": "payment_url", "label": "Payoneer payment-request URL",
             "secret": False, "required": True,
             "hint": "The payment-request link from the Payoneer dashboard."},
            {"name": "instructions", "label": "Payment instructions",
             "secret": False, "required": False,
             "hint": "Shown to the user next to the payment link."},
        ]

    @classmethod
    def is_configured(cls, config: Optional[dict]) -> bool:
        if not super().is_configured(config):
            return False
        url = str((config or {}).get("payment_url") or "").strip()
        return url.startswith("http://") or url.startswith("https://")

    @classmethod
    def payment_url(cls, config: Optional[dict]) -> Optional[str]:
        url = str((config or {}).get("payment_url") or "").strip()
        return url or None

    @classmethod
    def build_instructions(cls, *, config: Optional[dict], amount_cents: int,
                           coupon: Any = None,
                           original_cents: Optional[int] = None) -> dict:
        from app.billing import apply_coupon_to_amount
        total_cents = apply_coupon_to_amount(amount_cents, coupon)
        return {
            "provider": cls.key,
            "label": cls.label,
            "flow": "link",
            "payment_url": cls.payment_url(config),
            "instructions": str((config or {}).get("instructions") or ""),
            "amount_cents": total_cents,
            "currency": "USD",
            "coupon_code": getattr(coupon, "code", None) if coupon else None,
            "original_cents": original_cents if original_cents is not None else amount_cents,
        }
