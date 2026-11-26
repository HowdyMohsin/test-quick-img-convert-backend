"""Manual payment providers (spec section 7): JazzCash, EasyPaisa, bank, USDT.

All four ship DISABLED until the admin enters real account details.
Flow: the user sees instructions with a copy button per field (the
frontend renders from the field labels the backend returns), the PKR
amount (USD x pkr_per_usd, rounded UP to the nearest 10 PKR, rate
snapshotted on the request) or the USDT amount (USD 1:1), and the
coupon-adjusted total. The user pays, then submits a reference
(REQUIRED), a note and optional proof. The request stays pending until
an admin approves, rejects, or it expires.

USDT warning is FIXED copy: "send only USDT on the TRON network".
"""
from __future__ import annotations

from typing import Any, Optional

from app.billing import pkr_amount
from app.payments.providers import PaymentProvider

USDT_WARNING = "send only USDT on the TRON network"

MANUAL_CONFIG_SCHEMAS: dict[str, list[dict[str, Any]]] = {
    "manual_jazzcash": [
        {"name": "account_number", "label": "JazzCash account number",
         "secret": False, "required": True},
        {"name": "account_title", "label": "Account title",
         "secret": False, "required": True},
        {"name": "instructions", "label": "Payment instructions",
         "secret": False, "required": True,
         "hint": "Shown to the user, e.g. how to send the payment."},
    ],
    "manual_easypaisa": [
        {"name": "account_number", "label": "EasyPaisa account number",
         "secret": False, "required": True},
        {"name": "account_title", "label": "Account title",
         "secret": False, "required": True},
        {"name": "instructions", "label": "Payment instructions",
         "secret": False, "required": True,
         "hint": "Shown to the user, e.g. how to send the payment."},
    ],
    "manual_bank": [
        {"name": "bank_name", "label": "Bank name",
         "secret": False, "required": True},
        {"name": "account_title", "label": "Account title",
         "secret": False, "required": True},
        {"name": "account_number", "label": "IBAN or account number",
         "secret": False, "required": True},
        {"name": "branch", "label": "Branch",
         "secret": False, "required": False},
        {"name": "instructions", "label": "Payment instructions",
         "secret": False, "required": True,
         "hint": "Shown to the user, e.g. how to send the payment."},
    ],
    "manual_usdt": [
        {"name": "trc20_address", "label": "USDT TRC20 address",
         "secret": False, "required": True},
        {"name": "instructions", "label": "Payment instructions",
         "secret": False, "required": True,
         "hint": "Shown to the user, e.g. how to send the payment."},
    ],
}


class ManualProvider(PaymentProvider):
    flow = "manual"

    @classmethod
    def config_fields(cls) -> list[dict[str, Any]]:
        return MANUAL_CONFIG_SCHEMAS.get(cls.key, [])

    @classmethod
    def instruction_fields(cls, config: Optional[dict]) -> list[dict[str, Any]]:
        """Fields the frontend renders with a copy button each.

        Returns ``[{label, value, copyable}]``. Values are payment
        instructions the user must see to pay — they are not secrets.
        """
        config = config or {}
        fields = []
        for f in cls.config_fields():
            if f["name"] == "instructions":
                continue
            value = str(config.get(f["name"]) or "")
            if value:
                fields.append({"label": f["label"], "value": value,
                               "copyable": True})
        return fields

    @classmethod
    def build_instructions(cls, *, config: Optional[dict], amount_cents: int,
                           coupon: Any = None, fx_rate: Optional[float] = None,
                           original_cents: Optional[int] = None) -> dict:
        """Instruction payload for checkout / manual-submit pages."""
        from app.billing import apply_coupon_to_amount
        config = config or {}
        total_cents = apply_coupon_to_amount(amount_cents, coupon)
        payload: dict[str, Any] = {
            "provider": cls.key,
            "label": cls.label,
            "flow": "manual",
            "fields": cls.instruction_fields(config),
            "instructions": str(config.get("instructions") or ""),
            "amount_cents": total_cents,
            "currency": "USD",
            "coupon_code": getattr(coupon, "code", None) if coupon else None,
            "original_cents": original_cents if original_cents is not None else amount_cents,
        }
        if cls.key == "manual_usdt":
            payload["display_currency"] = "USDT"
            payload["display_amount"] = total_cents / 100.0  # USD 1:1 on TRC20
            payload["warning"] = USDT_WARNING
            payload["fx_rate"] = None
        else:
            rate = fx_rate if fx_rate is not None else 0.0
            payload["display_currency"] = "PKR"
            payload["display_amount"] = pkr_amount(total_cents, rate) if rate else None
            payload["fx_rate"] = rate
        return payload


class JazzCashProvider(ManualProvider):
    key = "manual_jazzcash"
    label = "JazzCash"


class EasyPaisaProvider(ManualProvider):
    key = "manual_easypaisa"
    label = "EasyPaisa"


class BankProvider(ManualProvider):
    key = "manual_bank"
    label = "Bank transfer"


class USDTProvider(ManualProvider):
    key = "manual_usdt"
    label = "USDT (TRC20)"


MANUAL_PROVIDERS = (JazzCashProvider, EasyPaisaProvider, BankProvider, USDTProvider)

# Proof upload rules (spec section 7 / spec section 4).
PROOF_MAX_BYTES = 5 * 1024 * 1024
PROOF_ALLOWED_TYPES = {
    "image/jpeg": ".jpg",
    "image/png": ".png",
    "application/pdf": ".pdf",
}
PROOF_ALLOWED_EXTENSIONS = {".jpg", ".jpeg", ".png", ".pdf"}


def validate_proof(filename: str, content_type: str, size: int) -> Optional[str]:
    """Return an error message when a proof file is rejected, else None."""
    if size > PROOF_MAX_BYTES:
        return "Proof file must be 5 MB or smaller."
    ext = "." + (filename.rsplit(".", 1)[-1].lower() if "." in filename else "")
    if content_type not in PROOF_ALLOWED_TYPES and ext not in PROOF_ALLOWED_EXTENSIONS:
        return "Proof must be a JPG, PNG or PDF file."
    return None
