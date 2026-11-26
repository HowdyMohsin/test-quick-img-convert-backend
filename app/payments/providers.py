"""Payment provider interface for Quick IMG Convert v5 (spec section 7).

Plugin guide (this docstring is the source the README provider guide is
assembled from):

Every provider is one class in ``app/payments/`` implementing
:class:`PaymentProvider`:

- ``key`` — stable slug, e.g. ``manual_jazzcash``. Never changes once live.
- ``label`` — human name shown at checkout.
- ``flow`` — ``manual`` | ``link`` | ``auto``.
- ``config_fields()`` — list of ``{name, label, secret, required, hint}``.
  ``secret`` fields are write-only through the admin API and shown masked.
- ``is_configured(config)`` — True ONLY when real config exists (every
  required field non-empty). A provider appears at checkout only when it
  is enabled AND ``is_configured()`` is True.
- ``create_checkout(...)`` — returns the data the frontend needs to start
  a payment (hosted URL, client token, or manual instructions). Must not
  make a network call that charges anything. Raises :class:`ApiError`
  (from ``app.billing``) with a plain message when the provider cannot
  serve the request (e.g. a coupon it cannot apply).
- ``verify_webhook(raw_body, headers)`` — verifies the signature on the
  RAW body and returns ``(event_id, event_type, payload_dict)``. Raises
  :class:`WebhookVerificationError` on any failure; the router turns that
  into a 401/400 in the standard error shape, never a stack trace.
- ``normalize_event(event_type, payload)`` — maps a provider event to a
  :class:`app.billing.NormalizedEvent` (kind ``activated`` | ``renewed`` |
  ``past_due`` | ``canceled`` | ``expired`` | ``ignored``). Unknown event
  types map to ``ignored``.
- ``apply_event(session, event)`` — default implementation in
  ``app.billing.apply_event``; providers override only when the provider
  needs extra handling.

Adding a provider: create one file in this package, subclass
``PaymentProvider``, add it to :data:`REGISTRY`, and add its env vars to
``.env.example``. No other file changes. There are no sandbox or
test-mode toggles anywhere: a provider is either configured with real
credentials or it does not appear.

Event names were checked against the providers' public documentation on
2026-11-24 (Paddle Billing webhook events; Lemon Squeezy event types):
the spec names match. One change since the spec: Lemon Squeezy's own docs
state it is no longer accepting new sign-ups and will shut down on
2027-03-31; the owner should confirm eligibility before enabling it.
Paddle additionally emits ``subscription.created`` / ``subscription.updated``
/ ``subscription.paused`` / ``subscription.resumed`` / ``transaction.paid``;
those are handled (created/updated/resumed map to activation state,
paused is recorded as ignored-with-note) so a provider-side rename or
extra event never breaks the endpoint.
"""
from __future__ import annotations

import os
from abc import ABC, abstractmethod
from typing import Any, Optional

from app.billing import ApiError, NormalizedEvent, err


class WebhookVerificationError(Exception):
    """Raised when a webhook signature, timestamp or payload is invalid."""


class ProviderNotAvailable(ApiError):
    def __init__(self, message: str, hint: str = ""):
        super().__init__(400, "provider_unavailable", message, hint)


# ------------------------------------------------------------------ env
# Env-var defaults for provider config. DB config (admin-entered, encrypted)
# always wins over env vars; see app.billing.load_provider_config.
ENV_CONFIG: dict[str, dict[str, str]] = {
    "paddle": {
        "api_key": "PADDLE_API_KEY",
        "client_token": "PADDLE_CLIENT_TOKEN",
        "webhook_secret": "PADDLE_WEBHOOK_SECRET",
    },
    "lemonsqueezy": {
        "api_key": "LEMONSQUEEZY_API_KEY",
        "store_id": "LEMONSQUEEZY_STORE_ID",
        "webhook_secret": "LEMONSQUEEZY_WEBHOOK_SECRET",
    },
    "stripe": {
        "secret_key": "STRIPE_SECRET_KEY",
        "publishable_key": "STRIPE_PUBLISHABLE_KEY",
    },
}


def env_config_for(key: str) -> dict[str, str]:
    out = {}
    for field, env_name in ENV_CONFIG.get(key, {}).items():
        value = os.environ.get(env_name)
        if value:
            out[field] = value
    return out


# -------------------------------------------------------------- interface
class PaymentProvider(ABC):
    key: str = ""
    label: str = ""
    flow: str = ""  # manual | link | auto
    reserved: bool = False  # reserved providers never appear at checkout

    @classmethod
    def config_fields(cls) -> list[dict[str, Any]]:
        return []

    @classmethod
    def required_fields(cls) -> list[str]:
        return [f["name"] for f in cls.config_fields() if f.get("required")]

    @classmethod
    def secret_fields(cls) -> set[str]:
        return {f["name"] for f in cls.config_fields() if f.get("secret")}

    @classmethod
    def is_configured(cls, config: Optional[dict]) -> bool:
        """True only when every required config field has a real value."""
        if not config:
            return False
        return all(str(config.get(name) or "").strip()
                   for name in cls.required_fields())

    @classmethod
    def create_checkout(cls, *, user: Any, plan: Any, interval: str,
                        amount_cents: int, coupon: Any = None,
                        config: Optional[dict] = None,
                        provider_price_id: Optional[str] = None) -> dict:
        raise ProviderNotAvailable(
            f"{cls.label or cls.key} does not offer an automatic checkout.",
            "Choose a different payment method.")

    @classmethod
    def verify_webhook(cls, raw_body: bytes, headers: Any) -> tuple[str, str, dict]:
        raise WebhookVerificationError("webhooks are not supported by this provider")

    @classmethod
    def normalize_event(cls, event_type: str, payload: dict) -> NormalizedEvent:
        return NormalizedEvent(kind="ignored", provider_key=cls.key,
                               event_id=str(payload.get("event_id") or payload.get("id") or ""),
                               event_type=event_type, raw=payload)

    @classmethod
    def supports_coupon(cls, coupon: Any) -> tuple[bool, str]:
        """(can_apply, reason). Automatic providers apply the coupon through
        the provider's discount mechanism; if they cannot, checkout must
        reject the coupon for that provider with a clear message."""
        return False, f"{cls.label} cannot apply coupons."

    @classmethod
    def public_info(cls, config: Optional[dict] = None) -> dict:
        return {"key": cls.key, "label": cls.label, "flow": cls.flow}


def _load_provider_modules():
    """Import every provider module so REGISTRY is complete."""
    from app.payments import manual, payoneer, paddle, lemonsqueezy, stripe  # noqa: F401
    return manual, payoneer, paddle, lemonsqueezy, stripe


def registry() -> dict[str, type[PaymentProvider]]:
    """All 8 providers, keyed by provider key."""
    from app.payments.manual import (
        JazzCashProvider, EasyPaisaProvider, BankProvider, USDTProvider)
    from app.payments.payoneer import PayoneerProvider
    from app.payments.paddle import PaddleProvider
    from app.payments.lemonsqueezy import LemonSqueezyProvider
    from app.payments.stripe import StripeProvider
    return {
        JazzCashProvider.key: JazzCashProvider,
        EasyPaisaProvider.key: EasyPaisaProvider,
        BankProvider.key: BankProvider,
        USDTProvider.key: USDTProvider,
        PayoneerProvider.key: PayoneerProvider,
        PaddleProvider.key: PaddleProvider,
        LemonSqueezyProvider.key: LemonSqueezyProvider,
        StripeProvider.key: StripeProvider,
    }


# Backwards-compatible name; REGISTRY is built lazily to avoid import cycles.
class _Registry(dict):
    def __missing__(self, key):
        return registry()[key]

    def keys(self):  # type: ignore[override]
        return registry().keys()

    def items(self):  # type: ignore[override]
        return registry().items()

    def values(self):  # type: ignore[override]
        return registry().values()

    def get(self, key, default=None):  # type: ignore[override]
        return registry().get(key, default)

    def __contains__(self, key):  # type: ignore[override]
        return key in registry()

    def __iter__(self):
        return iter(registry())


REGISTRY: dict[str, type[PaymentProvider]] = _Registry()


def get_provider(key: str) -> type[PaymentProvider]:
    providers = registry()
    if key not in providers:
        raise err(400, "unknown_provider",
                  "That payment method is not available.",
                  "Choose one of the payment methods shown at checkout.")
    return providers[key]


def is_manual_provider(key: str) -> bool:
    return key.startswith("manual_")


def is_link_provider(key: str) -> bool:
    return key == "payoneer_link"
