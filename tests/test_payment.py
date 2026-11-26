"""Payment tests: manual submit, coupons, PKR rounding, checkout guards,
admin approve/reject, receipts, ads eligibility, grace sweep.

Runs against SQLite + TestClient with the canonical models
(``app.models``, via the ``app.billing`` rebind). No network, no Docker,
no SMTP.
"""
import asyncio
import os
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ.setdefault("APP_SECRET", "test-app-secret-for-payment-tests")
os.environ.setdefault("PKR_PER_USD", "280")
os.environ.setdefault("DATA_DIR", "/tmp/qic-test-data")

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.billing import (
    ApiError, api_error_handler, encrypt_config, pkr_amount, run_grace_sweep,
    utcnow,
)
from app.billing import FallbackBase as Base
from app.billing import (
    AdSlot, Coupon, PaymentProviderRow, Plan, User,
)

DB_PATH = "/tmp/qic-test-payments.db"
if os.path.exists(DB_PATH):
    os.remove(DB_PATH)
ENGINE = create_engine(f"sqlite:///{DB_PATH}")
Base.metadata.create_all(ENGINE)


def seed():
    from app.billing import PaymentRequest, Subscription
    with Session(ENGINE) as s:
        for m in (PaymentRequest, Subscription, AdSlot, Coupon,
                  PaymentProviderRow, Plan, User):
            s.query(m).delete()
        s.add(User(id="user-1", email="buyer@example.com",
                   email_verified_at=utcnow(), display_name="Buyer", plan="free"))
        s.add(User(id="user-2", email="unverified@example.com",
                   email_verified_at=None, display_name="Unverified", plan="free"))
        s.add(User(id="user-3", email="pro@example.com",
                   email_verified_at=utcnow(), display_name="Pro User", plan="pro"))
        s.add(Plan(id="free", name="Free", price_cents=0, price_yearly_cents=0,
                   limits={"ads": True}))
        s.add(Plan(id="basic", name="Basic", price_cents=400,
                   price_yearly_cents=4000, limits={"ads": False}))
        s.add(Plan(id="pro", name="Pro", price_cents=900,
                   price_yearly_cents=9000, limits={"ads": False}))
        s.add(PaymentProviderRow(
            key="manual_jazzcash", label="JazzCash", flow="manual", enabled=True,
            config=encrypt_config({"account_number": "03001234567",
                                   "account_title": "Quick IMG Convert",
                                   "instructions": "Send via JazzCash app."})))
        s.add(PaymentProviderRow(
            key="manual_easypaisa", label="EasyPaisa", flow="manual",
            enabled=False,
            config=encrypt_config({"account_number": "03007654321",
                                   "account_title": "Quick IMG Convert",
                                   "instructions": "Send via EasyPaisa app."})))
        s.add(PaymentProviderRow(
            key="manual_bank", label="Bank transfer", flow="manual",
            enabled=True, config=None))  # enabled but NOT configured
        s.add(PaymentProviderRow(
            key="manual_usdt", label="USDT (TRC20)", flow="manual", enabled=True,
            config=encrypt_config({"trc20_address": "T" + "A" * 33,
                                   "instructions": "Send USDT on TRON."})))
        s.add(PaymentProviderRow(
            key="payoneer_link", label="Payoneer", flow="link", enabled=True,
            config=encrypt_config({"payment_url": "https://payoneer.example/pay/1",
                                   "instructions": "Pay via the link."})))
        s.add(PaymentProviderRow(
            key="paddle", label="Paddle", flow="auto", enabled=True,
            config=encrypt_config({"api_key": "pk_x", "client_token": "ct_x",
                                   "webhook_secret": "wh_x"})))
        s.add(Coupon(code="PERCENT10", type="percent", value=10,
                     plans=["basic", "pro"], intervals=["both"],
                     recurring=False, max_uses=100, used=0, active=True))
        s.add(Coupon(code="FIXED100", type="fixed", value=100,
                     plans=None, intervals=["monthly"],
                     recurring=False, max_uses=100, used=0, active=True))
        s.add(Coupon(code="EXPIRED", type="percent", value=50,
                     plans=None, intervals=["both"],
                     recurring=False, max_uses=100, used=0,
                     expires_at=datetime(2020, 1, 1, tzinfo=timezone.utc),
                     active=True))
        s.add(Coupon(code="BASICONLY", type="percent", value=20,
                     plans=["basic"], intervals=["both"],
                     recurring=False, max_uses=100, used=0, active=True))
        s.add(AdSlot(key="home_top", label="Home top", placement="home_top",
                     network="adsense", unit_id="ca-pub-1",
                     size="responsive", device="all", enabled=True, sort=1))
        s.commit()


CURRENT_USER = {"id": "user-1"}


@pytest.fixture(scope="module")
def client():
    seed()
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
    from app.billing import get_current_admin, get_current_user, get_db, get_optional_user
    from app.admin_auth import require_csrf
    from app.routers_admin_ads import router as admin_ads_router
    from app.routers_admin_payments import router as admin_payments_router
    from app.routers_ads import ads_txt_router, router as ads_router
    from app.routers_marketing import notifications_router, router as marketing_router
    from app.routers_payments import router as payments_router
    async_engine = create_async_engine(f"sqlite+aiosqlite:///{DB_PATH}")
    maker = async_sessionmaker(async_engine, expire_on_commit=False)

    async def override_get_db():
        async with maker() as session:
            yield session

    async def override_user():
        with Session(ENGINE) as s:
            return s.get(User, CURRENT_USER["id"])

    async def override_admin():
        from types import SimpleNamespace
        return SimpleNamespace(email="admin@example.com", id="admin-1")

    app = FastAPI()
    app.add_exception_handler(ApiError, api_error_handler)
    for r in (payments_router, ads_router, ads_txt_router, marketing_router,
              notifications_router, admin_payments_router, admin_ads_router):
        app.include_router(r)
    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_current_user] = override_user
    app.dependency_overrides[get_optional_user] = override_user
    app.dependency_overrides[get_current_admin] = override_admin
    # The admin mutations enforce CSRF (spec 13.2); the stubbed admin has
    # no real session, so the check is stubbed like the admin itself.
    app.dependency_overrides[require_csrf] = lambda: True
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c


@pytest.fixture(autouse=True)
def _clear_rate_limits():
    from app.billing import _RATE_BUCKETS
    _RATE_BUCKETS.clear()
    CURRENT_USER["id"] = "user-1"
    yield
    _RATE_BUCKETS.clear()


def user_plan(user_id="user-1"):
    with Session(ENGINE) as s:
        return s.get(User, user_id).plan


# ------------------------------------------------------------------- config
def test_config_lists_only_enabled_and_configured(client):
    r = client.get("/v1/payments/config")
    assert r.status_code == 200, r.text
    keys = {p["key"] for p in r.json()["providers"]}
    assert "manual_jazzcash" in keys
    assert "manual_usdt" in keys
    assert "payoneer_link" in keys
    assert "paddle" in keys
    assert "manual_easypaisa" not in keys  # disabled
    assert "manual_bank" not in keys  # enabled but not configured
    assert "stripe" not in keys  # reserved
    # No secrets leak through the config endpoint.
    assert "03001234567" not in r.text
    assert "pk_x" not in r.text


# ----------------------------------------------------------------- checkout
def test_checkout_manual_returns_pkr_instructions(client):
    r = client.post("/v1/payments/checkout", json={
        "plan": "basic", "interval": "monthly", "provider": "manual_jazzcash"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["display_currency"] == "PKR"
    assert body["display_amount"] == 1120  # $4.00 x 280 = 1120 PKR
    assert body["fx_rate"] == 280.0
    labels = [f["label"] for f in body["fields"]]
    assert "JazzCash account number" in labels
    assert "03001234567" in r.text  # instructions must show where to pay


def test_checkout_manual_with_coupon_adjusts_total(client):
    r = client.post("/v1/payments/checkout", json={
        "plan": "basic", "interval": "monthly",
        "provider": "manual_jazzcash", "coupon": "PERCENT10"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["amount_cents"] == 360  # $4.00 - 10%
    assert body["display_amount"] == 1010  # $3.60 x 280 = 1008 -> up to 1010
    assert body["coupon_code"] == "PERCENT10"


def test_checkout_usdt_is_one_to_one_with_warning(client):
    r = client.post("/v1/payments/checkout", json={
        "plan": "basic", "interval": "monthly", "provider": "manual_usdt"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["display_currency"] == "USDT"
    assert body["display_amount"] == 4.0
    assert body["warning"] == "send only USDT on the TRON network"


def test_checkout_requires_verified_email(client):
    CURRENT_USER["id"] = "user-2"
    r = client.post("/v1/payments/checkout", json={
        "plan": "basic", "interval": "monthly", "provider": "manual_jazzcash"})
    assert r.status_code == 403, r.text
    assert r.json()["error"]["code"] == "email_not_verified"


def test_checkout_paddle_rejects_coupon_it_cannot_apply(client):
    r = client.post("/v1/payments/checkout", json={
        "plan": "basic", "interval": "monthly",
        "provider": "paddle", "coupon": "PERCENT10"})
    assert r.status_code == 400, r.text
    assert r.json()["error"]["code"] == "coupon_not_supported"


def test_checkout_unconfigured_provider_rejected(client):
    r = client.post("/v1/payments/checkout", json={
        "plan": "basic", "interval": "monthly", "provider": "manual_bank"})
    assert r.status_code == 400, r.text
    assert r.json()["error"]["code"] == "provider_unavailable"


def test_pkr_rounding_up_to_nearest_10():
    assert pkr_amount(400, 280) == 1120
    assert pkr_amount(400, 277.3) == 1110  # 1109.2 rounds UP to 1110
    assert pkr_amount(900, 280) == 2520
    assert pkr_amount(401, 280) == 1130  # $4.01 x 280 = 1122.8 -> 1130


# ------------------------------------------------------------ manual submit
def _submit(client, reference, provider="manual_jazzcash", plan="basic",
            proof=None, coupon=None):
    data = {"plan": plan, "interval": "monthly", "provider": provider,
            "reference": reference, "note": "paid"}
    if coupon:
        data["coupon"] = coupon
    files = {"proof": proof} if proof else None
    return client.post("/v1/payments/manual/submit", data=data, files=files)


def test_manual_submit_happy_path(client):
    png = ("proof.png", b"\x89PNG\r\n\x1a\n" + b"x" * 100, "image/png")
    r = _submit(client, "TXN-HAPPY-1", proof=png)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "pending"
    assert body["display_amount"] == 1120
    assert body["display_currency"] == "PKR"
    from app.billing import Notification, PaymentRequest
    with Session(ENGINE) as s:
        req = s.query(PaymentRequest).filter_by(reference="TXN-HAPPY-1").one()
        assert req.proof_path and os.path.exists(req.proof_path)
        assert (os.stat(req.proof_path).st_mode & 0o777) == 0o600
        note = s.query(Notification).filter_by(
            user_id="user-1", kind="payment_submitted").first()
        assert note is not None


def test_manual_submit_duplicate_reference_rejected(client):
    _submit(client, "TXN-DUP-1")
    r = _submit(client, "TXN-DUP-1")
    assert r.status_code == 409, r.text
    assert r.json()["error"]["code"] == "duplicate_reference"


def test_manual_submit_missing_reference_rejected(client):
    r = _submit(client, "   ")
    assert r.status_code == 400, r.text
    assert r.json()["error"]["code"] == "reference_required"


def test_manual_submit_proof_too_large_rejected(client):
    big = ("proof.png", b"x" * (6 * 1024 * 1024), "image/png")
    r = _submit(client, "TXN-BIG-1", proof=big)
    assert r.status_code == 400, r.text
    assert r.json()["error"]["code"] == "invalid_proof"


def test_manual_submit_proof_wrong_type_rejected(client):
    exe = ("proof.exe", b"MZ" + b"x" * 100, "application/octet-stream")
    r = _submit(client, "TXN-EXE-1", proof=exe)
    assert r.status_code == 400, r.text
    assert r.json()["error"]["code"] == "invalid_proof"


# ------------------------------------------------------------------ coupons
def test_coupon_validate_percent_and_fixed(client):
    r = client.post("/v1/payments/coupons/validate",
                    json={"code": "PERCENT10", "plan": "basic",
                          "interval": "monthly"})
    assert r.status_code == 200, r.text
    assert r.json()["discount_cents"] == 40
    assert r.json()["total_cents"] == 360
    r = client.post("/v1/payments/coupons/validate",
                    json={"code": "FIXED100", "plan": "basic",
                          "interval": "monthly"})
    assert r.status_code == 200, r.text
    assert r.json()["discount_cents"] == 100


def test_coupon_validate_expired_and_wrong_plan(client):
    r = client.post("/v1/payments/coupons/validate",
                    json={"code": "EXPIRED", "plan": "basic",
                          "interval": "monthly"})
    assert r.status_code == 400, r.text
    assert r.json()["error"]["code"] == "coupon_expired"
    r = client.post("/v1/payments/coupons/validate",
                    json={"code": "BASICONLY", "plan": "pro",
                          "interval": "monthly"})
    assert r.status_code == 400, r.text
    assert r.json()["error"]["code"] == "coupon_wrong_plan"


# ------------------------------------------------------- cancel + admin flow
def test_cancel_pending_request(client):
    r = _submit(client, "TXN-CANCEL-1")
    req_id = r.json()["id"]
    r = client.post("/v1/payments/cancel", json={"request_id": req_id})
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "canceled"
    r = client.post("/v1/payments/cancel", json={"request_id": req_id})
    assert r.status_code == 400, r.text


def test_admin_approve_activates_and_receipt_downloads(client):
    r = _submit(client, "TXN-APPROVE-1")
    req_id = r.json()["id"]
    r = client.post(f"/admin/payments/requests/{req_id}/approve",
                    json={"admin_note": "verified"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "approved"
    receipt_no = body["receipt_no"]
    assert receipt_no.startswith("QIC-2026-"), receipt_no
    assert user_plan() == "basic"
    r = client.get(f"/v1/payments/receipts/{receipt_no}")
    assert r.status_code == 200, r.text
    assert r.headers["content-type"] == "application/pdf"
    assert r.content[:5] == b"%PDF-"


def test_admin_reject_requires_reason(client):
    r = _submit(client, "TXN-REJECT-1")
    req_id = r.json()["id"]
    r = client.post(f"/admin/payments/requests/{req_id}/reject",
                    json={"reason": "   "})
    assert r.status_code == 400, r.text
    r = client.post(f"/admin/payments/requests/{req_id}/reject",
                    json={"reason": "Reference does not match any payment."})
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "rejected"


def test_admin_provider_check_and_masked_config(client):
    r = client.post("/admin/payments/providers/manual_jazzcash/check")
    assert r.status_code == 200, r.text
    assert r.json()["configured"] is True
    r = client.post("/admin/payments/providers/manual_bank/check")
    assert r.status_code == 200, r.text
    assert r.json()["configured"] is False
    assert r.json()["missing"]
    r = client.get("/admin/payments/providers")
    assert r.status_code == 200, r.text
    jazz = [p for p in r.json()["providers"]
            if p["key"] == "manual_jazzcash"][0]
    assert "03001234567" not in str(jazz["config"])
    assert jazz["webhook_url"] is None
    paddle = [p for p in r.json()["providers"] if p["key"] == "paddle"][0]
    assert paddle["webhook_url"] == "/webhooks/paddle"


# ---------------------------------------------------------------------- ads
def test_ads_only_for_eligible_plans(client):
    # user-2 is on the free plan (ads on). user-1 was upgraded to Basic
    # by the approve test, so it is no longer ad-eligible here.
    CURRENT_USER["id"] = "user-2"
    r = client.get("/v1/ads", params={"slots": "home_top", "page": "/"})
    assert r.status_code == 200, r.text
    assert r.json()["eligible"] is True
    assert len(r.json()["ads"]) == 1
    assert r.json()["ads"][0]["key"] == "home_top"
    CURRENT_USER["id"] = "user-3"  # pro plan: ads off
    r = client.get("/v1/ads", params={"slots": "home_top", "page": "/"})
    assert r.json()["eligible"] is False
    assert r.json()["ads"] == []


def test_admin_slot_rejects_banned_placement(client):
    r = client.post("/admin/ads/slots", json={
        "key": "tool_card", "network": "adsense", "unit_id": "x",
        "size": "responsive", "device": "all"})
    assert r.status_code == 400, r.text
    assert r.json()["error"]["code"] == "banned_placement"


def test_impressions_deduplicated_per_page_view(client):
    payload = {"events": [
        {"slot": "home_top", "page_view_id": "pv-1", "page": "/", "device": "desktop"},
        {"slot": "home_top", "page_view_id": "pv-1", "page": "/", "device": "desktop"},
        {"slot": "home_top", "page_view_id": "pv-2", "page": "/", "device": "desktop"},
    ]}
    r = client.post("/v1/ads/impressions", json=payload)
    assert r.status_code == 200, r.text
    assert r.json()["inserted"] == 2
    assert r.json()["duplicates"] == 1


# -------------------------------------------------------------- grace sweep
def test_grace_sweep_expires_past_due_after_grace():
    from app.billing import Subscription
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
    with Session(ENGINE) as s:
        sub = Subscription(user_id="user-1", plan_id="basic",
                           provider_key="manual_jazzcash", interval="monthly",
                           status="past_due",
                           grace_ends_at=utcnow() - timedelta(hours=1),
                           current_period_end=utcnow() - timedelta(days=1))
        s.add(sub)
        s.commit()
        sub_id = sub.id

    async def _run():
        engine = create_async_engine(f"sqlite+aiosqlite:///{DB_PATH}")
        maker = async_sessionmaker(engine, expire_on_commit=False)
        from app.billing import resolve_models
        async with maker() as session:
            result = await run_grace_sweep(session, resolve_models())
            return result

    result = asyncio.run(_run())
    assert result["expired"] >= 1
    with Session(ENGINE) as s:
        assert s.get(Subscription, sub_id).status == "expired"
        assert s.get(User, "user-1").plan == "free"


def test_receipt_pdf_starts_with_pdf_header():
    from app.receipts import generate_receipt_pdf, receipt_data
    data = receipt_data(receipt_no="QIC-2026-000001", plan_name="Basic",
                        interval="monthly", amount_cents=400,
                        provider_label="JazzCash", reference="TXN-1",
                        email="buyer@example.com")
    pdf_bytes, renderer = generate_receipt_pdf(data)
    assert pdf_bytes[:5] == b"%PDF-"
    assert renderer in ("reportlab", "fpdf2", "minimal")


def test_billing_send_mail_awaits_async_helper(monkeypatch):
    """Regression: billing.send_mail used to call the async app.mail
    helper without awaiting it, so every payment email was silently
    dropped (RuntimeWarning: coroutine was never awaited) while the
    function still returned True."""
    import app.mail as mail_mod
    from app.billing import send_mail as billing_send_mail

    calls = []

    async def fake_send(to_email, subject, body, html_body=None, attachment=None):
        calls.append((to_email, subject, body, attachment))
        return True

    monkeypatch.setattr(mail_mod, "send_mail", fake_send)
    assert asyncio.run(
        billing_send_mail("buyer@example.com", "Subject", "Body")) is True
    assert len(calls) == 1
    assert calls[0][0] == "buyer@example.com"
    # The receipt attachment passes through to the helper.
    assert asyncio.run(
        billing_send_mail("buyer@example.com", "Receipt", "Body",
                          attachment=("receipt-1.pdf", b"%PDF"))) is True
    assert calls[1][3] == ("receipt-1.pdf", b"%PDF")

    async def fake_fail(*args, **kwargs):
        return False

    monkeypatch.setattr(mail_mod, "send_mail", fake_fail)
    assert asyncio.run(
        billing_send_mail("buyer@example.com", "Subject", "Body")) is False


def test_billing_send_mail_false_without_smtp(monkeypatch):
    """With no SMTP configured the real mail helper returns False and
    billing.send_mail reports False instead of raising."""
    from types import SimpleNamespace

    import app.mail as mail_mod
    from app.billing import send_mail as billing_send_mail

    monkeypatch.setattr(
        mail_mod, "get_settings",
        lambda: SimpleNamespace(smtp_host="", smtp_port=587, smtp_user="",
                                smtp_password="", smtp_from=""))
    assert asyncio.run(
        billing_send_mail("buyer@example.com", "Subject", "Body")) is False
