"""Webhook tests: signed Paddle + Lemon Squeezy fixtures replayed.

Covers: activate, renew, past_due, cancel (Paddle); activate, renew,
past_due, cancel, expired (Lemon Squeezy); bad signature rejected;
duplicate event ignored; timestamp too old rejected.

Runs against SQLite + TestClient with the fallback models (the core
agent's app.models does not exist yet). No network, no Docker, no live
webhooks.
"""
import hashlib
import hmac
import json
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ.setdefault("APP_SECRET", "test-app-secret-for-webhook-tests")
os.environ.setdefault("PKR_PER_USD", "280")

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.billing import ApiError, api_error_handler, encrypt_config, utcnow
from app.billing import FallbackBase as Base
from app.billing import Plan, PaymentProviderRow, PlanPrice, User
from app.routers_payments import webhook_router

DB_PATH = "/tmp/qic-test-webhooks.db"
PADDLE_SECRET = "paddle-webhook-secret"
LS_SECRET = "ls-webhook-secret"

if os.path.exists(DB_PATH):
    os.remove(DB_PATH)
ENGINE = create_engine(f"sqlite:///{DB_PATH}")
Base.metadata.create_all(ENGINE)


def seed():
    with Session(ENGINE) as s:
        s.query(User).delete()
        s.query(Plan).delete()
        s.query(PaymentProviderRow).delete()
        s.query(PlanPrice).delete()
        s.add(User(id="user-1", email="buyer@example.com",
                   email_verified_at=utcnow(), display_name="Buyer",
                   plan="free"))
        s.add(Plan(id="basic", name="Basic", price_cents=400,
                   price_yearly_cents=4000, limits={"ads": False}))
        s.add(Plan(id="pro", name="Pro", price_cents=900,
                   price_yearly_cents=9000, limits={"ads": False}))
        s.add(Plan(id="free", name="Free", price_cents=0,
                   price_yearly_cents=0, limits={"ads": True}))
        s.add(PaymentProviderRow(
            key="paddle", label="Paddle", flow="auto", enabled=True,
            config=encrypt_config({"api_key": "pk_live_x",
                                   "client_token": "ct_x",
                                   "webhook_secret": PADDLE_SECRET})))
        s.add(PaymentProviderRow(
            key="lemonsqueezy", label="Lemon Squeezy", flow="auto",
            enabled=True,
            config=encrypt_config({"api_key": "ls_x", "store_id": "123",
                                   "webhook_secret": LS_SECRET})))
        s.add(PlanPrice(plan_id="pro", provider_key="paddle",
                        interval="monthly", provider_price_id="pri_pro_m"))
        s.add(PlanPrice(plan_id="basic", provider_key="lemonsqueezy",
                        interval="monthly", provider_price_id="var_basic_m"))
        s.commit()


@pytest.fixture(scope="module")
def client():
    seed()
    from sqlalchemy.ext.asyncio import (
        async_sessionmaker, create_async_engine)
    from app.billing import get_db
    async_engine = create_async_engine(f"sqlite+aiosqlite:///{DB_PATH}")
    maker = async_sessionmaker(async_engine, expire_on_commit=False)

    async def override_get_db():
        async with maker() as session:
            yield session

    app = FastAPI()
    app.add_exception_handler(ApiError, api_error_handler)
    app.include_router(webhook_router)
    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c


def paddle_sign(body: bytes, ts: int | None = None) -> str:
    ts = ts if ts is not None else int(time.time())
    sig = hmac.new(PADDLE_SECRET.encode(), f"{ts}:".encode() + body,
                   hashlib.sha256).hexdigest()
    return f"ts={ts};h1={sig}"


def ls_sign(body: bytes) -> str:
    return hmac.new(LS_SECRET.encode(), body, hashlib.sha256).hexdigest()


def paddle_payload(event_id, event_type, **data):
    payload = {"event_id": event_id, "event_type": event_type,
               "occurred_at": "2026-11-24T00:00:00Z", "data": data}
    return json.dumps(payload).encode()


def ls_payload(event_name, sub_id, **attrs):
    payload = {"meta": {"event_name": event_name,
                        "custom_data": {"user_id": "user-1",
                                        "plan_id": "basic",
                                        "interval": "monthly"}},
               "data": {"id": sub_id, "type": "subscriptions",
                        "attributes": attrs}}
    return json.dumps(payload).encode()


def user_plan():
    with Session(ENGINE) as s:
        return s.get(User, "user-1").plan


def subscription_status():
    from app.billing import Subscription
    with Session(ENGINE) as s:
        rows = s.query(Subscription).all()
        return [(r.plan_id, r.status, r.cancel_at_period_end) for r in rows]


# ------------------------------------------------------------------ Paddle
def test_paddle_activate(client):
    body = paddle_payload(
        "evt-act-1", "subscription.activated",
        id="sub_p1", customer_id="cus_1", customer_email="buyer@example.com",
        status="active",
        custom_data={"user_id": "user-1", "plan_id": "pro", "interval": "monthly"},
        current_billing_period={"ends_at": "2026-12-24T00:00:00Z"},
        items=[{"price": {"id": "pri_pro_m"}}])
    r = client.post("/webhooks/paddle", content=body,
                    headers={"Paddle-Signature": paddle_sign(body),
                             "Content-Type": "application/json"})
    assert r.status_code == 200, r.text
    assert r.json()["applied"] == "applied"
    assert user_plan() == "pro"
    assert ("pro", "active", False) in subscription_status()


def test_paddle_renew_via_transaction_completed(client):
    body = paddle_payload(
        "evt-txn-1", "transaction.completed",
        id="txn_1", subscription_id="sub_p1", customer_id="cus_1",
        custom_data={"user_id": "user-1", "plan_id": "pro", "interval": "monthly"},
        items=[{"price": {"id": "pri_pro_m"}}])
    r = client.post("/webhooks/paddle", content=body,
                    headers={"Paddle-Signature": paddle_sign(body),
                             "Content-Type": "application/json"})
    assert r.status_code == 200, r.text
    assert r.json()["applied"] == "applied"
    assert ("pro", "active", False) in subscription_status()


def test_paddle_past_due(client):
    body = paddle_payload(
        "evt-pd-1", "subscription.past_due",
        id="sub_p1", customer_id="cus_1",
        custom_data={"user_id": "user-1", "plan_id": "pro", "interval": "monthly"})
    r = client.post("/webhooks/paddle", content=body,
                    headers={"Paddle-Signature": paddle_sign(body),
                             "Content-Type": "application/json"})
    assert r.status_code == 200, r.text
    assert ("pro", "past_due", False) in subscription_status()
    from app.billing import Notification
    with Session(ENGINE) as s:
        notes = s.query(Notification).filter_by(user_id="user-1",
                                                kind="past_due").all()
        assert len(notes) >= 1


def test_paddle_cancel_keeps_plan_until_period_end(client):
    body = paddle_payload(
        "evt-can-1", "subscription.canceled",
        id="sub_p1", customer_id="cus_1",
        custom_data={"user_id": "user-1", "plan_id": "pro", "interval": "monthly"})
    r = client.post("/webhooks/paddle", content=body,
                    headers={"Paddle-Signature": paddle_sign(body),
                             "Content-Type": "application/json"})
    assert r.status_code == 200, r.text
    assert ("pro", "past_due", True) in subscription_status() or \
        ("pro", "active", True) in subscription_status()
    assert user_plan() == "pro"  # stays on plan until period end


def test_paddle_duplicate_event_ignored(client):
    body = paddle_payload(
        "evt-act-1", "subscription.activated",
        id="sub_p1", customer_id="cus_1",
        custom_data={"user_id": "user-1", "plan_id": "pro", "interval": "monthly"})
    r = client.post("/webhooks/paddle", content=body,
                    headers={"Paddle-Signature": paddle_sign(body),
                             "Content-Type": "application/json"})
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "duplicate"


def test_paddle_bad_signature_rejected(client):
    body = paddle_payload("evt-bad-1", "subscription.activated",
                          id="sub_x", customer_id="cus_x")
    r = client.post("/webhooks/paddle", content=body,
                    headers={"Paddle-Signature": "ts=1;h1=deadbeef",
                             "Content-Type": "application/json"})
    assert r.status_code == 401, r.text
    assert r.json()["error"]["code"] == "invalid_signature"


def test_paddle_old_timestamp_rejected(client):
    body = paddle_payload("evt-old-1", "subscription.activated",
                          id="sub_x", customer_id="cus_x")
    old_ts = int(time.time()) - 3600  # 1 hour old, tolerance is 5 minutes
    r = client.post("/webhooks/paddle", content=body,
                    headers={"Paddle-Signature": paddle_sign(body, ts=old_ts),
                             "Content-Type": "application/json"})
    assert r.status_code == 401, r.text


def test_paddle_plan_resolved_from_price_id(client):
    # No custom_data at all: plan comes from plan_prices via the price id.
    body = paddle_payload(
        "evt-price-1", "subscription.activated",
        id="sub_p2", customer_id="cus_1", customer_email="buyer@example.com",
        status="active",
        current_billing_period={"ends_at": "2026-12-24T00:00:00Z"},
        items=[{"price": {"id": "pri_pro_m"}}])
    r = client.post("/webhooks/paddle", content=body,
                    headers={"Paddle-Signature": paddle_sign(body),
                             "Content-Type": "application/json"})
    assert r.status_code == 200, r.text
    assert r.json()["applied"] == "applied"


# ------------------------------------------------------------ Lemon Squeezy
def test_ls_activate(client):
    body = ls_payload("subscription_created", "ls_sub_1",
                      user_email="buyer@example.com", customer_id=7,
                      ends_at="2026-12-24T00:00:00Z",
                      first_subscription_item={"variant_id": "var_basic_m"})
    r = client.post("/webhooks/lemonsqueezy", content=body,
                    headers={"X-Signature": ls_sign(body),
                             "Content-Type": "application/json"})
    assert r.status_code == 200, r.text
    assert r.json()["applied"] == "applied"
    assert user_plan() == "basic"


def test_ls_renew_and_failed_and_cancel_and_expire(client):
    # renew
    body = ls_payload("subscription_payment_success", "ls_sub_1",
                      user_email="buyer@example.com")
    r = client.post("/webhooks/lemonsqueezy", content=body,
                    headers={"X-Signature": ls_sign(body),
                             "Content-Type": "application/json"})
    assert r.status_code == 200, r.text
    assert r.json()["applied"] == "applied"
    # failed payment -> past_due
    body = ls_payload("subscription_payment_failed", "ls_sub_1",
                      user_email="buyer@example.com")
    r = client.post("/webhooks/lemonsqueezy", content=body,
                    headers={"X-Signature": ls_sign(body),
                             "Content-Type": "application/json"})
    assert r.status_code == 200, r.text
    assert r.json()["applied"] == "applied"
    assert ("basic", "past_due", False) in subscription_status()
    # cancelled -> stays until period end
    body = ls_payload("subscription_cancelled", "ls_sub_1",
                      user_email="buyer@example.com")
    r = client.post("/webhooks/lemonsqueezy", content=body,
                    headers={"X-Signature": ls_sign(body),
                             "Content-Type": "application/json"})
    assert r.status_code == 200, r.text
    assert r.json()["applied"] == "applied"
    # expired -> downgraded to free
    body = ls_payload("subscription_expired", "ls_sub_1",
                      user_email="buyer@example.com")
    r = client.post("/webhooks/lemonsqueezy", content=body,
                    headers={"X-Signature": ls_sign(body),
                             "Content-Type": "application/json"})
    assert r.status_code == 200, r.text
    assert r.json()["applied"] == "applied"
    assert user_plan() == "free"


def test_ls_duplicate_event_ignored(client):
    body = ls_payload("subscription_created", "ls_sub_1",
                      user_email="buyer@example.com")
    r = client.post("/webhooks/lemonsqueezy", content=body,
                    headers={"X-Signature": ls_sign(body),
                             "Content-Type": "application/json"})
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "duplicate"


def test_ls_bad_signature_rejected(client):
    body = ls_payload("subscription_created", "ls_sub_9",
                      user_email="buyer@example.com")
    r = client.post("/webhooks/lemonsqueezy", content=body,
                    headers={"X-Signature": "0" * 64,
                             "Content-Type": "application/json"})
    assert r.status_code == 401, r.text
    assert r.json()["error"]["code"] == "invalid_signature"


def test_unknown_provider_webhook_404(client):
    body = b"{}"
    r = client.post("/webhooks/nope", content=body,
                    headers={"Content-Type": "application/json"})
    assert r.status_code == 404, r.text
    assert "error" in r.json()
