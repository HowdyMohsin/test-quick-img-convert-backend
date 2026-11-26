"""Quota tests (v5 section 4.2): anonymous 5/day, free 25/day, refund
on failure, Karachi midnight reset, stricter-of-two anonymous counters.
"""

from __future__ import annotations

import asyncio
import os
import tempfile
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

import pytest
from fastapi.testclient import TestClient

VALID_PASSWORD = "correct horse battery staple"


@pytest.fixture()
def env_client():
    tmp = tempfile.TemporaryDirectory()
    db_path = os.path.join(tmp.name, "test.db")
    os.environ["DATABASE_URL"] = f"sqlite+aiosqlite:///{db_path}"
    os.environ["SECRET_KEY"] = "test-secret-key-0123456789abcdef-test"
    os.environ["APP_SECRET"] = "test-app-secret-0123456789abcdef-test"
    os.environ["SITE_URL"] = "http://localhost:3000"
    os.environ["SMTP_HOST"] = ""
    os.environ["GOOGLE_CLIENT_ID"] = ""
    os.environ["DATA_DIR"] = os.path.join(tmp.name, "data")
    os.environ["API_DOCS"] = "false"
    os.environ["QUOTA_TZ"] = "Asia/Karachi"

    from app import deps
    from app.rate_limit import reset_rate_limits

    deps.reset_settings()
    deps.reset_engine()
    reset_rate_limits()

    async def _setup():
        from app.deps import get_engine, get_sessionmaker
        from app.models import Base
        from app.seed import seed

        engine = get_engine()
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        async with get_sessionmaker()() as db:
            await seed(db)
        await engine.dispose()

    asyncio.run(_setup())
    deps.reset_engine()
    reset_rate_limits()

    from app.main import create_app

    client = TestClient(create_app())
    client.db_path = db_path  # type: ignore[attr-defined]
    client.tmp = tmp  # type: ignore[attr-defined]
    yield client
    client.close()
    tmp.cleanup()
    deps.reset_engine()
    deps.reset_settings()


def _run(coro):
    return asyncio.run(coro)


def _db_session(db_path: str):
    from app import deps

    deps.reset_engine()
    return deps.get_sessionmaker()()


def test_anonymous_quota_5_per_day(env_client):
    c = env_client
    from app.quotas import check_and_consume, get_used, quota_day

    async def _t():
        db = _db_session(c.db_path)
        try:
            keys = ["device:test-device-1", "ip:test-ip-1"]
            for _ in range(5):
                await check_and_consume(db, keys, 5)
            assert await get_used(db, keys[0], quota_day()) == 5
            with pytest.raises(Exception) as exc:
                await check_and_consume(db, keys, 5)
            assert "quota_exceeded" in str(getattr(exc.value, "detail", exc.value))
        finally:
            await db.close()

    _run(_t())


def test_free_quota_25_per_day_via_me(env_client):
    c = env_client

    def csrf():
        return c.get("/v1/auth/csrf").json()["csrf_token"]

    r = c.post("/v1/auth/register", json={
        "name": "Alice", "email": "alice@example.com",
        "password": VALID_PASSWORD, "terms_accepted": True,
    }, headers={"X-CSRF-Token": csrf()})
    assert r.status_code == 200, r.text
    me = c.get("/v1/me").json()
    assert me["usage"]["limit"] == 25
    assert me["usage"]["used"] == 0
    assert me["usage"]["remaining"] == 25

    from app.quotas import check_and_consume, get_used, quota_day, user_owner_key

    async def _t():
        db = _db_session(c.db_path)
        try:
            user_id = me["user"]["id"]
            for _ in range(25):
                await check_and_consume(db, [user_owner_key(user_id)], 25)
            assert await get_used(db, user_owner_key(user_id), quota_day()) == 25
            with pytest.raises(Exception):
                await check_and_consume(db, [user_owner_key(user_id)], 25)
        finally:
            await db.close()

    _run(_t())
    assert c.get("/v1/me").json()["usage"]["used"] == 25


def test_refund_on_failure(env_client):
    c = env_client
    from app.quotas import consume, get_used, quota_day, refund

    async def _t():
        db = _db_session(c.db_path)
        try:
            key = "user:refund-test"
            assert await consume(db, key) == 1
            assert await consume(db, key) == 2
            assert await refund(db, key) == 1  # job failed before start
            assert await refund(db, key) == 0
            assert await refund(db, key) == 0  # never below zero
            assert await get_used(db, key, quota_day()) == 0
        finally:
            await db.close()

    _run(_t())


def test_karachi_reset_time(env_client):
    from app.quotas import quota_day, resets_at

    day = quota_day("Asia/Karachi")
    assert day == datetime.now(ZoneInfo("Asia/Karachi")).date()
    reset = resets_at("Asia/Karachi")
    assert reset.tzinfo is not None
    local = reset.astimezone(ZoneInfo("Asia/Karachi"))
    assert (local.hour, local.minute, local.second) == (0, 0, 0)
    # The next reset is within 24h from now.
    assert 0 < (reset - datetime.now(timezone.utc)).total_seconds() <= 86400


def test_anonymous_stricter_counter_applies(env_client):
    c = env_client
    from app.quotas import consume, usage_for

    async def _t():
        db = _db_session(c.db_path)
        try:
            device_key = "device:shared-device"
            ip_key = "ip:shared-ip"
            for _ in range(5):
                await consume(db, device_key)
            summary = await usage_for(db, [device_key, ip_key], 5)
            assert summary["used"] == 5  # device counter is the stricter one
            assert summary["remaining"] == 0
            summary2 = await usage_for(db, [ip_key], 5)
            assert summary2["used"] == 0
        finally:
            await db.close()

    _run(_t())


def test_anonymous_device_cookie_is_signed(env_client):
    from app.quotas import get_or_create_device_id, signed_device_cookie
    from app.security import unsign_value
    from app.deps import get_settings

    class _Req:
        cookies = {}

    device_id, is_new = get_or_create_device_id(_Req())  # type: ignore[arg-type]
    assert is_new is True
    signed = signed_device_cookie(device_id)
    assert unsign_value(get_settings().secret, signed) == device_id
    assert unsign_value(get_settings().secret, signed + "tampered") is None
