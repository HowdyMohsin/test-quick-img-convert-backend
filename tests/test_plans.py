"""Plans & coupons tests (v5 sections 4.1-4.4): seeded limits, coupon
validation, PKR rounding, admin plan/coupon CRUD, archive
grandfathering, ordering warning.
"""

from __future__ import annotations

import asyncio
import os
import tempfile
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient


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


def _db_write(db_path: str, fn) -> None:
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session as SyncSession

    engine = create_engine(f"sqlite:///{db_path}")
    with SyncSession(engine) as session:
        fn(session)
        session.commit()
    engine.dispose()


def _run(coro):
    return asyncio.run(coro)


# ---------------------------------------------------------------- seeded plans

def test_seeded_plan_limits(env_client):
    c = env_client
    site = c.get("/v1/site")
    assert site.status_code == 200, site.text
    plans = {p["id"]: p for p in site.json()["plans"]}
    assert plans["anonymous"]["limits"]["daily"] == 5
    assert plans["free"]["price_cents"] == 0
    assert plans["free"]["limits"] == {
        "daily": 25, "batch": 10, "img_mb": 200, "aud_mb": 100,
        "vid_mb": 500, "vid_min": 30, "parallel": 2, "priority": False, "ads": True,
        "editor": False,
    }
    assert plans["anonymous"]["limits"]["editor"] is False
    assert plans["basic"]["limits"]["editor"] is True
    assert plans["pro"]["limits"]["editor"] is True
    assert plans["basic"]["price_cents"] == 400
    assert plans["basic"]["price_yearly_cents"] == 4000
    assert plans["basic"]["limits"]["daily"] == 100
    assert plans["basic"]["limits"]["img_mb"] == 500
    assert plans["basic"]["limits"]["ads"] is False
    assert plans["pro"]["price_cents"] == 900
    assert plans["pro"]["price_yearly_cents"] == 9000
    assert plans["pro"]["limits"]["daily"] == 2000
    assert plans["pro"]["limits"]["vid_mb"] == 4096
    assert plans["pro"]["limits"]["priority"] is True
    # Providers ship disabled: no provider labels are exposed.
    assert site.json()["providers"] == []


def test_seed_is_idempotent(env_client):
    c = env_client

    async def _t():
        from app import deps

        deps.reset_engine()
        db = deps.get_sessionmaker()()
        try:
            from app.seed import seed

            counts = await seed(db)
            assert sum(counts.values()) == 0, counts
        finally:
            await db.close()

    _run(_t())


# ---------------------------------------------------------------- PKR + coupons

def test_pkr_rounding():
    from app.routers_admin_plans import pkr_display

    assert pkr_display(400, 280) == 1120   # $4.00 x 280 = 1120 exactly
    assert pkr_display(900, 280) == 2520   # $9.00 x 280 = 2520 exactly
    assert pkr_display(401, 280) == 1130   # $4.01 x 280 = 1122.80 -> 1130
    assert pkr_display(100, 280) == 280    # $1.00 x 280 = 280
    assert pkr_display(101, 280) == 290    # $1.01 x 280 = 282.80 -> 290
    assert pkr_display(400, 277.5) == 1110  # $4 x 277.5 = 1110


def test_coupon_validate_and_discount(env_client):
    c = env_client

    def _add_coupon(s):
        from app.models import Coupon

        s.add(Coupon(code="WELCOME10", type="percent", value=10,
                     plans=["basic", "pro"], intervals=["monthly", "yearly"],
                     recurring=False, max_uses=100, used=0, per_user_limit=1,
                     expires_at=datetime.now(timezone.utc) + timedelta(days=30),
                     active=True))
        s.add(Coupon(code="FLAT5", type="fixed", value=500,
                     plans=None, intervals=None, recurring=False,
                     max_uses=None, used=0, per_user_limit=1, active=True))

    _db_write(c.db_path, _add_coupon)

    from app import deps
    from app.routers_admin_plans import apply_coupon, validate_coupon

    async def _t():
        deps.reset_engine()
        db = deps.get_sessionmaker()()
        try:
            info = await validate_coupon(db, "welcome10", "basic", "monthly")
            assert info["type"] == "percent" and info["value"] == 10
            assert apply_coupon(400, info["coupon"]) == 360  # $4.00 -> $3.60
            flat = await validate_coupon(db, "FLAT5", "pro", "yearly")
            assert apply_coupon(900, flat["coupon"]) == 400
            assert apply_coupon(300, flat["coupon"]) == 0  # never negative
            with pytest.raises(Exception) as exc:
                await validate_coupon(db, "WELCOME10", "free", "monthly")
            assert "coupon_plan_mismatch" in str(exc.value.detail)
            with pytest.raises(Exception) as exc:
                await validate_coupon(db, "NOPE", "basic", "monthly")
            assert "coupon_not_found" in str(exc.value.detail)
        finally:
            await db.close()

    _run(_t())


def test_coupon_expired_and_max_uses(env_client):
    c = env_client

    def _add(s):
        from app.models import Coupon

        s.add(Coupon(code="OLD", type="percent", value=50, active=True,
                     expires_at=datetime.now(timezone.utc) - timedelta(days=1)))
        s.add(Coupon(code="USEDUP", type="percent", value=50, active=True,
                     max_uses=1, used=1))

    _db_write(c.db_path, _add)

    from app import deps
    from app.routers_admin_plans import validate_coupon

    async def _t():
        deps.reset_engine()
        db = deps.get_sessionmaker()()
        try:
            with pytest.raises(Exception) as exc:
                await validate_coupon(db, "OLD", "basic", "monthly")
            assert "coupon_expired" in str(exc.value.detail)
            with pytest.raises(Exception) as exc:
                await validate_coupon(db, "USEDUP", "basic", "monthly")
            assert "coupon_exhausted" in str(exc.value.detail)
        finally:
            await db.close()

    _run(_t())


# ---------------------------------------------------------------- admin CRUD

def _make_admin_client(c: TestClient):
    """Create an admin + session in the DB; return (client, headers)."""
    from app.admin_auth import make_csrf_token
    from app.deps import hash_session_token
    from app.passwords import hash_password, random_token

    token = random_token()
    admin_holder: dict = {}

    def _add(s):
        from app.models import AdminSession, AdminUser

        admin = AdminUser(email="admin@example.com",
                          password_hash=hash_password("admin password here"),
                          role="super_admin", permissions={"*": "write"},
                          active=True, must_change_password=False)
        s.add(admin)
        s.flush()
        admin_holder["id"] = admin.id
        s.add(AdminSession(
            admin_id=admin.id, token_hash=hash_session_token(token),
            expires_at=datetime.now(timezone.utc) + timedelta(days=7)))

    _db_write(c.db_path, _add)
    c.cookies.set("qic_admin", token)
    headers = {"X-CSRF-Token": make_csrf_token(hash_session_token(token))}
    return headers


def test_admin_plans_crud_and_order_warning(env_client):
    c = env_client
    headers = _make_admin_client(c)

    r = c.get("/admin/plans", headers=headers)
    assert r.status_code == 200, r.text
    assert [p["id"] for p in r.json()["plans"]] == ["free", "basic", "pro"]

    # Unauthenticated admin access is rejected.
    from app.main import create_app

    fresh = TestClient(create_app())
    assert fresh.get("/admin/plans").status_code == 401

    # Break the ordering: basic daily below free daily -> warning.
    r = c.patch("/admin/plans/basic",
                json={"limits": {"daily": 10, "batch": 30, "img_mb": 500, "aud_mb": 250,
                                 "vid_mb": 1024, "vid_min": 60, "parallel": 3,
                                 "priority": False, "ads": False}},
                headers=headers)
    assert r.status_code == 200, r.text
    assert r.json()["warning"] is not None
    assert "daily" in r.json()["warning"]

    # Restore a valid ordering -> no warning.
    r = c.patch("/admin/plans/basic",
                json={"limits": {"daily": 100, "batch": 30, "img_mb": 500, "aud_mb": 250,
                                 "vid_mb": 1024, "vid_min": 60, "parallel": 3,
                                 "priority": False, "ads": False}},
                headers=headers)
    assert r.json()["warning"] is None

    # Archive keeps the plan row but hides it from /v1/site.
    r = c.post("/admin/plans/basic/archive", headers=headers)
    assert r.status_code == 200, r.text
    assert r.json()["plan"]["archived"] is True
    assert "basic" not in {p["id"] for p in c.get("/v1/site").json()["plans"]}


def test_admin_coupons_crud(env_client):
    c = env_client
    headers = _make_admin_client(c)

    r = c.post("/admin/coupons", json={
        "code": "save20", "type": "percent", "value": 20,
        "plans": ["pro"], "intervals": ["monthly"], "max_uses": 50,
    }, headers=headers)
    assert r.status_code == 200, r.text
    assert r.json()["coupon"]["code"] == "SAVE20"

    r = c.post("/admin/coupons", json={
        "code": "SAVE20", "type": "percent", "value": 20,
    }, headers=headers)
    assert r.status_code == 409

    r = c.post("/admin/coupons", json={
        "code": "BADPCT", "type": "percent", "value": 150,
    }, headers=headers)
    assert r.status_code == 400

    r = c.get("/admin/coupons", headers=headers)
    assert r.status_code == 200
    assert any(cc["code"] == "SAVE20" for cc in r.json()["coupons"])

    r = c.post("/admin/coupons/SAVE20/deactivate", headers=headers)
    assert r.status_code == 200
    assert r.json()["coupon"]["active"] is False
