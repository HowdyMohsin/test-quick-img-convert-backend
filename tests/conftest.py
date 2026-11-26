"""Shared fixtures for the admin-backend tests.

Builds a throwaway SQLite database per test, creates the fallback tables
from ``app.admin_auth.Base`` and ``app.routers_admin.Base``, seeds one
super admin, one staff admin, one must-change admin, one user and a small
set of jobs / events / payment requests, and returns a TestClient whose
``get_db`` dependency points at the throwaway database.

Nothing here touches PostgreSQL, Docker, SMTP or the network.
"""

import asyncio
import os
import sys
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# Test-only secrets (never production values). Must be set before the app
# modules are imported: app.security binds APP_SECRET at import time and
# the admin CSRF/reset HMACs derive from SECRET_KEY.
os.environ.setdefault("APP_SECRET", "test-only-admin-secret")
os.environ.setdefault("SECRET_KEY", "test-only-secret-key")

import app.admin_auth as admin_auth  # noqa: E402
import app.routers_admin as routers_admin  # noqa: E402
from app.admin_auth import (  # noqa: E402
    AdminSession,
    AdminUser,
    hash_password,
    install_admin_error_handlers,
    reset_admin_login_attempts,
)
from app.routers_admin import (  # noqa: E402
    Event,
    Job,
    PairHealth,
    PaymentRequest,
    Plan,
    Subscription,
    User,
    UserSession,
)

DB_PATH = "/tmp/qic-admin-tests.db"

SUPER_EMAIL = "admin@qic.local"
SUPER_PASSWORD = "SuperAdminPass123"
STAFF_EMAIL = "staff@qic.local"
STAFF_PASSWORD = "StaffAdminPass123"
FORCED_EMAIL = "forced@qic.local"
FORCED_PASSWORD = "ForcedAdminPass123"
USER_EMAIL = "user@example.com"


def _utcnow():
    return datetime.now(timezone.utc)


async def _seed(session):
    session.add_all(
        [
            AdminUser(
                email=SUPER_EMAIL,
                password_hash=hash_password(SUPER_PASSWORD),
                role="super_admin",
                permissions={},
                active=True,
                must_change_password=False,
            ),
            AdminUser(
                email=STAFF_EMAIL,
                password_hash=hash_password(STAFF_PASSWORD),
                role="staff",
                permissions={"dashboard": ["read"]},
                active=True,
                must_change_password=False,
            ),
            AdminUser(
                email=FORCED_EMAIL,
                password_hash=hash_password(FORCED_PASSWORD),
                role="staff",
                permissions={"dashboard": ["read"], "users": ["read", "write"]},
                active=True,
                must_change_password=True,
            ),
            Plan(id="free", name="Free", price_cents=0, price_yearly_cents=0,
                 limits={"daily": 25, "batch": 10}),
            Plan(id="basic", name="Basic", price_cents=400, price_yearly_cents=4000,
                 limits={"daily": 100, "batch": 30}),
            Plan(id="pro", name="Pro", price_cents=900, price_yearly_cents=9000,
                 limits={"daily": 2000, "batch": 100}),
        ]
    )
    await session.flush()
    user = User(
        email=USER_EMAIL,
        display_name="Test User",
        plan="free",
        banned=False,
        email_verified_at=_utcnow(),
    )
    session.add(user)
    await session.flush()
    session.add_all(
        [
            UserSession(
                user_id=user.id,
                token_hash="a" * 64,
                csrf_secret="test-csrf-secret",
                expires_at=_utcnow() + timedelta(days=30),
            ),
            Subscription(
                user_id=user.id,
                plan_id="basic",
                provider_key="manual",
                interval="monthly",
                status="active",
                current_period_end=_utcnow() + timedelta(days=30),
            ),
            PaymentRequest(
                user_id=user.id,
                plan_id="basic",
                interval="monthly",
                provider_key="jazzcash",
                amount_cents=400,
                currency="USD",
                display_amount="PKR 1120",
                reference="JC-1001",
                status="pending",
            ),
            PaymentRequest(
                user_id=user.id,
                plan_id="pro",
                interval="monthly",
                provider_key="easypaisa",
                amount_cents=900,
                currency="USD",
                display_amount="PKR 2520",
                reference="EP-1002",
                status="approved",
                receipt_no="QIC-2026-000001",
            ),
        ]
    )
    now = _utcnow()
    jobs = []
    for i in range(5):
        jobs.append(
            Job(
                user_id=user.id,
                owner_key=user.id,
                pair_slug="jpg-to-png",
                from_slug="jpg",
                to_slug="png",
                category="image",
                status="done",
                in_size=1000 + i,
                out_size=800 + i,
                created_at=now - timedelta(minutes=i),
            )
        )
    jobs.append(
        Job(
            user_id=user.id,
            owner_key=user.id,
            pair_slug="mp3-to-wav",
            from_slug="mp3",
            to_slug="wav",
            category="audio",
            status="failed",
            error_code="engine_missing",
            error_message="ffmpeg not available",
            created_at=now - timedelta(minutes=10),
        )
    )
    jobs.append(
        Job(
            user_id=user.id,
            owner_key=user.id,
            pair_slug="jpg-to-png",
            from_slug="jpg",
            to_slug="png",
            category="image",
            status="done",
            created_at=now - timedelta(days=1, minutes=5),
        )
    )
    session.add_all(jobs)
    session.add_all(
        [
            # Core models use BigInteger PKs for events; SQLite only
            # auto-generates ids for INTEGER PRIMARY KEY, so seed rows
            # carry explicit ids (Postgres sequences handle this natively).
            Event(id=1, owner_type="anonymous", plan="anonymous", pair_slug="jpg-to-png",
                  category="image", status="done", bytes_in=1000, bytes_out=800),
            Event(id=2, owner_type="anonymous", plan="anonymous", pair_slug="jpg-to-png",
                  category="image", status="done", bytes_in=2000, bytes_out=1500),
            Event(id=3, owner_type="user", plan="free", pair_slug="mp3-to-wav",
                  category="audio", status="failed", bytes_in=5000, bytes_out=0),
            PairHealth(pair_slug="heic-to-jpg", status="disabled",
                       last_error="libheif missing"),
            PairHealth(pair_slug="jpg-to-png", status="healthy"),
        ]
    )
    await session.commit()
    return user.id


@pytest.fixture()
def client():
    """Fresh app + fresh database per test (unique file, no cross-test sharing)."""
    reset_admin_login_attempts()
    db_path = f"/tmp/qic-admin-tests-{uuid.uuid4().hex}.db"
    engine = create_async_engine(f"sqlite+aiosqlite:///{db_path}", future=True)
    factory = async_sessionmaker(bind=engine, expire_on_commit=False)

    async def build():
        # Create tables from every metadata in play: the core models' Base
        # (when the core agent has landed app.models) plus the fallback
        # Bases in admin_auth / routers_admin (empty once core models exist).
        metadatas = [admin_auth.Base.metadata, routers_admin.Base.metadata]
        try:
            import app.models as _core_models

            metadatas.append(_core_models.Base.metadata)
        except Exception:
            pass
        async with engine.begin() as conn:
            for metadata in metadatas:
                await conn.run_sync(metadata.create_all)
        async with factory() as session:
            user_id = await _seed(session)
        return user_id

    user_id = asyncio.run(build())

    async def override_get_db():
        async with factory() as session:
            yield session

    app = FastAPI()
    install_admin_error_handlers(app)
    app.include_router(admin_auth.router)
    app.include_router(routers_admin.router)
    app.dependency_overrides[admin_auth.get_db] = override_get_db

    test_client = TestClient(app, raise_server_exceptions=False)
    test_client.user_id = user_id
    yield test_client
    asyncio.run(engine.dispose())
    if os.path.exists(db_path):
        os.remove(db_path)


def login_as(test_client, email, password, totp_code=None):
    body = {"email": email, "password": password}
    if totp_code:
        body["totp_code"] = totp_code
    resp = test_client.post("/admin/auth/login", json=body)
    assert resp.status_code == 200, resp.text
    return resp


def login_super(test_client):
    return login_as(test_client, SUPER_EMAIL, SUPER_PASSWORD)


def csrf_token(test_client):
    resp = test_client.get("/admin/auth/csrf")
    assert resp.status_code == 200, resp.text
    return resp.json()["csrf_token"]


def csrf_headers(test_client):
    return {"X-CSRF-Token": csrf_token(test_client)}
