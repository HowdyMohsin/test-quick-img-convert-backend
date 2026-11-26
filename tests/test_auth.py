"""Auth tests (v5 section 8): register/login/logout, CSRF, throttling,
banned users, password rules, forgot/reset, verify/resend, change
password/email, sessions, Google-off, export, delete.

Each test gets a fresh SQLite file + seeded app. No production code
branches on a test environment; the tests only drive the public API
(plus direct DB rows for tokens the API never reveals in cleartext).
"""

from __future__ import annotations

import asyncio
import os
import tempfile

import pytest
from fastapi.testclient import TestClient

VALID_PASSWORD = "correct horse battery staple"


# ---------------------------------------------------------------- harness

@pytest.fixture()
def env_client():
    tmp = tempfile.TemporaryDirectory()
    db_path = os.path.join(tmp.name, "test.db")
    data_dir = os.path.join(tmp.name, "data")
    os.environ["DATABASE_URL"] = f"sqlite+aiosqlite:///{db_path}"
    os.environ["SECRET_KEY"] = "test-secret-key-0123456789abcdef-test"
    os.environ["APP_SECRET"] = "test-app-secret-0123456789abcdef-test"
    os.environ["SITE_URL"] = "http://localhost:3000"
    os.environ["SMTP_HOST"] = ""
    os.environ["GOOGLE_CLIENT_ID"] = ""
    os.environ["DATA_DIR"] = data_dir
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


def csrf(client: TestClient) -> str:
    r = client.get("/v1/auth/csrf")
    assert r.status_code == 200, r.text
    return r.json()["csrf_token"]


def post(client: TestClient, url: str, payload: dict | None = None):
    return client.post(url, json=payload or {},
                       headers={"X-CSRF-Token": csrf(client)})


def register(client: TestClient, email="alice@example.com",
             password=VALID_PASSWORD, name="Alice"):
    return post(client, "/v1/auth/register", {
        "name": name, "email": email, "password": password,
        "terms_accepted": True,
    })


def login(client: TestClient, email="alice@example.com", password=VALID_PASSWORD):
    return post(client, "/v1/auth/login", {"email": email, "password": password})


def db_write(db_path: str, fn) -> None:
    """Run fn(sync_session) against the test DB file and commit."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session as SyncSession

    engine = create_engine(f"sqlite:///{db_path}")
    with SyncSession(engine) as session:
        fn(session)
        session.commit()
    engine.dispose()


def insert_email_token(db_path: str, user_id: str, kind: str, token: str,
                       new_email: str | None = None) -> None:
    from datetime import datetime, timedelta, timezone

    from app.models import EmailToken
    from app.passwords import hash_token

    def _fn(s):
        s.add(EmailToken(
            user_id=user_id, kind=kind, token_hash=hash_token(token),
            new_email=new_email,
            expires_at=datetime.now(timezone.utc) + timedelta(hours=2),
        ))

    db_write(db_path, _fn)


# ---------------------------------------------------------------- register / login

def test_register_login_me_logout(env_client):
    c = env_client
    r = register(c)
    assert r.status_code == 200, r.text
    assert r.json()["user"]["plan"] == "free"
    assert r.json()["email_verified"] is False
    assert "qic_session" in r.cookies

    me = c.get("/v1/me")
    assert me.status_code == 200, me.text
    assert me.json()["user"]["email"] == "alice@example.com"
    assert me.json()["usage"]["limit"] == 25
    assert me.json()["usage"]["used"] == 0

    out = post(c, "/v1/auth/logout")
    assert out.status_code == 200
    assert c.get("/v1/me").status_code == 401


def test_register_duplicate_email(env_client):
    c = env_client
    assert register(c).status_code == 200
    r = register(c)
    assert r.status_code == 409
    assert r.json()["error"]["code"] == "email_taken"


def test_register_requires_terms(env_client):
    c = env_client
    r = post(c, "/v1/auth/register", {
        "name": "Alice", "email": "alice@example.com",
        "password": VALID_PASSWORD, "terms_accepted": False,
    })
    assert r.status_code == 400
    assert r.json()["error"]["code"] == "terms_required"


def test_register_rejects_short_common_and_too_long_passwords(env_client):
    c = env_client
    for bad in ["short1234", "password123", "1234567890", "x" * 129]:
        r = register(c, email=f"u{len(bad)}-{bad[:4]}@example.com", password=bad)
        assert r.status_code == 400, (bad, r.text)
        assert r.json()["error"]["code"] == "weak_password"


def test_password_length_boundaries(env_client):
    c = env_client
    assert register(c, email="ten@example.com", password="Zx9!qwerty").status_code == 200
    assert register(c, email="max@example.com", password="A" * 128).status_code == 200


def test_login_wrong_password_is_generic(env_client):
    c = env_client
    assert register(c).status_code == 200
    # Fresh client (no session) attempting login with a wrong password.
    from app.main import create_app

    fresh = TestClient(create_app())
    r = post(fresh, "/v1/auth/login", {"email": "alice@example.com", "password": "wrong password here"})
    assert r.status_code == 401
    assert r.json()["error"]["message"] == "Email or password is incorrect."
    r2 = post(fresh, "/v1/auth/login", {"email": "nobody@example.com", "password": "wrong password here"})
    assert r2.status_code == 401
    assert r2.json()["error"]["message"] == "Email or password is incorrect."


def test_csrf_required_on_mutations(env_client):
    c = env_client
    r = c.post("/v1/auth/register", json={
        "name": "Alice", "email": "alice@example.com",
        "password": VALID_PASSWORD, "terms_accepted": True,
    })
    assert r.status_code == 403
    assert r.json()["error"]["code"] == "csrf_required"


def test_login_lockout_after_repeated_failures(env_client):
    c = env_client
    assert register(c).status_code == 200
    from app.main import create_app

    fresh = TestClient(create_app())
    for _ in range(5):
        r = post(fresh, "/v1/auth/login", {"email": "alice@example.com", "password": "wrong password here"})
        assert r.status_code == 401
    r = post(fresh, "/v1/auth/login", {"email": "alice@example.com", "password": "wrong password here"})
    assert r.status_code == 429, r.text
    assert r.json()["error"]["code"] == "login_locked"


def test_banned_user_blocked_on_login_and_api(env_client):
    c = env_client
    assert register(c).status_code == 200

    def _ban(s):
        from app.models import User

        user = s.query(User).filter_by(email="alice@example.com").one()
        user.banned = True
        user.ban_reason = "Abuse of the service."

    db_write(c.db_path, _ban)
    from app.main import create_app

    fresh = TestClient(create_app())
    r = post(fresh, "/v1/auth/login", {"email": "alice@example.com", "password": VALID_PASSWORD})
    assert r.status_code == 403
    assert r.json()["error"]["code"] == "account_banned"
    assert "Abuse of the service." in r.json()["error"]["message"]
    # A session created before the ban is also blocked on every call.
    assert c.get("/v1/me").status_code == 403


# ---------------------------------------------------------------- forgot / reset / verify

def test_forgot_password_always_same_message(env_client):
    c = env_client
    r = post(c, "/v1/auth/forgot-password", {"email": "ghost@example.com"})
    assert r.status_code == 200
    assert r.json()["message"] == "If that email exists, we sent a reset link."


def test_reset_password_flow(env_client):
    c = env_client
    assert register(c).status_code == 200
    user_id = c.get("/v1/me").json()["user"]["id"]
    insert_email_token(c.db_path, user_id, "reset", "reset-token-123")
    r = post(c, "/v1/auth/reset-password",
             {"token": "reset-token-123", "password": "brand new password here"})
    assert r.status_code == 200, r.text
    # Token is single-use.
    r2 = post(c, "/v1/auth/reset-password",
              {"token": "reset-token-123", "password": "another new password"})
    assert r2.status_code == 400
    # Old session was revoked by the reset; new password works.
    from app.main import create_app

    fresh = TestClient(create_app())
    assert post(fresh, "/v1/auth/login",
                {"email": "alice@example.com", "password": "brand new password here"}).status_code == 200
    assert c.get("/v1/me").status_code == 401


def test_verify_email_flow(env_client):
    c = env_client
    assert register(c).status_code == 200
    user_id = c.get("/v1/me").json()["user"]["id"]
    insert_email_token(c.db_path, user_id, "verify", "verify-token-123")
    r = post(c, "/v1/auth/verify-email", {"token": "verify-token-123"})
    assert r.status_code == 200, r.text
    assert c.get("/v1/me").json()["user"]["email_verified"] is True


def test_resend_verification_cooldown(env_client):
    c = env_client
    assert register(c).status_code == 200
    # Register already sent a verification email, so an immediate
    # resend is inside the 60-second cooldown.
    r = post(c, "/v1/auth/resend-verification")
    assert r.status_code == 429
    assert r.json()["error"]["code"] == "resend_cooldown"
    # Age the registration token past the cooldown, then resend works.
    user_id = c.get("/v1/me").json()["user"]["id"]

    def _age(s):
        from datetime import datetime, timedelta, timezone

        from app.models import EmailToken

        token = s.query(EmailToken).filter_by(user_id=user_id, kind="verify").one()
        token.created_at = datetime.now(timezone.utc) - timedelta(seconds=61)

    db_write(c.db_path, _age)
    r2 = post(c, "/v1/auth/resend-verification")
    assert r2.status_code == 200, r2.text


def test_change_password_revokes_other_sessions(env_client):
    c = env_client
    assert register(c).status_code == 200
    from app.main import create_app

    other = TestClient(create_app())
    assert post(other, "/v1/auth/login",
                {"email": "alice@example.com", "password": VALID_PASSWORD}).status_code == 200
    r = post(c, "/v1/auth/change-password", {
        "current_password": VALID_PASSWORD, "new_password": "a totally different password"})
    assert r.status_code == 200, r.text
    assert c.get("/v1/me").status_code == 200  # current session survives
    assert other.get("/v1/me").status_code == 401  # other session revoked


def test_change_email_swaps_only_after_click(env_client):
    c = env_client
    assert register(c).status_code == 200
    user_id = c.get("/v1/me").json()["user"]["id"]
    r = post(c, "/v1/auth/change-email",
             {"password": VALID_PASSWORD, "new_email": "alice.new@example.com"})
    assert r.status_code == 200, r.text
    assert c.get("/v1/me").json()["user"]["email"] == "alice@example.com"
    # The token was created by the endpoint; find its cleartext via a
    # fresh token inserted the same way the endpoint does.
    insert_email_token(c.db_path, user_id, "change_email", "change-token-1",
                       new_email="alice.new@example.com")
    r2 = post(c, "/v1/auth/verify-email", {"token": "change-token-1"})
    assert r2.status_code == 200, r2.text
    assert c.get("/v1/me").json()["user"]["email"] == "alice.new@example.com"


def test_sessions_list_and_revoke(env_client):
    c = env_client
    assert register(c).status_code == 200
    r = c.get("/v1/auth/sessions")
    assert r.status_code == 200, r.text
    sessions = r.json()["sessions"]
    assert len(sessions) == 1
    assert sessions[0]["current"] is True
    assert "***" in sessions[0]["ip"] or sessions[0]["ip"] == "—"

    from app.main import create_app

    other = TestClient(create_app())
    assert post(other, "/v1/auth/login",
                {"email": "alice@example.com", "password": VALID_PASSWORD}).status_code == 200
    assert len(c.get("/v1/auth/sessions").json()["sessions"]) == 2
    other_id = [s for s in c.get("/v1/auth/sessions").json()["sessions"]
                if not s["current"]][0]["id"]
    revoke = c.delete(f"/v1/auth/sessions/{other_id}",
                      headers={"X-CSRF-Token": csrf(c)})
    assert revoke.status_code == 200
    assert other.get("/v1/me").status_code == 401


def test_google_signin_not_configured(env_client):
    c = env_client
    r = post(c, "/v1/auth/google", {"id_token": "fake"})
    assert r.status_code == 503
    assert r.json()["error"]["code"] == "google_not_configured"


# ---------------------------------------------------------------- export / delete

def test_export_download(env_client):
    c = env_client
    assert register(c).status_code == 200
    r = c.get("/v1/me/export")
    assert r.status_code == 200
    assert "attachment" in r.headers["content-disposition"]
    payload = r.json()
    assert payload["profile"]["email"] == "alice@example.com"
    assert "conversion_history" in payload and "payments" in payload


def test_delete_account(env_client):
    c = env_client
    assert register(c).status_code == 200
    r = post(c, "/v1/me/delete", {"password": VALID_PASSWORD, "confirmation": "delete"})
    assert r.status_code == 400  # must type DELETE exactly
    r = post(c, "/v1/me/delete", {"password": VALID_PASSWORD, "confirmation": "DELETE"})
    assert r.status_code == 200, r.text
    assert c.get("/v1/me").status_code == 401
    from app.main import create_app

    fresh = TestClient(create_app())
    r = post(fresh, "/v1/auth/login", {"email": "alice@example.com", "password": VALID_PASSWORD})
    assert r.status_code == 401  # anonymized email no longer matches
