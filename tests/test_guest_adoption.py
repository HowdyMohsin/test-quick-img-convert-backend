"""Regression tests for guest-upload adoption on sign-in.

A file uploaded while signed out belongs to the device key
(``device:<id>`` from the signed ``qic_device`` cookie). After sign-in
the owner key becomes ``user:<id>``, so POST /v1/convert on that upload
failed with 403 "This upload belongs to someone else." — the exact
error the live sweep saw after signing in with a guest upload staged.
Sign-in (register, login and Google sign-in) now adopts the device's
uploads and jobs to the user, so the convert goes through.
"""

import base64
import os
import sys
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

os.environ.setdefault("APP_SECRET", "test-only-admin-secret")
os.environ.setdefault("SECRET_KEY", "test-only-secret-key")
os.environ.setdefault("QIC_STARTUP_HEALTH_CHECK", "0")

from app.main import create_app  # noqa: E402

DB_PATH = "/tmp/qic-guest-adoption-tests.db"

# 1x1 transparent PNG (valid magic bytes + a real image the pipeline accepts).
PNG_1X1 = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg=="
)


@pytest.fixture(scope="module")
def client():
    from app.deps import reset_settings

    os.environ["DATABASE_URL"] = f"sqlite+aiosqlite:///{DB_PATH}"
    # SITE_URL must be http here: the code default is the https Vercel
    # URL, which makes is_https True, which marks every cookie secure —
    # and a secure cookie is never sent back over the TestClient's
    # http://testserver, so CSRF/session flows fail (same pattern as
    # test_auth.py).
    os.environ["SITE_URL"] = "http://localhost:3000"
    reset_settings()
    app = create_app()
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    os.environ.pop("DATABASE_URL", None)
    os.environ.pop("SITE_URL", None)
    reset_settings()


def _csrf(client):
    r = client.get("/v1/auth/csrf")
    assert r.status_code == 200, r.text
    return r.json()["csrf_token"]


def _guest_upload(client):
    # No session: the response sets the signed qic_device cookie, and
    # the upload belongs to the device key. TestClient keeps the cookie.
    r = client.post("/v1/uploads", files={"file": ("red.png", PNG_1X1)})
    assert r.status_code == 201, r.text
    upload_id = r.json().get("id") or r.json().get("upload_id")
    assert upload_id, r.text
    return upload_id


def _convert(client, upload_id, token):
    return client.post(
        "/v1/convert",
        json={"upload_id": upload_id, "to": "webp", "settings": {}},
        headers={"X-CSRF-Token": token},
    )


def _register(client, email, token):
    r = client.post(
        "/v1/auth/register",
        json={
            "name": "Adopt Test",
            "email": email,
            "password": "correct-horse-battery-1",
            "terms_accepted": True,
            "remember_me": False,
        },
        headers={"X-CSRF-Token": token},
    )
    assert r.status_code == 200, r.text
    return r


def _seed_device_job(upload_id, hours=0):
    # Insert a device-owned job row for the guest upload, as it would
    # exist from before the suspense lock (anonymous convert is 403
    # now, so the API cannot create one anymore — the live stray job
    # predates the lock). Returns the job id.
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session as SyncSession

    from app.models import Job, Upload

    engine = create_engine(f"sqlite:///{DB_PATH}")
    with SyncSession(engine) as session:
        up = session.get(Upload, upload_id)
        assert up is not None, f"upload {upload_id} missing"
        job = Job(
            owner_key=up.owner_key, user_id=None, upload_id=upload_id,
            pair_slug="png-to-jpg", from_slug="png", to_slug="jpg",
            category="Images", route="local", settings={},
            plan="anonymous", status="queued",
            created_at=datetime.now(timezone.utc) - timedelta(hours=hours),
        )
        session.add(job)
        session.flush()
        job_id = job.id
        session.commit()
    engine.dispose()
    return job_id


def _history(client):
    r = client.get("/v1/history")
    assert r.status_code == 200, r.text
    return r


def _assert_no_store(r):
    assert r.headers.get("cache-control") == "no-store, private", r.headers
    assert "Cookie" in (r.headers.get("vary") or ""), r.headers


def test_guest_upload_converts_after_register(client):
    # Before the fix this returned 403 "This upload belongs to someone
    # else." — the upload stayed on the device key while the convert
    # resolved the owner as the new user key.
    upload_id = _guest_upload(client)
    token = _csrf(client)
    r = client.post(
        "/v1/auth/register",
        json={
            "name": "Adopt Test",
            "email": "adopt-test-20261126@example.com",
            "password": "correct-horse-battery-1",
            "terms_accepted": True,
            "remember_me": False,
        },
        headers={"X-CSRF-Token": token},
    )
    assert r.status_code == 200, r.text

    r = _convert(client, upload_id, token)
    assert r.status_code == 202, r.text
    assert r.json().get("id") or r.json().get("job_id"), r.text


def test_guest_upload_converts_after_login(client):
    # Same flow, but the account already exists: sign out (fresh device),
    # upload as guest, sign in, convert.
    client.cookies.clear()
    upload_id = _guest_upload(client)
    token = _csrf(client)
    r = client.post(
        "/v1/auth/login",
        json={
            "email": "adopt-test-20261126@example.com",
            "password": "correct-horse-battery-1",
            "remember_me": False,
        },
        headers={"X-CSRF-Token": token},
    )
    assert r.status_code == 200, r.text

    r = _convert(client, upload_id, token)
    assert r.status_code == 202, r.text
    assert r.json().get("id") or r.json().get("job_id"), r.text


def test_stale_device_job_not_adopted_on_register(client):
    # The stray-history bug, reproduced exactly: a device-owned job
    # from an earlier anonymous session (here: created 2 hours ago)
    # was adopted wholesale at register and sat in the fresh account's
    # "Last 5 conversions" forever. The fix bounds adoption to rows
    # created within 60 minutes, and a job moves only with its upload.
    client.cookies.clear()
    upload_id = _guest_upload(client)
    token = _csrf(client)
    _seed_device_job(upload_id, hours=2)

    _register(client, "stale-adopt-20261126@example.com", token)

    # The fresh upload itself WAS adopted (it is minutes old), so it
    # still opens for the new user — only the stale job stays behind.
    r = client.get(f"/v1/uploads/{upload_id}/file")
    assert r.status_code == 200, r.text
    # ...but the stale job must not appear in the new account's history.
    r = _history(client)
    _assert_no_store(r)
    assert r.json()["total"] == 0, r.text
    assert r.json()["jobs"] == []


def test_fresh_device_job_adopted_on_register(client):
    # The bound must not break the real case: a guest upload converted
    # minutes ago (both rows fresh) still moves to the new account.
    client.cookies.clear()
    upload_id = _guest_upload(client)
    token = _csrf(client)
    job_id = _seed_device_job(upload_id, hours=0)

    _register(client, "fresh-adopt-20261126@example.com", token)

    r = _history(client)
    _assert_no_store(r)
    assert r.json()["total"] == 1, r.text
    assert r.json()["jobs"][0]["id"] == job_id
    # /v1/me is per-user data too: same no-store hardening.
    r = client.get("/v1/me")
    assert r.status_code == 200, r.text
    _assert_no_store(r)
