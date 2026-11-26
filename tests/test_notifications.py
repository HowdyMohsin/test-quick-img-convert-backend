"""Regression tests for the notifications list endpoint.

GET /v1/notifications was defined in app.routers_marketing
(notifications_router) but never mounted in app.main.create_app, so the
live frontend got a 404 on every list fetch while /v1/me still reported
the unread count — the bell and the account tab showed "Could not load
your notifications" for a user with exactly 1 unread notification.
These tests build the real create_app() and prove the routes exist and
serve the welcome notification created at registration.
"""

import os
import sys

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

os.environ.setdefault("APP_SECRET", "test-only-admin-secret")
os.environ.setdefault("SECRET_KEY", "test-only-secret-key")
os.environ.setdefault("QIC_STARTUP_HEALTH_CHECK", "0")

from app.main import create_app  # noqa: E402

DB_PATH = "/tmp/qic-notifications-tests.db"


@pytest.fixture(scope="module")
def client():
    # Settings are cached process-wide; point them at the scratch DB
    # for this module and restore afterwards so other test modules
    # are unaffected.
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


def test_notifications_routes_are_mounted(client):
    # Before the fix this returned 404 (route not mounted at all);
    # mounted + unauthenticated it must be 401.
    assert client.get("/v1/notifications").status_code == 401
    assert client.post("/v1/notifications/read-all").status_code == 401


def test_notifications_list_after_register(client):
    token = _csrf(client)
    r = client.post(
        "/v1/auth/register",
        json={
            "name": "Notif Test",
            "email": "notif-test-20261126@example.com",
            "password": "correct-horse-battery-1",
            "terms_accepted": True,
            "remember_me": False,
        },
        headers={"X-CSRF-Token": token},
    )
    assert r.status_code == 200, r.text

    r = client.get("/v1/notifications")
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["unread"] == 1
    assert len(data["notifications"]) == 1
    note = data["notifications"][0]
    assert note["kind"] == "welcome"
    assert note["read"] is False
    assert note["title"]

    token = _csrf(client)
    r = client.post("/v1/notifications/read-all", json={},
                    headers={"X-CSRF-Token": token})
    assert r.status_code == 200, r.text
    assert r.json()["read"] == 1

    r = client.get("/v1/notifications")
    assert r.status_code == 200, r.text
    assert r.json()["unread"] == 0
    assert r.json()["notifications"][0]["read"] is True
