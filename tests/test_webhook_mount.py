"""Regression tests for the Stripe webhook mount.

POST /webhooks/{key} was defined in app.routers_payments
(webhook_router, prefix /webhooks) but never mounted in
app.main.create_app — the mounting loop only included
("routers_payments", "router"). So POST /webhooks/stripe returned
FastAPI's plain 404 and Stripe webhooks could never land, even with
the test keys configured. The existing tests/test_webhooks.py did not
catch this: it mounts webhook_router directly on a bare FastAPI app.

These tests build the real create_app() and prove the routes exist:
an unsigned POST to /webhooks/stripe must be 401 (mounted, but the
provider is not configured on this scratch app), never a plain 404;
an unknown provider key must be the endpoint's own 404 with
error.code == "unknown_provider".
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

DB_PATH = "/tmp/qic-webhook-mount-tests.db"


@pytest.fixture(scope="module")
def client():
    # Settings are cached process-wide; point them at the scratch DB
    # for this module and restore afterwards so other test modules
    # are unaffected.
    from app.deps import reset_settings

    os.environ["DATABASE_URL"] = f"sqlite+aiosqlite:///{DB_PATH}"
    reset_settings()
    app = create_app()
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    os.environ.pop("DATABASE_URL", None)
    reset_settings()


def test_webhook_router_is_mounted(client):
    # Before the fix this returned FastAPI's plain 404
    # ({"detail": "Not Found"}); mounted + unconfigured it must be
    # 401 with the endpoint's own error envelope.
    r = client.post("/webhooks/stripe", content=b"{}",
                    headers={"Content-Type": "application/json"})
    assert r.status_code == 401, r.text
    assert r.json()["error"]["code"] == "webhook_not_configured"


def test_webhook_unknown_provider_404_has_error_code(client):
    # The endpoint's own 404 (not FastAPI's plain one) proves the
    # route is mounted and answering.
    r = client.post("/webhooks/nope", content=b"{}",
                    headers={"Content-Type": "application/json"})
    assert r.status_code == 404, r.text
    assert r.json()["error"]["code"] == "unknown_provider"
