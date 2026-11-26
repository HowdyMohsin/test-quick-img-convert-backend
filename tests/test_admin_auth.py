"""Admin auth tests: login, lockout, CSRF, forced password change, TOTP."""

import re

from conftest import (
    FORCED_EMAIL,
    FORCED_PASSWORD,
    STAFF_EMAIL,
    STAFF_PASSWORD,
    SUPER_EMAIL,
    SUPER_PASSWORD,
    csrf_token,
    login_as,
    login_super,
)


def test_login_success_sets_cookie(client):
    resp = login_super(client)
    assert resp.json()["email"] == SUPER_EMAIL
    assert resp.json()["must_change_password"] is False
    assert "qic_admin" in resp.cookies
    me = client.get("/admin/auth/me")
    assert me.status_code == 200
    assert me.json()["role"] == "super_admin"


def test_login_wrong_password_uses_standard_error_shape(client):
    resp = client.post(
        "/admin/auth/login",
        json={"email": SUPER_EMAIL, "password": "WrongPassword123"},
    )
    assert resp.status_code == 401
    body = resp.json()
    assert body["error"]["code"] == "admin_invalid_credentials"
    assert "incorrect" in body["error"]["message"]
    assert "hint" in body["error"]


def test_login_unknown_email_does_not_enumerate(client):
    resp = client.post(
        "/admin/auth/login",
        json={"email": "nobody@qic.local", "password": "Whatever12345"},
    )
    assert resp.status_code == 401
    assert resp.json()["error"]["code"] == "admin_invalid_credentials"


def test_lockout_after_8_failed_attempts(client):
    for attempt in range(7):
        resp = client.post(
            "/admin/auth/login",
            json={"email": STAFF_EMAIL, "password": "WrongPassword123"},
        )
        assert resp.status_code == 401, f"attempt {attempt + 1}: {resp.text}"
    resp = client.post(
        "/admin/auth/login",
        json={"email": STAFF_EMAIL, "password": "WrongPassword123"},
    )
    assert resp.status_code == 429
    assert resp.json()["error"]["code"] == "admin_locked_out"
    assert resp.json()["error"]["retry_after_seconds"] > 0
    assert "minute" in resp.json()["error"]["message"]
    # Still locked out even with the right password.
    resp = client.post(
        "/admin/auth/login",
        json={"email": STAFF_EMAIL, "password": STAFF_PASSWORD},
    )
    assert resp.status_code == 429


def test_csrf_token_issued_and_required_on_mutation(client):
    login_super(client)
    token = csrf_token(client)
    assert re.fullmatch(r"[0-9a-f]{64}", token)
    # No CSRF header -> 403.
    resp = client.post(
        f"/admin/users/{client.user_id}/ban", json={"reason": "abuse"}
    )
    assert resp.status_code == 403
    assert resp.json()["error"]["code"] == "csrf_required"
    # With a valid token the mutation goes through.
    resp = client.post(
        f"/admin/users/{client.user_id}/ban",
        json={"reason": "abuse"},
        headers={"X-CSRF-Token": token},
    )
    assert resp.status_code == 200, resp.text


def test_forced_password_change_flow(client):
    resp = login_as(client, FORCED_EMAIL, FORCED_PASSWORD)
    assert resp.json()["must_change_password"] is True
    # Protected sections are blocked until the password is changed.
    resp = client.get("/admin/dashboard")
    assert resp.status_code == 403
    assert resp.json()["error"]["code"] == "password_change_required"
    # /me still works while the change is pending.
    assert client.get("/admin/auth/me").status_code == 200
    # 7 characters is too short for admins.
    resp = client.post(
        "/admin/auth/change-password",
        json={"current_password": FORCED_PASSWORD, "new_password": "Short12"},
    )
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "admin_password_too_short"
    # Exactly 8 characters is accepted.
    resp = client.post(
        "/admin/auth/change-password",
        json={"current_password": FORCED_PASSWORD, "new_password": "NewAdmin"},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["changed"] is True
    # Password change revokes the session: a fresh login is required.
    assert client.get("/admin/auth/me").status_code == 401
    resp = login_as(client, FORCED_EMAIL, "NewAdmin")
    assert resp.json()["must_change_password"] is False
    assert client.get("/admin/dashboard").status_code == 200


def test_change_password_wrong_current_password(client):
    login_super(client)
    resp = client.post(
        "/admin/auth/change-password",
        json={"current_password": "NopeNopeNope1", "new_password": "AnotherPass123"},
    )
    assert resp.status_code == 401


def test_totp_setup_verify_and_login(client):
    import app.admin_auth as admin_auth

    login_super(client)
    setup = client.post("/admin/auth/totp/setup")
    assert setup.status_code == 200, setup.text
    secret = setup.json()["secret"]
    assert setup.json()["otpauth_url"].startswith("otpauth://totp/")
    code = admin_auth._totp_code(secret)
    verify = client.post("/admin/auth/totp/verify", json={"code": code})
    assert verify.status_code == 200, verify.text
    recovery_codes = verify.json()["recovery_codes"]
    assert len(recovery_codes) == 10
    # Wrong code is rejected at setup-time verify for a fresh secret; here
    # TOTP is already enabled, so a login without a code must fail.
    client.post("/admin/auth/logout")
    resp = client.post(
        "/admin/auth/login",
        json={"email": SUPER_EMAIL, "password": SUPER_PASSWORD},
    )
    assert resp.status_code == 401
    assert resp.json()["error"]["code"] == "admin_totp_required"
    # Login with a current TOTP code succeeds.
    code = admin_auth._totp_code(secret)
    resp = login_as(client, SUPER_EMAIL, SUPER_PASSWORD, totp_code=code)
    assert resp.status_code == 200
    # A recovery code also works, once.
    client.post("/admin/auth/logout")
    resp = login_as(
        client, SUPER_EMAIL, SUPER_PASSWORD, totp_code=recovery_codes[0]
    )
    assert resp.status_code == 200
    client.post("/admin/auth/logout")
    resp = client.post(
        "/admin/auth/login",
        json={"email": SUPER_EMAIL, "password": SUPER_PASSWORD,
              "totp_code": recovery_codes[0]},
    )
    assert resp.status_code == 401  # already used


def test_reset_password_token_round_trip(client):
    import app.admin_auth as admin_auth

    login_super(client)
    me = client.get("/admin/auth/me").json()
    token = admin_auth.make_admin_reset_token(me["id"])
    resp = client.post(
        "/admin/auth/reset-password",
        json={"token": token, "new_password": "ResetAdminPass1"},
    )
    assert resp.status_code == 200, resp.text
    # Old password no longer works; new one does.
    assert client.post(
        "/admin/auth/login",
        json={"email": SUPER_EMAIL, "password": SUPER_PASSWORD},
    ).status_code == 401
    assert login_as(client, SUPER_EMAIL, "ResetAdminPass1").status_code == 200
    # A bad token is rejected.
    resp = client.post(
        "/admin/auth/reset-password",
        json={"token": "bad.token", "new_password": "ResetAdminPass2"},
    )
    assert resp.status_code == 401


def test_logout_revokes_session(client):
    login_super(client)
    assert client.get("/admin/auth/me").status_code == 200
    assert client.post("/admin/auth/logout").status_code == 200
    assert client.get("/admin/auth/me").status_code == 401


def test_user_session_cookie_does_not_grant_admin_access(client):
    client.cookies.set("qic_session", "a" * 64)
    resp = client.get("/admin/auth/me")
    assert resp.status_code == 401
    assert resp.json()["error"]["code"] == "admin_auth_required"
