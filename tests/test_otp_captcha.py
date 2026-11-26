"""Email OTP + test captcha tests (v5 register hardening).

The OTP code is random and only its hash is stored, so tests pin the
code by monkeypatching secrets.randbelow. Captcha tests stub the Google
call (no network in tests); the live test-key behaviour is verified
against Render after deploy.
"""

from datetime import datetime, timedelta, timezone

import pytest

from test_auth import csrf, db_write, env_client, post, register  # noqa: F401

OTP_CODE = 123456


def _pin_otp(monkeypatch):
    monkeypatch.setattr("secrets.randbelow", lambda n: OTP_CODE)


def _set_otp_expiry(client, minutes_ago):
    def _fn(s):
        from app.models import EmailOtp

        row = s.query(EmailOtp).order_by(EmailOtp.created_at.desc()).first()
        row.expires_at = datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)
    db_write(client.db_path, _fn)


def _set_otp_created(client, seconds_ago):
    def _fn(s):
        from app.models import EmailOtp

        row = s.query(EmailOtp).order_by(EmailOtp.created_at.desc()).first()
        row.created_at = datetime.now(timezone.utc) - timedelta(seconds=seconds_ago)
    db_write(client.db_path, _fn)


def _user_verified(client, email="alice@example.com"):
    def _fn(s):
        from app.models import User

        return s.query(User).filter_by(email=email).first().email_verified_at is not None
    out = []
    db_write(client.db_path, lambda s: out.append(_fn(s)))
    return out[0]


def test_register_returns_otp_sent_false_without_smtp(env_client, monkeypatch):
    _pin_otp(monkeypatch)
    resp = register(env_client)
    assert resp.status_code == 200, resp.text
    # No SMTP in this harness: the code exists server-side but no mail
    # was sent, and registration still succeeds.
    assert resp.json()["otp_sent"] is False


def test_register_skips_otp_when_verification_off(env_client, monkeypatch):
    # TEMPORARY flag (user order 2026-11-26): with
    # REQUIRE_EMAIL_VERIFICATION=false registration sends no
    # verification email and issues no OTP code at all.
    from app.deps import reset_settings
    monkeypatch.setenv("REQUIRE_EMAIL_VERIFICATION", "false")
    reset_settings()
    try:
        _pin_otp(monkeypatch)
        resp = register(env_client)
        assert resp.status_code == 200, resp.text
        assert resp.json()["otp_sent"] is False
        assert resp.json()["require_email_verification"] is False

        def _count(s):
            from app.models import EmailOtp
            return s.query(EmailOtp).count()
        out = []
        db_write(env_client.db_path, lambda s: out.append(_count(s)))
        assert out[0] == 0  # no OTP row was created at all
    finally:
        monkeypatch.delenv("REQUIRE_EMAIL_VERIFICATION", raising=False)
        reset_settings()


def test_resend_verification_sends_nothing_when_verification_off(env_client, monkeypatch):
    # TEMPORARY flag, site-wide expansion (user order 2026-11-26): the
    # resend endpoint must not send a verification email while off.
    from app.deps import reset_settings
    monkeypatch.setenv("REQUIRE_EMAIL_VERIFICATION", "false")
    reset_settings()
    try:
        assert register(env_client).status_code == 200
        resp = post(env_client, "/v1/auth/resend-verification", {})
        assert resp.status_code == 200, resp.text

        def _count(s):
            from app.models import EmailToken
            return s.query(EmailToken).filter_by(kind="verify").count()
        out = []
        db_write(env_client.db_path, lambda s: out.append(_count(s)))
        assert out[0] == 0  # no verification token was created
    finally:
        monkeypatch.delenv("REQUIRE_EMAIL_VERIFICATION", raising=False)
        reset_settings()


def test_resend_otp_issues_nothing_when_verification_off(env_client, monkeypatch):
    # TEMPORARY flag, site-wide expansion (user order 2026-11-26): the
    # resend-code endpoint must not issue an OTP code while off.
    from app.deps import reset_settings
    monkeypatch.setenv("REQUIRE_EMAIL_VERIFICATION", "false")
    reset_settings()
    try:
        assert register(env_client).status_code == 200
        resp = post(env_client, "/v1/auth/resend-otp", {"email": "alice@example.com"})
        assert resp.status_code == 200, resp.text

        def _count(s):
            from app.models import EmailOtp
            return s.query(EmailOtp).count()
        out = []
        db_write(env_client.db_path, lambda s: out.append(_count(s)))
        assert out[0] == 0  # no OTP row was created at all
    finally:
        monkeypatch.delenv("REQUIRE_EMAIL_VERIFICATION", raising=False)
        reset_settings()


def test_change_email_applies_immediately_when_verification_off(env_client, monkeypatch):
    # TEMPORARY flag, site-wide expansion (user order 2026-11-26): with
    # verification off, changing email applies at once — no token, no
    # verification email to the new address.
    from test_auth import VALID_PASSWORD
    from app.deps import reset_settings
    monkeypatch.setenv("REQUIRE_EMAIL_VERIFICATION", "false")
    reset_settings()
    try:
        resp = register(env_client)
        assert resp.status_code == 200, resp.text
        user_id = resp.json()["user"]["id"]
        resp = post(env_client, "/v1/auth/change-email",
                    {"new_email": "alice-new@example.com", "password": VALID_PASSWORD})
        assert resp.status_code == 200, resp.text
        assert "changed" in resp.json()["message"]
        out = []
        def _check(s):
            from app.models import EmailToken, User
            user = s.query(User).filter_by(id=user_id).first()
            out.append((user.email,
                        s.query(EmailToken).filter_by(kind="change_email").count()))
        db_write(env_client.db_path, _check)
        assert out[0] == ("alice-new@example.com", 0)
    finally:
        monkeypatch.delenv("REQUIRE_EMAIL_VERIFICATION", raising=False)
        reset_settings()


def test_verify_otp_happy_path(env_client, monkeypatch):
    _pin_otp(monkeypatch)
    assert register(env_client).status_code == 200
    resp = post(env_client, "/v1/auth/verify-otp",
                {"email": "alice@example.com", "code": "123456"})
    assert resp.status_code == 200, resp.text
    assert resp.json()["ok"] is True
    assert _user_verified(env_client) is True


def test_verify_otp_wrong_code(env_client, monkeypatch):
    _pin_otp(monkeypatch)
    assert register(env_client).status_code == 200
    resp = post(env_client, "/v1/auth/verify-otp",
                {"email": "alice@example.com", "code": "000000"})
    assert resp.status_code == 400, resp.text
    assert resp.json()["error"]["code"] == "invalid_code"
    assert _user_verified(env_client) is False


def test_verify_otp_expired(env_client, monkeypatch):
    _pin_otp(monkeypatch)
    assert register(env_client).status_code == 200
    _set_otp_expiry(env_client, minutes_ago=1)
    resp = post(env_client, "/v1/auth/verify-otp",
                {"email": "alice@example.com", "code": "123456"})
    assert resp.status_code == 400, resp.text
    assert resp.json()["error"]["code"] == "expired_code"


def test_verify_otp_too_many_attempts(env_client, monkeypatch):
    _pin_otp(monkeypatch)
    assert register(env_client).status_code == 200
    for _ in range(5):
        resp = post(env_client, "/v1/auth/verify-otp",
                    {"email": "alice@example.com", "code": "000000"})
        assert resp.status_code == 400
        assert resp.json()["error"]["code"] == "invalid_code"
    # The 6th attempt — even with the right code — is void.
    resp = post(env_client, "/v1/auth/verify-otp",
                {"email": "alice@example.com", "code": "123456"})
    assert resp.status_code == 400, resp.text
    assert resp.json()["error"]["code"] == "too_many_attempts"
    assert _user_verified(env_client) is False


def test_resend_otp_cooldown_then_success(env_client, monkeypatch):
    _pin_otp(monkeypatch)
    assert register(env_client).status_code == 200
    resp = post(env_client, "/v1/auth/resend-otp", {"email": "alice@example.com"})
    assert resp.status_code == 429, resp.text
    assert resp.json()["error"]["code"] == "resend_cooldown"
    assert resp.json()["retry_after"] > 0
    # After the 60-second window a fresh code is issued.
    _set_otp_created(env_client, seconds_ago=61)
    resp = post(env_client, "/v1/auth/resend-otp", {"email": "alice@example.com"})
    assert resp.status_code == 200, resp.text
    assert resp.json()["ok"] is True
    # The new code verifies (old one was invalidated).
    resp = post(env_client, "/v1/auth/verify-otp",
                {"email": "alice@example.com", "code": "123456"})
    assert resp.status_code == 200, resp.text


def test_verify_otp_unknown_email(env_client):
    resp = post(env_client, "/v1/auth/verify-otp",
                {"email": "nobody@example.com", "code": "123456"})
    assert resp.status_code == 400, resp.text
    assert resp.json()["error"]["code"] == "invalid_code"


def test_captcha_empty_token(env_client):
    resp = env_client.post("/v1/captcha/verify", json={"token": ""})
    assert resp.status_code == 200, resp.text
    assert resp.json()["ok"] is False
    assert resp.json()["error"] == "missing_token"


def test_captcha_test_key_passes(env_client, monkeypatch):
    monkeypatch.setattr("app.routers_captcha._verify_with_google",
                        lambda secret, token: True)
    resp = env_client.post("/v1/captcha/verify", json={"token": "test-token"})
    assert resp.status_code == 200, resp.text
    assert resp.json() == {"ok": True}


def test_captcha_failed_and_unreachable(env_client, monkeypatch):
    monkeypatch.setattr("app.routers_captcha._verify_with_google",
                        lambda secret, token: False)
    resp = env_client.post("/v1/captcha/verify", json={"token": "bad"})
    assert resp.json()["ok"] is False
    assert resp.json()["error"] == "captcha_failed"
    monkeypatch.setattr("app.routers_captcha._verify_with_google",
                        lambda secret, token: None)
    resp = env_client.post("/v1/captcha/verify", json={"token": "bad"})
    assert resp.json()["ok"] is False
    assert resp.json()["error"] == "verification_unavailable"
