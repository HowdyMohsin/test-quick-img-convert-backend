"""First-party authentication (v5 section 8). Own system, own database.

Flows: register, login, logout, Google OIDC, forgot/reset password,
verify email (+ resend), change password, change email, session list /
revoke, all behind the ``qic_session`` cookie (random 256-bit token,
only its SHA-256 hash stored) and a CSRF token bound to the session.

Account states: active / banned (403 ``account_banned`` with the
reason on login, the account page and every API call) / deleted.
Banning revokes all sessions.
"""

from __future__ import annotations

import secrets
import unicodedata
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from . import mail, passwords
from .deps import (
    ensure_aware,
    SESSION_BROWSER_HOURS,
    SESSION_ABSOLUTE_DAYS,
    SESSION_COOKIE,
    SESSION_SLIDING_DAYS,
    api_error,
    client_ip,
    csrf_token_for,
    get_current_session,
    get_current_user,
    get_db,
    get_session_and_user,
    get_settings,
    hash_session_token,
    new_session_token,
    parse_user_agent,
    require_csrf,
)
from .models import AuthIdentity, EmailOtp, EmailToken, Notification, Session, User
from .rate_limit import (
    ip_key,
    login_locked,
    rate_limit_or_429,
    record_auth_attempt,
)
from .security import hash_email, mask_ip

router = APIRouter(prefix="/v1/auth", tags=["auth"])

GENERIC_LOGIN_ERROR = "Email or password is incorrect."
FORGOT_MESSAGE = "If that email exists, we sent a reset link."


# ---------------------------------------------------------------- helpers

def normalize_email(email: str) -> str:
    return unicodedata.normalize("NFC", email or "").strip().lower()


def _now() -> datetime:
    return datetime.now(timezone.utc)


async def get_template(db: AsyncSession, key: str) -> tuple[str, str] | None:
    from .models import EmailTemplate

    row = await db.get(EmailTemplate, key)
    if row is None:
        return None
    return row.subject, row.body


async def send_template_email(
    db: AsyncSession, key: str, to_email: str, fallback_subject: str,
    fallback_body: str, **values: object,
) -> bool:
    tpl = await get_template(db, key)
    if tpl is not None:
        subject, body = mail.render_template(tpl[0], tpl[1], **values)
    else:
        subject, body = mail.render_template(fallback_subject, fallback_body, **values)
    site_url = get_settings().site_url.rstrip("/")
    body = body.replace("{site_url}", site_url)
    return await mail.send_mail(to_email, subject, body)


async def add_notification(
    db: AsyncSession, user_id: str, kind: str, title: str,
    body: str = "", href: str | None = None,
) -> None:
    db.add(Notification(user_id=user_id, kind=kind, title=title, body=body, href=href))
    await db.commit()


async def create_email_token(
    db: AsyncSession, user: User, kind: str, minutes: int,
    new_email: str | None = None,
) -> str:
    token = passwords.random_token()
    db.add(EmailToken(
        user_id=user.id,
        kind=kind,
        token_hash=passwords.hash_token(token),
        new_email=new_email,
        expires_at=_now() + timedelta(minutes=minutes),
    ))
    await db.commit()
    return token


async def find_email_token(db: AsyncSession, token: str, kind: str) -> EmailToken | None:
    result = await db.execute(
        select(EmailToken).where(
            EmailToken.token_hash == passwords.hash_token(token),
            EmailToken.kind == kind,
        )
    )
    return result.scalar_one_or_none()


async def revoke_all_sessions(db: AsyncSession, user_id: str, except_id: str | None = None) -> None:
    result = await db.execute(
        select(Session).where(Session.user_id == user_id, Session.revoked_at.is_(None))
    )
    for s in result.scalars().all():
        if except_id is not None and s.id == except_id:
            continue
        s.revoked_at = _now()
    await db.commit()


async def create_session(
    db: AsyncSession, user: User, request: Request, remember: bool,
) -> tuple[str, Session]:
    token = new_session_token()
    now = _now()
    if remember:
        expires = now + timedelta(days=SESSION_SLIDING_DAYS)
    else:
        expires = now + timedelta(hours=SESSION_BROWSER_HOURS)
    device, _browser = parse_user_agent(request)
    session = Session(
        user_id=user.id,
        token_hash=hash_session_token(token),
        csrf_secret=secrets.token_hex(32),
        ip=client_ip(request),
        user_agent=request.headers.get("user-agent", ""),
        remember=remember,
        expires_at=expires,
        last_seen_at=now,
    )
    db.add(session)
    await db.commit()
    return token, session


def set_session_cookie(response: Response, token: str | None, remember: bool) -> None:
    settings = get_settings()
    if token is None:
        response.delete_cookie(SESSION_COOKIE, path="/")
        return
    kwargs: dict = {
        "key": SESSION_COOKIE,
        "value": token,
        "httponly": True,
        "secure": settings.is_https,
        "samesite": "lax",
        "path": "/",
    }
    if remember:
        kwargs["max_age"] = SESSION_SLIDING_DAYS * 86400
    response.set_cookie(**kwargs)


def _verification_link(token: str) -> str:
    return f"{get_settings().site_url.rstrip('/')}/verify-email?token={token}"


def _reset_link(token: str) -> str:
    return f"{get_settings().site_url.rstrip('/')}/reset-password?token={token}"


async def _send_verification(db: AsyncSession, user: User) -> None:
    token = await create_email_token(db, user, "verify", 24 * 60)
    await send_template_email(
        db, "verify_email", user.email,
        "Verify your email — Quick IMG Convert",
        "Hi {name},\n\nPlease verify your email by opening this link:\n{link}\n\n"
        "The link works for 24 hours.",
        name=user.display_name or "there", link=_verification_link(token),
    )


# ---------------------------------------------------------------- email OTP
# 6-digit verification codes (the register flow sends one alongside the
# verification link). Only the SHA-256 hash is stored; one active code
# per user; 10-minute expiry; 5 failed attempts voids the code. Sending
# is best-effort (mail.send_mail returns False without SMTP) and never
# breaks registration — the caller reports otp_sent so the UI knows.
OTP_TTL_MINUTES = 10
OTP_MAX_ATTEMPTS = 5
OTP_RESEND_COOLDOWN_SECONDS = 60


async def _active_otp(db: AsyncSession, user: User) -> EmailOtp | None:
    result = await db.execute(
        select(EmailOtp).where(
            EmailOtp.user_id == user.id, EmailOtp.used_at.is_(None),
        ).order_by(EmailOtp.created_at.desc())
    )
    return result.scalars().first()


async def _issue_otp(db: AsyncSession, user: User) -> tuple[str, bool]:
    """Create a fresh code (invalidating any earlier unused one) and
    email it. Returns (code, sent)."""
    old = await db.execute(
        select(EmailOtp).where(
            EmailOtp.user_id == user.id, EmailOtp.used_at.is_(None),
        )
    )
    for row in old.scalars().all():
        row.used_at = _now()
    code = f"{secrets.randbelow(1_000_000):06d}"
    db.add(EmailOtp(
        user_id=user.id,
        code_hash=passwords.hash_token(code),
        expires_at=_now() + timedelta(minutes=OTP_TTL_MINUTES),
    ))
    await db.commit()
    sent = await send_template_email(
        db, "verify_otp", user.email,
        "Your verification code — Quick IMG Convert",
        "Hi {name},\n\nYour verification code is: {code}\n\n"
        "It expires in 10 minutes. If you did not ask for this, ignore this email.",
        name=user.display_name or "there", code=code,
    )
    return code, sent


def _device_browser(user_agent: str) -> tuple[str, str]:
    """Best-effort (device, browser) labels from a stored User-Agent."""
    ua_low = user_agent.lower()
    if "iphone" in ua_low:
        device = "iPhone"
    elif "ipad" in ua_low:
        device = "iPad"
    elif "android" in ua_low:
        device = "Android device"
    elif "macintosh" in ua_low or "mac os" in ua_low:
        device = "Mac"
    elif "windows" in ua_low:
        device = "Windows PC"
    elif "linux" in ua_low:
        device = "Linux PC"
    else:
        device = "Unknown device"
    if "edg/" in ua_low:
        browser = "Edge"
    elif "chrome/" in ua_low:
        browser = "Chrome"
    elif "firefox/" in ua_low:
        browser = "Firefox"
    elif "safari/" in ua_low and "chrome" not in ua_low:
        browser = "Safari"
    else:
        browser = "Unknown browser"
    return device, browser


# ---------------------------------------------------------------- schemas

class RegisterBody(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    email: str = Field(min_length=3, max_length=255)
    password: str
    terms_accepted: bool = False
    remember_me: bool = False


class LoginBody(BaseModel):
    email: str
    password: str
    remember_me: bool = False


class GoogleBody(BaseModel):
    id_token: str
    remember_me: bool = False


class ForgotBody(BaseModel):
    email: str


class ResetBody(BaseModel):
    token: str
    password: str


class VerifyBody(BaseModel):
    token: str


class ChangePasswordBody(BaseModel):
    current_password: str
    new_password: str


class ChangeEmailBody(BaseModel):
    password: str
    new_email: str


class DeleteMeBody(BaseModel):
    password: str | None = None
    confirmation: str = ""


# ---------------------------------------------------------------- CSRF

@router.get("/csrf")
async def get_csrf(request: Request, db: AsyncSession = Depends(get_db)):
    """Return a CSRF token bound to the session (or, when signed out,
    to an anonymous secret cookie)."""
    session, _user = await get_session_and_user(request, db)
    if session is not None:
        return {"csrf_token": csrf_token_for(session.csrf_secret)}
    from fastapi.responses import JSONResponse

    secret = request.cookies.get("qic_csrf_secret", "")
    if not secret:
        secret = secrets.token_hex(16)
    resp = JSONResponse({"csrf_token": csrf_token_for(secret)})
    settings = get_settings()
    resp.set_cookie(
        "qic_csrf_secret", secret, httponly=True, secure=settings.is_https,
        samesite="lax", path="/", max_age=86400,
    )
    return resp


# ---------------------------------------------------------------- register

@router.post("/register")
async def register(
    body: RegisterBody, request: Request, response: Response,
    db: AsyncSession = Depends(get_db),
):
    session, _ = await get_session_and_user(request, db)
    require_csrf(request, session)
    rate_limit_or_429(ip_key(request, "register"), 5, 3600, "registration")
    ip = client_ip(request)
    email = normalize_email(body.email)
    if not body.terms_accepted:
        raise api_error(400, "terms_required",
                        "Please accept the Terms and Privacy Policy to create an account.",
                        "Tick the checkbox for the Terms and Privacy Policy.")
    pw_error = passwords.validate_password(body.password)
    if pw_error:
        await record_auth_attempt(db, "register", email, ip, False)
        raise api_error(400, "weak_password", pw_error, "Choose a stronger password.")
    existing = await db.execute(select(User).where(User.email == email))
    if existing.scalar_one_or_none() is not None:
        await record_auth_attempt(db, "register", email, ip, False)
        raise api_error(409, "email_taken",
                        "An account with this email already exists.",
                        "Sign in instead, or reset your password.")
    user = User(
        email=email,
        display_name=body.name.strip(),
        password_hash=passwords.hash_password(body.password),
        plan="free",
    )
    db.add(user)
    await db.commit()
    await record_auth_attempt(db, "register", email, ip, True)
    token, sess = await create_session(db, user, request, body.remember_me)
    set_session_cookie(response, token, body.remember_me)
    await add_notification(
        db, user.id, "welcome",
        "Welcome to Quick IMG Convert",
        "Your account is ready. You get 25 free conversions every day.",
        href="/account",
    )
    # Email verification is OFF in the code (user order 2026-11-26):
    # the verification link email and the OTP code are skipped
    # entirely, so registration lands straight on the account. The
    # verification endpoints stay live for when the flag is turned back on.
    otp_sent = False
    if get_settings().require_email_verification:
        await _send_verification(db, user)
        _otp_code, otp_sent = await _issue_otp(db, user)
    return {
        "user": _public_user(user),
        "email_verified": False,
        "otp_sent": otp_sent,
        "require_email_verification": get_settings().require_email_verification,
        "message": "Account created. Check your inbox to verify your email.",
    }


def _public_user(user: User) -> dict:
    return {
        "id": user.id,
        "email": user.email,
        "display_name": user.display_name,
        "plan": user.plan,
        "email_verified": user.email_verified_at is not None,
        "banned": user.banned,
        "created_at": user.created_at.isoformat() if user.created_at else None,
    }


# ---------------------------------------------------------------- login/logout

@router.post("/login")
async def login(
    body: LoginBody, request: Request, response: Response,
    db: AsyncSession = Depends(get_db),
):
    session, _ = await get_session_and_user(request, db)
    require_csrf(request, session)
    ip = client_ip(request)
    email = normalize_email(body.email)
    rate_limit_or_429(ip_key(request, "login"), 10, 900, "login")
    locked = await login_locked(db, email, ip)
    if locked is not None:
        raise api_error(429, "login_locked",
                        f"Too many failed sign-in attempts. Try again in {locked} seconds.",
                        f"Wait {locked} seconds and try again.")
    result = await db.execute(select(User).where(User.email == email))
    user = result.scalar_one_or_none()
    ok = False
    if user is not None and user.deleted_at is None:
        ok = passwords.verify_password(user.password_hash, body.password)
    if not ok:
        await record_auth_attempt(db, "login", email, ip, False)
        raise api_error(401, "invalid_credentials", GENERIC_LOGIN_ERROR,
                        "Check your email and password and try again.")
    if user.banned:
        await record_auth_attempt(db, "login", email, ip, False)
        raise api_error(403, "account_banned",
                        f"Your account is banned. {user.ban_reason or ''}".strip(),
                        "Contact support if you think this is a mistake.")
    await record_auth_attempt(db, "login", email, ip, True)
    if passwords.needs_rehash(user.password_hash):
        user.password_hash = passwords.hash_password(body.password)
    user.last_login_at = _now()
    await db.commit()
    token, _sess = await create_session(db, user, request, body.remember_me)
    set_session_cookie(response, token, body.remember_me)
    return {"user": _public_user(user), "message": "Signed in."}


@router.post("/logout")
async def logout(
    request: Request, response: Response, db: AsyncSession = Depends(get_db),
):
    session, _ = await get_session_and_user(request, db)
    require_csrf(request, session)
    if session is not None:
        session.revoked_at = _now()
        await db.commit()
    set_session_cookie(response, None, False)
    return {"message": "Signed out."}


# ---------------------------------------------------------------- Google OIDC

@router.post("/google")
async def google_signin(
    body: GoogleBody, request: Request, response: Response,
    db: AsyncSession = Depends(get_db),
):
    session, _ = await get_session_and_user(request, db)
    require_csrf(request, session)
    settings = get_settings()
    if not settings.google_client_id:
        raise api_error(503, "google_not_configured",
                        "Sign in with Google is not set up yet.",
                        "Use email and password instead.")
    try:
        from google.auth.transport import requests as google_requests
        from google.oauth2 import id_token as google_id_token

        info = google_id_token.verify_oauth2_token(
            body.id_token, google_requests.Request(), settings.google_client_id
        )
    except Exception:
        raise api_error(401, "invalid_google_token",
                        "Google could not verify this sign-in. Please try again.",
                        "Try signing in with Google again, or use email and password.")
    if info.get("iss") not in ("https://accounts.google.com", "accounts.google.com"):
        raise api_error(401, "invalid_google_token",
                        "Google could not verify this sign-in. Please try again.",
                        "Try signing in again.")
    if not info.get("email_verified"):
        raise api_error(401, "google_email_unverified",
                        "Your Google email address is not verified.",
                        "Verify your email with Google first.")
    email = normalize_email(info.get("email", ""))
    subject = str(info.get("sub", ""))
    if not email or not subject:
        raise api_error(401, "invalid_google_token",
                        "Google did not return an email address.",
                        "Try signing in again.")
    result = await db.execute(
        select(AuthIdentity).where(
            AuthIdentity.provider == "google", AuthIdentity.subject == subject
        )
    )
    identity = result.scalar_one_or_none()
    user: User | None = None
    if identity is not None:
        user = await db.get(User, identity.user_id)
    if user is None:
        result = await db.execute(select(User).where(User.email == email))
        user = result.scalar_one_or_none()
    is_new = False
    if user is None:
        user = User(
            email=email,
            display_name=str(info.get("name") or email.split("@")[0]),
            password_hash=None,
            plan="free",
            email_verified_at=_now(),
        )
        db.add(user)
        await db.commit()
        is_new = True
    if identity is None:
        db.add(AuthIdentity(user_id=user.id, provider="google", subject=subject, email=email))
        await db.commit()
    if user.email_verified_at is None:
        user.email_verified_at = _now()
        await db.commit()
    if user.banned:
        raise api_error(403, "account_banned",
                        f"Your account is banned. {user.ban_reason or ''}".strip(),
                        "Contact support if you think this is a mistake.")
    if is_new:
        await add_notification(
            db, user.id, "welcome", "Welcome to Quick IMG Convert",
            "Your account is ready. You get 25 free conversions every day.",
            href="/account",
        )
    token, _sess = await create_session(db, user, request, body.remember_me)
    set_session_cookie(response, token, body.remember_me)
    return {"user": _public_user(user), "message": "Signed in with Google."}


# ---------------------------------------------------------------- forgot / reset

@router.post("/forgot-password")
async def forgot_password(
    body: ForgotBody, request: Request, db: AsyncSession = Depends(get_db),
):
    session, _ = await get_session_and_user(request, db)
    require_csrf(request, session)
    ip = client_ip(request)
    email = normalize_email(body.email)
    rate_limit_or_429(ip_key(request, "forgot"), 5, 3600, "password reset")
    rate_limit_or_429(f"forgot:email:{hash_email(email)}", 3, 3600, "password reset")
    result = await db.execute(select(User).where(User.email == email))
    user = result.scalar_one_or_none()
    if user is not None and user.deleted_at is None and user.password_hash is not None:
        # 60-second resend cooldown, enforced silently.
        recent = await db.execute(
            select(EmailToken).where(
                EmailToken.user_id == user.id,
                EmailToken.kind == "reset",
                EmailToken.created_at >= _now() - timedelta(seconds=60),
            )
        )
        if recent.scalar_one_or_none() is None:
            token = await create_email_token(db, user, "reset", 60)
            await send_template_email(
                db, "reset_password", user.email,
                "Reset your password — Quick IMG Convert",
                "Hi {name},\n\nReset your password by opening this link:\n{link}\n\n"
                "The link works for 60 minutes.",
                name=user.display_name or "there", link=_reset_link(token),
            )
    return {"message": FORGOT_MESSAGE}


@router.post("/reset-password")
async def reset_password(
    body: ResetBody, request: Request, db: AsyncSession = Depends(get_db),
):
    session, _ = await get_session_and_user(request, db)
    require_csrf(request, session)
    pw_error = passwords.validate_password(body.password)
    if pw_error:
        raise api_error(400, "weak_password", pw_error, "Choose a stronger password.")
    record = await find_email_token(db, body.token, "reset")
    if record is None or record.used_at is not None or (ensure_aware(record.expires_at) or _now()) <= _now():
        raise api_error(400, "invalid_token",
                        "This reset link is invalid or has expired.",
                        "Request a new reset link.")
    user = await db.get(User, record.user_id)
    if user is None or user.deleted_at is not None:
        raise api_error(400, "invalid_token",
                        "This reset link is invalid or has expired.",
                        "Request a new reset link.")
    record.used_at = _now()
    user.password_hash = passwords.hash_password(body.password)
    await db.commit()
    await revoke_all_sessions(db, user.id)
    await send_template_email(
        db, "password_changed", user.email,
        "Your password was changed — Quick IMG Convert",
        "Hi {name},\n\nYour password was changed. All other devices were signed out.\n\n"
        "If this was not you, contact support right away.",
        name=user.display_name or "there",
    )
    return {"message": "Your password has been reset. Please sign in."}


# ---------------------------------------------------------------- verify email

@router.post("/verify-email")
async def verify_email(
    body: VerifyBody, request: Request, db: AsyncSession = Depends(get_db),
):
    session, _ = await get_session_and_user(request, db)
    require_csrf(request, session)
    for kind in ("verify", "change_email"):
        record = await find_email_token(db, body.token, kind)
        if record is None or record.used_at is not None or (ensure_aware(record.expires_at) or _now()) <= _now():
            continue
        user = await db.get(User, record.user_id)
        if user is None or user.deleted_at is not None:
            continue
        record.used_at = _now()
        if kind == "change_email" and record.new_email:
            old_email = user.email
            user.email = normalize_email(record.new_email)
            user.email_verified_at = _now()
            await db.commit()
            await send_template_email(
                db, "email_change_notice", old_email,
                "Your email address was changed — Quick IMG Convert",
                "Hi {name},\n\nThe email address on your account was changed to {new_email}.\n\n"
                "If this was not you, contact support right away.",
                name=user.display_name or "there", new_email=user.email,
            )
            return {"message": "Your email address has been changed."}
        user.email_verified_at = _now()
        await db.commit()
        return {"message": "Your email is verified."}
    raise api_error(400, "invalid_token",
                    "This verification link is invalid or has expired.",
                    "Request a new verification email.")


@router.post("/resend-verification")
async def resend_verification(
    request: Request, db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    session, _ = await get_session_and_user(request, db)
    require_csrf(request, session)
    rate_limit_or_429(f"resend:{user.id}", 3, 3600, "verification email")
    # Email verification is OFF in the code (user order 2026-11-26):
    # no verification email is sent anywhere on the site. The endpoint
    # stays live and returns the usual success shape so no caller hits
    # a dead end; it comes back when the flag is turned back on.
    if not get_settings().require_email_verification:
        return {"message": "Verification email sent."}
    recent = await db.execute(
        select(EmailToken).where(
            EmailToken.user_id == user.id,
            EmailToken.kind == "verify",
            EmailToken.created_at >= _now() - timedelta(seconds=60),
        )
    )
    if recent.scalar_one_or_none() is not None:
        raise api_error(429, "resend_cooldown",
                        "Please wait 60 seconds before requesting another verification email.",
                        "Wait a minute and try again.")
    await _send_verification(db, user)
    return {"message": "Verification email sent."}


class VerifyOtpBody(BaseModel):
    email: str = Field(min_length=3, max_length=255)
    code: str = Field(min_length=1, max_length=10)


class ResendOtpBody(BaseModel):
    email: str = Field(min_length=3, max_length=255)


@router.post("/verify-otp")
async def verify_otp(
    body: VerifyOtpBody, request: Request, db: AsyncSession = Depends(get_db),
):
    """Verify the 6-digit email code. On success the email is marked
    verified (same as the verification link). Wrong / expired / exhausted
    codes return a clear 400, never a 500."""
    session, _ = await get_session_and_user(request, db)
    require_csrf(request, session)
    rate_limit_or_429(ip_key(request, "verify-otp"), 10, 900, "verification code")
    email = normalize_email(body.email)
    code = (body.code or "").strip()
    user = (await db.execute(select(User).where(User.email == email))).scalar_one_or_none()
    if user is None or user.deleted_at is not None:
        raise api_error(400, "invalid_code",
                        "No verification code is active for this email. Request a new code.",
                        "Request a new code and try again.")
    if user.banned:
        raise api_error(403, "account_banned",
                        f"Your account is banned. {user.ban_reason or ''}".strip(),
                        "Contact support if you think this is a mistake.")
    if len(code) != 6 or not code.isdigit():
        raise api_error(400, "invalid_code",
                        "Enter the 6-digit code we sent to your email.",
                        "Check the email and enter all 6 digits.")
    record = await _active_otp(db, user)
    if record is None:
        raise api_error(400, "invalid_code",
                        "No verification code is active for this email. Request a new code.",
                        "Request a new code and try again.")
    if record.attempts >= OTP_MAX_ATTEMPTS:
        record.used_at = _now()
        await db.commit()
        raise api_error(400, "too_many_attempts",
                        "Too many wrong attempts. This code is void — request a new one.",
                        "Request a new code.")
    if (ensure_aware(record.expires_at) or _now()) <= _now():
        record.used_at = _now()
        await db.commit()
        raise api_error(400, "expired_code",
                        "This code has expired. Request a new one.",
                        "Request a new code.")
    if not passwords.constant_time_equal(passwords.hash_token(code), record.code_hash):
        record.attempts += 1
        await db.commit()
        raise api_error(400, "invalid_code",
                        "That code is not correct. Check the email and try again.",
                        "Check the email and try again.")
    record.used_at = _now()
    user.email_verified_at = _now()
    await db.commit()
    return {"ok": True, "message": "Your email is verified."}


@router.post("/resend-otp")
async def resend_otp(
    body: ResendOtpBody, request: Request, db: AsyncSession = Depends(get_db),
):
    """Issue a fresh code (invalidates the previous one). 60-second
    server-side cooldown: too soon returns 429 with retry_after."""
    from fastapi import HTTPException

    session, _ = await get_session_and_user(request, db)
    require_csrf(request, session)
    rate_limit_or_429(ip_key(request, "resend-otp"), 5, 3600, "verification code")
    email = normalize_email(body.email)
    user = (await db.execute(select(User).where(User.email == email))).scalar_one_or_none()
    if user is None or user.deleted_at is not None:
        # Do not reveal whether the email has an account.
        return {"ok": True,
                "message": "If that email has an account, a new code was sent."}
    if user.email_verified_at is not None:
        return {"ok": True, "message": "Your email is already verified."}
    recent = await db.execute(
        select(EmailOtp).where(
            EmailOtp.user_id == user.id,
            EmailOtp.created_at >= _now() - timedelta(seconds=OTP_RESEND_COOLDOWN_SECONDS),
        ).order_by(EmailOtp.created_at.desc())
    )
    last = recent.scalars().first()
    if last is not None:
        elapsed = (_now() - (ensure_aware(last.created_at) or _now())).total_seconds()
        wait = max(1, OTP_RESEND_COOLDOWN_SECONDS - int(elapsed))
        raise HTTPException(status_code=429, detail={
            "error": {"code": "resend_cooldown",
                      "message": f"Please wait {wait} seconds before requesting another code.",
                      "hint": "Wait a minute and try again."},
            "retry_after": wait,
        })
    # Email verification is OFF in the code (user order 2026-11-26):
    # no OTP code is issued anywhere on the site. Same success shape,
    # no code — the OTP screen is unreachable while the flag is off.
    if not get_settings().require_email_verification:
        return {"ok": True, "message": "A new verification code was sent."}
    await _issue_otp(db, user)
    return {"ok": True, "message": "A new verification code was sent."}


# ---------------------------------------------------------------- change password/email

@router.post("/change-password")
async def change_password(
    body: ChangePasswordBody, request: Request, db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    session, _ = await get_session_and_user(request, db)
    require_csrf(request, session)
    if not passwords.verify_password(user.password_hash, body.current_password):
        raise api_error(401, "invalid_credentials",
                        "Your current password is incorrect.",
                        "Check your current password and try again.")
    pw_error = passwords.validate_password(body.new_password)
    if pw_error:
        raise api_error(400, "weak_password", pw_error, "Choose a stronger password.")
    user.password_hash = passwords.hash_password(body.new_password)
    await db.commit()
    await revoke_all_sessions(db, user.id, except_id=session.id if session else None)
    await send_template_email(
        db, "password_changed", user.email,
        "Your password was changed — Quick IMG Convert",
        "Hi {name},\n\nYour password was changed. All other devices were signed out.\n\n"
        "If this was not you, contact support right away.",
        name=user.display_name or "there",
    )
    return {"message": "Your password has been changed."}


@router.post("/change-email")
async def change_email(
    body: ChangeEmailBody, request: Request, db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    session, _ = await get_session_and_user(request, db)
    require_csrf(request, session)
    if not passwords.verify_password(user.password_hash, body.password):
        raise api_error(401, "invalid_credentials",
                        "Your password is incorrect.",
                        "Check your password and try again.")
    new_email = normalize_email(body.new_email)
    if new_email == user.email:
        raise api_error(400, "same_email",
                        "That is already your email address.",
                        "Enter a different email address.")
    existing = await db.execute(select(User).where(User.email == new_email))
    if existing.scalar_one_or_none() is not None:
        raise api_error(409, "email_taken",
                        "An account with this email already exists.",
                        "Choose a different email address.")
    # Email verification is OFF in the code (user order 2026-11-26):
    # the new email is applied immediately — no verification link is
    # sent and no token is created. The link flow below is the
    # behaviour when the flag is turned back on.
    if not get_settings().require_email_verification:
        user.email = new_email
        await db.commit()
        return {"message": "Your email has been changed."}
    token = await create_email_token(db, user, "change_email", 24 * 60, new_email=new_email)
    await send_template_email(
        db, "verify_email", new_email,
        "Verify your new email — Quick IMG Convert",
        "Hi {name},\n\nPlease verify your new email address by opening this link:\n{link}\n\n"
        "The link works for 24 hours.",
        name=user.display_name or "there", link=_verification_link(token),
    )
    return {"message": "We sent a verification link to your new email address."}


# ---------------------------------------------------------------- sessions

@router.get("/sessions")
async def list_sessions(
    request: Request, db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    current, _ = await get_session_and_user(request, db)
    result = await db.execute(
        select(Session).where(
            Session.user_id == user.id, Session.revoked_at.is_(None)
        ).order_by(Session.last_seen_at.desc())
    )
    out = []
    for s in result.scalars().all():
        device, browser = _device_browser(s.user_agent or "")
        out.append({
            "id": s.id,
            "device": device,
            "browser": browser,
            "ip": mask_ip(s.ip),
            "current": current is not None and s.id == current.id,
            "remember": s.remember,
            "last_seen_at": s.last_seen_at.isoformat() if s.last_seen_at else None,
            "created_at": s.created_at.isoformat() if s.created_at else None,
            "expires_at": s.expires_at.isoformat() if s.expires_at else None,
        })
    return {"sessions": out}


@router.delete("/sessions/{session_id}")
async def revoke_session(
    session_id: str, request: Request, response: Response,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    current, _ = await get_session_and_user(request, db)
    require_csrf(request, current)
    target = await db.get(Session, session_id)
    if target is None or target.user_id != user.id:
        raise api_error(404, "not_found", "That session was not found.", "It may already be revoked.")
    target.revoked_at = _now()
    await db.commit()
    if current is not None and target.id == current.id:
        set_session_cookie(response, None, False)
    return {"message": "Session revoked."}


@router.post("/sessions/revoke-others")
async def revoke_others(
    request: Request, db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    current, _ = await get_session_and_user(request, db)
    require_csrf(request, current)
    await revoke_all_sessions(db, user.id, except_id=current.id if current else None)
    return {"message": "All other devices have been signed out."}
