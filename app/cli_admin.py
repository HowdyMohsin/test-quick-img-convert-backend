"""CLI (v5 section 11): create-admin, seed, check-config.

First admin via CLI only — there are no default credentials anywhere.
Run from ``api/`` as ``python -m app.cli_admin <command>``.
``check-config`` validates env + provider configuration completeness
and makes NO network calls to payment providers.
"""

from __future__ import annotations

import argparse
import asyncio
import getpass
import os
import sys

from . import passwords
from .deps import get_engine, get_sessionmaker, get_settings, reset_engine, reset_settings
from .models import AdminUser, Base, PaymentProvider
from .seed import seed as run_seed


async def _ensure_tables() -> None:
    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def cmd_seed(_args) -> int:
    await _ensure_tables()
    session_maker = get_sessionmaker()
    async with session_maker() as db:
        counts = await run_seed(db)
    total = sum(counts.values())
    print(f"seed: inserted {total} rows " + str(counts))
    return 0


async def cmd_create_admin(args) -> int:
    await _ensure_tables()
    email = (args.email or "").strip().lower()
    if not email or "@" not in email:
        print("create-admin: --email must be a valid email address", file=sys.stderr)
        return 2
    password = args.password
    if not password:
        password = getpass.getpass("Admin password: ")
        confirm = getpass.getpass("Confirm admin password: ")
        if password != confirm:
            print("create-admin: passwords do not match", file=sys.stderr)
            return 2
    # Admin passwords: v5 section 13.2 requires a minimum of 12
    # characters at first login; enforce it here too.
    if len(password) < 12:
        print("create-admin: admin password must be at least 12 characters", file=sys.stderr)
        return 2
    error = passwords.validate_password(password)
    if error:
        print(f"create-admin: {error}", file=sys.stderr)
        return 2
    session_maker = get_sessionmaker()
    async with session_maker() as db:
        from sqlalchemy import select

        existing = await db.execute(select(AdminUser).where(AdminUser.email == email))
        if existing.scalar_one_or_none() is not None:
            print(f"create-admin: admin {email} already exists", file=sys.stderr)
            return 1
        admin = AdminUser(
            email=email,
            password_hash=passwords.hash_password(password),
            role="super_admin",
            permissions={"*": "write"},
            active=True,
            must_change_password=True,
        )
        db.add(admin)
        await db.commit()
    print(f"create-admin: created super_admin {email} (must change password at first login)")
    return 0


async def cmd_bootstrap_admin(_args) -> int:
    """Create the first admin from ADMIN_EMAIL/ADMIN_PASSWORD env vars.

    Localhost convenience, on the owner's explicit instruction: the
    final zip ships a .env with these values, so a fresh
    `docker compose up` already has a working admin login and no CLI
    step is needed to test. Idempotent — if the admin already exists
    it does nothing and returns 0. If either variable is unset it
    does nothing and returns 0 (CLI-only admin creation still works).
    Unlike create-admin, the bootstrapped admin is NOT forced to
    change the password at first login — change these credentials
    before going live.
    """
    await _ensure_tables()
    email = (os.environ.get("ADMIN_EMAIL") or "").strip().lower()
    password = os.environ.get("ADMIN_PASSWORD") or ""
    if not email or not password:
        print("bootstrap-admin: skipped (ADMIN_EMAIL/ADMIN_PASSWORD not set)")
        return 0
    if "@" not in email:
        print("bootstrap-admin: ADMIN_EMAIL must be a valid email address", file=sys.stderr)
        return 2
    if len(password) < 12:
        print("bootstrap-admin: ADMIN_PASSWORD must be at least 12 characters", file=sys.stderr)
        return 2
    error = passwords.validate_password(password)
    if error:
        print(f"bootstrap-admin: {error}", file=sys.stderr)
        return 2
    session_maker = get_sessionmaker()
    async with session_maker() as db:
        from sqlalchemy import select

        existing = await db.execute(select(AdminUser).where(AdminUser.email == email))
        if existing.scalar_one_or_none() is not None:
            print(f"bootstrap-admin: admin {email} already exists")
            return 0
        admin = AdminUser(
            email=email,
            password_hash=passwords.hash_password(password),
            role="super_admin",
            permissions={"*": "write"},
            active=True,
            must_change_password=False,
        )
        db.add(admin)
        await db.commit()
    print(f"bootstrap-admin: created super_admin {email} (ready to sign in)")
    return 0


async def cmd_check_config(_args) -> int:
    """Validate env + provider configuration. No network calls."""
    settings = get_settings()
    errors: list[str] = []
    warnings: list[str] = []

    def check(name: str, ok: bool, required: bool, detail: str = "") -> None:
        status = "ok" if ok else ("MISSING" if required else "warn")
        print(f"[{status}] {name}" + (f" — {detail}" if detail else ""))
        if not ok and required:
            errors.append(name)
        elif not ok:
            warnings.append(name)

    check("DATABASE_URL", bool(settings.database_url), True, settings.database_url.split("://")[0])
    check("SECRET_KEY", len(settings.secret_key) >= 32, True,
          "at least 32 characters" if len(settings.secret_key) >= 32 else "too short or unset")
    check("APP_SECRET", len(settings.app_secret) >= 32, True,
          "at least 32 characters" if len(settings.app_secret) >= 32 else "too short or unset")
    check("SITE_URL", bool(settings.site_url), True, settings.site_url)
    check("QUOTA_TZ", bool(settings.quota_tz), False, settings.quota_tz)
    check("DATA_DIR", bool(settings.data_dir), False, settings.data_dir)
    try:
        os.makedirs(settings.data_dir, exist_ok=True)
        probe = os.path.join(settings.data_dir, ".write-test")
        with open(probe, "w") as fh:
            fh.write("ok")
        os.remove(probe)
        check("DATA_DIR writable", True, True, settings.data_dir)
    except OSError as exc:
        check("DATA_DIR writable", False, True, str(exc))
    check("SMTP_HOST", bool(settings.smtp_host), False,
          settings.smtp_host or "transactional email will not send")
    if settings.smtp_host:
        check("SMTP_FROM", bool(settings.smtp_from), True, settings.smtp_from)
    check("GOOGLE_CLIENT_ID", bool(settings.google_client_id), False,
          "Google sign-in hidden" if not settings.google_client_id else "set")
    check("PKR_PER_USD", settings.pkr_per_usd > 0, False, str(settings.pkr_per_usd))
    check("common-password list", True, False, passwords.common_password_source())

    # Provider configuration completeness (DB read only, no network).
    try:
        await _ensure_tables()
        session_maker = get_sessionmaker()
        async with session_maker() as db:
            from sqlalchemy import select

            result = await db.execute(select(PaymentProvider).order_by(PaymentProvider.key))
            providers = result.scalars().all()
        if not providers:
            print("[warn] payment providers — no providers seeded (run seed)")
            warnings.append("payment providers")
        for p in providers:
            configured = bool(p.config)
            state = "enabled+configured" if (p.enabled and configured) else (
                "enabled, NOT configured" if p.enabled else "disabled")
            print(f"[{'ok' if p.enabled and configured else 'warn'}] provider {p.key} ({p.label}): {state}")
            if p.enabled and not configured:
                warnings.append(f"provider {p.key} enabled but not configured")
    except Exception as exc:  # DB unreachable: env checks above still stand
        print(f"[warn] payment providers — could not read database: {exc}")
        warnings.append("payment providers unreadable")

    print(f"check-config: {len(errors)} errors, {len(warnings)} warnings")
    return 1 if errors else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.cli_admin")
    sub = parser.add_subparsers(dest="command", required=True)
    p_admin = sub.add_parser("create-admin", help="Create the first admin (CLI only)")
    p_admin.add_argument("--email", required=True)
    p_admin.add_argument("--password", default=None,
                         help="If omitted, prompted securely")
    p_admin.set_defaults(func=cmd_create_admin)
    p_boot = sub.add_parser("bootstrap-admin",
                            help="Create the admin from ADMIN_EMAIL/ADMIN_PASSWORD env vars (idempotent)")
    p_boot.set_defaults(func=cmd_bootstrap_admin)
    p_seed = sub.add_parser("seed", help="Insert default plans/providers/slots/templates")
    p_seed.set_defaults(func=cmd_seed)
    p_check = sub.add_parser("check-config", help="Validate env + provider configuration")
    p_check.set_defaults(func=cmd_check_config)
    args = parser.parse_args(argv)
    reset_settings()
    reset_engine()
    return asyncio.run(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
