"""Transactional mail (v5 section 9): SMTP via environment, stdlib only.

All sending is synchronous smtplib executed in a thread (via
``asyncio.to_thread``) so the async API never blocks. Templates are
rendered from the ``email_templates`` table with ``{name} {plan}
{reference} {amount} {reason} {date} {link}`` placeholders; the seed
data supplies the default copy.
"""

from __future__ import annotations

import asyncio
import smtplib
from email.message import EmailMessage

from .brand import BRAND_FROM_NAME
from .deps import get_settings


def render_template(subject: str, body: str, **values: object) -> tuple[str, str]:
    """Substitute ``{placeholder}`` values; unknown placeholders stay put."""
    mapping = {k: "" if v is None else str(v) for k, v in values.items()}

    class _SafeDict(dict):
        def __missing__(self, key):
            return "{" + key + "}"

    return subject.format_map(_SafeDict(mapping)), body.format_map(_SafeDict(mapping))


def send_mail_sync(to_email: str, subject: str, body: str, html_body: str | None = None) -> None:
    """Send one message with smtplib. Raises on SMTP failure (caller logs)."""
    settings = get_settings()
    msg = EmailMessage()
    msg["From"] = f"{BRAND_FROM_NAME} <{settings.smtp_from}>"
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.set_content(body)
    if html_body:
        msg.add_alternative(html_body, subtype="html")
    host = settings.smtp_host
    port = settings.smtp_port
    if port == 465:
        server: smtplib.SMTP = smtplib.SMTP_SSL(host, port, timeout=20)
    else:
        server = smtplib.SMTP(host, port, timeout=20)
    try:
        server.ehlo()
        if port == 587:
            server.starttls()
            server.ehlo()
        if settings.smtp_user:
            server.login(settings.smtp_user, settings.smtp_password or "")
        server.send_message(msg)
    finally:
        try:
            server.quit()
        except Exception:
            pass


async def send_mail(to_email: str, subject: str, body: str, html_body: str | None = None) -> bool:
    """Best-effort async send. Returns False (never raises) when mail is
    not configured or delivery fails, so auth flows are not blocked by
    a mail outage; the caller logs the failure."""
    settings = get_settings()
    if not settings.smtp_host:
        return False
    try:
        await asyncio.to_thread(send_mail_sync, to_email, subject, body, html_body)
        return True
    except Exception:
        return False


def mail_configured() -> bool:
    settings = get_settings()
    return bool(settings.smtp_host and settings.smtp_from)
