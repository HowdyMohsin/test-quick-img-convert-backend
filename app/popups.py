"""Popups and marketing config for Quick IMG Convert v5 (spec section 6).

Popup keys and triggers:
- limit_popup: daily cap hit -> plan-compare modal, once per session.
- batch_popup: dropped files exceed the batch limit -> explainer + upgrade
  CTA, once per session.
- exit_popup: exit intent on home and pricing, desktop only, once per
  7 days per visitor.
- announce_bar: slim top banner with start/end schedule, always while
  scheduled, dismissible.
- success_toast: post-conversion nudge for ad-viewing plans, once per
  session.

Rules: only one overlay may show at a time; priority is limit, batch,
success, exit. Popups never appear on /login, /account, checkout or
legal pages.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import select

POPUP_KEYS = ("limit_popup", "batch_popup", "exit_popup", "announce_bar",
              "success_toast")
POPUP_PRIORITY = ["limit_popup", "batch_popup", "success_toast", "exit_popup"]
POPUP_BANNED_PAGES = {
    "/login", "/forgot-password", "/reset-password", "/verify-email",
    "/account", "/privacy-policy", "/terms", "/contact",
}
POPUP_BANNED_PREFIXES = ("/admin", "/account", "/checkout")


def popup_allowed_on_page(key: str, page: str) -> bool:
    page = (page or "/").split("?")[0].rstrip("/") or "/"
    if page in POPUP_BANNED_PAGES:
        return False
    for prefix in POPUP_BANNED_PREFIXES:
        if page == prefix or page.startswith(prefix + "/"):
            return False
    if key == "exit_popup" and page not in ("/", "/pricing"):
        return False
    return True


def validate_popup(data: dict) -> dict:
    key = str(data.get("key") or "").strip()
    if key not in POPUP_KEYS:
        raise ValueError(
            f"Unknown popup '{key}'. Use one of: " + ", ".join(POPUP_KEYS))
    cleaned = dict(data)
    cleaned["key"] = key
    cleaned["enabled"] = bool(data.get("enabled", True))
    return cleaned


def _schedule_window(popup: Any) -> tuple[Optional[datetime], Optional[datetime]]:
    """Start/end window for a popup. The Popup model stores the window in
    its ``schedule`` JSON column ({"start": ..., "end": ...}) — there are
    no schedule_start/schedule_end columns."""
    schedule = getattr(popup, "schedule", None) or {}
    if not isinstance(schedule, dict):
        return None, None
    start = schedule.get("start") or schedule.get("schedule_start")
    end = schedule.get("end") or schedule.get("schedule_end")
    return _coerce_dt(start), _coerce_dt(end)


def _coerce_dt(value: Any) -> Optional[datetime]:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def popup_payload(popup: Any) -> dict:
    start, end = _schedule_window(popup)
    return {
        "key": popup.key,
        "enabled": popup.enabled,
        "title": popup.title,
        "body": popup.body,
        "cta_text": popup.cta_text,
        "cta_href": popup.cta_href,
        "frequency": popup.frequency,
        "schedule_start": start.isoformat() if start else None,
        "schedule_end": end.isoformat() if end else None,
        "pages": popup.pages,
    }


def pick_overlay(popups: list[dict]) -> Optional[dict]:
    """At most one overlay at a time, by priority limit > batch > success > exit."""
    enabled = {p["key"]: p for p in popups if p.get("enabled")}
    for key in POPUP_PRIORITY:
        if key in enabled:
            return enabled[key]
    return None


def _in_schedule(start: Optional[datetime], end: Optional[datetime],
                 now: Optional[datetime] = None) -> bool:
    now = now or datetime.now(timezone.utc)
    if start is not None:
        s = start if start.tzinfo else start.replace(tzinfo=timezone.utc)
        if now < s:
            return False
    if end is not None:
        e = end if end.tzinfo else end.replace(tzinfo=timezone.utc)
        if now > e:
            return False
    return True


async def get_marketing_payload(db, models, *, page: str = "/") -> dict:
    """Payload for GET /v1/marketing: announcement, popup configs, consent."""
    from app.ads import get_consent_config, get_consent_settings
    now = datetime.now(timezone.utc)
    popups = (await db.execute(
        select(models.Popup).order_by(models.Popup.key)
    )).scalars().all()
    popup_list = []
    for p in popups:
        if not p.enabled:
            continue
        if not popup_allowed_on_page(p.key, page):
            continue
        start, end = _schedule_window(p)
        if p.key == "announce_bar" and not _in_schedule(start, end, now):
            continue
        popup_list.append(popup_payload(p))
    announcements = (await db.execute(
        select(models.Announcement).where(models.Announcement.enabled.is_(True))
        .order_by(models.Announcement.id.desc())
    )).scalars().all()
    active_announcement = None
    for a in announcements:
        if _in_schedule(a.starts_at, a.ends_at, now):
            # The Announcement model has a single `text` column; the web
            # app reads announcement.text.
            active_announcement = {
                "id": a.id, "text": a.text, "enabled": a.enabled,
                "starts_at": a.starts_at.isoformat() if a.starts_at else None,
                "ends_at": a.ends_at.isoformat() if a.ends_at else None,
            }
            break
    consent_settings = await get_consent_settings(db, models)
    return {
        "announcement": active_announcement,
        "popups": popup_list,
        "overlay": pick_overlay(popup_list),
        "consent": get_consent_config(consent_settings),
    }
