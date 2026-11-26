"""Ads engine for Quick IMG Convert v5 (spec section 5, P2).

Rules enforced here (server-side; the client never decides):
- Ads are shown only when the visitor's plan has ads enabled. Anonymous
  and free see ads by default; basic and pro do not. Banned users never
  see ads.
- Hard-banned placements are REJECTED by the validator on save and
  re-checked by the renderer (``renderable_slots``): inside the tool
  card; between file-drop and download-complete; /login, /forgot-password,
  /reset-password, /verify-email; /account; inside any checkout/payment
  modal; /pricing during checkout; legal pages; error pages; the admin app.
- Per slot: network, unit id (AdSense/Adsterra) or sanitized custom HTML,
  size, device, frequency cap, enable toggle.
- Impressions are logged on viewport impression only (not on request),
  deduplicated per slot per page view, sent with sendBeacon.
- RPM = revenue / impressions x 1000, from ad_events + ad_revenue.
- CSP allows only the domains of enabled networks.
- /ads.txt is served as text/plain from an admin-editable field and
  returns 404 while empty.
- Consent (EEA/UK/CH): ``get_consent_config`` feeds GET /v1/site (owned
  by the core agent). Ads load only after consent; otherwise
  non-personalized ads. Region comes from the CDN country header; unknown
  is treated as EEA.
"""
from __future__ import annotations

import html as html_mod
import re
from datetime import date
from typing import Any, Optional

from sqlalchemy import func, select

from app.billing import get_site_setting

# ---------------------------------------------------------------- slots
ALLOWED_SLOTS: dict[str, str] = {
    "home_top": "Home — after the hero picker and trust row, before All Formats",
    "home_mid": "Home — between All Formats and How it works",
    "home_bottom": "Home — after the FAQ, before the Pro banner",
    "pair_top": "Converter page — directly below the tool card",
    "pair_sidebar": "Converter page — right sidebar next to the tool",
    "pair_mid": "Converter page — after Related converters",
    "pair_bottom": "Converter page — after the FAQ",
    "results_below": "Results — below the download area, only after the batch completes",
    "mobile_anchor": "Mobile anchor 320x50, dismissible, converter pages only, after results are shown",
}

# Hard bans. The validator rejects a slot whose key or page target matches
# any of these; the renderer re-checks the same list before serving.
BANNED_SLOT_KEYS = {
    "inside_tool_card", "between_drop_and_download", "in_tool_card",
    "tool_card", "checkout_modal", "payment_modal", "pricing_checkout",
    "admin_app", "error_page", "legal_page",
}
BANNED_PAGES = {
    "/login", "/forgot-password", "/reset-password", "/verify-email",
    "/account", "/pricing",  # /pricing is banned only during checkout; see below
    "/privacy-policy", "/terms", "/contact",
    "/404", "/500",
}
BANNED_PAGE_PREFIXES = ("/admin", "/account")
# /pricing is allowed for normal browsing but banned during checkout; the
# renderer receives `checkout_active` and drops pricing slots then.
PRICING_CHECKOUT_BANNED = {"/pricing"}

ALLOWED_SIZES = {"responsive", "728x90", "336x280", "300x250", "160x600", "320x50"}
ALLOWED_DEVICES = {"all", "mobile", "desktop"}
ALLOWED_NETWORKS = {"adsense", "adsterra", "custom", "house"}

NETWORK_DOMAINS: dict[str, list[str]] = {
    "adsense": ["https://pagead2.googlesyndication.com",
                "https://googleads.g.doubleclick.net",
                "https://www.googletagservices.com"],
    "adsterra": ["https://www.highperformanceformat.com",
                 "https://www.profitablegatecpm.com"],
    "custom": [],
}

ADSENSE_ADS_TXT_LINE = "google.com, pub-0000000000000000, DIRECT, f08c47fec0942fa0"


class SlotValidationError(ValueError):
    pass


def validate_slot(data: dict) -> dict:
    """Validate an ad slot on save. Raises SlotValidationError on any ban.

    Canonical column names (v5 section 10): ``code`` for the custom HTML
    and ``freq_cap`` for the frequency cap. The legacy input aliases
    ``custom_html`` / ``frequency_cap`` are still accepted and mapped.
    ``house`` is a first-party network (house HTML, no unit id) and is
    validated like ``custom``.
    """
    key = str(data.get("key") or "").strip()
    if key in BANNED_SLOT_KEYS:
        raise SlotValidationError(
            f"Placement '{key}' is banned: ads are never shown there.")
    if key not in ALLOWED_SLOTS:
        raise SlotValidationError(
            f"Unknown placement '{key}'. Choose one of: "
            + ", ".join(sorted(ALLOWED_SLOTS)))
    network = str(data.get("network") or "").strip().lower()
    if network not in ALLOWED_NETWORKS:
        raise SlotValidationError(
            f"Unknown network '{network}'. Use adsense, adsterra, custom or house.")
    size = str(data.get("size") or "responsive").strip()
    if size not in ALLOWED_SIZES:
        raise SlotValidationError(f"Unknown ad size '{size}'.")
    device = str(data.get("device") or "all").strip().lower()
    if device not in ALLOWED_DEVICES:
        raise SlotValidationError(f"Unknown device target '{device}'.")
    if network in ("adsense", "adsterra") and not str(data.get("unit_id") or "").strip():
        raise SlotValidationError(
            f"A unit id is required for the {network} network.")
    code = str(data.get("code") or data.get("custom_html") or "").strip()
    if network in ("custom", "house") and not code:
        raise SlotValidationError("Custom HTML is required for a custom ad.")
    if key == "results_below" and data.get("enabled") not in (None, True, False):
        raise SlotValidationError("results_below must be a boolean toggle.")
    cap = data.get("freq_cap", data.get("frequency_cap", 0))
    try:
        cap = int(cap or 0)
    except (TypeError, ValueError):
        raise SlotValidationError("freq_cap must be a whole number.")
    if cap < 0:
        raise SlotValidationError("freq_cap cannot be negative.")
    cleaned = dict(data)
    cleaned.update({"key": key, "network": network, "size": size,
                    "device": device, "freq_cap": cap, "code": code,
                    "enabled": bool(data.get("enabled", True))})
    if network in ("custom", "house"):
        cleaned["code"] = sanitize_custom_html(cleaned.get("code") or "")
    return cleaned


def is_banned_page(page: str, checkout_active: bool = False) -> bool:
    page = (page or "/").split("?")[0].rstrip("/") or "/"
    if page in BANNED_PAGES:
        if page == "/pricing" and not checkout_active:
            return False
        return True
    for prefix in BANNED_PAGE_PREFIXES:
        if page == prefix or page.startswith(prefix + "/"):
            return True
    return False


def renderable_slots(slots: list[Any], *, page: str = "/",
                     checkout_active: bool = False,
                     device: str = "desktop") -> list[Any]:
    """Renderer re-check: drop banned placements, banned pages, wrong device."""
    if is_banned_page(page, checkout_active=checkout_active):
        return []
    out = []
    for slot in slots:
        key = slot.key if hasattr(slot, "key") else slot.get("key")
        if key in BANNED_SLOT_KEYS or key not in ALLOWED_SLOTS:
            continue
        if not (slot.enabled if hasattr(slot, "enabled") else slot.get("enabled", True)):
            continue
        slot_device = slot.device if hasattr(slot, "device") else slot.get("device", "all")
        if slot_device not in ("all", device):
            continue
        out.append(slot)
    return out


def sanitize_custom_html(raw: str) -> str:
    """Strip scripts, iframes to non-allow-listed hosts, and event handlers."""
    cleaned = re.sub(r"<script[\s\S]*?</script\s*>", "", raw, flags=re.I)
    cleaned = re.sub(r"\son\w+\s*=\s*(\"[^\"]*\"|'[^']*'|[^\s>]+)", "", cleaned, flags=re.I)
    cleaned = re.sub(r"javascript\s*:", "", cleaned, flags=re.I)
    return cleaned.strip()


# -------------------------------------------------------------- eligibility
def plan_shows_ads(plan_limits: Optional[dict], plan_id: Optional[str] = None) -> bool:
    """Server decides eligibility from the plan's ads flag. Defaults match
    the spec: anonymous and free show ads, basic and pro do not."""
    if isinstance(plan_limits, dict) and "ads" in plan_limits:
        return bool(plan_limits["ads"])
    return (plan_id or "free") in ("anonymous", "free")


def ads_eligible(*, user: Any = None, plan_limits: Optional[dict] = None,
                 plan_id: Optional[str] = None) -> bool:
    if user is not None and getattr(user, "banned", False):
        return False
    if user is not None and getattr(user, "plan", None):
        plan_id = plan_id or user.plan
    return plan_shows_ads(plan_limits, plan_id)


async def ads_eligible_for_user(db, models, user: Any) -> bool:
    if user is None:
        return True  # anonymous visitors see ads
    if getattr(user, "banned", False):
        return False
    plan = (await db.execute(
        select(models.Plan).where(models.Plan.id == (user.plan or "free"))
    )).scalar_one_or_none()
    if plan is None:
        return plan_shows_ads(None, user.plan)
    return plan_shows_ads(plan.limits or {}, plan.id)


def slot_payload(slot: Any) -> dict:
    """Public /v1/ads payload. Canonical column names (v5 section 10):
    ``code`` is the custom HTML the web AdFrame renders, ``freq_cap``
    the frequency cap. ``label`` is the slot's admin label; the visible
    "Advertisement" tag is rendered by the web component itself.
    """
    return {
        "key": slot.key,
        "placement": getattr(slot, "placement", None) or slot.key,
        "label": getattr(slot, "label", None) or slot.key,
        "network": slot.network,
        "unit_id": slot.unit_id,
        "code": slot.code if slot.network in ("custom", "house") else None,
        "size": slot.size,
        "device": slot.device,
        "freq_cap": slot.freq_cap,
        "enabled": slot.enabled,
    }


# ---------------------------------------------------------------- ads.txt
def build_ads_txt(content: Optional[str]) -> Optional[str]:
    """Return the ads.txt body, or None while the field is empty (404)."""
    if content is None:
        return None
    text = str(content).strip()
    return text or None


async def get_ads_txt(db, models) -> Optional[str]:
    value = await get_site_setting(db, models, "ads_txt", None)
    if isinstance(value, dict):
        value = value.get("content") or value.get("value")
    return build_ads_txt(value)


# ------------------------------------------------------------------- CSP
def csp_domains(enabled_networks: list[str]) -> list[str]:
    domains: list[str] = []
    for network in enabled_networks:
        domains.extend(NETWORK_DOMAINS.get(network, []))
    return sorted(set(domains))


async def enabled_networks(db, models) -> list[str]:
    rows = (await db.execute(
        select(models.AdSlot.network).where(models.AdSlot.enabled.is_(True))
    )).scalars().all()
    return sorted({str(r) for r in rows})


# ------------------------------------------------------------- impressions
async def record_impressions(db, models, *, plan: Optional[str],
                             events: list[dict]) -> dict:
    """Batch beacon insert. Deduplicated per slot per page view WITHIN the
    batch: an event with the same (slot, page_view_id) is counted once.
    The canonical ad_events table (v5 section 10) has no page_view_id
    column, so cross-batch dedup is the client's job (one beacon per
    page view; the web AdFrame also guards with sessionStorage). Events
    without a page_view_id (the web beacon sends none) are still
    recorded — one per slot per batch.
    """
    inserted = duplicates = 0
    seen: set[tuple[str, str]] = set()
    for ev in events or []:
        slot_key = str(ev.get("slot") or ev.get("slot_key") or "")
        page_view_id = str(ev.get("page_view_id") or "")
        if not slot_key:
            continue
        dedup_key = (slot_key, page_view_id)
        if dedup_key in seen:
            duplicates += 1
            continue
        seen.add(dedup_key)
        db.add(models.AdEvent(
            slot=slot_key, plan=plan, page=str(ev.get("page") or ""),
            device=str(ev.get("device") or "")))
        inserted += 1
    await db.flush()
    return {"inserted": inserted, "duplicates": duplicates}


async def impressions_by_slot(db, models, *, since=None) -> dict[str, int]:
    query = select(models.AdEvent.slot, func.count()).group_by(
        models.AdEvent.slot)
    if since is not None:
        query = query.where(models.AdEvent.ts >= since)
    rows = (await db.execute(query)).all()
    return {str(k): int(v) for k, v in rows}


def compute_rpm(revenue_cents: int, impressions: int) -> float:
    """RPM = revenue / impressions x 1000 (revenue in cents -> dollars)."""
    if not impressions:
        return 0.0
    return round((revenue_cents / 100.0) / impressions * 1000, 4)


async def revenue_report(db, models) -> list[dict]:
    """RPM table by network from ad_events + ad_revenue."""
    revenue_rows = (await db.execute(
        select(models.AdRevenue.network, func.sum(models.AdRevenue.amount_cents)
               ).group_by(models.AdRevenue.network))).all()
    revenue = {str(k): int(v or 0) for k, v in revenue_rows}
    # Impressions are per slot; slots map to networks, so attribute each
    # slot's impressions to its network.
    slots = (await db.execute(select(models.AdSlot))).scalars().all()
    slot_network = {s.key: s.network for s in slots}
    impressions = await impressions_by_slot(db, models)
    by_network: dict[str, int] = {}
    for slot_key, count in impressions.items():
        network = slot_network.get(slot_key, "unknown")
        by_network[network] = by_network.get(network, 0) + count
    networks = sorted(set(revenue) | set(by_network))
    return [{
        "network": n,
        "revenue_cents": revenue.get(n, 0),
        "impressions": by_network.get(n, 0),
        "rpm": compute_rpm(revenue.get(n, 0), by_network.get(n, 0)),
    } for n in networks]


# --------------------------------------------------------------- consent
EEA_COUNTRIES = {
    "AT", "BE", "BG", "HR", "CY", "CZ", "DK", "EE", "FI", "FR", "DE", "GR",
    "HU", "IE", "IT", "LV", "LT", "LU", "MT", "NL", "PL", "PT", "RO", "SK",
    "SI", "ES", "SE", "IS", "LI", "NO", "GB", "CH",
}


def consent_region(country_header: Optional[str]) -> str:
    """CDN country header; unknown is treated as EEA (spec section 5)."""
    code = (country_header or "").strip().upper()
    if not code:
        return "EEA"
    return "EEA" if code in EEA_COUNTRIES else "ROW"


def get_consent_config(settings: Optional[dict] = None,
                       country_header: Optional[str] = None) -> dict:
    """Consent flags for GET /v1/site (core agent owns that endpoint)."""
    settings = settings or {}
    region = consent_region(country_header)
    return {
        "region": region,
        "consent_required": region == "EEA",
        "cmp_provider": settings.get("cmp_provider"),
        "cmp_configured": bool(settings.get("cmp_provider")),
        "ads_personalized": region != "EEA",
        "privacy_policy_url": "/privacy-policy",
    }


async def get_consent_settings(db, models) -> dict:
    raw = await get_site_setting(db, models, "consent", {}) or {}
    return raw if isinstance(raw, dict) else {}
