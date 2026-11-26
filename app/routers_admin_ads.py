"""Admin ads + popups + announcements endpoints (spec sections 5, 6, 13).

- Ad slots CRUD (validator rejects hard-banned placements; the renderer
  re-checks the same list), reorder, toggles.
- Networks + ads.txt (admin-editable field), consent configuration.
- Revenue entry + CSV import, RPM report.
- Popups and announcements CRUD (admin side; public read is
  GET /v1/marketing).

Every mutation writes an audit_log entry with a before/after diff.
"""
from __future__ import annotations

import csv
import io
from datetime import date, datetime, timezone
from typing import Any, Optional

from fastapi import APIRouter, Depends, File, Request, UploadFile
from pydantic import BaseModel
from sqlalchemy import select

from app.ads import (
    ADSENSE_ADS_TXT_LINE, SlotValidationError, build_ads_txt,
    revenue_report, validate_slot,
)
from app.billing import (
    client_ip, err, get_current_admin, get_db, get_site_setting,
    record_audit, resolve_models, utcnow,
)
from app.admin_auth import require_csrf
from app.popups import POPUP_KEYS, validate_popup

router = APIRouter(prefix="/admin/ads", tags=["admin-ads"])


class SlotBody(BaseModel):
    key: str
    label: Optional[str] = None
    placement: Optional[str] = None
    network: str
    unit_id: Optional[str] = None
    code: Optional[str] = None
    size: str = "responsive"
    device: str = "all"
    freq_cap: int = 0
    enabled: bool = True
    sort: int = 0
    # Legacy aliases (accepted, mapped to code / freq_cap by validate_slot).
    custom_html: Optional[str] = None
    frequency_cap: Optional[int] = None


class SlotPatchBody(BaseModel):
    label: Optional[str] = None
    placement: Optional[str] = None
    network: Optional[str] = None
    unit_id: Optional[str] = None
    code: Optional[str] = None
    size: Optional[str] = None
    device: Optional[str] = None
    freq_cap: Optional[int] = None
    enabled: Optional[bool] = None
    sort: Optional[int] = None
    # Legacy aliases (accepted, mapped to code / freq_cap).
    custom_html: Optional[str] = None
    frequency_cap: Optional[int] = None


class NetworksBody(BaseModel):
    adsense_publisher_id: Optional[str] = None
    auto_ads: Optional[bool] = None
    adsterra_key: Optional[str] = None
    ads_txt: Optional[str] = None
    cmp_provider: Optional[str] = None


class RevenueBody(BaseModel):
    network: str
    day: str  # YYYY-MM-DD
    amount_cents: int


class PopupBody(BaseModel):
    key: str
    enabled: bool = True
    title: Optional[str] = None
    body: Optional[str] = None
    cta_text: Optional[str] = None
    cta_href: Optional[str] = None
    frequency: Optional[str] = None
    schedule_start: Optional[str] = None
    schedule_end: Optional[str] = None
    pages: Optional[list[str]] = None
    sort: int = 0


class AnnouncementBody(BaseModel):
    title: Optional[str] = None
    body: Optional[str] = None
    enabled: bool = True
    starts_at: Optional[str] = None
    ends_at: Optional[str] = None
    dismissible: bool = True


def _admin_email(admin: Any) -> str:
    return getattr(admin, "email", "admin") or "admin"


def _slot_payload(slot: Any) -> dict:
    """Admin slot payload. Canonical column names (v5 section 10):
    the slot key IS its id (``key`` is the primary key)."""
    return {
        "key": slot.key, "label": slot.label,
        "placement": slot.placement, "network": slot.network,
        "unit_id": slot.unit_id, "code": slot.code,
        "size": slot.size, "device": slot.device,
        "freq_cap": slot.freq_cap, "enabled": slot.enabled,
        "sort": slot.sort,
    }


def _parse_dt(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except ValueError:
        raise err(400, "invalid_date", f"'{value}' is not a valid date/time.",
                  "Use ISO format, e.g. 2026-12-01T00:00:00Z.")


async def _get_setting(db, models, key: str) -> Optional[dict]:
    return await get_site_setting(db, models, key, None)


async def _set_setting(db, models, key: str, value: Any) -> None:
    row = (await db.execute(
        select(models.SiteSetting).where(models.SiteSetting.key == key)
    )).scalar_one_or_none()
    if row is None:
        row = models.SiteSetting(key=key, value=value)
    else:
        row.value = value
    db.add(row)


# ------------------------------------------------------------------- slots
@router.get("/slots")
async def list_slots(admin=Depends(get_current_admin), db=Depends(get_db)):
    models = resolve_models()
    rows = (await db.execute(
        select(models.AdSlot).order_by(models.AdSlot.sort)
    )).scalars().all()
    return {"slots": [_slot_payload(r) for r in rows]}


@router.post("/slots")
async def create_slot(body: SlotBody, http_request: Request,
                      admin=Depends(get_current_admin), _csrf: bool = Depends(require_csrf), db=Depends(get_db)):
    models = resolve_models()
    try:
        cleaned = validate_slot(body.model_dump())
    except SlotValidationError as exc:
        raise err(400, "banned_placement", str(exc),
                  "Choose one of the allowed placements.")
    slot = models.AdSlot(
        key=cleaned["key"],
        label=(body.label or "").strip() or cleaned["key"],
        placement=(body.placement or "").strip() or cleaned["key"],
        network=cleaned["network"], unit_id=cleaned.get("unit_id"),
        code=cleaned.get("code"), size=cleaned["size"],
        device=cleaned["device"], freq_cap=cleaned["freq_cap"],
        enabled=cleaned["enabled"], sort=body.sort)
    db.add(slot)
    await db.flush()
    await record_audit(db, models, _admin_email(admin), "ads.slot.create",
                       f"ad_slot:{slot.key}", None, _slot_payload(slot),
                       ip=client_ip(http_request))
    await db.commit()
    return _slot_payload(slot)


@router.patch("/slots/{slot_id}")
async def update_slot(slot_id: str, body: SlotPatchBody, http_request: Request,
                      admin=Depends(get_current_admin), _csrf: bool = Depends(require_csrf), db=Depends(get_db)):
    models = resolve_models()
    slot = (await db.execute(
        select(models.AdSlot).where(models.AdSlot.key == slot_id)
    )).scalar_one_or_none()
    if slot is None:
        raise err(404, "not_found", "That ad slot was not found.",
                  "Check the slot and try again.")
    before = _slot_payload(slot)
    merged = dict(before)
    incoming = {k: v for k, v in body.model_dump().items() if v is not None}
    # Legacy aliases map onto the canonical fields.
    if "custom_html" in incoming and "code" not in incoming:
        incoming["code"] = incoming.pop("custom_html")
    else:
        incoming.pop("custom_html", None)
    if "frequency_cap" in incoming and "freq_cap" not in incoming:
        incoming["freq_cap"] = incoming.pop("frequency_cap")
    else:
        incoming.pop("frequency_cap", None)
    merged.update(incoming)
    try:
        cleaned = validate_slot(merged)
    except SlotValidationError as exc:
        raise err(400, "banned_placement", str(exc),
                  "Choose one of the allowed placements.")
    for k in ("label", "placement", "network", "unit_id", "code", "size",
              "device", "freq_cap", "enabled", "sort"):
        if k in cleaned:
            setattr(slot, k, cleaned.get(k))
    db.add(slot)
    await record_audit(db, models, _admin_email(admin), "ads.slot.update",
                       f"ad_slot:{slot.key}", before, _slot_payload(slot),
                       ip=client_ip(http_request))
    await db.commit()
    return _slot_payload(slot)


class ReorderBody(BaseModel):
    direction: int  # -1 = up, +1 = down


@router.post("/slots/{slot_id}/reorder")
async def reorder_slot(slot_id: str, body: ReorderBody, http_request: Request,
                       admin=Depends(get_current_admin), _csrf: bool = Depends(require_csrf), db=Depends(get_db)):
    """Move a slot up/down by swapping its sort value with its neighbour."""
    models = resolve_models()
    rows = (await db.execute(
        select(models.AdSlot).order_by(models.AdSlot.sort, models.AdSlot.key)
    )).scalars().all()
    idx = next((i for i, r in enumerate(rows) if r.key == slot_id), None)
    if idx is None:
        raise err(404, "not_found", "That ad slot was not found.",
                  "Check the slot and try again.")
    neighbour = idx - 1 if body.direction < 0 else idx + 1
    if neighbour < 0 or neighbour >= len(rows):
        return {"slots": [_slot_payload(r) for r in rows]}
    rows[idx].sort, rows[neighbour].sort = rows[neighbour].sort, rows[idx].sort
    db.add(rows[idx])
    db.add(rows[neighbour])
    await record_audit(db, models, _admin_email(admin), "ads.slot.reorder",
                       f"ad_slot:{slot_id}", {"sort": rows[neighbour].sort},
                       {"sort": rows[idx].sort}, ip=client_ip(http_request))
    await db.commit()
    rows = (await db.execute(
        select(models.AdSlot).order_by(models.AdSlot.sort, models.AdSlot.key)
    )).scalars().all()
    return {"slots": [_slot_payload(r) for r in rows]}


@router.delete("/slots/{slot_id}")
async def delete_slot(slot_id: str, http_request: Request,
                      admin=Depends(get_current_admin), _csrf: bool = Depends(require_csrf), db=Depends(get_db)):
    models = resolve_models()
    slot = (await db.execute(
        select(models.AdSlot).where(models.AdSlot.key == slot_id)
    )).scalar_one_or_none()
    if slot is None:
        raise err(404, "not_found", "That ad slot was not found.",
                  "Check the slot and try again.")
    before = _slot_payload(slot)
    await db.delete(slot)
    await record_audit(db, models, _admin_email(admin), "ads.slot.delete",
                       f"ad_slot:{slot.key}", before, None,
                       ip=client_ip(http_request))
    await db.commit()
    return {"deleted": slot_id}


# ------------------------------------------------------- networks + ads.txt
@router.get("/networks")
async def get_networks(admin=Depends(get_current_admin), db=Depends(get_db)):
    models = resolve_models()
    settings = await _get_setting(db, models, "ads_networks") or {}
    if not isinstance(settings, dict):
        settings = {}
    ads_txt = await _get_setting(db, models, "ads_txt")
    if isinstance(ads_txt, dict):
        ads_txt = ads_txt.get("content")
    return {
        "adsense_publisher_id": settings.get("adsense_publisher_id"),
        "auto_ads": bool(settings.get("auto_ads", False)),
        "adsterra_key": settings.get("adsterra_key"),
        "ads_txt": ads_txt,
        "ads_txt_example": ADSENSE_ADS_TXT_LINE,
        "cmp_provider": (await _get_setting(db, models, "consent") or {}).get("cmp_provider"),
    }


@router.patch("/networks")
async def update_networks(body: NetworksBody, http_request: Request,
                          admin=Depends(get_current_admin), _csrf: bool = Depends(require_csrf), db=Depends(get_db)):
    models = resolve_models()
    before = await _get_setting(db, models, "ads_networks") or {}
    settings = dict(before if isinstance(before, dict) else {})
    for field in ("adsense_publisher_id", "auto_ads", "adsterra_key"):
        value = getattr(body, field)
        if value is not None:
            settings[field] = value
    await _set_setting(db, models, "ads_networks", settings)
    if body.ads_txt is not None:
        await _set_setting(db, models, "ads_txt", {"content": body.ads_txt})
    if body.cmp_provider is not None:
        consent = await _get_setting(db, models, "consent") or {}
        consent = dict(consent if isinstance(consent, dict) else {})
        consent["cmp_provider"] = body.cmp_provider
        await _set_setting(db, models, "consent", consent)
    await record_audit(db, models, _admin_email(admin), "ads.networks.update",
                       "ads_networks", before, settings, ip=client_ip(http_request))
    await db.commit()
    return {"updated": True, "ads_txt_set": body.ads_txt is not None}


@router.get("/ads-txt")
async def get_ads_txt_admin(admin=Depends(get_current_admin), db=Depends(get_db)):
    models = resolve_models()
    raw = await _get_setting(db, models, "ads_txt")
    content = None
    if isinstance(raw, dict):
        content = raw.get("content")
    elif isinstance(raw, str):
        content = raw
    return {"ads_txt": build_ads_txt(content),
            "example": ADSENSE_ADS_TXT_LINE}


# ------------------------------------------------------------ revenue / RPM
@router.get("/revenue")
async def get_revenue(admin=Depends(get_current_admin), db=Depends(get_db)):
    models = resolve_models()
    return {"networks": await revenue_report(db, models)}


@router.post("/revenue")
async def add_revenue(body: RevenueBody, http_request: Request,
                      admin=Depends(get_current_admin), _csrf: bool = Depends(require_csrf), db=Depends(get_db)):
    models = resolve_models()
    try:
        day = date.fromisoformat(body.day)
    except ValueError:
        raise err(400, "invalid_date", "Day must be YYYY-MM-DD.",
                  "Use the date picker to choose the day.")
    if body.amount_cents < 0:
        raise err(400, "invalid_amount", "Revenue cannot be negative.",
                  "Enter a valid amount in cents.")
    row = (await db.execute(
        select(models.AdRevenue).where(
            models.AdRevenue.network == body.network,
            models.AdRevenue.day == day)
    )).scalar_one_or_none()
    before = {"amount_cents": row.amount_cents} if row else None
    if row is None:
        row = models.AdRevenue(network=body.network, day=day,
                               amount_cents=body.amount_cents)
    else:
        row.amount_cents = body.amount_cents
    db.add(row)
    await record_audit(db, models, _admin_email(admin), "ads.revenue.set",
                       f"ad_revenue:{body.network}:{body.day}", before,
                       {"amount_cents": body.amount_cents},
                       ip=client_ip(http_request))
    await db.commit()
    return {"network": body.network, "day": body.day,
            "amount_cents": body.amount_cents}


@router.post("/revenue/import")
async def import_revenue(file: UploadFile = File(...), http_request: Request = None,
                         admin=Depends(get_current_admin), _csrf: bool = Depends(require_csrf), db=Depends(get_db)):
    models = resolve_models()
    raw = (await file.read()).decode("utf-8-sig", errors="replace")
    reader = csv.DictReader(io.StringIO(raw))
    imported = skipped = 0
    for line in reader:
        try:
            network = str(line.get("network") or "").strip()
            day = date.fromisoformat(str(line.get("day") or "").strip())
            amount = int(float(str(line.get("amount_cents") or "0").strip()))
        except (ValueError, TypeError):
            skipped += 1
            continue
        if not network or amount < 0:
            skipped += 1
            continue
        row = (await db.execute(
            select(models.AdRevenue).where(
                models.AdRevenue.network == network,
                models.AdRevenue.day == day)
        )).scalar_one_or_none()
        if row is None:
            row = models.AdRevenue(network=network, day=day, amount_cents=amount)
        else:
            row.amount_cents = amount
        db.add(row)
        imported += 1
    await record_audit(db, models, _admin_email(admin), "ads.revenue.import",
                       "ad_revenue", None, {"imported": imported, "skipped": skipped},
                       ip=client_ip(http_request) if http_request else None)
    await db.commit()
    return {"imported": imported, "skipped": skipped}


# ------------------------------------------------------------------ popups
@router.get("/popups")
async def list_popups(admin=Depends(get_current_admin), db=Depends(get_db)):
    models = resolve_models()
    rows = (await db.execute(
        select(models.Popup).order_by(models.Popup.sort)
    )).scalars().all()
    return {"popups": [{
        "key": p.key, "enabled": p.enabled, "title": p.title, "body": p.body,
        "cta_text": p.cta_text, "cta_href": p.cta_href,
        "frequency": p.frequency,
        "schedule_start": p.schedule_start.isoformat() if p.schedule_start else None,
        "schedule_end": p.schedule_end.isoformat() if p.schedule_end else None,
        "pages": p.pages, "sort": p.sort,
    } for p in rows]}


@router.put("/popups/{key}")
async def upsert_popup(key: str, body: PopupBody, http_request: Request,
                       admin=Depends(get_current_admin), _csrf: bool = Depends(require_csrf), db=Depends(get_db)):
    models = resolve_models()
    if key not in POPUP_KEYS:
        raise err(400, "unknown_popup", f"Unknown popup '{key}'.",
                  "Use one of: " + ", ".join(POPUP_KEYS))
    try:
        validate_popup({"key": key, "enabled": body.enabled})
    except ValueError as exc:
        raise err(400, "invalid_popup", str(exc), "Check the popup fields.")
    row = (await db.execute(
        select(models.Popup).where(models.Popup.key == key)
    )).scalar_one_or_none()
    before = {"enabled": row.enabled, "title": row.title} if row else None
    if row is None:
        row = models.Popup(key=key)
    row.enabled = body.enabled
    row.title = body.title
    row.body = body.body
    row.cta_text = body.cta_text
    row.cta_href = body.cta_href
    row.frequency = body.frequency
    row.schedule_start = _parse_dt(body.schedule_start)
    row.schedule_end = _parse_dt(body.schedule_end)
    row.pages = body.pages
    row.sort = body.sort
    db.add(row)
    await record_audit(db, models, _admin_email(admin), "ads.popup.update",
                       f"popup:{key}", before,
                       {"enabled": row.enabled, "title": row.title},
                       ip=client_ip(http_request))
    await db.commit()
    return {"key": key, "enabled": row.enabled}


# ------------------------------------------------------------ announcements
@router.get("/announcements")
async def list_announcements(admin=Depends(get_current_admin), db=Depends(get_db)):
    models = resolve_models()
    rows = (await db.execute(
        select(models.Announcement).order_by(models.Announcement.id.desc())
    )).scalars().all()
    return {"announcements": [{
        "id": a.id, "title": a.title, "body": a.body, "enabled": a.enabled,
        "starts_at": a.starts_at.isoformat() if a.starts_at else None,
        "ends_at": a.ends_at.isoformat() if a.ends_at else None,
        "dismissible": a.dismissible,
    } for a in rows]}


@router.post("/announcements")
async def create_announcement(body: AnnouncementBody, http_request: Request,
                              admin=Depends(get_current_admin), _csrf: bool = Depends(require_csrf), db=Depends(get_db)):
    models = resolve_models()
    row = models.Announcement(
        title=body.title, body=body.body, enabled=body.enabled,
        starts_at=_parse_dt(body.starts_at), ends_at=_parse_dt(body.ends_at),
        dismissible=body.dismissible)
    db.add(row)
    await db.flush()
    await record_audit(db, models, _admin_email(admin), "ads.announcement.create",
                       f"announcement:{row.id}", None,
                       {"title": row.title, "enabled": row.enabled},
                       ip=client_ip(http_request))
    await db.commit()
    return {"id": row.id, "title": row.title, "enabled": row.enabled}


@router.delete("/announcements/{announcement_id}")
async def delete_announcement(announcement_id: int, http_request: Request,
                              admin=Depends(get_current_admin), _csrf: bool = Depends(require_csrf), db=Depends(get_db)):
    models = resolve_models()
    row = (await db.execute(
        select(models.Announcement).where(models.Announcement.id == announcement_id)
    )).scalar_one_or_none()
    if row is None:
        raise err(404, "not_found", "That announcement was not found.",
                  "Check the announcement and try again.")
    await db.delete(row)
    await record_audit(db, models, _admin_email(admin), "ads.announcement.delete",
                       f"announcement:{announcement_id}",
                       {"title": row.title}, None, ip=client_ip(http_request))
    await db.commit()
    return {"deleted": announcement_id}
