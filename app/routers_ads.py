"""Public ads endpoints (spec sections 5, 11).

- GET /v1/ads?slots= — payloads ONLY for ad-eligible plans; the server
  decides eligibility from the plan's ads flag, the client never does.
  Banned users never see ads. The renderer re-checks banned placements.
- POST /v1/ads/impressions — batched viewport-impression beacons,
  deduplicated per slot per page view.
- GET /ads.txt — served as text/plain from the admin-editable field;
  404 while empty. (The web app also serves it; this route is the API
  fallback.)
"""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, Request
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel
from sqlalchemy import select

from app.ads import (
    ads_eligible_for_user, get_ads_txt, record_impressions,
    renderable_slots, slot_payload,
)
from app.billing import err, get_db, get_optional_user, resolve_models

router = APIRouter(prefix="/v1/ads", tags=["ads"])
ads_txt_router = APIRouter(tags=["ads-txt"])


class ImpressionEvent(BaseModel):
    slot: str
    # The web beacon sends no page_view_id (one beacon per page view);
    # dedup within a batch still applies when it is present.
    page_view_id: Optional[str] = ""
    page: Optional[str] = ""
    device: Optional[str] = ""


class ImpressionsBody(BaseModel):
    events: list[ImpressionEvent] = []


@router.get("")
async def get_ads(slots: str = "", page: str = "/",
                  checkout_active: bool = False,
                  device: str = "desktop",
                  user=Depends(get_optional_user), db=Depends(get_db)):
    models = resolve_models()
    if not await ads_eligible_for_user(db, models, user):
        return {"ads": [], "eligible": False}
    plan_id = getattr(user, "plan", None) if user is not None else "anonymous"
    wanted = [s.strip() for s in (slots or "").split(",") if s.strip()]
    rows = (await db.execute(
        select(models.AdSlot).where(models.AdSlot.enabled.is_(True))
        .order_by(models.AdSlot.sort)
    )).scalars().all()
    if wanted:
        rows = [r for r in rows if r.key in wanted]
    renderable = renderable_slots(rows, page=page,
                                  checkout_active=checkout_active, device=device)
    return {
        "ads": [slot_payload(s) for s in renderable],
        "eligible": True,
        "plan": plan_id,
        "house_ad": {
            "title": "Enjoying Quick IMG Convert? Go ad-free with Pro",
            "href": "/pricing",
        },
    }


@router.post("/impressions")
async def post_impressions(body: ImpressionsBody,
                           user=Depends(get_optional_user), db=Depends(get_db)):
    models = resolve_models()
    plan_id = getattr(user, "plan", None) if user is not None else "anonymous"
    result = await record_impressions(
        db, models, plan=plan_id,
        events=[e.model_dump() for e in body.events])
    await db.commit()
    return result


@ads_txt_router.get("/ads.txt", response_class=PlainTextResponse)
async def ads_txt(db=Depends(get_db)):
    models = resolve_models()
    content = await get_ads_txt(db, models)
    if content is None:
        raise err(404, "not_found", "ads.txt is not configured yet.",
                  "The site owner adds it in the admin panel.")
    return PlainTextResponse(content=content, media_type="text/plain")
