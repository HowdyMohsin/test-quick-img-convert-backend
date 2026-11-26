"""Marketing + notifications endpoints (spec sections 6, 11).

- GET /v1/marketing — announcement, popup configs, consent.
- GET /v1/notifications, POST /v1/notifications/read,
  POST /v1/notifications/read-all.
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import select

from app.billing import err, get_current_user, get_db, resolve_models
from app.notifications import (
    list_notifications, mark_all_read, mark_read, notification_payload,
    unread_count,
)
from app.popups import get_marketing_payload

logger = logging.getLogger(__name__)

router = APIRouter(tags=["marketing"])
notifications_router = APIRouter(prefix="/v1/notifications",
                                 tags=["notifications"])


class ReadBody(BaseModel):
    id: str


@router.get("/v1/marketing")
async def marketing(page: str = "/", db=Depends(get_db)):
    models = resolve_models()
    return await get_marketing_payload(db, models, page=page)


@notifications_router.get("")
async def get_notifications(unread_only: bool = False, limit: int = 50,
                            user=Depends(get_current_user), db=Depends(get_db)):
    models = resolve_models()
    notes = await list_notifications(db, models, user.id, limit=limit,
                                     unread_only=unread_only)
    payloads = []
    for n in notes:
        try:
            payloads.append(notification_payload(n))
        except Exception:
            # One bad row must never take down the whole list.
            logger.warning("skipping unserializable notification %s",
                           getattr(n, "id", "?"), exc_info=True)
    return {
        "notifications": payloads,
        "unread": await unread_count(db, models, user.id),
    }


@notifications_router.post("/read")
async def read_notification(body: ReadBody, user=Depends(get_current_user),
                            db=Depends(get_db)):
    models = resolve_models()
    if not await mark_read(db, models, user.id, body.id):
        raise err(404, "not_found", "That notification was not found.",
                  "Check the notification and try again.")
    await db.commit()
    return {"id": body.id, "read": True}


@notifications_router.post("/read-all")
async def read_all_notifications(user=Depends(get_current_user),
                                 db=Depends(get_db)):
    models = resolve_models()
    count = await mark_all_read(db, models, user.id)
    await db.commit()
    return {"read": count}
