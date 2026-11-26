"""In-app notifications for Quick IMG Convert v5.

Created on: payment submitted / approved / rejected, past_due,
subscription ended / renewed / canceled / activated, verification,
welcome. The core agent's ``GET /v1/me`` reads the unread count from
here; the endpoints live in ``app.routers_marketing``.

Column mapping (canonical ``app.models.Notification``, v5 section 10):
the table stores ``href`` and a boolean ``read`` flag. Callers pass
``link=`` (the API field name); this module maps it to ``href`` so the
public payload keeps the stable ``link`` / ``read`` shape.
"""
from __future__ import annotations

from typing import Any, Optional

from sqlalchemy import func, select

from app.billing import new_uuid


async def create_notification(db, models, user_id: str, kind: str,
                              title: str, body: str = "",
                              link: Optional[str] = None):
    note = models.Notification(
        id=new_uuid(), user_id=user_id, kind=kind, title=title,
        body=body, href=link)
    db.add(note)
    await db.flush()
    return note


async def list_notifications(db, models, user_id: str, limit: int = 50,
                             offset: int = 0, unread_only: bool = False):
    query = select(models.Notification).where(
        models.Notification.user_id == user_id)
    if unread_only:
        query = query.where(models.Notification.read.is_(False))
    query = query.order_by(models.Notification.created_at.desc()
                           ).limit(limit).offset(offset)
    return (await db.execute(query)).scalars().all()


async def unread_count(db, models, user_id: str) -> int:
    return int((await db.execute(
        select(func.count()).select_from(models.Notification).where(
            models.Notification.user_id == user_id,
            models.Notification.read.is_(False))
    )).scalar_one() or 0)


async def mark_read(db, models, user_id: str, notification_id: str) -> bool:
    note = (await db.execute(
        select(models.Notification).where(
            models.Notification.id == notification_id,
            models.Notification.user_id == user_id)
    )).scalar_one_or_none()
    if note is None:
        return False
    note.read = True
    db.add(note)
    await db.flush()
    return True


async def mark_all_read(db, models, user_id: str) -> int:
    notes = (await db.execute(
        select(models.Notification).where(
            models.Notification.user_id == user_id,
            models.Notification.read.is_(False))
    )).scalars().all()
    for note in notes:
        note.read = True
        db.add(note)
    await db.flush()
    return len(notes)


def notification_payload(note: Any) -> dict:
    return {
        "id": note.id,
        "kind": note.kind,
        "title": note.title,
        "body": note.body,
        "link": note.href,
        "read": bool(note.read),
        "created_at": note.created_at.isoformat() if note.created_at else None,
    }
