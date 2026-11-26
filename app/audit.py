"""Admin audit logging for Quick IMG Convert v5 (spec §13.2 / §10).

Every admin mutation writes one ``audit_log`` row with a before/after diff.

Import path is stable by contract: ``from app.audit import audit``.
Other router owners import this module defensively::

    try:
        from app.audit import audit
    except ImportError:  # pragma: no cover - audit module not present yet
        audit = None
    ...
    if audit is not None:
        await audit(db, admin.email, "plans.update", plan.id, before, after, ip)

The ``db`` argument is an async SQLAlchemy session (``AsyncSession``), the
same session the calling endpoint already uses, so the audit row commits
with the mutation itself. If the core ``app.models.AuditLog`` model exists
it is used; otherwise the row is inserted with raw SQL, which works on both
SQLite (dev) and PostgreSQL (the ``before``/``after`` values are stored as
JSON text and cast by the ORM model in production).
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import func, select, text


def _is_sqlite(db) -> bool:
    try:
        return db.get_bind().dialect.name == "sqlite"
    except Exception:
        return False

# ---------------------------------------------------------------------------
# Diff helper
# ---------------------------------------------------------------------------

def diff_dicts(before: Optional[dict], after: Optional[dict]) -> dict:
    """Return a minimal ``{field: {"before": ..., "after": ...}}`` diff.

    Fields present in only one side, or whose value changed, are included.
    Values must already be JSON-serialisable (callers pass plain dicts).
    """
    before = before or {}
    after = after or {}
    diff: dict[str, dict[str, Any]] = {}
    for key in sorted(set(before) | set(after)):
        b, a = before.get(key), after.get(key)
        if b != a:
            diff[key] = {"before": b, "after": a}
    return diff


def _jsonable(value: Any) -> Any:
    """Best-effort conversion of a value to something ``json.dumps`` accepts."""
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(v) for v in value]
    return str(value)


# ---------------------------------------------------------------------------
# Core audit write
# ---------------------------------------------------------------------------

async def audit(
    db,
    admin_email: str,
    action: str,
    target: Any,
    before: Optional[dict] = None,
    after: Optional[dict] = None,
    ip: Optional[str] = None,
) -> None:
    """Write one ``audit_log`` row. Never raises for a logging failure.

    ``before``/``after`` are plain dicts (the state before and after the
    mutation). They are stored verbatim; callers that want a minimal diff
    can pass ``diff_dicts(before, after)`` as ``after`` instead, but the
    full before/after pair is the contract default because the admin Audit
    Log page shows the JSON diff reconstructed from both sides.
    """
    before = _jsonable(before) if before is not None else None
    after = _jsonable(after) if after is not None else None
    target = "" if target is None else str(target)
    now = datetime.now(timezone.utc)
    try:
        from app.models import AuditLog  # type: ignore

        row = AuditLog(
            ts=now,
            admin_email=admin_email,
            action=action,
            target=target,
            before=before,
            after=after,
            ip=ip,
        )
        if _is_sqlite(db):
            # Core AuditLog.id is BigInteger; SQLite only auto-generates
            # ids for INTEGER PRIMARY KEY, so assign max(id)+1 on SQLite.
            # PostgreSQL uses its sequence and needs no explicit id.
            max_id = await db.execute(select(func.coalesce(func.max(AuditLog.id), 0)))
            row.id = int(max_id.scalar_one()) + 1
        db.add(row)
        await db.flush()
        return
    except Exception:
        # Core models not present (or the ORM insert failed): fall back to
        # raw SQL so the audit trail is still written. Roll back the failed
        # flush attempt state is not possible here without breaking the
        # caller's transaction, so we only attempt the raw insert when the
        # import itself was unavailable; any other failure is swallowed so
        # audit logging can never break an admin mutation.
        try:
            from app.models import AuditLog  # type: ignore
        except Exception:
            pass
        else:
            return
    try:
        await db.execute(
            text(
                "INSERT INTO audit_log (ts, admin_email, action, target, "
                "\"before\", \"after\", ip) VALUES "
                "(:ts, :admin_email, :action, :target, :before, :after, :ip)"
            ),
            {
                "ts": now,
                "admin_email": admin_email,
                "action": action,
                "target": target,
                "before": json.dumps(before) if before is not None else None,
                "after": json.dumps(after) if after is not None else None,
                "ip": ip,
            },
        )
        await db.flush()
    except Exception:
        # Audit logging must never break the mutation it records.
        pass


# ---------------------------------------------------------------------------
# Helper for other routers: a small writer bound to one request
# ---------------------------------------------------------------------------

class AdminAudit:
    """Convenience wrapper so other routers can write audits in one line.

    Usage::

        auditor = AdminAudit(db, admin, request.client.host)
        await auditor.record("users.ban", user.id, before, after)
    """

    def __init__(self, db, admin_email: str, ip: Optional[str] = None):
        if not isinstance(admin_email, str):
            admin_email = getattr(admin_email, "email", str(admin_email))
        self.db = db
        self.admin_email = admin_email
        self.ip = ip

    async def record(
        self,
        action: str,
        target: Any,
        before: Optional[dict] = None,
        after: Optional[dict] = None,
    ) -> None:
        await audit(self.db, self.admin_email, action, target, before, after, self.ip)
