"""Admin formats router: /admin/formats.

Pair status matrix (healthy / disabled + last error), visibility toggles,
per-plan gating, Run health check with progress, sample file management.

ADMIN AUTH — WIRED TO app.admin_auth WHEN PRESENT: the admin-backend
agent's ``require_admin(section, level)`` factory is used at import time
(admin session + CSRF + section permission, per spec section 13). If
``app.admin_auth`` cannot be imported, ``require_admin`` falls back to a
placeholder that refuses every call with 503 (``admin_auth_not_wired``)
rather than running without admin authentication.
"""
from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from .catalog import CATALOG
from .health import (
    SAMPLES_DIR,
    generate_sample,
    health_check,
    list_samples,
    verify_engines_report,
)
from .pipeline import get_default_store

router = APIRouter(prefix="/admin/formats", tags=["admin-formats"])


def _placeholder_admin(request: Request):
    """Refuses every call until app.admin_auth is wired (see docstring)."""
    from fastapi import HTTPException

    raise HTTPException(
        status_code=503,
        detail={"error": {"code": "admin_auth_not_wired",
                          "message": "Admin authentication is not wired yet.",
                          "hint": "The coordinator wires app.admin_auth into this router."}},
    )


try:
    # app.admin_auth.require_admin is a factory: require_admin(section, level)
    # returns the FastAPI dependency (admin session + CSRF + section permission).
    from app.admin_auth import require_admin as _require_admin_factory

    require_admin = _require_admin_factory("formats", "read")
    require_admin_write = _require_admin_factory("formats", "write")
    from app.admin_auth import require_csrf as _require_csrf
    require_csrf = _require_csrf
except Exception:  # noqa: BLE001 - admin_auth may not exist yet, or its deps
    require_admin = _placeholder_admin
    require_admin_write = _placeholder_admin
    require_csrf = _placeholder_admin


def _audit(request: Request, action: str, target: str, before: dict, after: dict) -> None:
    """Write an audit_log entry when app.audit exists AND a DB session is
    available on request.state (the admin-backend agent's audit(db, ...)
    needs one). Otherwise this is a no-op — audit is best-effort here."""
    db = getattr(request.state, "db", None)
    if db is None:
        return
    try:
        from app.audit import audit  # type: ignore

        admin = getattr(request.state, "admin_email", "unknown")
        result = audit(db=db, admin_email=admin, action=action, target=target,
                       before=before, after=after,
                       ip=request.client.host if request.client else None)
        # audit() is async; schedule it if an event loop is running.
        import asyncio

        try:
            asyncio.get_running_loop().create_task(result)
        except RuntimeError:
            pass
    except Exception:  # noqa: BLE001 - audit is best-effort here
        pass


def _store(request: Request):
    return getattr(request.app.state, "pipeline_store", None) or get_default_store()


class PairOverrideBody(BaseModel):
    visible: bool | None = None
    plans: list[str] | None = None


@router.get("")
def formats_matrix(request: Request, _admin=Depends(require_admin)):
    store = _store(request)
    health = store.get_pair_health() if hasattr(store, "get_pair_health") else {}
    pairs = []
    for pair in CATALOG.pairs:
        entry = dict(pair)
        entry["status"] = health.get(pair["slug"], {}).get("status", "healthy")
        entry["last_error"] = health.get(pair["slug"], {}).get("last_error")
        entry["last_checked_at"] = health.get(pair["slug"], {}).get("last_checked_at")
        override = store.get_pair_override(pair["slug"]) \
            if hasattr(store, "get_pair_override") else {"visible": True, "plans": None}
        entry["visible"] = override.get("visible", True)
        entry["plans"] = override.get("plans")
        pairs.append(entry)
    samples = list_samples(SAMPLES_DIR)
    return {
        "pairs": pairs,
        "total": len(pairs),
        "healthy": sum(1 for p in pairs if p["status"] == "healthy"),
        "disabled": sum(1 for p in pairs if p["status"] == "disabled"),
        "samples": samples,
        "engines": verify_engines_report(),
    }


@router.get("/pairs/{pair_slug}")
def pair_detail(pair_slug: str, request: Request, _admin=Depends(require_admin)):
    pair = CATALOG.pairs_by_slug.get(pair_slug)
    if pair is None:
        return JSONResponse(status_code=404, content={
            "error": {"code": "not_found", "message": f"Unknown pair: {pair_slug}",
                      "hint": ""}})
    store = _store(request)
    health = store.get_pair_health().get(pair_slug, {}) \
        if hasattr(store, "get_pair_health") else {}
    override = store.get_pair_override(pair_slug) \
        if hasattr(store, "get_pair_override") else {"visible": True, "plans": None}
    return {**pair, "status": health.get("status", "healthy"),
            "last_error": health.get("last_error"),
            "last_checked_at": health.get("last_checked_at"),
            "visible": override.get("visible", True),
            "plans": override.get("plans")}


@router.patch("/pairs/{pair_slug}")
def update_pair(pair_slug: str, body: PairOverrideBody, request: Request,
                _admin=Depends(require_admin_write), _csrf: bool = Depends(require_csrf)):
    pair = CATALOG.pairs_by_slug.get(pair_slug)
    if pair is None:
        return JSONResponse(status_code=404, content={
            "error": {"code": "not_found", "message": f"Unknown pair: {pair_slug}",
                      "hint": ""}})
    store = _store(request)
    before = store.get_pair_override(pair_slug) \
        if hasattr(store, "get_pair_override") else {}
    after = dict(before)
    if body.visible is not None:
        after["visible"] = body.visible
    if body.plans is not None:
        after["plans"] = body.plans
    if hasattr(store, "set_pair_override"):
        store.set_pair_override(pair_slug, after)
    _audit(request, "formats.pair_override", pair_slug, before, after)
    return {"pair_slug": pair_slug, **after}


@router.post("/health-check")
def run_health_check(request: Request, _admin=Depends(require_admin_write), _csrf: bool = Depends(require_csrf)):
    """Run the health check now and return the summary (progress is the
    per-pair result list; the check runs synchronously in this process)."""
    store = _store(request)
    summary = health_check(store, SAMPLES_DIR)
    _audit(request, "formats.health_check", "all", {}, {
        "healthy": summary["healthy"], "disabled": summary["disabled"],
        "no_sample": summary["no_sample"]})
    return summary


@router.get("/samples")
def samples_list(request: Request, _admin=Depends(require_admin)):
    return {"samples": list_samples(SAMPLES_DIR)}


@router.post("/samples/{format_slug}/regenerate")
def regenerate_sample(format_slug: str, request: Request,
                      _admin=Depends(require_admin_write), _csrf: bool = Depends(require_csrf)):
    slug = CATALOG.resolve_slug(format_slug)
    if slug is None:
        return JSONResponse(status_code=404, content={
            "error": {"code": "not_found", "message": f"Unknown format: {format_slug}",
                      "hint": ""}})
    path, reason = generate_sample(slug, SAMPLES_DIR)
    if path is None:
        return JSONResponse(status_code=422, content={
            "error": {"code": "sample_unavailable",
                      "message": reason or "Sample cannot be generated here.",
                      "hint": "Upload a real sample file for this format instead."}})
    _audit(request, "formats.sample_regenerate", slug, {}, {"path": str(path)})
    return {"format": slug, "path": str(path),
            "size": Path(path).stat().st_size}
