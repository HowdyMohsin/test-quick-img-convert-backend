"""Public pipeline router: /v1/uploads, /v1/convert, /v1/jobs, /v1/history,
/v1/samples and GET /v1/formats.

Owner / plan resolution (wired, v5 sections 4.1/4.2/8): signed-in users
resolve through ``app.deps.get_optional_user`` (user id owner key, the
user's plan and its database limits); anonymous visitors resolve to the
signed device cookie (``qic_device``) plus an IP-HMAC key, and the
stricter of the two quota counters applies. The plan's effective limits
come from the database Plan row (anonymous limits from site settings)
with the seeded ``PLAN_LIMITS`` defaults as fallback. Quota is counted
when a job is accepted and refunded automatically on failure/cancel.

The router keeps working on a bare test app with no database: when the
pipeline store is a ``MemoryStore`` (tests) it resolves anonymous owners
with seeded limits and never touches the database; ``app.state.
plan_resolver`` (a callable owner_key -> plan) still overrides the plan
for tests, and ``app.state.test_user_id`` (a user id string) forces a
signed-in owner without a database, so convert tests can run as a user
while anonymous tests clear it. Only the identity is faked — the plan
still comes from ``plan_resolver`` / the resolved limits.

Rate limiting lives at the app level (``app.rate_limit``); this router
does not duplicate it. All errors use the shared shape
``{"error": {"code", "message", "hint"}}``.
"""
from __future__ import annotations

import asyncio
import hashlib
import mimetypes
import os
import uuid
from pathlib import Path
from typing import AsyncGenerator

from fastapi import APIRouter, Depends, File, Request, Response, UploadFile
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .catalog import CATALOG
from .deps import (
    DEVICE_COOKIE,
    client_ip,
    get_db,
    get_optional_user,
    get_settings,
)
from .health import SAMPLES_DIR, list_samples
from .models import Plan, SiteSetting
from .pipeline import (
    PLAN_LIMITS,
    DbStore,
    MemoryStore,
    PipelineError,
    build_download_token,
    cancel_job,
    create_conversion,
    create_upload,
    create_upload_from_path,
    delete_upload,
    download_path_for_job,
    get_data_dir,
    get_default_store,
    get_jobs,
    list_history,
    zip_batch,
)
from .quotas import (
    device_owner_key,
    get_or_create_device_id,
    ip_owner_key,
    signed_device_cookie,
    user_owner_key,
)

router = APIRouter(prefix="/v1", tags=["pipeline"])


def error_response(exc: PipelineError) -> JSONResponse:
    return JSONResponse(
        status_code=exc.status,
        content={"error": {"code": exc.code, "message": exc.message,
                           "hint": exc.hint}},
    )


def get_store(request: Request):
    return getattr(request.app.state, "pipeline_store", None) or get_default_store()


def get_data_dir_for(request: Request) -> Path:
    return getattr(request.app.state, "data_dir", None) or get_data_dir()


async def _optional_db() -> AsyncGenerator[AsyncSession | None, None]:
    """Yield a DB session when one is available; None otherwise.

    The pipeline router must keep working on a bare test app with no
    database configured, so a failure to open a session degrades to
    anonymous + seeded limits instead of a 500.
    """
    yielded = False
    try:
        async for session in get_db():
            yielded = True
            yield session
            return
    except Exception:  # noqa: BLE001 - no database available
        if yielded:
            # The endpoint already ran and an exception was thrown into
            # this generator (e.g. FastAPI body validation). Let it
            # propagate so the framework answers it (422); yielding a
            # second value here breaks the generator protocol (500).
            raise
        yield None


async def _plan_limits(db: AsyncSession | None, plan_id: str) -> dict:
    """Effective limits for a plan: database row over seeded defaults."""
    limits = dict(PLAN_LIMITS.get(plan_id, PLAN_LIMITS["free"]))
    if db is None:
        return limits
    try:
        row = await db.get(Plan, plan_id)
        if row is not None and isinstance(row.limits, dict) and row.limits:
            merged = dict(limits)
            merged.update(row.limits)
            return merged
    except Exception:  # noqa: BLE001 - fall back to seeded limits
        pass
    return limits


async def _anonymous_limits(db: AsyncSession | None) -> dict:
    """Effective anonymous limits: site settings over seeded defaults."""
    limits = dict(PLAN_LIMITS["anonymous"])
    if db is None:
        return limits
    try:
        row = await db.execute(
            select(SiteSetting).where(SiteSetting.key == "anonymous_limits"))
        setting = row.scalar_one_or_none()
        value = setting.value if setting is not None else None
        if isinstance(value, dict) and "limits" in value and isinstance(value["limits"], dict):
            value = value["limits"]
        if isinstance(value, dict) and value:
            merged = dict(limits)
            merged.update(value)
            return merged
    except Exception:  # noqa: BLE001 - fall back to seeded limits
        pass
    return limits


async def _resolve_owner(
    request: Request,
    response: Response,
    db: AsyncSession | None = Depends(_optional_db),
) -> dict:
    """Resolve (owner_key, plan, quota_keys, user_id, limits) for a request.

    Signed-in: owner is the user key, plan is the user's plan, quota is
    counted on the user key. Anonymous: owner is the device key, plan is
    anonymous, quota is counted on BOTH the device key and the IP-HMAC
    key (stricter applies). The signed device cookie is set when newly
    created. Database access happens only when the pipeline store is a
    DbStore (production); a MemoryStore (tests) resolves anonymous owners
    with seeded limits and never touches the database.
    """
    store = get_store(request)
    use_db = isinstance(store, DbStore)
    session_db = db if use_db else None

    user = None
    if session_db is not None:
        try:
            user = await get_optional_user(request, session_db)
        except Exception:  # noqa: BLE001 - treat as anonymous
            user = None

    if user is not None:
        plan_id = user.plan or "free"
        limits = await _plan_limits(session_db, plan_id)
        resolved = {
            "owner_key": user_owner_key(user.id),
            "plan": plan_id,
            "quota_keys": [user_owner_key(user.id)],
            "user_id": user.id,
            "limits": limits,
        }
    else:
        device_id, is_new = get_or_create_device_id(request)
        if is_new:
            response.set_cookie(
                DEVICE_COOKIE, signed_device_cookie(device_id),
                httponly=True, samesite="lax",
                secure=get_settings().is_https, path="/")
        ip = client_ip(request)
        keys = [device_owner_key(device_id), ip_owner_key(ip)]
        limits = await _anonymous_limits(session_db)
        resolved = {
            "owner_key": keys[0],
            "plan": "anonymous",
            "quota_keys": keys,
            "user_id": None,
            "limits": limits,
        }

    # Test hook (see module docstring): force a plan without a database.
    resolver = getattr(request.app.state, "plan_resolver", None)
    if callable(resolver):
        forced = resolver(resolved["owner_key"])
        if forced:
            resolved["plan"] = forced
            resolved["limits"] = dict(PLAN_LIMITS.get(forced, resolved["limits"]))
    # Test hook (see module docstring): force a signed-in owner without
    # a database. Only the identity is faked — the plan above is kept.
    test_user = getattr(request.app.state, "test_user_id", None)
    if test_user:
        resolved["user_id"] = test_user
        resolved["owner_key"] = user_owner_key(test_user)
        resolved["quota_keys"] = [user_owner_key(test_user)]
    return resolved


class ConvertBody(BaseModel):
    upload_id: str
    to: str
    settings: dict = Field(default_factory=dict)
    batch_id: str | None = None
    name_pattern: str | None = None


class ZipBody(BaseModel):
    job_ids: list[str]


@router.get("/formats")
def get_formats(request: Request):
    store = get_store(request)
    health = store.get_pair_health() if hasattr(store, "get_pair_health") else {}
    samples = {slug: info["present"]
               for slug, info in list_samples(SAMPLES_DIR).items()}
    return CATALOG.formats_response(health=health, samples=samples)


# Streaming uploads: the request body is written to disk in 1 MB chunks
# and the API never holds more than one chunk in RAM. Before this
# change the endpoint did `await file.read()` — a whole 4 GB pro video
# would have landed in API memory before the size check ran, which is
# exactly how a burst of big uploads OOMs a small box. The hard cap
# below is the plan's largest category limit (video is the largest in
# every seeded plan, but it is computed from the effective limits, not
# assumed); the exact per-category limit is still enforced by
# create_upload_from_path, with the same error codes as before.
UPLOAD_CHUNK_BYTES = 1024 * 1024


@router.post("/uploads", status_code=201)
async def upload_file(request: Request, file: UploadFile = File(...),
                      owner: dict = Depends(_resolve_owner)):
    store = get_store(request)
    data_dir = get_data_dir_for(request)
    limits = owner["limits"]
    max_bytes = max(int(limits.get(k, 0)) for k in ("img_mb", "aud_mb", "vid_mb")) * 1024 * 1024
    if max_bytes <= 0:  # defensive: a limit set without size keys
        max_bytes = PLAN_LIMITS["anonymous"]["vid_mb"] * 1024 * 1024
    tmp_dir = data_dir / "tmp"
    tmp_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(tmp_dir, 0o700)
    tmp_path = tmp_dir / f"upload-{uuid.uuid4().hex}.part"
    size = 0
    try:
        with open(tmp_path, "wb") as fh:
            while True:
                chunk = await file.read(UPLOAD_CHUNK_BYTES)
                if not chunk:
                    break
                size += len(chunk)
                if size > max_bytes:
                    raise PipelineError(
                        "file_too_large",
                        f"This file is over the {max_bytes // (1024 * 1024)} MB limit for your plan.",
                        "Choose a smaller file or upgrade your plan.", status=413)
                fh.write(chunk)
        # The pipeline store is synchronous (SQLAlchemy sync sessions);
        # run it off the event loop so a burst of uploads/converts can
        # never block /healthz and the rest of the API while the store
        # works. The store opens a short session per call, so it is
        # safe to call from worker threads.
        record = await asyncio.to_thread(
            create_upload_from_path, store, owner["owner_key"], owner["plan"],
            file.filename or "file", tmp_path, data_dir)
    except PipelineError as exc:
        tmp_path.unlink(missing_ok=True)
        return error_response(exc)
    return {**record.to_dict(), "download_url": None}


@router.post("/convert", status_code=202)
async def convert(request: Request, body: ConvertBody,
                  owner: dict = Depends(_resolve_owner)):
    store = get_store(request)
    # Suspense lock (user order 2026-11-26): converting needs a signed-in
    # account. Anonymous visitors can upload and preview, but the convert
    # call itself is refused with a friendly sign-in message — never a
    # raw code. The UI locks "Convert to" + the Convert button for
    # anonymous users with files staged; this is the API backstop, so the
    # rule cannot be bypassed from the browser console. Consequence:
    # anonymous users can no longer convert without an account — the
    # anonymous 5/day is upload-only preview until they sign in free.
    if owner["user_id"] is None:
        return error_response(PipelineError(
            "signin_required", "Sign in — it's free — to convert your files.",
            "Create a free account and convert right away; no email verification needed.",
            status=403))
    # Plan-gated conversion settings (backstop for the UI gating): a plan
    # without the flag cannot smuggle the option through the API.
    _settings = body.settings or {}
    if _settings.get("strip_gps") and not owner["limits"].get("gps_remover", False):
        return error_response(PipelineError(
            "feature_locked", "Removing GPS location needs Basic or Pro.",
            "See /pricing to upgrade", status=403))
    if _settings.get("target_size_kb") and not owner["limits"].get("target_size", False):
        return error_response(PipelineError(
            "feature_locked", "Target file size needs Basic or Pro.",
            "See /pricing to upgrade", status=403))
    try:
        # Sync store, off the event loop (see the upload endpoint).
        job = await asyncio.to_thread(
            create_conversion,
            store, owner["owner_key"], owner["plan"], body.upload_id, body.to,
            body.settings, body.batch_id, body.name_pattern,
            quota_keys=owner["quota_keys"], user_id=owner["user_id"],
            limits=owner["limits"])
    except PipelineError as exc:
        return error_response(exc)
    result = job.to_dict()
    result["download_url"] = (
        f"/v1/jobs/{job.id}/download?token={build_download_token(job.id)}"
        if job.status == "done" else None)
    return result


@router.get("/jobs")
async def list_jobs_endpoint(request: Request, ids: str | None = None,
                             owner: dict = Depends(_resolve_owner)):
    store = get_store(request)
    wanted = [i.strip() for i in ids.split(",") if i.strip()] if ids else None
    try:
        jobs = get_jobs(store, owner["owner_key"], wanted)
    except PipelineError as exc:
        return error_response(exc)
    out = []
    for job in jobs:
        data = job.to_dict()
        data["download_url"] = (
            f"/v1/jobs/{job.id}/download?token={build_download_token(job.id)}"
            if job.status == "done" else None)
        out.append(data)
    return {"jobs": out}


@router.post("/jobs/{job_id}/cancel")
async def cancel_job_endpoint(request: Request, job_id: str,
                              owner: dict = Depends(_resolve_owner)):
    store = get_store(request)
    try:
        job, refunded = cancel_job(store, owner["owner_key"], job_id)
    except PipelineError as exc:
        return error_response(exc)
    return {**job.to_dict(), "quota_refunded": refunded}


@router.post("/jobs/zip")
async def zip_jobs_endpoint(request: Request, body: ZipBody,
                            owner: dict = Depends(_resolve_owner)):
    store = get_store(request)
    try:
        zip_path, zip_name = zip_batch(store, owner["owner_key"], body.job_ids,
                                       get_data_dir_for(request))
    except PipelineError as exc:
        return error_response(exc)
    return FileResponse(
        zip_path, media_type="application/zip", filename=zip_name,
        headers={"Content-Disposition": f'attachment; filename="{zip_name}"',
                 "X-Content-Type-Options": "nosniff"})


@router.get("/jobs/{job_id}/download")
async def download_job(request: Request, job_id: str, token: str | None = None,
                       owner: dict = Depends(_resolve_owner)):
    store = get_store(request)
    try:
        path, filename = download_path_for_job(store, job_id, token,
                                               owner["owner_key"])
    except PipelineError as exc:
        return error_response(exc)
    media_type, _ = mimetypes.guess_type(filename)
    return FileResponse(
        path, media_type=media_type or "application/octet-stream",
        filename=filename,
        headers={"Content-Disposition": f'attachment; filename="{filename}"',
                 "X-Content-Type-Options": "nosniff"})


@router.delete("/uploads/{upload_id}")
async def delete_upload_endpoint(request: Request, upload_id: str,
                                 owner: dict = Depends(_resolve_owner)):
    store = get_store(request)
    try:
        delete_upload(store, owner["owner_key"], upload_id)
    except PipelineError as exc:
        return error_response(exc)
    return {"deleted": True}


def _find_owned_upload(store, owner_key: str, upload_id: str):
    """Upload record for this owner, or None when missing / not theirs."""
    rec = store.get_upload(upload_id)
    if rec is None or rec.owner_key != owner_key:
        return None
    return rec


def _serve_upload_file(rec):
    """Return an upload's original bytes as an attachment download."""
    path = Path(rec.path)
    if not path.exists():
        return error_response(PipelineError(
            "not_found", "Upload not found.", status=404))
    media_type, _ = mimetypes.guess_type(rec.filename)
    return FileResponse(
        path, media_type=media_type or "application/octet-stream",
        filename=rec.filename,
        headers={"Content-Disposition": f'attachment; filename="{rec.filename}"',
                 "X-Content-Type-Options": "nosniff"})


@router.get("/uploads/{upload_id}/file")
async def get_upload_file_endpoint(request: Request, upload_id: str,
                                   owner: dict = Depends(_resolve_owner)):
    rec = _find_owned_upload(get_store(request), owner["owner_key"], upload_id)
    if rec is None:
        return error_response(PipelineError(
            "not_found", "Upload not found.", status=404))
    return _serve_upload_file(rec)


@router.get("/editor/access")
async def editor_access_endpoint(owner: dict = Depends(_resolve_owner)):
    # Effective limits were already resolved by _resolve_owner (database
    # Plan row over PLAN_LIMITS defaults, via _plan_limits for signed-in
    # users and _anonymous_limits for anonymous visitors).
    return {"plan": owner["plan"],
            "editor_allowed": bool(owner["limits"].get("editor", False))}


@router.get("/features")
async def features_endpoint(owner: dict = Depends(_resolve_owner)):
    """Plan-gated converter features, same limits-dict pattern as the
    editor lock: GPS remover, compare slider, batch rename, target size.
    Anonymous and free get them off; basic and pro get them on — the admin
    can flip each per plan from Plans (limits)."""
    limits = owner["limits"]
    return {"gps_remover": bool(limits.get("gps_remover", False)),
            "compare": bool(limits.get("compare", False)),
            "batch_rename": bool(limits.get("batch_rename", False)),
            "target_size": bool(limits.get("target_size", False))}


@router.get("/editor/file/{upload_id}")
async def editor_file_endpoint(request: Request, upload_id: str,
                               owner: dict = Depends(_resolve_owner)):
    if not bool(owner["limits"].get("editor", False)):
        return error_response(PipelineError(
            "editor_locked",
            "The image editor needs Basic or Pro.",
            "See /pricing to upgrade", status=403))
    rec = _find_owned_upload(get_store(request), owner["owner_key"], upload_id)
    if rec is None:
        return error_response(PipelineError(
            "not_found", "Upload not found.", status=404))
    if rec.category != "Images":
        return error_response(PipelineError(
            "unsupported_media_type",
            "The image editor only works with image files.",
            "Upload an image file to edit it.", status=415))
    return _serve_upload_file(rec)


@router.get("/history")
async def history_endpoint(request: Request, response: Response, page: int = 1, page_size: int = 20,
                           owner: dict = Depends(_resolve_owner)):
    # Per-user data resolved from the session cookie: never let a cache
    # serve one account's history to another browser.
    response.headers["Cache-Control"] = "no-store, private"
    response.headers["Vary"] = "Cookie"
    store = get_store(request)
    return list_history(store, owner["owner_key"], days=90, page=max(1, page),
                        page_size=min(100, max(1, page_size)))


@router.get("/samples/{format_slug}")
def sample_endpoint(request: Request, format_slug: str):
    slug = CATALOG.resolve_slug(format_slug)
    if slug is None:
        return error_response(PipelineError(
            "not_found", f"Unknown format: {format_slug}", status=404))
    path = SAMPLES_DIR / f"{slug}.{CATALOG.by_slug[slug]['extensions'][0]}"
    if not path.exists():
        return error_response(PipelineError(
            "not_found", f"No bundled sample is available for {slug.upper()}.",
            "Camera RAW samples need a real camera file; see the sample notes.",
            status=404))
    media_type, _ = mimetypes.guess_type(path.name)
    return FileResponse(
        path, media_type=media_type or "application/octet-stream",
        filename=path.name,
        headers={"Content-Disposition": f'attachment; filename="{path.name}"',
                 "X-Content-Type-Options": "nosniff"})
