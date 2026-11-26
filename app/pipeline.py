"""Conversion pipeline: uploads, quota, jobs, downloads, retention.

This module is the pipeline *service*: pure logic over a small store
interface. It deliberately does NOT import the database models (owned by
the backend-core agent) or FastAPI. The routers in ``routers_pipeline.py``
adapt it to HTTP, and ``worker.py`` drives jobs through it.

Store contract: any object with the methods used below. ``MemoryStore``
is the in-process implementation used for local development and tests;
production wires a database-backed store with the same methods (the
coordinator owns that swap — the method names mirror the ``uploads`` /
``jobs`` / ``quotas`` tables in spec section 3).

Quota (spec section 4.2): one file = one conversion, counted when the job
is ACCEPTED, refunded automatically if the job fails or is cancelled
before it starts. PDF to images is one conversion regardless of page
count. The daily quota resets at 00:00 in QUOTA_TZ (default Asia/Karachi).

Plan limits (spec section 4.1) are the seeded defaults; the admin edits
them live in the database, and the routers pass the effective limits in.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re
import secrets
import shutil
import threading
import uuid
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

from . import engines
from .catalog import CATALOG

# --- plan limits (spec 4.1, seeded defaults; admin-editable in the DB) -----
PLAN_LIMITS = {
    "anonymous": {"daily": 5, "batch": 10, "img_mb": 200, "aud_mb": 100,
                  "vid_mb": 500, "vid_min": 30, "parallel": 1,
                  "priority": False, "ads": True, "editor": False,
                  "gps_remover": False, "compare": False,
                  "batch_rename": False, "target_size": False},
    "free": {"daily": 25, "batch": 10, "img_mb": 200, "aud_mb": 100,
             "vid_mb": 500, "vid_min": 30, "parallel": 2,
             "priority": False, "ads": True, "editor": False,
             "gps_remover": False, "compare": False,
             "batch_rename": False, "target_size": False},
    "basic": {"daily": 100, "batch": 30, "img_mb": 500, "aud_mb": 250,
              "vid_mb": 1024, "vid_min": 60, "parallel": 3,
              "priority": False, "ads": False, "editor": True,
              "gps_remover": True, "compare": True,
              "batch_rename": True, "target_size": True},
    "pro": {"daily": 2000, "batch": 100, "img_mb": 2048, "aud_mb": 1024,
            "vid_mb": 4096, "vid_min": 120, "parallel": 6,
            "priority": True, "ads": False, "editor": True,
            "gps_remover": True, "compare": True,
            "batch_rename": True, "target_size": True},
}

CATEGORY_LIMIT_KEY = {"Images": "img_mb", "Camera RAW": "img_mb",
                      "Audio": "aud_mb", "Video": "vid_mb",
                      "Documents and vector": "img_mb"}

QUOTA_TZ = ZoneInfo(os.environ.get("QUOTA_TZ", "Asia/Karachi"))
RETENTION_HOURS = int(os.environ.get("RETENTION_HOURS", "24"))
MAX_BATCH_FILES = 100

_EPHEMERAL_SECRET = secrets.token_bytes(32)


def get_secret_key() -> bytes:
    """Signing key for download URLs. SECRET_KEY from the environment in
    production; an ephemeral per-process key otherwise (downloads then only
    work within this process — never a hard-coded default)."""
    value = os.environ.get("SECRET_KEY")
    return value.encode() if value else _EPHEMERAL_SECRET


def get_data_dir() -> Path:
    env = os.environ.get("DATA_DIR")
    if env:
        return Path(env)
    return Path(__file__).resolve().parents[2] / "data"


def quota_day(now: datetime | None = None) -> str:
    now = now or datetime.now(timezone.utc)
    return now.astimezone(QUOTA_TZ).date().isoformat()


# --- errors ------------------------------------------------------------------
class PipelineError(Exception):
    def __init__(self, code: str, message: str, hint: str = "", status: int = 400):
        self.code = code
        self.message = message
        self.hint = hint
        self.status = status
        super().__init__(message)


# --- records -----------------------------------------------------------------
def _now() -> datetime:
    return datetime.now(timezone.utc)


def _new_id() -> str:
    return uuid.uuid4().hex


@dataclass
class UploadRecord:
    id: str
    owner_key: str
    filename: str
    original_filename: str
    size: int
    detected_format: str
    category: str
    path: str
    created_at: datetime = field(default_factory=_now)
    expires_at: datetime = field(default_factory=lambda: _now() + timedelta(hours=RETENTION_HOURS))

    def to_dict(self) -> dict:
        return {**self.__dict__,
                "created_at": self.created_at.isoformat(),
                "expires_at": self.expires_at.isoformat()}


@dataclass
class JobRecord:
    id: str
    batch_id: str
    owner_key: str
    user_id: str | None
    upload_id: str
    pair_slug: str
    from_slug: str
    to_slug: str
    category: str
    route: str
    settings: dict
    plan: str
    status: str = "queued"  # queued | running | done | failed | cancelled
    progress: float = 0.0
    error_code: str | None = None
    error_message: str | None = None
    out_name: str | None = None
    out_path: str | None = None
    out_size: int | None = None
    in_size: int = 0
    out_info: dict = field(default_factory=dict)
    cancel_requested: bool = False
    # Quota counters this job consumed (owner key plus, for anonymous
    # users, the IP-HMAC key). Persisted by DbStore; refunds decrement
    # every key in this list. None means [owner_key].
    quota_keys: list[str] | None = None
    created_at: datetime = field(default_factory=_now)
    started_at: datetime | None = None
    finished_at: datetime | None = None
    expires_at: datetime = field(default_factory=lambda: _now() + timedelta(hours=RETENTION_HOURS))

    def to_dict(self) -> dict:
        data = {**self.__dict__}
        for key in ("created_at", "started_at", "finished_at", "expires_at"):
            value = data[key]
            data[key] = value.isoformat() if value else None
        return data


# --- store -------------------------------------------------------------------
class MemoryStore:
    """Thread-safe in-memory store. Development / tests only; production
    replaces it with a database-backed store exposing the same methods."""

    def __init__(self):
        self._lock = threading.Lock()
        self.uploads: dict[str, UploadRecord] = {}
        self.jobs: dict[str, JobRecord] = {}
        self.quotas: dict[tuple[str, str], int] = {}
        self.pair_health: dict[str, dict] = {}
        self.pair_overrides: dict[str, dict] = {}
        self.events: list[dict] = []

    # uploads
    def save_upload(self, rec: UploadRecord) -> None:
        with self._lock:
            self.uploads[rec.id] = rec

    def get_upload(self, upload_id: str) -> UploadRecord | None:
        return self.uploads.get(upload_id)

    def delete_upload(self, upload_id: str) -> None:
        with self._lock:
            self.uploads.pop(upload_id, None)

    def list_uploads(self, owner_key: str) -> list[UploadRecord]:
        return [u for u in self.uploads.values() if u.owner_key == owner_key]

    def list_all_uploads(self) -> list[UploadRecord]:
        return list(self.uploads.values())

    def delete_job(self, job_id: str) -> None:
        with self._lock:
            self.jobs.pop(job_id, None)

    # jobs
    def save_job(self, rec: JobRecord) -> None:
        with self._lock:
            self.jobs[rec.id] = rec

    def claim_job(self, job_id: str) -> bool:
        """Atomically claim a queued job for processing (queued -> running).

        Prevents two workers from processing the same job. Returns False
        when the job is not queued (already claimed, cancelled or done).
        """
        with self._lock:
            rec = self.jobs.get(job_id)
            if rec is None or rec.status != "queued":
                return False
            rec.status = "running"
            return True

    def get_job(self, job_id: str) -> JobRecord | None:
        return self.jobs.get(job_id)

    def list_jobs(self, owner_key: str | None = None) -> list[JobRecord]:
        jobs = list(self.jobs.values())
        if owner_key is not None:
            jobs = [j for j in jobs if j.owner_key == owner_key]
        return sorted(jobs, key=lambda j: j.created_at)

    def list_history(self, owner_key: str, days: int, page: int,
                     page_size: int) -> tuple[list[JobRecord], int]:
        cutoff = _now() - timedelta(days=days)
        jobs = [j for j in self.list_jobs(owner_key) if j.created_at >= cutoff]
        jobs.sort(key=lambda j: j.created_at, reverse=True)
        total = len(jobs)
        start = (page - 1) * page_size
        return jobs[start:start + page_size], total

    # quota
    def quota_used(self, owner_key: str, day: str) -> int:
        return self.quotas.get((owner_key, day), 0)

    def quota_increment(self, owner_key: str, day: str) -> int:
        with self._lock:
            key = (owner_key, day)
            self.quotas[key] = self.quotas.get(key, 0) + 1
            return self.quotas[key]

    def quota_decrement(self, owner_key: str, day: str) -> int:
        with self._lock:
            key = (owner_key, day)
            self.quotas[key] = max(0, self.quotas.get(key, 0) - 1)
            return self.quotas[key]

    def active_job_count(self, owner_key: str) -> int:
        return sum(1 for j in self.jobs.values()
                   if j.owner_key == owner_key and j.status in ("queued", "running"))

    def batch_job_count(self, owner_key: str, batch_id: str) -> int:
        return sum(1 for j in self.jobs.values()
                   if j.owner_key == owner_key and j.batch_id == batch_id)

    # pair health / overrides
    def get_pair_health(self) -> dict[str, dict]:
        return dict(self.pair_health)

    def set_pair_health(self, pair_slug: str, status: str, last_error: str | None) -> None:
        with self._lock:
            self.pair_health[pair_slug] = {
                "status": status, "last_error": last_error,
                "last_checked_at": _now().isoformat(),
            }

    def get_pair_override(self, pair_slug: str) -> dict:
        return self.pair_overrides.get(pair_slug, {"visible": True, "plans": None})

    def set_pair_override(self, pair_slug: str, override: dict) -> None:
        with self._lock:
            self.pair_overrides[pair_slug] = override

    # events
    def record_event(self, event: dict) -> None:
        with self._lock:
            self.events.append({**event, "ts": _now().isoformat()})


# --- database-backed store ---------------------------------------------------
# The API and the worker run in separate processes (separate containers in
# Docker Compose), so they can only share job/upload/quota state through
# the database. DbStore implements the same interface as MemoryStore with
# sync SQLAlchemy (the pipeline is synchronous by design), mapping the
# dataclass records to the canonical ``app.models`` tables. Datetimes
# coming back from SQLite are naive; they are normalised to aware UTC on
# every read (same rule as ``deps.ensure_aware``).


def _sync_db_url(async_url: str) -> str:
    """Convert an async SQLAlchemy URL to its sync equivalent."""
    if "+aiosqlite" in async_url:
        return async_url.replace("+aiosqlite", "", 1)
    if "+asyncpg" in async_url:
        return async_url.replace("+asyncpg", "+psycopg2", 1)
    return async_url


def _ensure_aware_db(dt):
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def _parse_day(day):
    """Quota day as a ``date`` (the quotas table PK is (owner_key, day))."""
    if isinstance(day, datetime):
        return day.date()
    try:
        from datetime import date as _date

        if isinstance(day, _date):
            return day
    except Exception:  # noqa: BLE001
        pass
    return datetime.fromisoformat(str(day)[:10]).date()


class DbStore:
    """Database-backed store (production). Same methods as MemoryStore."""

    def __init__(self, database_url: str | None = None):
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker

        from . import models as _models

        self._models = _models
        if database_url is None:
            from .deps import get_settings

            database_url = get_settings().database_url
        url = _sync_db_url(database_url)
        kwargs: dict = {}
        if url.startswith("sqlite"):
            # check_same_thread=False: the API calls this store from
            # worker threads (asyncio.to_thread) as well as the event
            # loop. timeout=30 is SQLite's busy timeout: with WAL, one
            # writer holds the file lock, and a burst of concurrent
            # writers would otherwise fail after the 5s default with
            # "database is locked". 30s lets them queue and succeed.
            # Production is PostgreSQL, where this branch never runs.
            kwargs["connect_args"] = {"check_same_thread": False, "timeout": 30}
            if ":memory:" in url:
                from sqlalchemy.pool import StaticPool

                kwargs["poolclass"] = StaticPool
        else:
            # Small pool for small PostgreSQL instances (see app/deps.py):
            # this sync store may hold at most 3 + 2 connections.
            kwargs["pool_size"] = 3
            kwargs["max_overflow"] = 2
            kwargs["pool_pre_ping"] = True
            kwargs["pool_recycle"] = 300
        self._engine = create_engine(url, **kwargs)
        # No-op for tables that already exist (the API boot / Alembic
        # creates them); required so the worker process can start alone.
        _models.Base.metadata.create_all(self._engine)
        if url.startswith("sqlite") and ":memory:" not in url:
            try:
                with self._engine.begin() as conn:
                    conn.exec_driver_sql("PRAGMA journal_mode=WAL")
            except Exception:  # noqa: BLE001 - WAL is best-effort
                pass
        self._Session = sessionmaker(bind=self._engine, expire_on_commit=False)

    def _session(self):
        return self._Session()

    # -- record mapping ------------------------------------------------------
    def _upload_to_record(self, row) -> UploadRecord:
        return UploadRecord(
            id=row.id, owner_key=row.owner_key, filename=row.filename,
            original_filename=row.original_filename or row.filename,
            size=row.size or 0, detected_format=row.detected_format or "",
            category=row.category or "", path=row.path,
            created_at=_ensure_aware_db(row.created_at) or _now(),
            expires_at=_ensure_aware_db(row.expires_at) or _now(),
        )

    def _job_to_record(self, row) -> JobRecord:
        return JobRecord(
            id=row.id, batch_id=row.batch_id or "", owner_key=row.owner_key,
            user_id=row.user_id, upload_id=row.upload_id or "",
            pair_slug=row.pair_slug or "", from_slug=row.from_slug or "",
            to_slug=row.to_slug or "", category=row.category or "",
            route=row.route or "", settings=dict(row.settings or {}),
            plan=row.plan or "anonymous", status=row.status or "queued",
            progress=float(row.progress or 0) / 100.0,
            error_code=row.error_code, error_message=row.error_message,
            out_name=row.out_name, out_path=row.out_path,
            out_size=row.out_size, in_size=row.in_size or 0,
            out_info=dict(row.out_info or {}),
            cancel_requested=bool(getattr(row, "cancel_requested", False)),
            quota_keys=list(row.quota_keys) if getattr(row, "quota_keys", None) else None,
            created_at=_ensure_aware_db(row.created_at) or _now(),
            started_at=_ensure_aware_db(row.started_at),
            finished_at=_ensure_aware_db(row.finished_at),
            expires_at=_ensure_aware_db(row.expires_at) or _now(),
        )

    def _apply_job_fields(self, row, rec: JobRecord) -> None:
        row.batch_id = rec.batch_id
        row.owner_key = rec.owner_key
        row.user_id = rec.user_id
        row.upload_id = rec.upload_id
        row.pair_slug = rec.pair_slug
        row.from_slug = rec.from_slug
        row.to_slug = rec.to_slug
        row.category = rec.category
        row.route = rec.route
        row.settings = dict(rec.settings or {})
        row.plan = rec.plan
        row.status = rec.status
        row.progress = int(round((rec.progress or 0.0) * 100))
        row.error_code = rec.error_code
        row.error_message = rec.error_message
        row.out_name = rec.out_name
        row.out_path = rec.out_path
        row.out_size = rec.out_size
        row.in_size = rec.in_size
        row.out_info = dict(rec.out_info or {})
        row.cancel_requested = bool(rec.cancel_requested)
        row.quota_keys = list(rec.quota_keys) if rec.quota_keys else None
        row.created_at = rec.created_at
        row.started_at = rec.started_at
        row.finished_at = rec.finished_at
        row.expires_at = rec.expires_at

    # -- uploads ---------------------------------------------------------------
    def save_upload(self, rec: UploadRecord) -> None:
        m = self._models
        with self._session() as s:
            row = s.get(m.Upload, rec.id)
            if row is None:
                row = m.Upload(id=rec.id)
                s.add(row)
            row.owner_key = rec.owner_key
            row.filename = rec.filename
            row.original_filename = rec.original_filename
            row.size = rec.size
            row.detected_format = rec.detected_format
            row.category = rec.category
            row.path = rec.path
            row.created_at = rec.created_at
            row.expires_at = rec.expires_at
            s.commit()

    def get_upload(self, upload_id: str) -> UploadRecord | None:
        m = self._models
        with self._session() as s:
            row = s.get(m.Upload, upload_id)
            return self._upload_to_record(row) if row is not None else None

    def delete_upload(self, upload_id: str) -> None:
        m = self._models
        with self._session() as s:
            row = s.get(m.Upload, upload_id)
            if row is not None:
                s.delete(row)
                s.commit()

    def list_uploads(self, owner_key: str) -> list[UploadRecord]:
        m = self._models
        with self._session() as s:
            rows = (s.query(m.Upload).filter(m.Upload.owner_key == owner_key)
                    .order_by(m.Upload.created_at).all())
            return [self._upload_to_record(r) for r in rows]

    def list_all_uploads(self) -> list[UploadRecord]:
        m = self._models
        with self._session() as s:
            rows = s.query(m.Upload).order_by(m.Upload.created_at).all()
            return [self._upload_to_record(r) for r in rows]

    def delete_job(self, job_id: str) -> None:
        m = self._models
        with self._session() as s:
            row = s.get(m.Job, job_id)
            if row is not None:
                s.delete(row)
                s.commit()

    # -- jobs ------------------------------------------------------------------
    def save_job(self, rec: JobRecord) -> None:
        m = self._models
        with self._session() as s:
            row = s.get(m.Job, rec.id)
            if row is None:
                row = m.Job(id=rec.id)
                s.add(row)
            self._apply_job_fields(row, rec)
            s.commit()

    def get_job(self, job_id: str) -> JobRecord | None:
        m = self._models
        with self._session() as s:
            row = s.get(m.Job, job_id)
            return self._job_to_record(row) if row is not None else None

    def claim_job(self, job_id: str) -> bool:
        """Atomically claim a queued job (queued -> running). Returns False
        when another worker already claimed it or it is not queued."""
        from sqlalchemy import update as _update

        m = self._models
        with self._session() as s:
            result = s.execute(
                _update(m.Job).where(
                    m.Job.id == job_id, m.Job.status == "queued"
                ).values(status="running"))
            s.commit()
            return result.rowcount == 1

    def list_jobs(self, owner_key: str | None = None) -> list[JobRecord]:
        m = self._models
        with self._session() as s:
            q = s.query(m.Job)
            if owner_key is not None:
                q = q.filter(m.Job.owner_key == owner_key)
            rows = q.order_by(m.Job.created_at).all()
            return [self._job_to_record(r) for r in rows]

    def list_history(self, owner_key: str, days: int, page: int,
                     page_size: int) -> tuple[list[JobRecord], int]:
        cutoff = _now() - timedelta(days=days)
        jobs = [j for j in self.list_jobs(owner_key)
                if _ensure_aware_db(j.created_at) >= cutoff]
        jobs.sort(key=lambda j: j.created_at, reverse=True)
        total = len(jobs)
        start = (page - 1) * page_size
        return jobs[start:start + page_size], total

    # -- quota (quotas table, shared with app.quotas) ---------------------------
    def quota_used(self, owner_key: str, day: str) -> int:
        m = self._models
        with self._session() as s:
            row = s.get(m.Quota, (owner_key, _parse_day(day)))
            return int(row.used) if row is not None else 0

    def quota_increment(self, owner_key: str, day: str) -> int:
        from sqlalchemy.exc import IntegrityError

        m = self._models
        day_d = _parse_day(day)
        with self._session() as s:
            row = s.get(m.Quota, (owner_key, day_d))
            if row is None:
                row = m.Quota(owner_key=owner_key, day=day_d, used=1)
                s.add(row)
                try:
                    s.commit()
                except IntegrityError:
                    s.rollback()
                    row = s.get(m.Quota, (owner_key, day_d))
                    row.used = int(row.used) + 1
                    s.commit()
            else:
                row.used = int(row.used) + 1
                s.commit()
            return int(row.used)

    def quota_decrement(self, owner_key: str, day: str) -> int:
        m = self._models
        day_d = _parse_day(day)
        with self._session() as s:
            row = s.get(m.Quota, (owner_key, day_d))
            if row is None or int(row.used) <= 0:
                return 0
            row.used = int(row.used) - 1
            s.commit()
            return int(row.used)

    def active_job_count(self, owner_key: str) -> int:
        m = self._models
        with self._session() as s:
            return int(s.query(m.Job).filter(
                m.Job.owner_key == owner_key,
                m.Job.status.in_(("queued", "running"))).count())

    def batch_job_count(self, owner_key: str, batch_id: str) -> int:
        m = self._models
        with self._session() as s:
            return int(s.query(m.Job).filter(
                m.Job.owner_key == owner_key,
                m.Job.batch_id == batch_id).count())

    # -- pair health / overrides ------------------------------------------------
    def get_pair_health(self) -> dict[str, dict]:
        m = self._models
        with self._session() as s:
            rows = s.query(m.PairHealth).all()
            return {r.pair_slug: {
                "status": r.status, "last_error": r.last_error,
                "last_checked_at": (
                    _ensure_aware_db(r.last_checked_at).isoformat()
                    if r.last_checked_at else None),
            } for r in rows}

    def set_pair_health(self, pair_slug: str, status: str,
                        last_error: str | None) -> None:
        m = self._models
        with self._session() as s:
            row = s.get(m.PairHealth, pair_slug)
            if row is None:
                row = m.PairHealth(pair_slug=pair_slug)
                s.add(row)
            row.status = status
            row.last_error = last_error
            row.last_checked_at = _now()
            s.commit()

    def get_pair_override(self, pair_slug: str) -> dict:
        m = self._models
        key = f"pair_override:{pair_slug}"
        with self._session() as s:
            row = s.get(m.SiteSetting, key)
            if row is not None and isinstance(row.value, dict):
                return dict(row.value)
            return {"visible": True, "plans": None}

    def set_pair_override(self, pair_slug: str, override: dict) -> None:
        m = self._models
        key = f"pair_override:{pair_slug}"
        with self._session() as s:
            row = s.get(m.SiteSetting, key)
            if row is None:
                row = m.SiteSetting(key=key, value=dict(override))
                s.add(row)
            else:
                row.value = dict(override)
            s.commit()

    # -- events -----------------------------------------------------------------
    def record_event(self, event: dict) -> None:
        m = self._models
        owner_key = str(event.get("owner_key", ""))
        with self._session() as s:
            s.add(m.Event(
                owner_type=("user" if owner_key.startswith("user:")
                            else "anonymous"),
                plan=event.get("plan"),
                pair_slug=event.get("pair_slug"),
                category=event.get("category"),
                status=event.get("status"),
                bytes_in=event.get("bytes_in"),
                bytes_out=event.get("bytes_out"),
                duration_ms=event.get("duration_ms"),
            ))
            s.commit()


_DEFAULT_STORE = None


def get_default_store():
    """Production store: database-backed (shared by the API and worker
    processes). Falls back to the in-memory store only if the database
    cannot be reached, so local tests and standalone CLIs keep working.
    """
    global _DEFAULT_STORE
    if _DEFAULT_STORE is None:
        try:
            _DEFAULT_STORE = DbStore()
        except Exception as exc:  # noqa: BLE001 - fall back, never crash boot
            import sys

            print(f"pipeline: DbStore unavailable ({exc}); using MemoryStore",
                  file=sys.stderr)
            _DEFAULT_STORE = MemoryStore()
    return _DEFAULT_STORE


# --- helpers -----------------------------------------------------------------
_UNSAFE = re.compile(r"[^A-Za-z0-9._-]+")
_EXT_OK = re.compile(r"^[A-Za-z0-9]{1,10}$")


def sanitize_filename(name: str) -> str:
    """Strip directories and unsafe characters; never trust a client name."""
    base = Path(name).name
    base = _UNSAFE.sub("_", base).strip("._")
    if not base:
        base = "file"
    stem, dot, ext = base.rpartition(".")
    if dot and _EXT_OK.match(ext):
        stem = stem[:80] or "file"
        return f"{stem}.{ext.lower()}"
    return base[:80]


def output_extension(to_slug: str) -> str:
    return to_slug


def _size_limit_bytes(plan: str, category: str) -> int:
    limits = PLAN_LIMITS.get(plan, PLAN_LIMITS["anonymous"])
    key = CATEGORY_LIMIT_KEY.get(category, "img_mb")
    return limits[key] * 1024 * 1024


def _store_file(data_dir: Path, subdir: str, record_id: str,
                filename: str, data: bytes) -> Path:
    folder = data_dir / subdir / record_id
    folder.mkdir(parents=True, exist_ok=True)
    os.chmod(folder, 0o700)
    path = folder / filename
    path.write_bytes(data)
    os.chmod(path, 0o600)
    return path


# --- uploads -----------------------------------------------------------------
def _validate_upload(plan: str, detected: str | None, size: int) -> dict:
    """Shared upload checks: format supported + plan size limit.

    Returns the catalog format entry. Raises PipelineError with the
    same codes/messages whichever upload path called it, so the size
    limit a plan sees never depends on how the file arrived."""
    if detected is None:
        raise PipelineError(
            "unsupported_format",
            "This file type is not supported.",
            "Check the format is listed on the home page and the file is not damaged.",
            status=400)
    if detected not in CATALOG.targets_by_input:
        raise PipelineError("unsupported_format",
                            f"{detected.upper()} files cannot be converted yet.",
                            "Pick a format from the home page list.", status=400)
    fmt = CATALOG.by_slug[detected]
    limit = _size_limit_bytes(plan, fmt["category"])
    if size > limit:
        raise PipelineError(
            "file_too_large",
            f"This file is over the {limit // (1024 * 1024)} MB limit for your plan.",
            "Choose a smaller file or upgrade your plan.", status=413)
    return fmt


def create_upload(store, owner_key: str, plan: str, filename: str,
                  data: bytes, data_dir: Path | None = None) -> UploadRecord:
    data_dir = data_dir or get_data_dir()
    detected = CATALOG.detect_format(data, filename)
    fmt = _validate_upload(plan, detected, len(data))
    safe_name = sanitize_filename(filename)
    record = UploadRecord(
        id=_new_id(), owner_key=owner_key, filename=safe_name,
        original_filename=filename[:200], size=len(data),
        detected_format=detected, category=fmt["category"], path="",
    )
    path = _store_file(data_dir, "uploads", record.id, safe_name, data)
    record.path = str(path)
    store.save_upload(record)
    return record


def create_upload_from_path(store, owner_key: str, plan: str, filename: str,
                            path: Path, data_dir: Path | None = None) -> UploadRecord:
    """Same checks as create_upload, but the file already sits on disk.

    The upload endpoint streams the request body to a temp file first
    (see routers_pipeline), so the API never holds a whole upload in
    RAM: only the first 4 KB are read, for format detection (magic
    bytes live in the head), and the size comes from the filesystem.
    The temp file is *moved* into place — the temp dir lives under
    data_dir, so this is a rename on the same filesystem, never a
    copy. On any validation failure the caller removes the temp file.
    """
    data_dir = data_dir or get_data_dir()
    path = Path(path)
    size = path.stat().st_size
    with open(path, "rb") as fh:
        head = fh.read(4096)
    detected = CATALOG.detect_format(head, filename)
    fmt = _validate_upload(plan, detected, size)
    safe_name = sanitize_filename(filename)
    record = UploadRecord(
        id=_new_id(), owner_key=owner_key, filename=safe_name,
        original_filename=filename[:200], size=size,
        detected_format=detected, category=fmt["category"], path="",
    )
    folder = data_dir / "uploads" / record.id
    folder.mkdir(parents=True, exist_ok=True)
    os.chmod(folder, 0o700)
    dest = folder / safe_name
    shutil.move(str(path), str(dest))
    os.chmod(dest, 0o600)
    record.path = str(dest)
    store.save_upload(record)
    return record


def delete_upload(store, owner_key: str, upload_id: str) -> None:
    rec = store.get_upload(upload_id)
    if rec is None:
        raise PipelineError("not_found", "Upload not found.", status=404)
    if rec.owner_key != owner_key:
        raise PipelineError("forbidden", "This upload belongs to someone else.",
                            status=403)
    path = Path(rec.path)
    if path.exists():
        path.unlink()
        try:
            path.parent.rmdir()
        except OSError:
            pass
    store.delete_upload(upload_id)


# --- conversions ---------------------------------------------------------------
def create_conversion(store, owner_key: str, plan: str, upload_id: str,
                      to_slug: str, settings: dict | None = None,
                      batch_id: str | None = None,
                      name_pattern: str | None = None,
                      quota_keys: list[str] | None = None,
                      user_id: str | None = None,
                      limits: dict | None = None) -> JobRecord:
    upload = store.get_upload(upload_id)
    if upload is None:
        raise PipelineError("not_found", "Upload not found.",
                            "Upload the file again.", status=404)
    if upload.owner_key != owner_key:
        raise PipelineError("forbidden", "This upload belongs to someone else.",
                            status=403)
    to_slug = CATALOG.resolve_slug(to_slug) or str(to_slug).lower()
    pair = CATALOG.get_pair(upload.detected_format, to_slug)
    if pair is None:
        raise PipelineError(
            "unsupported_pair",
            f"{upload.detected_format.upper()} to {to_slug.upper()} is not a supported conversion.",
            "Pick a target from the list for your file.", status=400)
    health = store.get_pair_health().get(pair["slug"], {})
    if health.get("status") == "disabled":
        raise PipelineError(
            "pair_disabled",
            "This converter is temporarily unavailable.",
            "Try one of the alternative converters shown on the page.",
            status=503)
    override = store.get_pair_override(pair["slug"])
    if not override.get("visible", True):
        raise PipelineError("pair_disabled", "This converter is temporarily unavailable.",
                            "Try one of the alternative converters shown on the page.",
                            status=503)
    allowed_plans = override.get("plans")
    if allowed_plans is not None and plan not in allowed_plans:
        raise PipelineError("plan_required",
                            "Your plan does not include this converter.",
                            "Upgrade your plan to use it.", status=403)
    limits = limits if limits is not None else PLAN_LIMITS.get(plan, PLAN_LIMITS["anonymous"])
    batch_id = batch_id or _new_id()
    if store.batch_job_count(owner_key, batch_id) >= limits["batch"]:
        raise PipelineError(
            "batch_limit",
            f"Your plan allows {limits['batch']} files per batch.",
            "Convert the remaining files as a second batch or upgrade.",
            status=429)
    if store.active_job_count(owner_key) >= limits["parallel"]:
        raise PipelineError(
            "parallel_limit",
            "Too many conversions are running at once.",
            "Wait for the current ones to finish.", status=429)
    day = quota_day()
    # Quota is counted when the job is ACCEPTED, on every counter in
    # quota_keys (anonymous: device key + IP-HMAC key, stricter applies;
    # signed-in: the user key). Defaults to [owner_key].
    keys = list(quota_keys) if quota_keys else [owner_key]
    for key in keys:
        if store.quota_used(key, day) >= limits["daily"]:
            raise PipelineError(
                "quota_exceeded",
                f"You have used all {limits['daily']} conversions for today.",
                "Your quota resets at midnight, or upgrade for more.",
                status=429)
    for key in keys:
        store.quota_increment(key, day)
    merged = engines.normalize_settings(to_slug, settings)
    if pair["category"] == "Video" or pair["route"] == "video":
        merged["max_duration_min"] = limits["vid_min"]
    stem = Path(upload.filename).stem
    out_name = (name_pattern or "{name}.{ext}").replace("{name}", stem).replace(
        "{ext}", output_extension(to_slug))
    out_name = sanitize_filename(out_name)
    job = JobRecord(
        id=_new_id(), batch_id=batch_id, owner_key=owner_key, user_id=user_id,
        upload_id=upload.id, pair_slug=pair["slug"],
        from_slug=pair["from"], to_slug=pair["to"], category=pair["category"],
        route=pair["route"], settings=merged, plan=plan, in_size=upload.size,
        out_name=out_name, quota_keys=keys,
    )
    store.save_job(job)
    return job


def refund_job_quota(store, job: JobRecord) -> None:
    """Refund one conversion (job failed or cancelled before it starts).

    Decrements every quota counter the job consumed."""
    day = quota_day(job.created_at)
    for key in (job.quota_keys or [job.owner_key]):
        store.quota_decrement(key, day)


def cancel_job(store, owner_key: str, job_id: str) -> tuple[JobRecord, bool]:
    """Cancel a job. Returns (job, refunded). A queued job is cancelled and
    refunded immediately; a running job is flagged and the worker refunds
    it when it stops."""
    job = store.get_job(job_id)
    if job is None:
        raise PipelineError("not_found", "Job not found.", status=404)
    if job.owner_key != owner_key:
        raise PipelineError("forbidden", "This job belongs to someone else.",
                            status=403)
    if job.status == "queued":
        job.status = "cancelled"
        job.finished_at = _now()
        store.save_job(job)
        refund_job_quota(store, job)
        return job, True
    if job.status == "running":
        job.cancel_requested = True
        store.save_job(job)
        return job, False
    return job, False


def get_jobs(store, owner_key: str, ids: list[str] | None) -> list[JobRecord]:
    if ids:
        jobs = []
        for job_id in ids:
            job = store.get_job(job_id)
            if job is None:
                raise PipelineError("not_found", f"Job {job_id} not found.",
                                    status=404)
            if job.owner_key != owner_key:
                raise PipelineError("forbidden", "A job belongs to someone else.",
                                    status=403)
            jobs.append(job)
        return jobs
    return store.list_jobs(owner_key)


# --- downloads ---------------------------------------------------------------
def build_download_token(job_id: str, expires_in_seconds: int = 3600) -> str:
    expires = int(_now().timestamp()) + expires_in_seconds
    payload = f"{job_id}.{expires}".encode()
    sig = hmac.new(get_secret_key(), payload, hashlib.sha256).digest()
    token = (base64.urlsafe_b64encode(payload).decode().rstrip("=") + "."
             + base64.urlsafe_b64encode(sig).decode().rstrip("="))
    return token


def verify_download_token(token: str) -> str | None:
    """Return the job id if the token is valid and unexpired, else None."""
    try:
        payload_b64, sig_b64 = token.split(".", 1)
        payload = base64.urlsafe_b64decode(payload_b64 + "=" * (-len(payload_b64) % 4))
        sig = base64.urlsafe_b64decode(sig_b64 + "=" * (-len(sig_b64) % 4))
        expected = hmac.new(get_secret_key(), payload, hashlib.sha256).digest()
        if not hmac.compare_digest(sig, expected):
            return None
        job_id, expires = payload.decode().rsplit(".", 1)
        if int(expires) < int(_now().timestamp()):
            return None
        return job_id
    except Exception:  # noqa: BLE001 - any malformed token is simply invalid
        return None


def download_path_for_job(store, job_id: str, token: str | None,
                          owner_key: str | None = None) -> tuple[Path, str]:
    """Authorize a download: a valid signed token, or the owning user.
    Returns (path, download filename)."""
    job = store.get_job(job_id)
    if job is None or job.status != "done" or not job.out_path:
        raise PipelineError("not_found", "Download is not available.",
                            "The file may have expired (files delete after 24 hours).",
                            status=404)
    authorized = False
    if token and verify_download_token(token) == job_id:
        authorized = True
    if owner_key is not None and owner_key == job.owner_key:
        authorized = True
    if not authorized:
        raise PipelineError("forbidden", "This download is not available to you.",
                            status=403)
    path = Path(job.out_path)
    if not path.exists():
        raise PipelineError("not_found", "The file has expired.",
                            "Files are deleted 24 hours after conversion.",
                            status=404)
    return path, job.out_name or path.name


# --- batch zip ---------------------------------------------------------------
def zip_batch(store, owner_key: str, job_ids: list[str],
              data_dir: Path | None = None) -> tuple[Path, str]:
    data_dir = data_dir or get_data_dir()
    jobs = get_jobs(store, owner_key, job_ids)
    done = [j for j in jobs if j.status == "done" and j.out_path
            and Path(j.out_path).exists()]
    if len(done) != len(jobs):
        raise PipelineError(
            "not_ready",
            "Some files in this batch are not finished yet.",
            "Wait for every conversion to finish, then download the ZIP.",
            status=409)
    batch_id = jobs[0].batch_id if jobs and jobs[0].batch_id else _new_id()
    zip_name = f"quick-img-convert-{batch_id}.zip"
    zip_dir = data_dir / "zips"
    zip_dir.mkdir(parents=True, exist_ok=True)
    zip_path = zip_dir / zip_name
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for job in done:
            zf.write(job.out_path, job.out_name or Path(job.out_path).name)
    os.chmod(zip_path, 0o600)
    return zip_path, zip_name


# --- history / retention -----------------------------------------------------
def list_history(store, owner_key: str, days: int = 90, page: int = 1,
                 page_size: int = 20) -> dict:
    jobs, total = store.list_history(owner_key, days, page, page_size)
    return {"jobs": [j.to_dict() for j in jobs], "total": total,
            "page": page, "page_size": page_size,
            "pages": (total + page_size - 1) // page_size}


def purge_expired(store, data_dir: Path | None = None,
                  retention_hours: int = RETENTION_HOURS) -> dict:
    """Delete uploads and outputs older than the retention window."""
    data_dir = data_dir or get_data_dir()
    cutoff = _now() - timedelta(hours=retention_hours)
    removed_uploads = removed_jobs = removed_files = 0
    list_all_uploads = getattr(store, "list_all_uploads", lambda: [])
    for upload in list_all_uploads():
        if upload.expires_at <= cutoff or upload.created_at <= cutoff:
            path = Path(upload.path)
            if path.exists():
                path.unlink()
                removed_files += 1
                try:
                    path.parent.rmdir()
                except OSError:
                    pass
            store.delete_upload(upload.id)
            removed_uploads += 1
    for job in store.list_jobs():
        if job.expires_at <= cutoff or job.created_at <= cutoff:
            if job.out_path:
                path = Path(job.out_path)
                if path.exists():
                    path.unlink()
                    removed_files += 1
            if hasattr(store, "delete_job"):
                store.delete_job(job.id)
            removed_jobs += 1
    return {"removed_uploads": removed_uploads, "removed_jobs": removed_jobs,
            "removed_files": removed_files}
