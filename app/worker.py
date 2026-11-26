"""In-process async worker queue (same codebase, ``python -m app.worker``).

Polls the jobs table (through the pipeline store), runs conversions via
``app.engines``, updates progress/status and records event rows. The
worker also runs the hourly grace sweep (``billing.run_grace_sweep``,
imported defensively — the billing module is owned by the payments-ads
agent and may not exist yet) and the retention purge job.

The worker survives engine failures per-job: a failed conversion marks
that one job failed (and refunds its quota) and the loop keeps going.
It never dies because one file was corrupt or one engine was missing.
"""
from __future__ import annotations

import asyncio
import os
import signal
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

from . import engines
from .pipeline import (
    JobRecord,
    MemoryStore,
    get_data_dir,
    get_default_store,
    purge_expired,
    refund_job_quota,
)

POLL_INTERVAL_SECONDS = float(os.environ.get("WORKER_POLL_SECONDS", "1"))
MAINTENANCE_INTERVAL_SECONDS = 3600  # hourly grace sweep + retention purge

# How many conversions the worker runs at once. Default 1: conversions
# queue in the database and are processed in turn, so a burst of
# requests can never run the box out of memory or CPU. Raising this
# only helps on a bigger machine — on the Oracle Always Free VPS
# (2 OCPU / 12 GB) it must never go above 2: each conversion can hold
# a decoded image / ffmpeg process in memory. Anything outside 1..2
# is clamped, never an error, so a bad env value cannot break boot.
def _parse_max_jobs() -> int:
    try:
        return int(os.environ.get("MAX_CONCURRENT_JOBS", "1"))
    except (TypeError, ValueError):
        return 1


def max_concurrent_jobs() -> int:
    """Worker concurrency cap: 1 by default, clamped to 1..2."""
    return max(1, min(2, _parse_max_jobs()))


def _now():
    return datetime.now(timezone.utc)


class Worker:
    def __init__(self, store=None, data_dir: Path | None = None,
                 poll_interval: float = POLL_INTERVAL_SECONDS,
                 max_concurrent: int | None = None):
        self.store = store if store is not None else get_default_store()
        self.data_dir = data_dir or get_data_dir()
        self.poll_interval = poll_interval
        # Explicit cap (default 1, clamped 1..2 — see max_concurrent_jobs).
        # A pool of 1 runs jobs strictly one at a time, in queue order;
        # a pool of 2 lets two conversions share the box. The pool is
        # created lazily so constructing a Worker never spawns threads.
        self.max_concurrent = (
            max(1, min(2, int(max_concurrent)))
            if max_concurrent is not None else max_concurrent_jobs())
        self._executor: ThreadPoolExecutor | None = None
        self._running = False
        self._last_maintenance = 0.0

    def _pool(self) -> ThreadPoolExecutor:
        if self._executor is None:
            self._executor = ThreadPoolExecutor(
                max_workers=self.max_concurrent,
                thread_name_prefix="qic-worker")
        return self._executor

    def close(self) -> None:
        """Stop the pool (lets short-lived callers exit cleanly)."""
        if self._executor is not None:
            self._executor.shutdown(wait=True)
            self._executor = None

    # -- job processing ------------------------------------------------------
    def _next_jobs(self) -> list[JobRecord]:
        jobs = [j for j in self.store.list_jobs() if j.status == "queued"]
        # Priority plans first, then oldest first.
        jobs.sort(key=lambda j: (0 if j.plan == "pro" else 1, j.created_at))
        return jobs

    def process_job(self, job: JobRecord) -> JobRecord:
        """Process one job synchronously. Never raises."""
        store = self.store
        # Claim atomically so two workers never process the same job.
        # (A job handed directly without being saved — tests only — skips
        # the claim and processes inline.)
        if hasattr(store, "claim_job"):
            if not store.claim_job(job.id):
                fresh = store.get_job(job.id)
                if fresh is not None:
                    return fresh
        # Re-read: another process may have cancelled it meanwhile.
        fresh = store.get_job(job.id)
        if fresh is not None:
            job = fresh
        if job.cancel_requested or job.status == "cancelled":
            job.status = "cancelled"
            job.finished_at = _now()
            store.save_job(job)
            refund_job_quota(store, job)
            return job
        upload = store.get_upload(job.upload_id)
        if upload is None:
            job.status = "failed"
            job.error_code = "not_found"
            job.error_message = "The uploaded file has expired."
            job.finished_at = _now()
            store.save_job(job)
            refund_job_quota(store, job)
            return job
        job.status = "running"
        job.started_at = _now()
        job.progress = 0.05
        store.save_job(job)
        src = Path(upload.path)
        out_dir = self.data_dir / "outputs" / job.id
        out_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(out_dir, 0o700)
        dst = out_dir / (job.out_name or f"output.{job.to_slug}")

        def _progress(value: float) -> None:
            job.progress = value
            store.save_job(job)

        try:
            info = engines.convert_file(
                src, job.from_slug, job.to_slug, job.settings, dst,
                progress_cb=_progress,
                event_sink=lambda event: store.record_event(
                    {**event, "job_id": job.id, "owner_key": job.owner_key,
                     "pair_slug": job.pair_slug, "plan": job.plan}),
            )
        except engines.ConversionError as exc:
            return self._fail_job(job, exc.code, exc.message)
        except Exception as exc:  # noqa: BLE001 - per-job survival
            return self._fail_job(job, "conversion_failed", str(exc)[:200])
        out_path = Path(info["output_path"])
        try:
            os.chmod(out_path, 0o600)
        except OSError:
            pass
        # Re-read: the cancel endpoint (another process) may have flagged
        # this job while it was converting.
        fresh = store.get_job(job.id)
        if fresh is not None:
            job = fresh
        if job.cancel_requested:
            out_path.unlink(missing_ok=True)
            job.status = "cancelled"
            job.finished_at = _now()
            job.progress = 0.0
            store.save_job(job)
            refund_job_quota(store, job)
            return job
        job.status = "done"
        job.progress = 1.0
        job.out_path = str(out_path)
        job.out_size = info.get("output_size")
        job.out_info = {k: v for k, v in info.items() if k != "output_path"}
        if out_path.suffix == ".zip":
            job.out_name = out_path.name
        job.finished_at = _now()
        store.save_job(job)
        return job

    def _fail_job(self, job: JobRecord, code: str, message: str) -> JobRecord:
        job.status = "failed"
        job.error_code = code
        job.error_message = message
        job.finished_at = _now()
        job.progress = 0.0
        self.store.save_job(job)
        refund_job_quota(self.store, job)
        self.store.record_event({
            "job_id": job.id, "owner_key": job.owner_key,
            "pair_slug": job.pair_slug, "plan": job.plan,
            "status": "failed", "error_code": code,
        })
        return job

    def run_once(self) -> list[JobRecord]:
        """Process every queued job once. Returns the processed jobs.

        Jobs run on a bounded pool (``max_concurrent``, default 1):
        extra jobs stay queued in the database and are picked up on the
        next poll — a burst can never start more conversions than the
        box can hold. With a pool of 1 this is strictly sequential, in
        queue order, exactly as before.
        """
        jobs = self._next_jobs()
        if not jobs:
            return []
        pool = self._pool()
        futures = [pool.submit(self.process_job, job) for job in jobs]
        processed = []
        for job, future in zip(jobs, futures):
            try:
                processed.append(future.result())
            except Exception as exc:  # noqa: BLE001 - loop survival
                print(f"worker: job {job.id} crashed the loop: {exc}", file=sys.stderr)
        return processed

    # -- maintenance -----------------------------------------------------------
    def run_maintenance(self) -> dict:
        """Hourly work: grace sweep + stale-request expiry + retention purge.

        The grace sweep and request expiry run on a real database session
        (async, via the core session factory); the purge runs on the
        shared pipeline store. Never raises.
        """
        result: dict = {"grace_sweep": "skipped", "purge": None}
        try:
            import asyncio as _asyncio

            result["grace_sweep"] = _asyncio.run(self._run_db_maintenance())
        except Exception as exc:  # noqa: BLE001
            result["grace_sweep"] = f"failed: {exc}"
        try:
            result["purge"] = purge_expired(self.store, self.data_dir)
        except Exception as exc:  # noqa: BLE001
            result["purge"] = {"error": str(exc)}
        return result

    async def _run_db_maintenance(self) -> str:
        """Grace sweep + stale payment-request expiry on a DB session."""
        from app.billing import resolve_models, run_grace_sweep
        from app.deps import get_sessionmaker
        from app.routers_admin_payments import expire_stale_requests

        session_maker = get_sessionmaker()
        async with session_maker() as db:
            models = resolve_models()
            sweep = await run_grace_sweep(db, models)
            expired = await expire_stale_requests(db, models)
            await db.commit()
        return f"ran (grace: {sweep}, expired_requests: {expired})"

    # -- async loop ------------------------------------------------------------
    async def run_forever(self) -> None:
        import time

        self._running = True
        while self._running:
            try:
                await asyncio.to_thread(self.run_once)
            except Exception as exc:  # noqa: BLE001
                print(f"worker: run_once failed: {exc}", file=sys.stderr)
            now = time.monotonic()
            if now - self._last_maintenance >= MAINTENANCE_INTERVAL_SECONDS:
                try:
                    await asyncio.to_thread(self.run_maintenance)
                except Exception as exc:  # noqa: BLE001
                    print(f"worker: maintenance failed: {exc}", file=sys.stderr)
                self._last_maintenance = now
            await asyncio.sleep(self.poll_interval)

    def stop(self) -> None:
        self._running = False


def process_all_once(store=None, data_dir: Path | None = None) -> list[JobRecord]:
    """Synchronous helper for tests and the CLI."""
    worker = Worker(store=store, data_dir=data_dir)
    try:
        return worker.run_once()
    finally:
        worker.close()


async def _main_async() -> None:
    worker = Worker()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, worker.stop)
        except (NotImplementedError, RuntimeError):
            pass
    print(f"worker started (data dir: {worker.data_dir}, "
          f"max_concurrent={worker.max_concurrent})", flush=True)
    try:
        await worker.run_forever()
    finally:
        worker.close()
    print("worker stopped", flush=True)


def main() -> int:
    try:
        asyncio.run(_main_async())
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
