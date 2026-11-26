"""Pipeline tests: upload sniffing, convert end-to-end, quota refund,
download auth. Tests needing an engine that is absent here are SKIPPED
(pytest.mark.skipif on the live probe) — a conversion is never faked."""
import io
import os
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app import engines  # noqa: E402
from app.catalog import CATALOG  # noqa: E402
from app.health import SAMPLES_DIR  # noqa: E402
from app.pipeline import (  # noqa: E402
    PLAN_LIMITS,
    MemoryStore,
    PipelineError,
    create_upload_from_path,
)
from app.routers_pipeline import router  # noqa: E402
from app.worker import Worker, max_concurrent_jobs  # noqa: E402

PNG_MAGIC = bytes.fromhex("89504E470D0A1A0A")


def make_png_bytes(size=(120, 90), color=(79, 70, 229)) -> bytes:
    from PIL import Image

    img = Image.new("RGB", size, color)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def make_svg_bytes() -> bytes:
    return (b'<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">'
            b'<script>alert(1)</script><rect width="100" height="100" fill="red"/>'
            b'</svg>')


@pytest.fixture()
def app_and_client(tmp_path):
    from app.deps import reset_settings

    old_site_url = os.environ.get("SITE_URL")
    # Anonymous flows need the device cookie round-tripped: the code
    # default SITE_URL is the https Vercel URL, which makes is_https
    # True, which marks the cookie secure — and a secure cookie is
    # never sent back over the TestClient's http://testserver, so each
    # anonymous request would get a fresh device id and uploads would
    # belong to "someone else" (same pattern as test_quota.py).
    os.environ["SITE_URL"] = "http://localhost:3000"
    reset_settings()
    try:
        app = FastAPI()
        app.include_router(router)
        app.state.pipeline_store = MemoryStore()
        app.state.data_dir = tmp_path / "data"
        app.state.plan_resolver = lambda owner: "anonymous"
        # Signed-in by default: most convert tests run as a user. Tests for
        # the anonymous behaviour clear this (set it to None) — anonymous
        # visitors convert under the normal anonymous quota (5/day), the
        # suspense lock having been removed on user order 2026-11-26.
        app.state.test_user_id = "test-user-1"
        yield app, TestClient(app), app.state.pipeline_store
    finally:
        if old_site_url is None:
            os.environ.pop("SITE_URL", None)
        else:
            os.environ["SITE_URL"] = old_site_url
        reset_settings()


@pytest.fixture()
def worker(app_and_client):
    app, client, store = app_and_client
    return Worker(store=store, data_dir=app.state.data_dir)


def upload(client, data: bytes, filename: str):
    return client.post("/v1/uploads", files={"file": (filename, data)})


def test_formats_endpoint(app_and_client):
    _, client, _ = app_and_client
    resp = client.get("/v1/formats")
    assert resp.status_code == 200
    body = resp.json()
    assert len(body["pairs"]) == 238
    assert body["targets_by_input"]["jpg"] == [
        "png", "webp", "avif", "gif", "tiff", "bmp", "ico", "pdf", "svg"]
    assert body["targets_by_input"]["mp3"] == ["wav", "ogg", "m4a", "flac"]


def test_upload_magic_byte_detection(app_and_client):
    _, client, _ = app_and_client
    png = make_png_bytes()
    # PNG magic with a .jpg name: magic wins.
    resp = upload(client, png, "photo.jpg")
    assert resp.status_code == 201, resp.text
    assert resp.json()["detected_format"] == "png"
    # Unknown bytes + unknown extension: rejected.
    resp = upload(client, b"hello world, not a file", "x.xyz")
    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == "unsupported_format"


def test_upload_sanitizes_filename(app_and_client):
    _, client, _ = app_and_client
    resp = upload(client, make_png_bytes(), "../../etc/passwd.png")
    assert resp.status_code == 201
    assert resp.json()["filename"] == "passwd.png"
    assert ".." not in resp.json()["path"]


def test_convert_png_to_jpg_end_to_end(app_and_client, worker):
    _, client, store = app_and_client
    resp = upload(client, make_png_bytes(), "photo.png")
    upload_id = resp.json()["id"]
    resp = client.post("/v1/convert", json={"upload_id": upload_id, "to": "jpg"})
    assert resp.status_code == 202, resp.text
    job_id = resp.json()["id"]
    assert resp.json()["status"] == "queued"
    processed = worker.run_once()
    assert len(processed) == 1
    job = store.get_job(job_id)
    assert job.status == "done", job.error_message
    assert job.out_size and job.out_size > 0
    out = Path(job.out_path)
    assert out.exists() and out.stat().st_mode & 0o777 == 0o600
    # Output is a real JPEG.
    assert out.read_bytes()[:2] == b"\xff\xd8"
    # Download with the signed URL from the job listing.
    listing = client.get(f"/v1/jobs?ids={job_id}").json()["jobs"][0]
    url = listing["download_url"]
    assert url is not None
    dl = client.get(url)
    assert dl.status_code == 200
    assert dl.headers["content-disposition"].startswith("attachment")
    assert dl.headers["x-content-type-options"] == "nosniff"
    assert dl.content[:2] == b"\xff\xd8"


def test_convert_allowed_for_anonymous_under_quota(app_and_client, worker):
    # Suspense lock REMOVED (user order 2026-11-26 22:52): an anonymous
    # visitor converts again under the normal anonymous quota (5/day,
    # parallel 1). The worker drains each job so the parallel limit
    # never trips; the 6th convert of the day hits the daily quota.
    app, client, _ = app_and_client
    app.state.test_user_id = None
    for _ in range(5):
        resp = upload(client, make_png_bytes(), "photo.png")
        assert resp.status_code == 201, resp.text
        resp = client.post("/v1/convert",
                           json={"upload_id": resp.json()["id"], "to": "jpg"})
        assert resp.status_code == 202, resp.text
        assert resp.json()["status"] == "queued"
        assert len(worker.run_once()) == 1
    resp = upload(client, make_png_bytes(), "photo.png")
    assert resp.status_code == 201, resp.text
    resp = client.post("/v1/convert",
                       json={"upload_id": resp.json()["id"], "to": "jpg"})
    assert resp.status_code == 429, resp.text
    assert resp.json()["error"]["code"] == "quota_exceeded"


def test_download_requires_auth(app_and_client, worker):
    app, client, store = app_and_client
    resp = upload(client, make_png_bytes(), "photo.png")
    job = client.post("/v1/convert",
                      json={"upload_id": resp.json()["id"], "to": "jpg"}).json()
    worker.run_once()
    # No token and a different owner (different user-agent -> different
    # anonymous owner key) -> 403. The "other" client must be anonymous:
    # app.state.test_user_id is shared by every TestClient on this app,
    # so clear it — otherwise the other client is the same signed-in user.
    app.state.test_user_id = None
    other = TestClient(client.app)
    resp = other.get(f"/v1/jobs/{job['id']}/download",
                     headers={"user-agent": "someone-else"})
    assert resp.status_code == 403
    # Bad token from a non-owner -> 403. (The owner themselves may
    # download without a token; the token is an additional path.)
    resp = other.get(f"/v1/jobs/{job['id']}/download?token=junk",
                     headers={"user-agent": "someone-else"})
    assert resp.status_code == 403


def test_quota_refund_on_engine_failure(app_and_client, worker):
    """A job that fails refunds its conversion. Uses a pair whose engine
    is missing on this machine (found live, never assumed)."""
    _, client, store = app_and_client
    probes = engines.probe_engines()
    missing_engine = next(
        (name for name in ("svg", "trace")
         if not probes[name].available), None)
    if missing_engine is None:
        pytest.skip("all engines are available here; nothing to fail on")
    pair = next(p for p in CATALOG.pairs if p["engine"] == missing_engine)
    if pair["from"] == "svg":
        data, name = make_svg_bytes(), "logo.svg"
    else:
        data, name = make_png_bytes(), "photo.png"
    from app.pipeline import quota_day

    day = quota_day()
    before = sum(store.quota_used(k, day) for k in list(store.quotas))
    resp = upload(client, data, name)
    assert resp.status_code == 201, resp.text
    resp = client.post("/v1/convert",
                       json={"upload_id": resp.json()["id"], "to": pair["to"]})
    assert resp.status_code == 202, resp.text
    job_id = resp.json()["id"]
    worker.run_once()
    job = store.get_job(job_id)
    assert job.status == "failed"
    assert job.error_code == "engine_missing"
    # Quota was counted on accept and refunded on failure.
    after = sum(store.quota_used(k, day) for k in list(store.quotas))
    assert after == before


def test_quota_refund_on_engine_failure_via_owner(app_and_client, worker):
    """Same refund check, counted through the real owner key."""
    _, client, store = app_and_client
    probes = engines.probe_engines()
    if probes["svg"].available:
        pytest.skip("an SVG renderer is available here")
    from app.pipeline import quota_day

    day = quota_day()
    before = sum(store.quota_used(k, day) for k in list(store.quotas))
    resp = upload(client, make_svg_bytes(), "logo.svg")
    assert resp.status_code == 201
    resp = client.post("/v1/convert",
                       json={"upload_id": resp.json()["id"], "to": "png"})
    assert resp.status_code == 202
    worker.run_once()
    job = store.get_job(resp.json()["id"])
    assert job.status == "failed" and job.error_code == "engine_missing"
    after = sum(store.quota_used(k, day) for k in list(store.quotas))
    assert after == before


def test_cancel_queued_job_refunds_quota(app_and_client):
    _, client, store = app_and_client
    from app.pipeline import quota_day

    day = quota_day()
    before = sum(store.quota_used(k, day) for k in list(store.quotas))
    resp = upload(client, make_png_bytes(), "photo.png")
    job = client.post("/v1/convert",
                      json={"upload_id": resp.json()["id"], "to": "jpg"}).json()
    assert job["status"] == "queued"
    resp = client.post(f"/v1/jobs/{job['id']}/cancel")
    assert resp.status_code == 200
    assert resp.json()["status"] == "cancelled"
    assert resp.json()["quota_refunded"] is True
    after = sum(store.quota_used(k, day) for k in list(store.quotas))
    assert after == before


def test_unsupported_pair_rejected(app_and_client):
    _, client, _ = app_and_client
    resp = upload(client, make_png_bytes(), "photo.png")
    resp = client.post("/v1/convert",
                       json={"upload_id": resp.json()["id"], "to": "mp3"})
    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == "unsupported_pair"


def test_history_and_zip(app_and_client, worker):
    app, client, store = app_and_client
    # Anonymous allows 1 parallel job; use the free plan (2 parallel)
    # so both conversions can be accepted while queued.
    app.state.plan_resolver = lambda owner: "free"
    job_ids = []
    for i in range(2):
        resp = upload(client, make_png_bytes(), f"photo{i}.png")
        job = client.post("/v1/convert",
                          json={"upload_id": resp.json()["id"], "to": "jpg",
                                "batch_id": "batch-1"}).json()
        job_ids.append(job["id"])
    worker.run_once()
    hist = client.get("/v1/history").json()
    assert hist["total"] == 2
    assert {j["id"] for j in hist["jobs"]} == set(job_ids)
    resp = client.post("/v1/jobs/zip", json={"job_ids": job_ids})
    assert resp.status_code == 200
    assert resp.headers["content-disposition"].startswith("attachment")
    assert "quick-img-convert-batch-1.zip" in resp.headers["content-disposition"]
    with zipfile.ZipFile(io.BytesIO(resp.content)) as zf:
        assert len(zf.namelist()) == 2


def test_engines_convert_png_to_jpg_directly(tmp_path):
    """Live engine check without HTTP: PNG -> JPG via the runner."""
    src = tmp_path / "in.png"
    src.write_bytes(make_png_bytes())
    dst = tmp_path / "out.jpg"
    info = engines.convert_file(src, "png", "jpg", {}, dst)
    assert dst.exists() and dst.stat().st_size > 0
    assert dst.read_bytes()[:2] == b"\xff\xd8"
    assert info["format"] == "jpg"
    assert info["engine_used"] in ("pillow", "vips")


@pytest.mark.skipif(shutil.which("ffmpeg") is None, reason="ffmpeg not installed")
def test_engines_convert_mp3_to_wav_directly(tmp_path):
    """Live ffmpeg check: MP3 -> WAV via the runner."""
    src = tmp_path / "tone.mp3"
    proc = subprocess.run(
        ["ffmpeg", "-nostdin", "-y", "-f", "lavfi", "-i",
         "sine=frequency=440:duration=1", "-c:a", "libmp3lame", "-b:a",
         "192k", str(src)],
        capture_output=True, timeout=60)
    assert proc.returncode == 0, proc.stderr.decode()[-300:]
    dst = tmp_path / "tone.wav"
    info = engines.convert_file(src, "mp3", "wav", {}, dst)
    assert dst.exists() and dst.stat().st_size > 0
    assert dst.read_bytes()[:4] == b"RIFF"
    assert info["engine_used"] == "ffmpeg"


def test_svg_input_is_sanitized(tmp_path):
    """Script tags and external references are stripped before rendering."""
    src = tmp_path / "evil.svg"
    src.write_bytes(make_svg_bytes())
    clean = engines._sanitize_svg(src)
    text = clean.read_text(encoding="utf-8")
    assert "<script" not in text.lower()
    assert "alert" not in text


def test_sample_endpoint_serves_real_sample(app_and_client):
    _, client, _ = app_and_client
    if not (SAMPLES_DIR / "png.png").exists():
        pytest.skip("png sample was not generated")
    resp = client.get("/v1/samples/png")
    assert resp.status_code == 200
    assert resp.content[:8] == PNG_MAGIC
    resp = client.get("/v1/samples/cr2")
    assert resp.status_code == 404  # no RAW sample can be generated here


@pytest.mark.parametrize("plan,allowed", [
    ("anonymous", False), ("free", False), ("basic", True), ("pro", True)])
def test_editor_access_by_plan(app_and_client, plan, allowed):
    app, client, _ = app_and_client
    app.state.plan_resolver = lambda owner, p=plan: p
    resp = client.get("/v1/editor/access")
    assert resp.status_code == 200
    assert resp.json() == {"plan": plan, "editor_allowed": allowed}


def test_editor_file_locked_for_anonymous_and_free(app_and_client):
    app, client, _ = app_and_client
    png = make_png_bytes()
    for plan in ("anonymous", "free"):
        app.state.plan_resolver = lambda owner, p=plan: p
        upload_id = upload(client, png, "photo.png").json()["id"]
        resp = client.get(f"/v1/editor/file/{upload_id}")
        assert resp.status_code == 403, resp.text
        err = resp.json()["error"]
        assert err["code"] == "editor_locked"
        assert "Basic or Pro" in err["message"]
        assert err["hint"] == "See /pricing to upgrade"


def test_editor_file_serves_image_for_basic(app_and_client):
    app, client, _ = app_and_client
    app.state.plan_resolver = lambda owner: "basic"
    png = make_png_bytes()
    upload_id = upload(client, png, "photo.png").json()["id"]
    resp = client.get(f"/v1/editor/file/{upload_id}")
    assert resp.status_code == 200
    assert resp.content == png
    assert resp.headers["content-type"].startswith("image/png")
    assert resp.headers["content-disposition"].startswith("attachment")


def test_editor_file_rejects_non_image_for_basic(app_and_client):
    app, client, _ = app_and_client
    app.state.plan_resolver = lambda owner: "basic"
    upload_id = upload(client, make_svg_bytes(), "logo.svg").json()["id"]
    resp = client.get(f"/v1/editor/file/{upload_id}")
    assert resp.status_code == 415
    assert resp.json()["error"]["code"] == "unsupported_media_type"


def test_upload_file_endpoint(app_and_client):
    app, client, _ = app_and_client
    png = make_png_bytes()
    upload_id = upload(client, png, "photo.png").json()["id"]
    resp = client.get(f"/v1/uploads/{upload_id}/file")
    assert resp.status_code == 200
    assert resp.content == png
    assert resp.headers["content-type"].startswith("image/png")
    assert resp.headers["content-disposition"].startswith("attachment")
    # Another anonymous owner cannot fetch it. The "other" client must
    # be anonymous: app.state.test_user_id is shared by every TestClient
    # on this app, so clear it — otherwise it is the same signed-in user.
    app.state.test_user_id = None
    other = TestClient(client.app)
    resp = other.get(f"/v1/uploads/{upload_id}/file",
                     headers={"user-agent": "someone-else"})
    assert resp.status_code == 404
    assert resp.json()["error"]["code"] == "not_found"


def test_upload_file_endpoint_missing_id(app_and_client):
    _, client, _ = app_and_client
    resp = client.get("/v1/uploads/does-not-exist/file")
    assert resp.status_code == 404
    assert resp.json()["error"]["code"] == "not_found"


def test_normalize_settings_clamps_compression():
    assert engines.normalize_settings("png", {"compression": 99})["compression"] == 9
    assert engines.normalize_settings("png", {"compression": -3})["compression"] == 0
    assert engines.normalize_settings("png", {"compression": 6})["compression"] == 6
    # Defaults stay in range and quality clamping is untouched.
    assert engines.normalize_settings("png", {})["compression"] == 6
    assert engines.normalize_settings("jpg", {"quality": 250})["quality"] == 100


# --- lightweight / safe-play (Oracle Always Free) ---------------------------

def test_max_concurrent_jobs_clamped(monkeypatch):
    """MAX_CONCURRENT_JOBS: default 1, never above 2, bad values fall back."""
    monkeypatch.delenv("MAX_CONCURRENT_JOBS", raising=False)
    assert max_concurrent_jobs() == 1
    monkeypatch.setenv("MAX_CONCURRENT_JOBS", "2")
    assert max_concurrent_jobs() == 2
    monkeypatch.setenv("MAX_CONCURRENT_JOBS", "99")
    assert max_concurrent_jobs() == 2
    monkeypatch.setenv("MAX_CONCURRENT_JOBS", "0")
    assert max_concurrent_jobs() == 1
    monkeypatch.setenv("MAX_CONCURRENT_JOBS", "not-a-number")
    assert max_concurrent_jobs() == 1


def test_worker_max_concurrent_argument_clamped(app_and_client):
    _, _, store = app_and_client
    assert Worker(store=store, max_concurrent=99).max_concurrent == 2
    assert Worker(store=store, max_concurrent=0).max_concurrent == 1
    assert Worker(store=store, max_concurrent=2).max_concurrent == 2


def test_worker_pool_drains_queue(app_and_client):
    """3 queued jobs, pool of 2: all finish, none lost, none doubled."""
    app, client, store = app_and_client
    app.state.plan_resolver = lambda owner: "pro"
    ids = []
    for i in range(3):
        upload_id = upload(client, make_png_bytes(), f"p{i}.png").json()["id"]
        resp = client.post("/v1/convert",
                           json={"upload_id": upload_id, "to": "jpg"})
        assert resp.status_code == 202, resp.text
        ids.append(resp.json()["id"])
    worker = Worker(store=store, data_dir=app.state.data_dir, max_concurrent=2)
    try:
        processed = worker.run_once()
    finally:
        worker.close()
    assert {j.id for j in processed} == set(ids)
    assert all(j.status == "done" for j in processed)


def test_create_upload_from_path(tmp_path):
    """Path-based upload: detection from the head, file moved into place."""
    from app.pipeline import create_upload

    store = MemoryStore()
    data_dir = tmp_path / "data"
    png = make_png_bytes()
    src = tmp_path / "photo.png"
    src.write_bytes(png)
    record = create_upload_from_path(store, "owner", "anonymous",
                                     "photo.png", src, data_dir)
    assert record.detected_format == "png"
    assert record.size == len(png)
    assert Path(record.path).read_bytes() == png
    assert not src.exists()  # moved, not copied
    # The bytes-based path still works and gives the same record shape.
    record2 = create_upload(store, "owner", "anonymous", "photo.png",
                            png, data_dir)
    assert record2.detected_format == "png"


def test_create_upload_from_path_enforces_limit(tmp_path, monkeypatch):
    """Oversize file: same 413 as the bytes path, temp file left for caller."""
    store = MemoryStore()
    data_dir = tmp_path / "data"
    src = tmp_path / "photo.png"
    src.write_bytes(make_png_bytes())
    monkeypatch.setitem(PLAN_LIMITS["anonymous"], "img_mb", 0)
    with pytest.raises(PipelineError) as excinfo:
        create_upload_from_path(store, "owner", "anonymous",
                                "photo.png", src, data_dir)
    assert excinfo.value.code == "file_too_large"
    assert excinfo.value.status == 413
    assert src.exists()  # not moved: the caller removes it


def test_upload_endpoint_enforces_category_limit(app_and_client, monkeypatch):
    """Small PNG, img limit forced to 0: streamed under the 1 MB plan cap,
    then rejected by the exact per-category limit — 413, no temp left."""
    app, client, _ = app_and_client
    monkeypatch.setitem(PLAN_LIMITS["anonymous"], "img_mb", 0)
    monkeypatch.setitem(PLAN_LIMITS["anonymous"], "vid_mb", 1)
    resp = upload(client, make_png_bytes(), "photo.png")
    assert resp.status_code == 413, resp.text
    assert resp.json()["error"]["code"] == "file_too_large"
    leftovers = list((app.state.data_dir / "tmp").glob("*.part"))
    assert leftovers == []


def test_upload_endpoint_aborts_over_plan_cap(app_and_client, monkeypatch):
    """All size limits forced to 0: the stream aborts on the first chunk
    with 413 instead of spooling the whole body — and leaves no temp."""
    app, client, _ = app_and_client
    monkeypatch.setitem(PLAN_LIMITS["anonymous"], "img_mb", 0)
    monkeypatch.setitem(PLAN_LIMITS["anonymous"], "aud_mb", 0)
    monkeypatch.setitem(PLAN_LIMITS["anonymous"], "vid_mb", 0)
    resp = upload(client, make_png_bytes(), "photo.png")
    assert resp.status_code == 413, resp.text
    assert resp.json()["error"]["code"] == "file_too_large"
    leftovers = list((app.state.data_dir / "tmp").glob("*.part"))
    assert leftovers == []
