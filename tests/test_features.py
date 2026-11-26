"""Plan-gated converter features: GPS remover, compare, batch rename,
target file size. GPS stripping and target-size fitting run in the real
engines (Pillow path here — libvips is absent on this machine, so the
vips path is exercised only on Docker); the features endpoint and the
convert-time enforcement run through the real pipeline router.
"""
import io
import random
import sys
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app import engines  # noqa: E402
from app.engines import _exif_without_gps, normalize_settings  # noqa: E402
from app.pipeline import PLAN_LIMITS, MemoryStore  # noqa: E402
from app.routers_pipeline import router  # noqa: E402

GPS_IFD = 0x8825


def make_gps_jpeg_bytes(size=(64, 64)) -> bytes:
    """Small JPEG with a GPS IFD plus kept tags (Make, ImageDescription)."""
    from PIL import Image

    img = Image.new("RGB", size, (200, 30, 40))
    exif = Image.Exif()
    exif[0x010F] = "TestMake"
    exif[0x010E] = "Test description"
    exif[GPS_IFD] = {0: b"\x02\x03\x00\x00", 1: "N", 2: (37.0, 46.0, 30.0),
                     3: "W", 4: (122.0, 25.0, 10.0), 5: 0, 6: 15.0}
    buf = io.BytesIO()
    img.save(buf, format="JPEG", exif=exif, quality=90)
    return buf.getvalue()


def make_noisy_jpeg_bytes(size=(800, 600)) -> bytes:
    """Random-pixel JPEG: compresses poorly, so target-size fitting has
    real work to do (quality 95 is ~430 KB as WebP, quality 10 ~125 KB)."""
    from PIL import Image

    rnd = random.Random(7)
    img = Image.new("RGB", size)
    img.putdata([(rnd.randrange(256), rnd.randrange(256), rnd.randrange(256))
                 for _ in range(size[0] * size[1])])
    buf = io.BytesIO()
    img.save(buf, format="JPEG", quality=95)
    return buf.getvalue()


def read_exif(path: Path):
    from PIL import Image

    with Image.open(path) as im:
        im.load()
        return im.getexif()


# --- GPS remover -----------------------------------------------------------

def test_exif_without_gps_removes_only_gps():
    raw = make_gps_jpeg_bytes()
    from PIL import Image

    with Image.open(io.BytesIO(raw)) as im:
        im.load()
        stripped = _exif_without_gps(im.info["exif"])
    from PIL import Image as _Image

    exif = _Image.Exif()
    exif.load(stripped)
    assert GPS_IFD not in exif
    assert exif.get(0x010F) == "TestMake"
    assert exif.get(0x010E) == "Test description"


def test_convert_strips_gps_but_keeps_other_metadata(tmp_path):
    src = tmp_path / "gps.jpg"
    src.write_bytes(make_gps_jpeg_bytes())
    dst = tmp_path / "out.tiff"
    info = engines.convert_file(src, "jpg", "tiff",
                                {"strip_metadata": False, "strip_gps": True}, dst)
    out_exif = read_exif(dst)
    assert GPS_IFD not in out_exif
    assert out_exif.get(0x010F) == "TestMake"
    assert info.get("engine_used") == "pillow"


def test_convert_keeps_gps_without_the_toggle(tmp_path):
    src = tmp_path / "gps.jpg"
    src.write_bytes(make_gps_jpeg_bytes())
    dst = tmp_path / "out.tiff"
    engines.convert_file(src, "jpg", "tiff", {"strip_metadata": False}, dst)
    out_exif = read_exif(dst)
    assert GPS_IFD in out_exif
    assert out_exif.get_ifd(GPS_IFD).get(2) is not None


def test_convert_strip_all_removes_everything(tmp_path):
    src = tmp_path / "gps.jpg"
    src.write_bytes(make_gps_jpeg_bytes())
    dst = tmp_path / "out.tiff"
    engines.convert_file(src, "jpg", "tiff", {"strip_metadata": True, "strip_gps": True}, dst)
    from PIL import Image

    with Image.open(dst) as im:
        assert not im.info.get("exif")


# --- Target file size ------------------------------------------------------

def test_target_size_fits_with_lower_quality(tmp_path):
    src = tmp_path / "noisy.jpg"
    src.write_bytes(make_noisy_jpeg_bytes())
    dst = tmp_path / "out.webp"
    info = engines.convert_file(src, "jpg", "webp",
                                {"quality": 95, "target_size_kb": 200}, dst)
    assert dst.stat().st_size <= 200 * 1024
    assert info["quality"] < 95
    assert info["quality"] >= 10


def test_target_size_unreachable_uses_floor_and_reports_real_size(tmp_path):
    src = tmp_path / "noisy.jpg"
    src.write_bytes(make_noisy_jpeg_bytes())
    dst = tmp_path / "out.webp"
    info = engines.convert_file(src, "jpg", "webp",
                                {"quality": 95, "target_size_kb": 1}, dst)
    # 1 KB cannot be reached for this image even at quality 10: the floor
    # is used and the real (larger) size is what the caller reports.
    assert info["quality"] == 10
    assert dst.stat().st_size > 1 * 1024


def test_normalize_settings_clamps_target_size():
    assert normalize_settings("webp", {"target_size_kb": 0})["target_size_kb"] == 1
    assert normalize_settings("webp", {"target_size_kb": 999999})["target_size_kb"] == 102400
    assert "target_size_kb" not in normalize_settings("webp", {"target_size_kb": "abc"})
    assert normalize_settings("webp", {"strip_gps": 1})["strip_gps"] is True


# --- Plan-gating defaults --------------------------------------------------

def test_feature_flag_defaults_mirror_editor():
    for plan in ("anonymous", "free"):
        for flag in ("gps_remover", "compare", "batch_rename", "target_size"):
            assert PLAN_LIMITS[plan][flag] is False, (plan, flag)
    for plan in ("basic", "pro"):
        for flag in ("gps_remover", "compare", "batch_rename", "target_size"):
            assert PLAN_LIMITS[plan][flag] is True, (plan, flag)


# --- Features endpoint + convert enforcement -------------------------------

@pytest.fixture()
def app_and_client(tmp_path):
    app = FastAPI()
    app.include_router(router)
    app.state.pipeline_store = MemoryStore()
    app.state.data_dir = tmp_path / "data"
    app.state.plan_resolver = lambda owner: "anonymous"
    return app, TestClient(app), app.state.pipeline_store


def _upload(client, data: bytes, filename: str):
    return client.post("/v1/uploads", files={"file": (filename, data)})


def test_features_endpoint_anonymous_all_off(app_and_client):
    _, client, _ = app_and_client
    resp = client.get("/v1/features")
    assert resp.status_code == 200
    assert resp.json() == {"gps_remover": False, "compare": False,
                           "batch_rename": False, "target_size": False}


def test_convert_gps_option_locked_for_anonymous(app_and_client):
    _, client, _ = app_and_client
    up = _upload(client, make_gps_jpeg_bytes(), "gps.jpg")
    assert up.status_code == 201
    resp = client.post("/v1/convert", json={
        "upload_id": up.json()["id"], "to": "webp",
        "settings": {"strip_metadata": False, "strip_gps": True}})
    assert resp.status_code == 403
    assert "feature_locked" in resp.text


def test_convert_target_size_locked_for_anonymous(app_and_client):
    _, client, _ = app_and_client
    up = _upload(client, make_noisy_jpeg_bytes(), "noisy.jpg")
    assert up.status_code == 201
    resp = client.post("/v1/convert", json={
        "upload_id": up.json()["id"], "to": "webp",
        "settings": {"quality": 95, "target_size_kb": 200}})
    assert resp.status_code == 403
    assert "feature_locked" in resp.text


def test_convert_without_gated_options_still_accepted(app_and_client):
    _, client, _ = app_and_client
    up = _upload(client, make_noisy_jpeg_bytes(), "noisy.jpg")
    assert up.status_code == 201
    resp = client.post("/v1/convert", json={
        "upload_id": up.json()["id"], "to": "webp",
        "settings": {"quality": 95}})
    assert resp.status_code == 202
