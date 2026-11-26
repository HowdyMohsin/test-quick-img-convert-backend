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
from app.engines import (  # noqa: E402
    _contains_ai_marker,
    _exif_without_ai,
    _exif_without_gps,
    _strip_ai_metadata_pillow,
    normalize_settings,
)
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


def make_gradient_jpeg_bytes(size=(800, 600)) -> bytes:
    """Smooth gradient JPEG: PNG level 9 compresses it far below level 0
    (random pixels do not — they are incompressible at every level)."""
    from PIL import Image

    img = Image.new("RGB", size)
    img.putdata([((x * 255) // size[0], (y * 255) // size[1],
                  ((x + y) * 255) // (size[0] + size[1]))
                 for y in range(size[1]) for x in range(size[0])])
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


# --- Compress toggle -------------------------------------------------------

def test_normalize_settings_compress_enabled_false_forces_level_zero():
    assert normalize_settings("png", {"compression": 9, "compress_enabled": False})["compression"] == 0
    assert normalize_settings("png", {"compression": 9, "compress_enabled": True})["compression"] == 9
    # Absent means ON: current behaviour unchanged.
    assert normalize_settings("png", {"compression": 9})["compression"] == 9
    assert normalize_settings("png", {"compress_enabled": 0})["compress_enabled"] is False
    assert normalize_settings("png", {"compress_enabled": 0})["compression"] == 0


def test_convert_png_compress_off_is_uncompressed(tmp_path):
    src = tmp_path / "gradient.jpg"
    src.write_bytes(make_gradient_jpeg_bytes())
    dst9 = tmp_path / "c9.png"
    engines.convert_file(src, "jpg", "png", {"compression": 9}, dst9)
    dst_off = tmp_path / "off.png"
    engines.convert_file(src, "jpg", "png",
                         {"compression": 9, "compress_enabled": False}, dst_off)
    # Level 0 stores the pixels uncompressed: an 800x600 RGB image is
    # ~1.44 MB raw, versus ~135 KB compressed at level 9.
    assert dst_off.stat().st_size > dst9.stat().st_size
    assert dst_off.stat().st_size > 1_400_000
    # NOTE: an explicit {"compression": 0} with the toggle ON does NOT
    # produce the same file — Pillow's optimize=True (the existing
    # default path) makes the encoder ignore compress_level, so level 0
    # still comes out compressed. That pre-existing slider quirk is
    # out of scope for the toggle; the toggle OFF path drops optimize
    # and is genuinely uncompressed.


# --- AI data remover -------------------------------------------------------

AI_XMP = ('<x:xmpmeta xmlns:x="adobe:ns:meta/">'
          '<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#" '
          'xmlns:xmp="http://ns.adobe.com/xap/1.0/" '
          'xmlns:Iptc4xmpExt="http://iptc.org/std/Iptc4xmpExt/2008-02-29/">'
          '<rdf:Description xmp:CreatorTool="Stable Diffusion" '
          'Iptc4xmpExt:DigitalSourceType="http://cv.iptc.org/newscodes/'
          'digitalsourcetype/compositeWithTrainedAlgorithmicMedia"/>'
          '</rdf:RDF></x:xmpmeta>')

CLEAN_XMP = ('<x:xmpmeta xmlns:x="adobe:ns:meta/">'
             '<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#" '
             'xmlns:dc="http://purl.org/dc/elements/1.1/">'
             '<rdf:Description><dc:title>Family photo</dc:title>'
             '</rdf:Description></rdf:RDF></x:xmpmeta>')


def make_ai_png_bytes(xmp: str = AI_XMP) -> bytes:
    """PNG with AI text chunks + an XMP packet, plus chunks to keep."""
    from PIL import Image
    from PIL.PngImagePlugin import PngInfo

    img = Image.new("RGB", (64, 64), (10, 200, 90))
    info = PngInfo()
    info.add_text("parameters", "Steps: 20, Sampler: Euler, CFG scale: 7")
    info.add_text("prompt", "a red cat")
    info.add_text("workflow", '{"nodes": []}')
    info.add_text("Comment", "keep me")
    info.add_text("Software", "keep me too")
    info.add_itxt("XML:com.adobe.xmp", xmp)
    buf = io.BytesIO()
    img.save(buf, format="PNG", pnginfo=info)
    return buf.getvalue()


def make_ai_exif_jpeg_bytes() -> bytes:
    """JPEG whose EXIF names an AI generator (Software) plus kept tags."""
    from PIL import Image

    img = Image.new("RGB", (64, 64), (200, 30, 40))
    exif = Image.Exif()
    exif[0x010F] = "TestMake"
    exif[0x010E] = "A beautiful sunset"
    exif[0x0131] = "Stable Diffusion"
    buf = io.BytesIO()
    img.save(buf, format="JPEG", exif=exif, quality=90)
    return buf.getvalue()


def test_ai_marker_detection():
    assert _contains_ai_marker("Stable Diffusion") is True
    assert _contains_ai_marker("http://cv.iptc.org/newscodes/digitalsourcetype/"
                                "compositeWithTrainedAlgorithmicMedia") is True
    assert _contains_ai_marker("Family photo") is False
    assert _contains_ai_marker("TestMake") is False


def test_strip_ai_data_removes_png_text_chunks_and_ai_xmp_keeps_other_metadata():
    from PIL import Image

    with Image.open(io.BytesIO(make_ai_png_bytes())) as im:
        im.load()
        _strip_ai_metadata_pillow(im, {"strip_ai_data": True})
        assert "parameters" not in im.info
        assert "prompt" not in im.info
        assert "workflow" not in im.info
        assert "XML:com.adobe.xmp" not in im.info
        assert "xmp" not in im.info
        assert im.info.get("Comment") == "keep me"
        assert im.info.get("Software") == "keep me too"


def test_strip_ai_data_off_keeps_everything():
    from PIL import Image

    with Image.open(io.BytesIO(make_ai_png_bytes())) as im:
        im.load()
        _strip_ai_metadata_pillow(im, {"strip_ai_data": False})
        assert im.info.get("parameters", "").startswith("Steps:")
        assert "XML:com.adobe.xmp" in im.info


def test_strip_ai_data_keeps_clean_xmp():
    from PIL import Image

    with Image.open(io.BytesIO(make_ai_png_bytes(xmp=CLEAN_XMP))) as im:
        im.load()
        _strip_ai_metadata_pillow(im, {"strip_ai_data": True})
        assert "XML:com.adobe.xmp" in im.info
        assert "xmp" in im.info


def test_exif_without_ai_removes_only_ai_software():
    from PIL import Image

    with Image.open(io.BytesIO(make_ai_exif_jpeg_bytes())) as im:
        im.load()
        stripped = _exif_without_ai(im.info["exif"])
    exif = Image.Exif()
    exif.load(stripped)
    assert 0x0131 not in exif
    assert exif.get(0x010F) == "TestMake"
    assert exif.get(0x010E) == "A beautiful sunset"


def test_convert_strips_ai_exif_software_keeps_make(tmp_path):
    src = tmp_path / "ai.jpg"
    src.write_bytes(make_ai_exif_jpeg_bytes())
    dst = tmp_path / "out.tiff"
    engines.convert_file(src, "jpg", "tiff",
                         {"strip_metadata": False, "strip_ai_data": True}, dst)
    out_exif = read_exif(dst)
    assert 0x0131 not in out_exif
    assert out_exif.get(0x010F) == "TestMake"
    assert out_exif.get(0x010E) == "A beautiful sunset"


def test_convert_keeps_ai_exif_without_the_toggle(tmp_path):
    src = tmp_path / "ai.jpg"
    src.write_bytes(make_ai_exif_jpeg_bytes())
    dst = tmp_path / "out.tiff"
    engines.convert_file(src, "jpg", "tiff", {"strip_metadata": False}, dst)
    out_exif = read_exif(dst)
    assert out_exif.get(0x0131) == "Stable Diffusion"


# --- Plan-gating defaults --------------------------------------------------

def test_feature_flag_defaults_mirror_editor():
    for plan in ("anonymous", "free"):
        for flag in ("gps_remover", "compare", "batch_rename", "target_size",
                     "compress_toggle", "ai_data_remover"):
            assert PLAN_LIMITS[plan][flag] is False, (plan, flag)
    for plan in ("basic", "pro"):
        for flag in ("gps_remover", "compare", "batch_rename", "target_size",
                     "compress_toggle", "ai_data_remover"):
            assert PLAN_LIMITS[plan][flag] is True, (plan, flag)


# --- Features endpoint + convert enforcement -------------------------------

@pytest.fixture()
def app_and_client(tmp_path):
    app = FastAPI()
    app.include_router(router)
    app.state.pipeline_store = MemoryStore()
    app.state.data_dir = tmp_path / "data"
    app.state.plan_resolver = lambda owner: "anonymous"
    # Signed-in by default (suspense lock, user order 2026-11-26): the
    # plan stays "anonymous" via plan_resolver, so the feature locks
    # below still trigger — only the identity is a user, not a visitor.
    app.state.test_user_id = "test-user-1"
    return app, TestClient(app), app.state.pipeline_store


def _upload(client, data: bytes, filename: str):
    return client.post("/v1/uploads", files={"file": (filename, data)})


def test_features_endpoint_anonymous_all_off(app_and_client):
    _, client, _ = app_and_client
    resp = client.get("/v1/features")
    assert resp.status_code == 200
    assert resp.json() == {"gps_remover": False, "compare": False,
                           "batch_rename": False, "target_size": False,
                           "compress_toggle": False, "ai_data_remover": False}


def test_convert_gps_option_locked_for_anonymous_plan(app_and_client):
    _, client, _ = app_and_client
    up = _upload(client, make_gps_jpeg_bytes(), "gps.jpg")
    assert up.status_code == 201
    resp = client.post("/v1/convert", json={
        "upload_id": up.json()["id"], "to": "webp",
        "settings": {"strip_metadata": False, "strip_gps": True}})
    assert resp.status_code == 403
    assert "feature_locked" in resp.text


def test_convert_target_size_locked_for_anonymous_plan(app_and_client):
    _, client, _ = app_and_client
    up = _upload(client, make_noisy_jpeg_bytes(), "noisy.jpg")
    assert up.status_code == 201
    resp = client.post("/v1/convert", json={
        "upload_id": up.json()["id"], "to": "webp",
        "settings": {"quality": 95, "target_size_kb": 200}})
    assert resp.status_code == 403
    assert "feature_locked" in resp.text


def test_convert_compress_off_locked_for_anonymous_plan(app_and_client):
    _, client, _ = app_and_client
    up = _upload(client, make_noisy_jpeg_bytes(), "noisy.jpg")
    assert up.status_code == 201
    resp = client.post("/v1/convert", json={
        "upload_id": up.json()["id"], "to": "png",
        "settings": {"compression": 9, "compress_enabled": False}})
    assert resp.status_code == 403
    assert "feature_locked" in resp.text


def test_convert_strip_ai_data_locked_for_anonymous_plan(app_and_client):
    _, client, _ = app_and_client
    up = _upload(client, make_ai_exif_jpeg_bytes(), "ai.jpg")
    assert up.status_code == 201
    resp = client.post("/v1/convert", json={
        "upload_id": up.json()["id"], "to": "tiff",
        "settings": {"strip_metadata": False, "strip_ai_data": True}})
    assert resp.status_code == 403
    assert "feature_locked" in resp.text


def test_convert_compress_on_still_accepted(app_and_client):
    _, client, _ = app_and_client
    up = _upload(client, make_noisy_jpeg_bytes(), "noisy.jpg")
    assert up.status_code == 201
    resp = client.post("/v1/convert", json={
        "upload_id": up.json()["id"], "to": "png",
        "settings": {"compression": 9, "compress_enabled": True}})
    assert resp.status_code == 202


def test_convert_without_gated_options_still_accepted(app_and_client):
    _, client, _ = app_and_client
    up = _upload(client, make_noisy_jpeg_bytes(), "noisy.jpg")
    assert up.status_code == 201
    resp = client.post("/v1/convert", json={
        "upload_id": up.json()["id"], "to": "webp",
        "settings": {"quality": 95}})
    assert resp.status_code == 202
