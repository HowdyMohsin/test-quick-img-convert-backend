"""Catalog tests: pair derivation, targets, aliases, detection, no hard-coding."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.catalog import CATALOG  # noqa: E402

EXPECTED_TOTAL = 238
EXPECTED_BY_ROUTE = {
    "raster": 82, "psd": 5, "svg": 5, "trace": 4,
    "raw": 54, "audio": 40, "video": 44, "pdf": 4,
}


def test_pair_total_is_computed():
    assert CATALOG.count_pairs() == EXPECTED_TOTAL


def test_pair_counts_by_group():
    from collections import Counter

    counts = Counter(p["route"] for p in CATALOG.pairs)
    assert dict(counts) == EXPECTED_BY_ROUTE


def test_no_self_pairs():
    assert all(p["from"] != p["to"] for p in CATALOG.pairs)


def test_pair_slugs_unique():
    slugs = [p["slug"] for p in CATALOG.pairs]
    assert len(slugs) == len(set(slugs))


def test_targets_by_input_raster():
    assert CATALOG.targets_by_input["jpg"] == [
        "png", "webp", "avif", "gif", "tiff", "bmp", "ico", "pdf", "svg"]
    assert CATALOG.targets_by_input["heic"] == [
        "jpg", "png", "webp", "avif", "gif", "tiff", "bmp", "ico", "pdf"]
    assert CATALOG.targets_by_input["tga"] == [
        "jpg", "png", "webp", "avif", "gif", "tiff", "bmp", "ico", "pdf"]


def test_targets_by_input_other_groups():
    assert CATALOG.targets_by_input["psd"] == ["jpg", "png", "webp", "tiff", "pdf"]
    assert CATALOG.targets_by_input["svg"] == ["png", "jpg", "webp", "ico", "pdf"]
    assert CATALOG.targets_by_input["pdf"] == ["jpg", "png", "webp", "tiff"]
    assert CATALOG.targets_by_input["cr2"] == ["jpg", "png", "tiff", "webp", "avif", "bmp"]
    assert CATALOG.targets_by_input["cr3"] == ["jpg", "png", "tiff", "webp", "avif", "bmp"]
    assert CATALOG.targets_by_input["mp3"] == ["wav", "ogg", "m4a", "flac"]
    assert CATALOG.targets_by_input["aac"] == ["mp3", "wav", "ogg", "m4a", "flac"]
    assert CATALOG.targets_by_input["mp4"] == ["webm", "mkv", "mov", "gif", "mp3"]
    assert CATALOG.targets_by_input["avi"] == ["mp4", "webm", "mkv", "mov", "gif", "mp3"]


def test_trace_pairs():
    assert CATALOG.get_pair("jpg", "svg") is not None
    assert CATALOG.get_pair("png", "svg") is not None
    assert CATALOG.get_pair("bmp", "svg") is not None
    assert CATALOG.get_pair("tiff", "svg") is not None
    assert CATALOG.get_pair("gif", "svg") is None


def test_formats_count_and_categories():
    assert len(CATALOG.formats) == 39
    assert {f["category"] for f in CATALOG.formats} == {
        "Images", "Camera RAW", "Audio", "Video", "Documents and vector"}


def test_aliases_resolve():
    assert CATALOG.resolve_slug("jpeg") == "jpg"
    assert CATALOG.resolve_slug("jpe") == "jpg"
    assert CATALOG.resolve_slug("tif") == "tiff"
    assert CATALOG.resolve_slug("heif") == "heic"
    assert CATALOG.resolve_slug("aif") == "aiff"
    assert CATALOG.resolve_slug("JPG") == "jpg"
    assert CATALOG.resolve_slug(".png") == "png"
    assert CATALOG.resolve_slug("nope") is None


def test_detection_magic_first():
    # PNG magic beats a .jpg extension.
    png = bytes.fromhex("89504E470D0A1A0A") + b"\x00" * 16
    assert CATALOG.detect_format(png, "photo.jpg") == "png"
    # PDF magic.
    assert CATALOG.detect_format(b"%PDF-1.7\n%...", "doc.pdf") == "pdf"
    # MP3 with an ID3 tag.
    assert CATALOG.detect_format(b"ID3\x04\x00\x00" + b"\x00" * 20, "song.mp3") == "mp3"
    # WAV: RIFF....WAVE.
    wav = bytes.fromhex("52494646") + b"\x00" * 4 + b"WAVE" + b"\x00" * 8
    assert CATALOG.detect_format(wav, "sound.wav") == "wav"
    # SVG text.
    assert CATALOG.detect_format(b'<svg xmlns="http://www.w3.org/2000/svg"/>',
                                 "logo.svg") == "svg"
    # GIF.
    assert CATALOG.detect_format(b"GIF89a" + b"\x00" * 10, "anim.gif") == "gif"


def test_detection_extension_fallback_for_shared_tiff_header():
    # NEF and TIFF share a 4-byte header; the extension decides.
    tiff_header = bytes.fromhex("4D4D002A") + b"\x00" * 20
    assert CATALOG.detect_format(tiff_header, "photo.nef") == "nef"
    assert CATALOG.detect_format(tiff_header, "scan.tiff") == "tiff"
    # Unknown bytes + unknown extension -> None.
    assert CATALOG.detect_format(b"hello world, not a file", "x.xyz") is None
    # Unknown bytes + known extension -> extension.
    assert CATALOG.detect_format(b"hello world", "x.png") == "png"


def test_pair_lookup_and_engine_routing():
    pair = CATALOG.get_pair("png", "jpg")
    assert pair["route"] == "raster" and pair["engine"] == "vips"
    assert CATALOG.get_pair("cr3", "jpg")["engine"] == "raw"
    assert CATALOG.get_pair("mp3", "wav")["engine"] == "ffmpeg"
    assert CATALOG.get_pair("mp4", "gif")["engine"] == "ffmpeg"
    assert CATALOG.get_pair("pdf", "png")["engine"] == "pdf"
    assert CATALOG.get_pair("psd", "jpg")["engine"] == "psd"
    assert CATALOG.get_pair("svg", "png")["engine"] == "svg"
    assert CATALOG.get_pair("jpg", "svg")["engine"] == "trace"
    assert CATALOG.get_pair("jpg", "jpg") is None
    assert CATALOG.get_pair("jpg", "mp3") is None


def test_no_hardcoded_total_in_production_code():
    """The pair total must be derived, never written as a literal."""
    source = (Path(__file__).resolve().parents[1] / "app" / "catalog.py").read_text()
    assert str(EXPECTED_TOTAL) not in source


def test_formats_response_shape():
    payload = CATALOG.formats_response(
        health={"png-to-jpg": {"status": "disabled", "last_error": "boom"}},
        samples={"jpg": True, "cr2": False})
    assert payload["categories"] == [
        "Images", "Camera RAW", "Audio", "Video", "Documents and vector"]
    assert len(payload["formats"]) == 39
    assert len(payload["pairs"]) == EXPECTED_TOTAL
    disabled = [p for p in payload["pairs"] if p["slug"] == "png-to-jpg"][0]
    assert disabled["status"] == "disabled"
    assert disabled["last_error"] == "boom"
    # Disabled pairs disappear from the dropdown targets.
    assert "jpg" not in payload["targets_by_input"]["png"]
    assert payload["samples"] == {"jpg": True, "cr2": False}
    assert "image" in payload["settings_schema"]
    assert "Web" in payload["presets"]["image"]


def test_settings_defaults():
    from app.engines import normalize_settings

    assert normalize_settings("jpg", {})["quality"] == 85
    assert normalize_settings("webp", {})["quality"] == 80
    assert normalize_settings("avif", {})["quality"] == 60
    assert normalize_settings("mp3", {})["bitrate_kbps"] == 192
    assert normalize_settings("mp4", {})["crf"] == 23
    assert normalize_settings("pdf", {})["dpi"] == 150
    assert normalize_settings("pdf", {"dpi": 999})["dpi"] == 300
    assert normalize_settings("pdf", {"dpi": 10})["dpi"] == 72
    assert normalize_settings("jpg", {"quality": 50})["quality"] == 50
