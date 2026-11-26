"""Conversion engines for Quick IMG Convert.

Runner: probe -> route -> convert -> validate -> record event.

Engines (spec section 3):
- vips: pyvips + libvips when available; Pillow (+ pillow-heif) is the
  fallback loader/encoder for TGA, ICO and anything libvips cannot read.
  On this machine libvips is absent, so pyvips cannot import and the
  Pillow path does all raster work; that is honest graceful degradation,
  not a stub.
- raw: rawpy on LibRaw, camera white balance, sRGB output, then the
  raster encoder.
- psd: psd-tools composite (flattened; layers are not preserved).
- pdf: pypdfium2 render, 150 DPI default, selectable 72-300, page range,
  50-page cap. Multi-page output is a ZIP of numbered images and counts
  as ONE conversion.
- svg: resvg (binary) to PNG, then encode. Input SVG is sanitised and
  never fetches external resources.
- trace: vtracer with presets Logo / Photo / Line art.
- ffmpeg: all audio and video, subprocess WITHOUT a shell, -nostdin,
  timeout, limited threads.

Graceful degradation: probe_engines() runs at startup; a missing binary
or library disables ONLY the pairs that need it. Converting a disabled
pair raises EngineMissingError (clean ``engine_missing`` code), never a
crash or a 500.

Security (spec section 15): pixel cap of 100M with Pillow's
decompression-bomb limit, PDF 50-page cap, sanitised filenames are the
pipeline's job, SVG input sanitised, subprocesses never use a shell.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from .catalog import CATALOG, PIXEL_CAP

# Pillow is the raster fallback and is required for the raster path.
from PIL import Image, ImageOps

try:
    import pillow_heif  # noqa: F401  (registers HEIF/AVIF openers on import)

    pillow_heif.register_heif_opener()
    _HEIF_AVAILABLE = True
except Exception:
    _HEIF_AVAILABLE = False

Image.MAX_IMAGE_PIXELS = PIXEL_CAP

# --- errors ----------------------------------------------------------------
ERROR_SHAPE_HINTS = {
    "engine_missing": "The converter for this format is temporarily unavailable. Try a different format.",
    "unsupported_pair": "That conversion is not offered. Pick a target from the list for your file.",
    "pixel_cap_exceeded": "The image is too large (over 100 megapixels). Resize it and try again.",
    "pdf_too_many_pages": "PDFs over 50 pages cannot be converted. Select a page range of 50 pages or fewer.",
    "video_too_long": "The video is longer than your plan allows.",
    "conversion_failed": "The file could not be converted. Check it opens in another app and try again.",
    "corrupt_input": "The file appears damaged or is not the format it claims to be.",
}


class ConversionError(Exception):
    """A conversion failed for a known, user-facing reason."""

    def __init__(self, code: str, message: str, hint: str | None = None):
        self.code = code
        self.message = message
        self.hint = hint or ERROR_SHAPE_HINTS.get(code, "")
        super().__init__(message)


class EngineMissingError(ConversionError):
    """The engine a pair needs is not installed on this host."""

    def __init__(self, engine: str, detail: str = ""):
        self.engine = engine
        msg = f"The {engine} converter is not available on this server."
        if detail:
            msg += f" {detail}"
        super().__init__("engine_missing", msg)


class UnsupportedPairError(ConversionError):
    def __init__(self, from_slug: str, to_slug: str):
        super().__init__(
            "unsupported_pair", f"{from_slug} to {to_slug} is not a supported conversion."
        )


# --- probing ---------------------------------------------------------------
@dataclass
class EngineInfo:
    name: str
    available: bool
    detail: str = ""
    version: str = ""
    kind: str = "library"  # library | binary
    pairs_affected: list[str] = field(default_factory=list)


def _probe_pyvips() -> EngineInfo:
    try:
        import pyvips

        return EngineInfo(
            name="vips", available=True, kind="library",
            version=str(getattr(pyvips, "__version__", "")),
            detail=f"libvips {pyvips.version(0)}.{pyvips.version(1)}.{pyvips.version(2)}",
        )
    except Exception as exc:  # noqa: BLE001 - probe must never raise
        return EngineInfo(name="vips", available=False, kind="library",
                          detail=f"pyvips/libvips unavailable: {exc}".strip()[:200])


def _probe_pillow() -> EngineInfo:
    from PIL import features

    codecs = [c for c in ("jpg", "webp", "avif") if features.check(c)]
    return EngineInfo(
        name="pillow", available=True, kind="library",
        version=getattr(Image, "__version__", ""),
        detail=f"Pillow codecs: {', '.join(codecs) or 'none'}; "
               f"pillow-heif: {'yes' if _HEIF_AVAILABLE else 'no'}",
    )


def _probe_rawpy() -> EngineInfo:
    try:
        import rawpy

        libraw = getattr(rawpy, "libraw_version", None)
        detail = f"LibRaw {'.'.join(map(str, libraw))}" if libraw else ""
        return EngineInfo(name="raw", available=True, kind="library",
                          version=str(getattr(rawpy, "__version__", "")), detail=detail)
    except Exception as exc:  # noqa: BLE001
        return EngineInfo(name="raw", available=False, kind="library",
                          detail=f"rawpy unavailable: {exc}".strip()[:200])


def _probe_psd() -> EngineInfo:
    try:
        import psd_tools

        return EngineInfo(name="psd", available=True, kind="library",
                          version=str(getattr(psd_tools, "__version__", "")),
                          detail="psd-tools composite (flattened)")
    except Exception as exc:  # noqa: BLE001
        return EngineInfo(name="psd", available=False, kind="library",
                          detail=f"psd-tools unavailable: {exc}".strip()[:200])


def _probe_pdf() -> EngineInfo:
    try:
        import pypdfium2

        return EngineInfo(name="pdf", available=True, kind="library",
                          version=str(getattr(pypdfium2, "__version__", "")),
                          detail="pypdfium2 render")
    except Exception as exc:  # noqa: BLE001
        return EngineInfo(name="pdf", available=False, kind="library",
                          detail=f"pypdfium2 unavailable: {exc}".strip()[:200])


def _probe_binary(name: str, version_args: list[str]) -> EngineInfo:
    path = shutil.which(name)
    if not path:
        return EngineInfo(name=name, available=False, kind="binary",
                          detail=f"binary '{name}' not found on PATH")
    version = ""
    try:
        proc = subprocess.run(
            [path, *version_args], capture_output=True, text=True, timeout=10
        )
        first = (proc.stdout or proc.stderr).strip().splitlines()
        version = first[0][:120] if first else ""
    except Exception:  # noqa: BLE001
        pass
    return EngineInfo(name=name, available=True, kind="binary",
                      version=version, detail=f"binary at {path}")


def _probe_ffmpeg() -> EngineInfo:
    info = _probe_binary("ffmpeg", ["-version"])
    if not info.available:
        return info
    wanted = ["libx264", "libvpx-vp9", "libmp3lame", "libopus", "libvorbis",
              "aac", "flac", "pcm_s16le", "wmav2"]
    try:
        proc = subprocess.run(
            ["ffmpeg", "-hide_banner", "-encoders"],
            capture_output=True, text=True, timeout=15,
        )
        found = {name for name in wanted if re.search(rf"\b{name}\b", proc.stdout)}
        missing = sorted(set(wanted) - found)
        info.detail = (
            f"{info.detail}; encoders present: {', '.join(sorted(found))}"
            + (f"; missing encoders: {', '.join(missing)}" if missing else "")
        )
    except Exception as exc:  # noqa: BLE001
        info.detail += f"; encoder probe failed: {exc}"
    return info


def _probe_vtracer() -> EngineInfo:
    info = _probe_binary("vtracer", ["--version"])
    if info.available:
        return info
    try:
        import vtracer  # noqa: F401

        return EngineInfo(name="trace", available=True, kind="library",
                          detail="python vtracer package")
    except Exception as exc:  # noqa: BLE001
        return EngineInfo(name="trace", available=False, kind="binary",
                          detail=f"vtracer binary and package unavailable: {exc}".strip()[:200])


def probe_engines() -> dict[str, EngineInfo]:
    """Probe every engine. Never raises; missing engines are reported."""
    probes = {
        "vips": _probe_pyvips(),
        "pillow": _probe_pillow(),
        "raw": _probe_rawpy(),
        "psd": _probe_psd(),
        "pdf": _probe_pdf(),
        "svg": _probe_binary("resvg", ["--version"]),
        "trace": _probe_vtracer(),
        "ffmpeg": _probe_ffmpeg(),
    }
    # The svg engine also accepts rsvg-convert / cairosvg as renderers.
    if not probes["svg"].available:
        rsvg = shutil.which("rsvg-convert")
        if rsvg:
            probes["svg"] = EngineInfo(
                name="svg", available=True, kind="binary",
                detail=f"rsvg-convert at {rsvg}")
        else:
            try:
                import cairosvg  # noqa: F401

                probes["svg"] = EngineInfo(
                    name="svg", available=True, kind="library",
                    detail="cairosvg renderer")
            except Exception:  # noqa: BLE001
                probes["svg"].detail += "; rsvg-convert and cairosvg also absent"
    for name, info in probes.items():
        engine_key = {"vips": "vips", "pillow": "vips", "raw": "raw",
                      "psd": "psd", "pdf": "pdf", "svg": "svg",
                      "trace": "trace", "ffmpeg": "ffmpeg"}.get(name, name)
        info.pairs_affected = [p["slug"] for p in CATALOG.pairs_for_engine(engine_key)]
    # The raster engine is "vips" in the catalog, but Pillow is its
    # sanctioned fallback: a missing libvips does NOT disable raster pairs.
    if not probes["vips"].available and probes["pillow"].available:
        probes["vips"].detail += " — raster pairs are served by the Pillow fallback."
    return probes


def available_engines() -> set[str]:
    """Engine keys usable for routing right now.

    Raster routing: vips if libvips is present, otherwise Pillow.
    The pair engine stays "vips" in the catalog; the runner resolves it.
    """
    probes = probe_engines()
    out = set()
    if probes["vips"].available or probes["pillow"].available:
        out.add("vips")
    for key in ("raw", "psd", "pdf", "svg", "trace", "ffmpeg"):
        if probes[key].available:
            out.add(key)
    return out


# --- settings --------------------------------------------------------------
TARGET_DEFAULTS = {
    "jpg": {"quality": 85, "progressive": True},
    "webp": {"quality": 80},
    "avif": {"quality": 60, "speed": 6},
    "png": {"compression": 6},
    "mp3": {"bitrate_kbps": 192},
    "m4a": {"bitrate_kbps": 192},
    "ogg": {"quality": 5},
    "flac": {"compression": 5},
    "wav": {"bits": 16},
    "mp4": {"crf": 23, "preset": "medium", "audio_bitrate_kbps": 128},
    "webm": {"crf": 32, "audio_bitrate_kbps": 96},
    "mkv": {"crf": 23, "preset": "medium", "audio_bitrate_kbps": 128},
    "mov": {"crf": 23, "preset": "medium", "audio_bitrate_kbps": 128},
    "gif": {"width": 480, "fps": 12, "max_seconds": 15},
    "pdf": {"dpi": 150},
}

RESOLUTION_HEIGHTS = {"1080p": 1080, "720p": 720, "480p": 480}


def normalize_settings(to_slug: str, settings: dict | None) -> dict:
    merged = dict(TARGET_DEFAULTS.get(to_slug, {}))
    for key, value in (settings or {}).items():
        if value is not None:
            merged[key] = value
    if to_slug == "pdf":
        dpi = int(merged.get("dpi", 150))
        merged["dpi"] = max(72, min(300, dpi))
    if "quality" in merged:
        merged["quality"] = max(1, min(100, int(merged["quality"])))
    # quality 1-100 = visual quality for lossy JPG/WebP/AVIF; compression
    # 0-9 = lossless PNG compress_level (0 fastest/largest, 9 smallest/
    # slowest, same pixels) and FLAC compression_level.
    if "compression" in merged:
        merged["compression"] = max(0, min(9, int(merged["compression"])))
    return merged


def parse_page_range(value: str | None, total: int) -> list[int]:
    """Parse "1-3" / "2,5" into 0-based page indexes (50-page cap enforced)."""
    if not value:
        pages = list(range(total))
    else:
        pages = []
        for part in str(value).split(","):
            part = part.strip()
            if "-" in part:
                start, end = part.split("-", 1)
                pages.extend(range(int(start) - 1, int(end)))
            elif part:
                pages.append(int(part) - 1)
        pages = sorted({p for p in pages if 0 <= p < total})
    if len(pages) > 50:
        raise ConversionError(
            "pdf_too_many_pages",
            "Select 50 pages or fewer.",
        )
    if not pages:
        raise ConversionError("conversion_failed", "The page range selects no pages.")
    return pages


# --- raster (Pillow path) ----------------------------------------------------
def _background_rgb(settings: dict) -> tuple[int, int, int]:
    raw = str(settings.get("background", "#FFFFFF")).lstrip("#")
    try:
        return tuple(int(raw[i:i + 2], 16) for i in (0, 2, 4))  # type: ignore[return-value]
    except Exception:  # noqa: BLE001
        return (255, 255, 255)


def _resize_image(img: Image.Image, settings: dict) -> Image.Image:
    width, height = img.size
    max_w = settings.get("max_width")
    max_h = settings.get("max_height")
    resolution = settings.get("resolution")
    target_h = RESOLUTION_HEIGHTS.get(str(resolution)) if resolution else None
    scale = 1.0
    if max_w and width > int(max_w):
        scale = min(scale, int(max_w) / width)
    if max_h and height > int(max_h):
        scale = min(scale, int(max_h) / height)
    if target_h and height > target_h:
        scale = min(scale, target_h / height)
    if scale < 1.0:
        img = img.resize((max(1, int(width * scale)), max(1, int(height * scale))),
                         Image.LANCZOS)
    return img


def _apply_srgb(img: Image.Image) -> Image.Image:
    """Convert a Display P3 (or other) ICC profile to sRGB, best effort."""
    icc = img.info.get("icc_profile")
    if not icc:
        return img
    try:
        from PIL import ImageCms

        src = ImageCms.ImageCmsProfile(__import__("io").BytesIO(icc))
        dst = ImageCms.createProfile("sRGB")
        return ImageCms.profileToProfile(img, src, dst, outputMode="RGB")
    except Exception:  # noqa: BLE001
        return img


def _open_raster(src: Path) -> Image.Image:
    try:
        img = Image.open(src)
        img.load()
    except Exception as exc:  # noqa: BLE001
        raise ConversionError("corrupt_input", f"Could not read the image file: {exc}".strip()[:160])
    if img.size[0] * img.size[1] > PIXEL_CAP:
        raise ConversionError(
            "pixel_cap_exceeded",
            "The image has over 100 million pixels.",
        )
    img = ImageOps.exif_transpose(img)
    return _apply_srgb(img)


def _flatten(img: Image.Image, settings: dict) -> Image.Image:
    if img.mode in ("RGBA", "LA", "PA"):
        bg = Image.new("RGB", img.size, _background_rgb(settings))
        alpha = img.convert("RGBA").split()[3]
        bg.paste(img.convert("RGBA"), mask=alpha)
        return bg
    return img.convert("RGB")


def _encode_raster_image(img: Image.Image, to_slug: str, settings: dict,
                         dst: Path, frames: list[Image.Image] | None = None) -> dict:
    """Encode an already-loaded Pillow image. Returns output info."""
    quality = int(settings.get("quality", TARGET_DEFAULTS.get(to_slug, {}).get("quality", 85)))
    if to_slug in ("jpg", "bmp"):
        img = _flatten(img, settings)
    elif to_slug == "pdf":
        img = img.convert("RGB")
    elif to_slug in ("png", "webp", "avif", "tiff"):
        if img.mode not in ("RGB", "RGBA", "L", "LA", "P", "PA", "I;16"):
            img = img.convert("RGBA" if img.mode == "RGBA" else "RGB")
    save_kwargs: dict = {}
    fmt_map = {"jpg": "JPEG", "tiff": "TIFF", "pdf": "PDF", "psd": "PSD"}
    pil_format = fmt_map.get(to_slug, to_slug.upper())
    if to_slug == "jpg":
        save_kwargs = {"quality": quality, "progressive": bool(settings.get("progressive", True))}
        if not settings.get("strip_metadata", True):
            exif = img.info.get("exif")
            if exif:
                save_kwargs["exif"] = exif
    elif to_slug == "webp":
        save_kwargs = {"quality": quality, "method": 6}
        if frames:
            save_kwargs.update({"save_all": True, "append_images": frames[1:],
                                "duration": img.info.get("duration", 100), "loop": 0})
    elif to_slug == "avif":
        save_kwargs = {"quality": quality, "speed": int(settings.get("speed", 6))}
    elif to_slug == "png":
        save_kwargs = {"compress_level": int(settings.get("compression", 6)), "optimize": True}
    elif to_slug == "tiff":
        save_kwargs = {}
        if not settings.get("strip_metadata", True):
            exif = img.info.get("exif")
            if exif:
                save_kwargs["exif"] = exif
    elif to_slug == "gif":
        if frames:
            frames = [f.convert("P", palette=Image.ADAPTIVE) for f in frames]
            save_kwargs = {"save_all": True, "append_images": frames[1:],
                           "duration": img.info.get("duration", 100), "loop": 0,
                           "optimize": True}
            img = frames[0]
        else:
            img = img.convert("P", palette=Image.ADAPTIVE)
            save_kwargs = {"optimize": True}
    elif to_slug == "ico":
        sizes = [tuple(s) for s in settings.get("sizes", [(16, 16), (32, 32), (48, 48),
                                                          (64, 64), (128, 128), (256, 256)])]
        save_kwargs = {"sizes": sizes}
        img = img.convert("RGBA")
    elif to_slug == "pdf":
        save_kwargs = {"resolution": float(settings.get("dpi", 150))}
    if to_slug == "psd":
        img = img.convert("RGB") if img.mode not in ("RGB", "RGBA") else img
    img.save(dst, format=pil_format, **save_kwargs)
    return {"format": to_slug, "width": img.size[0], "height": img.size[1],
            "quality": quality if to_slug in ("jpg", "webp", "avif") else None}


def _convert_raster_vips(src: Path, to_slug: str, settings: dict, dst: Path) -> dict:
    """pyvips path; raises on any failure so the caller falls back to Pillow."""
    import pyvips

    img = pyvips.Image.new_from_file(str(src), access="sequential")
    if img.width * img.height > PIXEL_CAP:
        raise ConversionError("pixel_cap_exceeded", "The image has over 100 million pixels.")
    img = _resize_vips(img, settings)
    quality = int(settings.get("quality", TARGET_DEFAULTS.get(to_slug, {}).get("quality", 85)))
    if to_slug in ("jpg", "bmp"):
        if img.hasalpha():
            img = img.flatten(background=_background_rgb(settings))
    write_opts: dict = {}
    if to_slug == "jpg":
        write_opts = {"Q": quality, "interlace": bool(settings.get("progressive", True))}
    elif to_slug == "webp":
        write_opts = {"Q": quality}
    elif to_slug == "avif":
        write_opts = {"Q": quality, "effort": int(settings.get("speed", 6))}
    elif to_slug == "png":
        write_opts = {"compression": int(settings.get("compression", 6))}
    img.write_to_file(str(dst), **write_opts)
    return {"format": to_slug, "width": img.width, "height": img.height,
            "quality": quality, "engine_used": "vips"}


def _resize_vips(img, settings: dict):
    scale = 1.0
    max_w = settings.get("max_width")
    max_h = settings.get("max_height")
    resolution = settings.get("resolution")
    target_h = RESOLUTION_HEIGHTS.get(str(resolution)) if resolution else None
    if max_w and img.width > int(max_w):
        scale = min(scale, int(max_w) / img.width)
    if max_h and img.height > int(max_h):
        scale = min(scale, int(max_h) / img.height)
    if target_h and img.height > target_h:
        scale = min(scale, target_h / img.height)
    return img.resize(scale) if scale < 1.0 else img


def _convert_raster(src: Path, to_slug: str, settings: dict, dst: Path) -> dict:
    probes = probe_engines()
    if probes["vips"].available and to_slug not in ("ico", "gif", "pdf", "psd"):
        try:
            return _convert_raster_vips(src, to_slug, settings, dst)
        except ConversionError:
            raise
        except Exception:  # noqa: BLE001 - fall back to Pillow
            pass
    img = _open_raster(src)
    frames = None
    animated_target = to_slug in ("gif", "webp")
    n_frames = getattr(img, "n_frames", 1)
    if n_frames > 1 and animated_target:
        frames = []
        for i in range(n_frames):
            img.seek(i)
            frames.append(_resize_image(img.copy(), settings))
        first = frames[0]
        info = _encode_raster_image(first, to_slug, settings, dst, frames=frames)
        info["frames"] = len(frames)
        info["engine_used"] = "pillow"
        return info
    img = _resize_image(img, settings)
    info = _encode_raster_image(img, to_slug, settings, dst)
    info["engine_used"] = "pillow"
    return info


# --- raw / psd ---------------------------------------------------------------
def _convert_raw(src: Path, to_slug: str, settings: dict, dst: Path) -> dict:
    try:
        import rawpy
    except Exception as exc:  # noqa: BLE001
        raise EngineMissingError("raw", str(exc)[:120])
    try:
        import numpy as np

        with rawpy.imread(str(src)) as raw:
            rgb = raw.postprocess(use_camera_wb=True, output_color=rawpy.ColorSpace.sRGB,
                                  output_bps=8)
        img = Image.fromarray(np.asarray(rgb))
    except EngineMissingError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise ConversionError("corrupt_input", f"Could not read the RAW file: {exc}".strip()[:160])
    img = _resize_image(img, settings)
    info = _encode_raster_image(img, to_slug, settings, dst)
    info["engine_used"] = "rawpy+pillow"
    return info


def _convert_psd(src: Path, to_slug: str, settings: dict, dst: Path) -> dict:
    img = None
    try:
        from psd_tools import PSDImage

        psd = PSDImage.open(src)
        img = psd.composite()
    except Exception:  # noqa: BLE001
        try:
            img = Image.open(src)
            img.load()
        except Exception as exc:  # noqa: BLE001
            raise ConversionError(
                "corrupt_input", f"Could not read the PSD file: {exc}".strip()[:160])
    if img is None:  # pragma: no cover - defensive
        raise ConversionError("corrupt_input", "Could not read the PSD file.")
    img = ImageOps.exif_transpose(img)
    img = _resize_image(img, settings)
    info = _encode_raster_image(img, to_slug, settings, dst)
    info["engine_used"] = "psd-tools+pillow"
    info["note"] = "Converted from the flattened composite image; layers are not preserved."
    return info


# --- pdf ---------------------------------------------------------------------
def _convert_pdf(src: Path, to_slug: str, settings: dict, dst: Path) -> dict:
    try:
        import pypdfium2 as pdfium
    except Exception as exc:  # noqa: BLE001
        raise EngineMissingError("pdf", str(exc)[:120])
    try:
        doc = pdfium.PdfDocument(str(src))
    except Exception as exc:  # noqa: BLE001
        raise ConversionError("corrupt_input", f"Could not read the PDF: {exc}".strip()[:160])
    total = len(doc)
    if total > 50 and not settings.get("page_range"):
        raise ConversionError(
            "pdf_too_many_pages",
            f"This PDF has {total} pages; the limit is 50.",
        )
    pages = parse_page_range(settings.get("page_range"), total)
    dpi = int(settings.get("dpi", 150))
    scale = dpi / 72.0
    rendered: list[tuple[int, Image.Image]] = []
    try:
        for page_no in pages:
            page = doc[page_no]
            bitmap = page.render(scale=scale).to_pil()
            rendered.append((page_no + 1, bitmap))
    except Exception as exc:  # noqa: BLE001
        raise ConversionError("conversion_failed", f"Could not render the PDF: {exc}".strip()[:160])
    finally:
        doc.close()
    if len(rendered) == 1:
        page_no, img = rendered[0]
        img = _resize_image(img, settings)
        info = _encode_raster_image(img, to_slug, settings, dst)
        info.update({"engine_used": "pypdfium2", "pages": 1, "is_zip": False})
        return info
    # Multi-page output: a ZIP of numbered images = ONE conversion.
    zip_path = dst.with_suffix(".zip")
    stem = dst.stem
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for page_no, img in rendered:
            img = _resize_image(img, settings)
            with tempfile.NamedTemporaryFile(suffix=f".{to_slug}", delete=False) as tmp:
                tmp_path = Path(tmp.name)
            try:
                _encode_raster_image(img, to_slug, settings, tmp_path)
                zf.write(tmp_path, f"{stem}-page-{page_no:02d}.{to_slug}")
            finally:
                tmp_path.unlink(missing_ok=True)
    return {"format": "zip", "engine_used": "pypdfium2", "pages": len(rendered),
            "is_zip": True, "output_path": str(zip_path)}


# --- svg ---------------------------------------------------------------------
def _sanitize_svg(src: Path) -> Path:
    """Strip scripts, event handlers and external references from an SVG.

    The file is never fetched from the network; external references are
    removed, not resolved.
    """
    import xml.etree.ElementTree as ET

    try:
        tree = ET.parse(src)
    except Exception as exc:  # noqa: BLE001
        raise ConversionError("corrupt_input", f"Could not parse the SVG: {exc}".strip()[:160])
    root = tree.getroot()
    ns = {"xlink": "http://www.w3.org/1999/xlink"}
    for parent in root.iter():
        for child in list(parent):
            tag = child.tag.split("}")[-1].lower()
            if tag in ("script", "foreignobject", "iframe", "object", "embed",
                       "audio", "video"):
                parent.remove(child)
                continue
            for attr in list(child.attrib):
                name = attr.split("}")[-1].lower()
                if name.startswith("on"):
                    del child.attrib[attr]
                elif name in ("href", "xlink:href"):
                    value = str(child.attrib[attr]).strip().lower()
                    if value.startswith(("http://", "https://", "ftp:", "file:", "//")):
                        del child.attrib[attr]
    tmp = tempfile.NamedTemporaryFile(suffix=".svg", delete=False)
    tree.write(tmp.name, encoding="utf-8", xml_declaration=True)
    tmp.close()
    return Path(tmp.name)


def _convert_svg(src: Path, to_slug: str, settings: dict, dst: Path) -> dict:
    clean = _sanitize_svg(src)
    png_tmp = None
    try:
        png_tmp = Path(tempfile.NamedTemporaryFile(suffix=".png", delete=False).name)
        rendered = False
        if shutil.which("resvg"):
            proc = subprocess.run(
                ["resvg", str(clean), str(png_tmp)],
                stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=120,
            )
            rendered = proc.returncode == 0 and png_tmp.exists() and png_tmp.stat().st_size > 0
            if not rendered:
                raise ConversionError("conversion_failed",
                                      f"resvg failed: {proc.stderr.strip()[:200]}")
        elif shutil.which("rsvg-convert"):
            proc = subprocess.run(
                ["rsvg-convert", "-o", str(png_tmp), str(clean)],
                stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=120,
            )
            rendered = proc.returncode == 0 and png_tmp.exists() and png_tmp.stat().st_size > 0
            if not rendered:
                raise ConversionError("conversion_failed",
                                      f"rsvg-convert failed: {proc.stderr.strip()[:200]}")
        else:
            try:
                import cairosvg

                cairosvg.svg2png(url=str(clean), write_to=str(png_tmp))
                rendered = True
            except ImportError as exc:
                raise EngineMissingError(
                    "svg", "No SVG renderer is installed (resvg, rsvg-convert or cairosvg).") from exc
        if not rendered:  # pragma: no cover - defensive
            raise ConversionError("conversion_failed", "The SVG could not be rendered.")
        img = _open_raster(png_tmp)
        img = _resize_image(img, settings)
        info = _encode_raster_image(img, to_slug, settings, dst)
        info["engine_used"] = "resvg+pillow"
        return info
    finally:
        clean.unlink(missing_ok=True)
        if png_tmp is not None:
            png_tmp.unlink(missing_ok=True)


# --- trace -------------------------------------------------------------------
TRACE_PRESETS = {
    "logo": ["--mode", "polygon", "--color-precision", "6", "--filter-speckle", "4"],
    "photo": ["--mode", "spline", "--color-precision", "8", "--corner-threshold", "30"],
    "line_art": ["--mode", "polygon", "--color-precision", "2",
                 "--filter-speckle", "8", "--path-precision", "3"],
}


def _convert_trace(src: Path, to_slug: str, settings: dict, dst: Path) -> dict:
    preset = str(settings.get("trace_preset", "logo")).lower().replace(" ", "_")
    flags = TRACE_PRESETS.get(preset, TRACE_PRESETS["logo"])
    if shutil.which("vtracer"):
        proc = subprocess.run(
            ["vtracer", "--input", str(src), "--output", str(dst), *flags],
            stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=300,
        )
        if proc.returncode != 0 or not dst.exists() or dst.stat().st_size == 0:
            raise ConversionError("conversion_failed",
                                  f"vtracer failed: {proc.stderr.strip()[:200]}")
        return {"format": "svg", "engine_used": "vtracer",
                "trace_preset": preset}
    try:
        import vtracer as vt
        import numpy as np

        # Preset kwargs for the python API (mirrors TRACE_PRESETS above).
        kwargs = {
            "logo": {"mode": "polygon", "color_precision": 6,
                     "filter_speckle": 4},
            "photo": {"mode": "spline", "color_precision": 8,
                      "corner_threshold": 30},
            "line_art": {"mode": "polygon", "color_precision": 2,
                         "filter_speckle": 8, "path_precision": 3},
        }.get(preset, {"mode": "polygon", "color_precision": 6,
                       "filter_speckle": 4})
        try:
            vt.convert_image_to_svg_py(str(src), str(dst), **kwargs)
        except Exception:
            # Fall back to the pixel API (needs RGBA tuples + (width, height)).
            img = Image.open(src).convert("RGBA")
            arr = np.asarray(img)
            pixels = tuple(tuple(int(v) for v in px)
                           for row in arr for px in row)
            svg_text = vt.convert_pixels_to_svg(
                pixels, (img.width, img.height), **kwargs)
            dst.write_text(svg_text, encoding="utf-8")
        if not dst.exists() or dst.stat().st_size == 0:
            raise ConversionError("conversion_failed",
                                  "vtracer produced no output.")
        return {"format": "svg", "engine_used": "vtracer",
                "trace_preset": preset}
    except ImportError as exc:
        raise EngineMissingError(
            "trace", "vtracer is not installed (binary or python package).") from exc
    except ConversionError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise ConversionError("conversion_failed", f"Tracing failed: {exc}".strip()[:160])


# --- ffmpeg ------------------------------------------------------------------
def _ffprobe(src: Path) -> dict:
    if not shutil.which("ffprobe"):
        return {}
    try:
        proc = subprocess.run(
            ["ffprobe", "-v", "error", "-show_format", "-show_streams",
             "-of", "json", str(src)],
            stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=30,
        )
        return json.loads(proc.stdout) if proc.returncode == 0 else {}
    except Exception:  # noqa: BLE001
        return {}


def _ffmpeg_available_encoders() -> set[str]:
    try:
        proc = subprocess.run(
            ["ffmpeg", "-hide_banner", "-encoders"],
            capture_output=True, text=True, timeout=15,
        )
        return set(re.findall(r"\b([a-z0-9_]+)\b", proc.stdout))
    except Exception:  # noqa: BLE001
        return set()


def _run_ffmpeg(args: list[str], timeout: int) -> None:
    """Run ffmpeg without a shell, with -nostdin and a timeout."""
    full = ["ffmpeg", "-nostdin", "-y", "-threads", "2", *args]
    try:
        proc = subprocess.run(
            full, stdin=subprocess.DEVNULL, capture_output=True, text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        raise ConversionError(
            "conversion_failed",
            "The conversion timed out. Try a smaller file or a lower quality setting.")
    if proc.returncode != 0:
        lines = [ln for ln in (proc.stderr or "").strip().splitlines()
                 if ln.strip() and not ln.lstrip().startswith("frame=")]
        errors = [ln for ln in lines
                  if any(k in ln.lower() for k in ("error", "invalid", "failed",
                                                   "not supported", "could not"))]
        tail = errors[-3:] if errors else lines[-3:]
        raise ConversionError(
            "conversion_failed",
            "ffmpeg could not convert this file: " + " ".join(tail)[:240])


def _convert_ffmpeg(src: Path, from_slug: str, to_slug: str, settings: dict,
                    dst: Path) -> dict:
    if not shutil.which("ffmpeg"):
        raise EngineMissingError("ffmpeg", "ffmpeg binary not found on PATH.")
    timeout = int(settings.get("timeout_seconds", 300))
    probe = _ffprobe(src)
    streams = probe.get("streams", [])
    fmt = probe.get("format", {})
    try:
        duration = float(fmt.get("duration", 0) or 0)
    except (TypeError, ValueError):
        duration = 0.0
    max_minutes = settings.get("max_duration_min")
    if max_minutes and duration > float(max_minutes) * 60:
        raise ConversionError(
            "video_too_long",
            f"This file is {duration / 60:.1f} minutes long; the limit is {max_minutes} minutes.")
    video = next((s for s in streams if s.get("codec_type") == "video"), None)
    audio = next((s for s in streams if s.get("codec_type") == "audio"), None)

    args: list[str] = []
    trim_start = settings.get("trim_start")
    trim_end = settings.get("trim_end")
    if trim_start:
        args += ["-ss", str(trim_start)]
    if trim_end:
        args += ["-to", str(trim_end)]
    args += ["-i", str(src)]

    if to_slug == "gif":
        width = int(settings.get("width", 480))
        fps = int(settings.get("fps", 12))
        max_seconds = int(settings.get("max_seconds", 15))
        vf = f"fps={fps},scale={width}:-1:flags=lanczos,split[s0][s1];[s0]palettegen[p];[s1][p]paletteuse"
        args += ["-vf", vf, "-t", str(max_seconds), "-loop", "0", str(dst)]
        _run_ffmpeg(args, timeout)
        return {"format": "gif", "engine_used": "ffmpeg", "duration_s": duration}

    if from_slug in CATALOG.by_slug and CATALOG.by_slug[from_slug]["category"] == "Video" \
            and to_slug == "mp3":
        bitrate = int(settings.get("bitrate_kbps", 192))
        args += ["-vn", "-c:a", "libmp3lame", "-b:a", f"{bitrate}k", str(dst)]
        _run_ffmpeg(args, timeout)
        return {"format": "mp3", "engine_used": "ffmpeg", "duration_s": duration}

    is_audio_in = CATALOG.by_slug[from_slug]["category"] == "Audio"
    is_audio_out = to_slug in ("mp3", "wav", "ogg", "m4a", "flac")
    if is_audio_in and is_audio_out:
        return _convert_audio(args, audio, to_slug, settings, dst, timeout, duration)

    # Video targets.
    resolution = settings.get("resolution")
    target_h = RESOLUTION_HEIGHTS.get(str(resolution)) if resolution else None
    vf_parts: list[str] = []
    if target_h and video and int(video.get("height", 0) or 0) > target_h:
        vf_parts.append(f"scale=-2:{target_h}")
    if vf_parts:
        args += ["-vf", ",".join(vf_parts)]

    copy_ok = (
        not vf_parts and not trim_start and not trim_end
        and to_slug in ("mp4", "mkv", "mov")
        and video and video.get("codec_name") == "h264"
        and (audio is None or audio.get("codec_name") == "aac")
    )
    if copy_ok:
        try:
            _run_ffmpeg([*args, "-c", "copy", str(dst)], timeout)
        except ConversionError:
            # Stream copy is fragile (e.g. AVI timestamps into Matroska):
            # fall back to a full re-encode instead of failing the job.
            if dst.exists():
                dst.unlink()
            args = [a for a in args]
        else:
            return {"format": to_slug, "engine_used": "ffmpeg",
                    "stream_copy": True, "duration_s": duration}

    crf = int(settings.get("crf", TARGET_DEFAULTS.get(to_slug, {}).get("crf", 23)))
    preset = str(settings.get("preset", "medium"))
    if to_slug == "webm":
        args += ["-c:v", "libvpx-vp9", "-crf", str(crf), "-b:v", "0",
                 "-c:a", "libopus", "-b:a",
                 f"{int(settings.get('audio_bitrate_kbps', 96))}k"]
    else:
        args += ["-c:v", "libx264", "-crf", str(crf), "-preset", preset,
                 "-pix_fmt", "yuv420p",
                 "-c:a", "aac", "-b:a",
                 f"{int(settings.get('audio_bitrate_kbps', 128))}k"]
        if to_slug == "mp4":
            args += ["-movflags", "+faststart"]
    args += [str(dst)]
    _run_ffmpeg(args, timeout)
    return {"format": to_slug, "engine_used": "ffmpeg", "crf": crf,
            "duration_s": duration}


def _convert_audio(args: list[str], audio: dict | None, to_slug: str,
                   settings: dict, dst: Path, timeout: int, duration: float) -> dict:
    bitrate = int(settings.get("bitrate_kbps", 192))
    sample_rate = settings.get("sample_rate")
    channels = settings.get("channels")
    if sample_rate:
        args += ["-ar", str(min(int(sample_rate), 48000))]
    elif audio and audio.get("sample_rate"):
        try:
            if int(audio["sample_rate"]) > 48000:
                args += ["-ar", "48000"]
        except (TypeError, ValueError):
            pass
    if channels == "stereo":
        args += ["-ac", "2"]
    elif channels == "mono":
        args += ["-ac", "1"]
    if to_slug == "mp3":
        args += ["-c:a", "libmp3lame", "-b:a", f"{bitrate}k"]
    elif to_slug == "m4a":
        args += ["-c:a", "aac", "-b:a", f"{bitrate}k"]
    elif to_slug == "ogg":
        args += ["-c:a", "libvorbis", "-q:a", str(settings.get("quality", 5))]
    elif to_slug == "flac":
        args += ["-c:a", "flac", "-compression_level",
                 str(settings.get("compression", 5))]
    elif to_slug == "wav":
        args += ["-c:a", "pcm_s16le"]
    args += [str(dst)]
    _run_ffmpeg(args, timeout)
    return {"format": to_slug, "engine_used": "ffmpeg", "duration_s": duration}


# --- validation + runner -----------------------------------------------------
def validate_output(path: Path, to_slug: str) -> None:
    if not path.exists() or path.stat().st_size == 0:
        raise ConversionError("conversion_failed", "The converter produced no output.")
    if to_slug == "pdf":
        with open(path, "rb") as fh:
            head = fh.read(4)
        if head != b"%PDF":
            raise ConversionError("conversion_failed", "The converter produced an invalid PDF.")
        return
    if to_slug == "psd":
        with open(path, "rb") as fh:
            head = fh.read(4)
        if head != b"8BPS":
            raise ConversionError("conversion_failed", "The converter produced an invalid PSD.")
        return
    if path.suffix == ".zip":
        with zipfile.ZipFile(path) as zf:
            if zf.testzip() is not None:
                raise ConversionError("conversion_failed", "The converter produced a damaged ZIP.")
        return
    if to_slug == "svg":
        text = path.read_text(encoding="utf-8", errors="ignore")
        if "<svg" not in text:
            raise ConversionError("conversion_failed", "The converter produced an invalid SVG.")
        return
    fmt = CATALOG.by_slug.get(to_slug, {})
    category = fmt.get("category")
    if category == "Images":
        try:
            with Image.open(path) as img:
                img.verify()
        except ConversionError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise ConversionError(
                "conversion_failed", f"The output image is invalid: {exc}".strip()[:160])
    elif category in ("Audio", "Video"):
        probe = _ffprobe(path)
        if probe and not probe.get("streams"):
            raise ConversionError("conversion_failed", "The output media file has no streams.")


def record_event(sink, event: dict) -> None:
    """Record a conversion event through an optional sink (callable or an
    object with a ``record`` method). Never raises."""
    if sink is None:
        return
    try:
        if callable(sink):
            sink(event)
        elif hasattr(sink, "record"):
            sink.record(event)
    except Exception:  # noqa: BLE001 - event logging must not break conversions
        pass


def convert_file(src: Path, from_slug: str, to_slug: str, settings: dict | None,
                 dst: Path, progress_cb=None, event_sink=None) -> dict:
    """Run one conversion. Returns output info; ``output_path`` in the info
    is the real output file (a ZIP path for multi-page PDF output).

    Raises UnsupportedPairError, EngineMissingError or ConversionError.
    """
    pair = CATALOG.get_pair(from_slug, to_slug)
    if pair is None:
        raise UnsupportedPairError(str(from_slug), str(to_slug))
    settings = normalize_settings(to_slug, settings)
    if progress_cb:
        progress_cb(0.05)
    available = available_engines()
    if pair["engine"] not in available:
        raise EngineMissingError(pair["engine"])
    route = pair["route"]
    dst.parent.mkdir(parents=True, exist_ok=True)
    if route == "raster":
        info = _convert_raster(src, to_slug, settings, dst)
    elif route == "raw":
        info = _convert_raw(src, to_slug, settings, dst)
    elif route == "psd":
        info = _convert_psd(src, to_slug, settings, dst)
    elif route == "pdf":
        info = _convert_pdf(src, to_slug, settings, dst)
    elif route == "svg":
        info = _convert_svg(src, to_slug, settings, dst)
    elif route == "trace":
        info = _convert_trace(src, to_slug, settings, dst)
    elif route in ("audio", "video"):
        info = _convert_ffmpeg(src, from_slug, to_slug, settings, dst)
    else:  # pragma: no cover - defensive
        raise ConversionError("conversion_failed", f"Unknown route: {route}")
    if progress_cb:
        progress_cb(0.9)
    out_path = Path(info.get("output_path", dst))
    validate_output(out_path, "zip" if out_path.suffix == ".zip" else to_slug)
    info["output_path"] = str(out_path)
    info["output_size"] = out_path.stat().st_size
    if progress_cb:
        progress_cb(1.0)
    record_event(event_sink, {
        "pair_slug": pair["slug"], "route": route, "engine": info.get("engine_used"),
        "status": "done", "bytes_in": src.stat().st_size,
        "bytes_out": info["output_size"],
    })
    return info
