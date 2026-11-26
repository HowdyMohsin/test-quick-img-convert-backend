"""Pair health, engine verification and bundled sample files.

- ``verify_engines_report()``: probe every engine binary/library and list
  which pairs each missing engine affects.
- ``health_check()``: convert each bundled sample and validate the output.
  Healthy pair -> listed everywhere. Failing pair -> status ``disabled``
  (it disappears from dropdowns, the All Formats section and the sitemap;
  its URL stays alive) + an admin notification. A pair with NO bundled
  sample is reported as ``no_sample`` — never as failed — and the check
  never crashes on it.
- ``generate_sample()``: make a real sample file for a format with Pillow
  (raster / PSD / PDF), hand-written SVG, or ffmpeg (audio / video).
  Camera RAW files cannot be synthesised locally and HEIC writing needs
  pillow-heif; those are documented as missing in ``samples/README.md``.

Pair-health persistence: the pipeline store (``MemoryStore`` in dev, the
database ``pair_health`` table in production) holds statuses. The CLI
uses ``JsonPairHealthStore`` (a JSON file under DATA_DIR) so
``health-check`` results survive between processes before the database
store is wired in.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from . import engines
from .catalog import CATALOG

SAMPLES_DIR = Path(__file__).resolve().parent / "samples"

# Formats whose samples cannot be generated on this machine, and why.
# (Kept in code so health-check and the README can never drift apart.)
UNGENERATABLE_SAMPLES = {
    "cr2": "Camera RAW files cannot be synthesised locally; a real Canon CR2 file is required.",
    "cr3": "Camera RAW files cannot be synthesised locally; a real Canon CR3 file is required.",
    "nef": "Camera RAW files cannot be synthesised locally; a real Nikon NEF file is required.",
    "arw": "Camera RAW files cannot be synthesised locally; a real Sony ARW file is required.",
    "orf": "Camera RAW files cannot be synthesised locally; a real Olympus ORF file is required.",
    "raf": "Camera RAW files cannot be synthesised locally; a real Fujifilm RAF file is required.",
    "rw2": "Camera RAW files cannot be synthesised locally; a real Panasonic RW2 file is required.",
    "dng": "Camera RAW files cannot be synthesised locally; a real DNG file is required.",
    "pef": "Camera RAW files cannot be synthesised locally; a real Pentax PEF file is required.",
}


def sample_filename(format_slug: str) -> str:
    fmt = CATALOG.by_slug.get(format_slug)
    if not fmt:
        raise ValueError(f"Unknown format: {format_slug}")
    return f"{format_slug}.{fmt['extensions'][0]}"


def sample_path(format_slug: str, samples_dir: Path | None = None) -> Path:
    return (samples_dir or SAMPLES_DIR) / sample_filename(format_slug)


def list_samples(samples_dir: Path | None = None) -> dict[str, dict]:
    """Map format slug -> {"present": bool, "reason": str|None}."""
    samples_dir = samples_dir or SAMPLES_DIR
    out: dict[str, dict] = {}
    for fmt in CATALOG.formats:
        slug = fmt["slug"]
        path = sample_path(slug, samples_dir)
        if path.exists() and path.stat().st_size > 0:
            out[slug] = {"present": True, "reason": None, "path": str(path)}
        else:
            out[slug] = {"present": False,
                         "reason": UNGENERATABLE_SAMPLES.get(slug),
                         "path": str(path)}
    return out


# --- sample generation -------------------------------------------------------
def _make_raster_image():
    from PIL import Image, ImageDraw

    img = Image.new("RGB", (400, 300), (79, 70, 229))
    draw = ImageDraw.Draw(img)
    for i in range(400):
        draw.line([(i, 0), (i, 300)], fill=(79 + i // 8, 70, 229 - i // 8))
    draw.ellipse([60, 50, 200, 190], fill=(255, 255, 255))
    draw.rectangle([220, 90, 350, 210], fill=(22, 163, 74))
    draw.polygon([(100, 260), (200, 220), (300, 260)], fill=(217, 119, 6))
    return img


def _generate_raster(slug: str, out: Path) -> str | None:
    """Return None on success, or a reason string when it cannot be made."""
    try:
        from PIL import Image

        img = _make_raster_image()
        if slug == "gif":
            frame2 = img.copy()
            frame2.paste((255, 255, 255), (60, 50, 200, 190))
            img.save(out, format="GIF", save_all=True, append_images=[frame2],
                     duration=500, loop=0)
        elif slug == "ico":
            img.save(out, format="ICO",
                     sizes=[(16, 16), (32, 32), (48, 48), (64, 64)])
        elif slug == "psd":
            # Pillow cannot write PSD (its PSD plugin is read-only), so
            # write a minimal valid PSD by hand: uncompressed 8-bit RGB,
            # planar channel data. Readable by Pillow and psd-tools.
            _write_minimal_psd(img, out)
        elif slug == "pdf":
            img2 = _make_raster_image()
            img.save(out, format="PDF", save_all=True, append_images=[img2])
        elif slug == "heic":
            try:
                import pillow_heif  # noqa: F401
            except ImportError:
                return "pillow-heif is not installed, so HEIC cannot be written here."
            try:
                img.save(out, format="HEIF")
            except Exception as exc:  # noqa: BLE001
                return f"pillow-heif could not write HEIC here: {exc}"
        elif slug == "avif":
            try:
                img.save(out, format="AVIF", quality=60)
            except Exception as exc:  # noqa: BLE001
                return f"Pillow here cannot write AVIF: {exc}"
        else:
            fmt_map = {"jpg": "JPEG", "tiff": "TIFF"}
            img.save(out, format=fmt_map.get(slug, slug.upper()))
        return None
    except Exception as exc:  # noqa: BLE001
        return f"Could not generate a {slug} sample: {exc}"


def _write_minimal_psd(img, out: Path) -> None:
    """Write a minimal valid PSD (8BPS, version 1, 8-bit RGB, uncompressed,
    planar channels). Pillow cannot write PSD, so this hand-built file is
    the sample; Pillow and psd-tools both read it back."""
    import struct

    rgb = img.convert("RGB")
    width, height = rgb.size
    pixels = list(rgb.getdata())
    with open(out, "wb") as fh:
        fh.write(b"8BPS")                       # signature
        fh.write(struct.pack(">H", 1))          # version
        fh.write(b"\x00" * 6)                   # reserved
        fh.write(struct.pack(">H", 3))          # channels
        fh.write(struct.pack(">I", height))
        fh.write(struct.pack(">I", width))
        fh.write(struct.pack(">H", 8))          # depth
        fh.write(struct.pack(">H", 3))          # colour mode: RGB
        fh.write(struct.pack(">I", 0))          # colour mode data length
        fh.write(struct.pack(">I", 0))          # image resources length
        fh.write(struct.pack(">I", 0))          # reserved data length
        fh.write(struct.pack(">H", 0))          # compression: raw
        for channel in range(3):
            fh.write(bytes(p[channel] for p in pixels))


_SVG_SAMPLE = """<svg xmlns="http://www.w3.org/2000/svg" width="400" height="300" viewBox="0 0 400 300">
  <rect width="400" height="300" fill="#4F46E5"/>
  <circle cx="150" cy="130" r="80" fill="#FFFFFF"/>
  <rect x="230" y="90" width="120" height="120" fill="#16A34A"/>
  <polygon points="100,260 200,220 300,260" fill="#D97706"/>
  <text x="200" y="285" font-size="20" fill="#FFFFFF" text-anchor="middle">Quick IMG Convert sample</text>
</svg>
"""


def _generate_ffmpeg(slug: str, out: Path) -> str | None:
    import shutil

    if not shutil.which("ffmpeg"):
        return "ffmpeg is not installed, so media samples cannot be generated."
    category = CATALOG.by_slug[slug]["category"]
    try:
        if category == "Audio":
            cmd = ["ffmpeg", "-nostdin", "-y", "-f", "lavfi", "-i",
                   "sine=frequency=440:duration=2", "-ac", "2"]
            if slug == "mp3":
                cmd += ["-c:a", "libmp3lame", "-b:a", "192k"]
            elif slug == "m4a":
                cmd += ["-c:a", "aac", "-b:a", "192k"]
            elif slug == "ogg":
                cmd += ["-c:a", "libvorbis", "-q:a", "5"]
            elif slug == "flac":
                cmd += ["-c:a", "flac"]
            elif slug == "wav":
                cmd += ["-c:a", "pcm_s16le"]
            elif slug == "aac":
                cmd += ["-c:a", "aac", "-b:a", "192k"]
            elif slug == "opus":
                cmd += ["-c:a", "libopus", "-b:a", "96k"]
            elif slug == "aiff":
                cmd += ["-c:a", "pcm_s16be"]
            elif slug == "wma":
                cmd += ["-c:a", "wmav2", "-b:a", "192k"]
            cmd += [str(out)]
        else:  # Video
            if slug == "gif":
                cmd = ["ffmpeg", "-nostdin", "-y", "-f", "lavfi", "-i",
                       "testsrc=duration=2:size=320x240:rate=12",
                       "-vf", "scale=320:-1", str(out)]
            elif slug == "webm":
                cmd = ["ffmpeg", "-nostdin", "-y", "-f", "lavfi", "-i",
                       "testsrc=duration=2:size=320x240:rate=15",
                       "-f", "lavfi", "-i", "sine=frequency=440:duration=2",
                       "-c:v", "libvpx-vp9", "-b:v", "0", "-crf", "32",
                       "-c:a", "libopus", "-b:a", "96k", str(out)]
            else:
                cmd = ["ffmpeg", "-nostdin", "-y", "-f", "lavfi", "-i",
                       "testsrc=duration=2:size=320x240:rate=15",
                       "-f", "lavfi", "-i", "sine=frequency=440:duration=2",
                       "-c:v", "libx264", "-pix_fmt", "yuv420p",
                       "-c:a", "aac", "-b:a", "128k", "-shortest", str(out)]
        proc = subprocess.run(cmd, stdin=subprocess.DEVNULL,
                              capture_output=True, text=True, timeout=120)
        if proc.returncode != 0 or not out.exists() or out.stat().st_size == 0:
            return f"ffmpeg failed for {slug}: {(proc.stderr or '').strip()[-200:]}"
        return None
    except Exception as exc:  # noqa: BLE001
        return f"Could not generate a {slug} sample: {exc}"


def generate_sample(format_slug: str,
                    samples_dir: Path | None = None) -> tuple[Path | None, str | None]:
    """Generate a real sample file. Returns (path, None) on success or
    (None, reason) when the format cannot be generated on this machine."""
    slug = CATALOG.resolve_slug(format_slug)
    if slug is None:
        return None, f"Unknown format: {format_slug}"
    if slug in UNGENERATABLE_SAMPLES:
        return None, UNGENERATABLE_SAMPLES[slug]
    samples_dir = samples_dir or SAMPLES_DIR
    samples_dir.mkdir(parents=True, exist_ok=True)
    out = sample_path(slug, samples_dir)
    category = CATALOG.by_slug[slug]["category"]
    if slug == "svg":
        out.write_text(_SVG_SAMPLE, encoding="utf-8")
        return out, None
    if category in ("Images", "Documents and vector"):
        reason = _generate_raster(slug, out)
    elif category in ("Audio", "Video"):
        reason = _generate_ffmpeg(slug, out)
    else:  # pragma: no cover - defensive
        reason = f"No generator for category {category}."
    if reason is not None:
        out.unlink(missing_ok=True)
        return None, reason
    return out, None


def generate_all_samples(samples_dir: Path | None = None) -> dict[str, dict]:
    """Generate every sample that can be made here. Returns per-format results."""
    results: dict[str, dict] = {}
    for fmt in CATALOG.formats:
        slug = fmt["slug"]
        path, reason = generate_sample(slug, samples_dir)
        results[slug] = {"path": str(path) if path else None, "reason": reason,
                         "generated": path is not None}
    return results


# --- engine verification -----------------------------------------------------
def verify_engines_report() -> dict:
    probes = engines.probe_engines()
    report = {"engines": {}, "missing": [], "available": []}
    for name, info in probes.items():
        report["engines"][name] = {
            "available": info.available, "kind": info.kind,
            "version": info.version, "detail": info.detail,
            "pairs_affected": info.pairs_affected,
            "pairs_affected_count": len(info.pairs_affected),
        }
        (report["available"] if info.available else report["missing"]).append(name)
    return report


# --- pair health ---------------------------------------------------------------
class JsonPairHealthStore:
    """Pair health + visibility overrides in a JSON file under DATA_DIR.
    Used by the CLI before the database store is wired in."""

    def __init__(self, path: Path | None = None):
        if path is None:
            from .pipeline import get_data_dir

            path = get_data_dir() / "pair_health.json"
        self.path = Path(path)
        self._data = {"health": {}, "overrides": {}}
        if self.path.exists():
            try:
                self._data = json.loads(self.path.read_text(encoding="utf-8"))
            except Exception:  # noqa: BLE001 - corrupt file starts fresh
                self._data = {"health": {}, "overrides": {}}

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self._data, indent=2), encoding="utf-8")
        os.chmod(self.path, 0o600)

    def get_pair_health(self) -> dict[str, dict]:
        return dict(self._data.get("health", {}))

    def set_pair_health(self, pair_slug: str, status: str,
                        last_error: str | None) -> None:
        self._data.setdefault("health", {})[pair_slug] = {
            "status": status, "last_error": last_error,
            "last_checked_at": datetime.now(timezone.utc).isoformat(),
        }
        self._save()

    def get_pair_override(self, pair_slug: str) -> dict:
        return self._data.get("overrides", {}).get(
            pair_slug, {"visible": True, "plans": None})

    def set_pair_override(self, pair_slug: str, override: dict) -> None:
        self._data.setdefault("overrides", {})[pair_slug] = override
        self._save()


def _notify_admin_disabled(pair_slug: str, error: str) -> None:
    """Notify the admin about a newly disabled pair. The notifications
    module is owned by the payments-ads agent; import it defensively."""
    try:
        from app import notifications  # type: ignore

        notify = getattr(notifications, "notify_admin", None)
        if callable(notify):
            notify(kind="pair_disabled", title=f"Converter disabled: {pair_slug}",
                   body=f"Health check failed for {pair_slug}: {error}")
    except Exception:  # noqa: BLE001 - notifications are best-effort
        pass


def health_check(store, samples_dir: Path | None = None,
                 notify=None, only_pairs: list[str] | None = None) -> dict:
    """Convert each bundled sample and validate the output.

    Returns a summary: total / healthy / disabled / no_sample counts plus
    per-pair results. Never raises for a missing sample or a failed pair.
    """
    samples_dir = samples_dir or SAMPLES_DIR
    samples = list_samples(samples_dir)
    results: dict[str, dict] = {}
    counts = {"total": 0, "healthy": 0, "disabled": 0, "no_sample": 0}
    previous = store.get_pair_health() if hasattr(store, "get_pair_health") else {}
    with tempfile.TemporaryDirectory(prefix="qic-health-") as tmp:
        tmp_dir = Path(tmp)
        for pair in CATALOG.pairs:
            if only_pairs and pair["slug"] not in only_pairs:
                continue
            counts["total"] += 1
            src_slug = pair["from"]
            sample = samples.get(src_slug, {})
            if not sample.get("present"):
                counts["no_sample"] += 1
                results[pair["slug"]] = {
                    "status": "no_sample",
                    "reason": sample.get("reason") or "No bundled sample file.",
                }
                continue
            src = Path(sample["path"])
            dst = tmp_dir / f"out.{pair['to']}"
            try:
                engines.convert_file(src, pair["from"], pair["to"], {}, dst)
                counts["healthy"] += 1
                results[pair["slug"]] = {"status": "healthy"}
                if hasattr(store, "set_pair_health"):
                    store.set_pair_health(pair["slug"], "healthy", None)
            except engines.EngineMissingError as exc:
                # A missing engine disables only the pairs that need it.
                counts["disabled"] += 1
                results[pair["slug"]] = {"status": "disabled",
                                         "error": exc.code, "message": exc.message}
                if hasattr(store, "set_pair_health"):
                    store.set_pair_health(pair["slug"], "disabled", exc.message)
                _flag_disabled(pair["slug"], exc.message, previous, notify)
            except engines.ConversionError as exc:
                counts["disabled"] += 1
                results[pair["slug"]] = {"status": "disabled",
                                         "error": exc.code, "message": exc.message}
                if hasattr(store, "set_pair_health"):
                    store.set_pair_health(pair["slug"], "disabled", exc.message)
                _flag_disabled(pair["slug"], exc.message, previous, notify)
            except Exception as exc:  # noqa: BLE001 - one bad pair never stops the check
                counts["disabled"] += 1
                results[pair["slug"]] = {"status": "disabled",
                                         "error": "conversion_failed", "message": str(exc)[:200]}
                if hasattr(store, "set_pair_health"):
                    store.set_pair_health(pair["slug"], "disabled", str(exc)[:200])
                _flag_disabled(pair["slug"], str(exc)[:200], previous, notify)
    return {**counts, "pairs": results}


def _flag_disabled(pair_slug: str, error: str, previous: dict, notify) -> None:
    was_disabled = previous.get(pair_slug, {}).get("status") == "disabled"
    if not was_disabled:
        _notify_admin_disabled(pair_slug, error)
    if callable(notify):
        try:
            notify(pair_slug, error)
        except Exception:  # noqa: BLE001
            pass


def run_startup_health_check(store, samples_dir: Path | None = None) -> dict | None:
    """Health check for app startup: never raises, never blocks boot."""
    try:
        return health_check(store, samples_dir)
    except Exception as exc:  # noqa: BLE001
        print(f"startup health check failed: {exc}", file=sys.stderr)
        return None
