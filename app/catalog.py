"""Format catalog for Quick IMG Convert.

Loads ``api/app/data/formats.json`` and DERIVES every conversion pair from
the rules in spec section 1. The pair total is computed, never written
as a literal anywhere in this module.

Pair rules (inputs -> targets, self-pairs excluded):
- raster: 10 image inputs -> 9 targets (jpg png webp avif gif tiff bmp ico
  pdf). NOTE on spec section 1: it claims the v5 table lists 8 raster
  targets and adds PSD as the 9th, but the v5 table itself lists 9 targets
  (the eight inputs that are also targets, plus PDF) and its own
  multipliers (8 x 8 + 2 x 9) already give the required raster total with
  those 9. Adding PSD as a tenth target would give 92 raster pairs and a
  larger overall total, breaking the required total. So this module follows
  the v5 spec exactly: PSD is a raster *input* only via its own row below,
  not a raster target. If the owner wants PSD as a raster target, it is a
  one-line change to RASTER_TARGETS (and the total then changes, or PDF
  must be dropped as a raster target to keep it).
- psd: psd -> jpg png webp tiff pdf
- svg: svg -> png jpg webp ico pdf
- trace: jpg png bmp tiff -> svg
- raw: 9 camera RAW inputs -> jpg png tiff webp avif bmp
- audio: 9 audio inputs -> mp3 wav ogg m4a flac
- video: 8 video inputs -> mp4 webm mkv mov gif mp3
- pdf: pdf -> jpg png webp tiff

Detection: magic bytes first, extension second. Magic entries in
formats.json are hex strings; "?" is a wildcard nibble. Entries starting
with "66747970" ("ftyp") are matched at byte offset 4 as well as offset 0,
because the ISO base-media file-type box sits after a 4-byte size field.
Short (4-byte) TIFF-header magics are shared by TIFF and several RAW
formats, so a short magic match never overrides an extension that resolves
to a format sharing the same prefix.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent / "data"
FORMATS_PATH = DATA_DIR / "formats.json"

CATEGORIES = ["Images", "Camera RAW", "Audio", "Video", "Documents and vector"]

# --- Pair derivation rules: (inputs, targets, route, engine) -------------
RASTER_INPUTS = ["jpg", "png", "webp", "avif", "gif", "tiff", "bmp", "heic", "ico", "tga"]
RASTER_TARGETS = ["jpg", "png", "webp", "avif", "gif", "tiff", "bmp", "ico", "pdf"]
PSD_TARGETS = ["jpg", "png", "webp", "tiff", "pdf"]
SVG_TARGETS = ["png", "jpg", "webp", "ico", "pdf"]
TRACE_INPUTS = ["jpg", "png", "bmp", "tiff"]
RAW_INPUTS = ["cr2", "cr3", "nef", "arw", "orf", "raf", "rw2", "dng", "pef"]
RAW_TARGETS = ["jpg", "png", "tiff", "webp", "avif", "bmp"]
AUDIO_INPUTS = ["mp3", "wav", "flac", "ogg", "m4a", "aac", "opus", "aiff", "wma"]
AUDIO_TARGETS = ["mp3", "wav", "ogg", "m4a", "flac"]
VIDEO_INPUTS = ["mp4", "mkv", "mov", "avi", "webm", "wmv", "m4v", "3gp"]
VIDEO_TARGETS = ["mp4", "webm", "mkv", "mov", "gif", "mp3"]
PDF_TARGETS = ["jpg", "png", "webp", "tiff"]

PAIR_RULES = [
    (RASTER_INPUTS, RASTER_TARGETS, "raster", "vips"),
    (["psd"], PSD_TARGETS, "psd", "psd"),
    (["svg"], SVG_TARGETS, "svg", "svg"),
    (TRACE_INPUTS, ["svg"], "trace", "trace"),
    (RAW_INPUTS, RAW_TARGETS, "raw", "raw"),
    (AUDIO_INPUTS, AUDIO_TARGETS, "audio", "ffmpeg"),
    (VIDEO_INPUTS, VIDEO_TARGETS, "video", "ffmpeg"),
    (["pdf"], PDF_TARGETS, "pdf", "pdf"),
]

# Route -> engine (kept in sync with PAIR_RULES; engines.py is authoritative
# for availability, this is only the routing table).
ROUTE_ENGINES = {
    "raster": "vips",
    "psd": "psd",
    "svg": "svg",
    "trace": "trace",
    "raw": "raw",
    "audio": "ffmpeg",
    "video": "ffmpeg",
    "pdf": "pdf",
}

# Default conversion settings per spec section 3. Each entry is shown in the
# settings panel with a tooltip and a recommended value.
DEFAULT_SETTINGS = {
    "jpg": {"quality": 85, "progressive": True},
    "webp": {"quality": 80},
    "avif": {"quality": 60, "speed": 6},
    "png": {"compression": 6},
    "tiff": {"compression": "none"},
    "gif": {"width": 480, "fps": 12, "max_seconds": 15},
    "ico": {"sizes": [16, 32, 48, 64, 128, 256]},
    "pdf": {"dpi": 150, "page_range": None},
    "mp3": {"bitrate_kbps": 192},
    "m4a": {"bitrate_kbps": 192},
    "ogg": {"quality": 5},
    "flac": {"compression": 5},
    "wav": {"bits": 16},
    "mp4": {"crf": 23, "preset": "medium", "audio_bitrate_kbps": 128},
    "webm": {"crf": 32, "audio_bitrate_kbps": 96},
    "mkv": {"crf": 23, "preset": "medium", "audio_bitrate_kbps": 128},
    "mov": {"crf": 23, "preset": "medium", "audio_bitrate_kbps": 128},
    "svg": {"trace_preset": "logo"},
}

# Settings schema exposed by GET /v1/formats. "kind" drives the web form
# control; "default" is the recommended value; "hint" is the tooltip text.
SETTINGS_SCHEMA = {
    "image": [
        {"key": "quality", "kind": "slider", "label": "Quality",
         "min": 1, "max": 100, "default": None,
         "hint": "Higher quality means a larger file. Recommended: JPG 85, WebP 80, AVIF 60."},
        {"key": "max_width", "kind": "number", "label": "Max width (px)",
         "min": 1, "max": 10000, "default": None,
         "hint": "Leave empty to keep the original width."},
        {"key": "max_height", "kind": "number", "label": "Max height (px)",
         "min": 1, "max": 10000, "default": None,
         "hint": "Leave empty to keep the original height."},
        {"key": "resolution", "kind": "select", "label": "Resolution",
         "options": ["Original", "1080p", "720p", "480p"], "default": "Original",
         "hint": "Downscale the longest side to a preset size."},
        {"key": "background", "kind": "color", "label": "Background colour",
         "default": "#FFFFFF",
         "hint": "Transparency is flattened onto this colour when the target (JPG, BMP) has no transparency."},
        {"key": "strip_metadata", "kind": "switch", "label": "Strip metadata",
         "default": True,
         "hint": "Removes location (GPS) and other metadata. Turn off to keep it."},
    ],
    "audio": [
        {"key": "bitrate_kbps", "kind": "select", "label": "Bitrate",
         "options": [96, 128, 192, 256, 320], "default": 192,
         "hint": "Recommended: 192 kbps for MP3 and M4A."},
        {"key": "sample_rate", "kind": "select", "label": "Sample rate",
         "options": [22050, 32000, 44100, 48000], "default": None,
         "hint": "Kept from the source by default, capped at 48 kHz."},
        {"key": "channels", "kind": "select", "label": "Channels",
         "options": ["keep", "stereo", "mono"], "default": "keep",
         "hint": "Keep the source channels, or force stereo or mono."},
    ],
    "video": [
        {"key": "crf", "kind": "slider", "label": "Quality (CRF)",
         "min": 0, "max": 51, "default": None,
         "hint": "Lower is better quality and a larger file. Recommended: MP4 23, WebM 32."},
        {"key": "preset", "kind": "select", "label": "Encoding preset",
         "options": ["ultrafast", "fast", "medium", "slow"], "default": "medium",
         "hint": "Slower presets compress better but take longer."},
        {"key": "resolution", "kind": "select", "label": "Resolution",
         "options": ["Original", "1080p", "720p", "480p"], "default": "Original",
         "hint": "Downscale the video to a preset height."},
        {"key": "trim_start", "kind": "number", "label": "Trim start (seconds)",
         "min": 0, "default": None, "hint": "Start the output at this time."},
        {"key": "trim_end", "kind": "number", "label": "Trim end (seconds)",
         "min": 0, "default": None, "hint": "End the output at this time."},
    ],
    "pdf": [
        {"key": "dpi", "kind": "select", "label": "Render DPI",
         "options": [72, 96, 150, 200, 300], "default": 150,
         "hint": "Higher DPI means sharper images and larger files. Range 72-300."},
        {"key": "page_range", "kind": "text", "label": "Page range",
         "default": None,
         "hint": "For example 1-3 or 2,5. Leave empty for all pages (50-page cap)."},
    ],
    "trace": [
        {"key": "trace_preset", "kind": "select", "label": "Trace preset",
         "options": ["logo", "photo", "line_art"], "default": "logo",
         "hint": "Logo: clean shapes. Photo: detailed. Line art: thin strokes."},
    ],
}

# Batch presets shown as chips in the converter tool.
PRESETS = {
    "image": {
        "Web": {"quality": 80, "resolution": "1080p", "strip_metadata": True},
        "Print": {"quality": 95, "resolution": "Original", "strip_metadata": False},
        "Social": {"quality": 82, "resolution": "1080p", "strip_metadata": True},
        "Archival": {"quality": 100, "resolution": "Original", "strip_metadata": False},
    },
    "audio": {
        "Web": {"bitrate_kbps": 128},
        "Standard": {"bitrate_kbps": 192},
        "High quality": {"bitrate_kbps": 320},
        "Archival": {"bitrate_kbps": 320},
    },
    "video": {
        "Web": {"crf": 28, "resolution": "720p", "preset": "fast"},
        "Standard": {"crf": 23, "resolution": "1080p", "preset": "medium"},
        "High quality": {"crf": 18, "resolution": "Original", "preset": "slow"},
        "Social": {"crf": 26, "resolution": "720p", "preset": "medium"},
    },
}

# Pixel cap from spec section 15 (100 million pixels).
PIXEL_CAP = 100_000_000


def _load_formats() -> list[dict]:
    with open(FORMATS_PATH, encoding="utf-8") as fh:
        data = json.load(fh)
    return data["formats"]


class Catalog:
    """All format/pair data, derived from formats.json + PAIR_RULES."""

    def __init__(self, formats: list[dict] | None = None):
        self.formats: list[dict] = formats if formats is not None else _load_formats()
        self.by_slug: dict[str, dict] = {f["slug"]: f for f in self.formats}
        self.by_extension: dict[str, str] = {}
        self.aliases: dict[str, str] = {}
        for fmt in self.formats:
            for ext in fmt.get("extensions", []):
                self.by_extension[ext.lower()] = fmt["slug"]
            for alias, target in fmt.get("aliases", {}).items():
                self.aliases[alias.lower()] = target
        self.pairs: list[dict] = self._derive_pairs()
        self.pairs_by_slug: dict[str, dict] = {p["slug"]: p for p in self.pairs}
        self.targets_by_input: dict[str, list[str]] = {}
        for pair in self.pairs:
            self.targets_by_input.setdefault(pair["from"], []).append(pair["to"])

    def _derive_pairs(self) -> list[dict]:
        pairs = []
        for inputs, targets, route, engine in PAIR_RULES:
            for src in inputs:
                for dst in targets:
                    if src == dst:
                        continue  # a format never converts to itself
                    src_fmt = self.by_slug[src]
                    dst_fmt = self.by_slug[dst]
                    pairs.append({
                        "slug": f"{src}-to-{dst}",
                        "from": src,
                        "to": dst,
                        "from_label": src_fmt["label"],
                        "to_label": dst_fmt["label"],
                        "category": src_fmt["category"],
                        "from_category": src_fmt["category"],
                        "to_category": dst_fmt["category"],
                        "route": route,
                        "engine": engine,
                    })
        return pairs

    # -- lookups -----------------------------------------------------------
    def resolve_slug(self, value: str | None) -> str | None:
        """Resolve a slug, alias or extension to a canonical format slug."""
        if not value:
            return None
        key = value.strip().lower().lstrip(".")
        if key in self.by_slug:
            return key
        if key in self.aliases:
            return self.aliases[key]
        return self.by_extension.get(key)

    def get_format(self, slug: str | None) -> dict | None:
        resolved = self.resolve_slug(slug)
        return self.by_slug.get(resolved) if resolved else None

    def get_pair(self, from_slug: str, to_slug: str) -> dict | None:
        src = self.resolve_slug(from_slug)
        dst = self.resolve_slug(to_slug)
        if not src or not dst:
            return None
        return self.pairs_by_slug.get(f"{src}-to-{dst}")

    def pairs_for_engine(self, engine: str) -> list[dict]:
        return [p for p in self.pairs if p["engine"] == engine]

    def count_pairs(self) -> int:
        return len(self.pairs)

    # -- detection ---------------------------------------------------------
    @staticmethod
    def _magic_matches(magic_hex: str, data: bytes) -> bool:
        """Nibble-wise match of a hex pattern ("?" = wildcard) at offset 0,
        or at offset 4 for "ftyp" patterns."""
        pattern = magic_hex.lower()
        n_bytes = len(pattern) // 2
        offsets = [0]
        if pattern.startswith("66747970"):
            offsets.append(4)
        for off in offsets:
            if len(data) < off + n_bytes:
                continue
            ok = True
            for i, ch in enumerate(pattern):
                if ch == "?":
                    continue
                byte_hex = f"{data[off + i // 2]:02x}"
                if byte_hex[i % 2] != ch:
                    ok = False
                    break
            if ok:
                return True
        return False

    def detect_format(self, data: bytes, filename: str | None = None) -> str | None:
        """Detect a format: magic bytes first, extension second.

        A magic match of 6+ bytes wins outright. Shorter magic matches
        (e.g. the shared 4-byte TIFF header) only win when the filename
        extension does not resolve to a format sharing that prefix.
        """
        ext_slug = None
        if filename and "." in filename:
            ext_slug = self.resolve_slug(filename.rsplit(".", 1)[-1])
        head = data[:4096]
        matches: list[tuple[str, int]] = []  # (slug, matched bytes)
        for fmt in self.formats:
            best = 0
            for magic in fmt.get("magic", []):
                if magic and self._magic_matches(magic, head):
                    best = max(best, len(magic) // 2)
            if best:
                matches.append((fmt["slug"], best))
        if not matches:
            return ext_slug
        matches.sort(key=lambda item: item[1], reverse=True)
        longest = matches[0][1]
        if longest >= 6:
            winners = [s for s, n in matches if n == longest]
            if ext_slug in winners:
                return ext_slug
            return winners[0]
        # Short magic only: prefer the extension when it also matched.
        if ext_slug and any(s == ext_slug for s, _ in matches):
            return ext_slug
        return matches[0][0]

    # -- API shape ---------------------------------------------------------
    def formats_response(
        self,
        health: dict[str, dict] | None = None,
        samples: dict[str, bool] | None = None,
    ) -> dict:
        """The GET /v1/formats payload.

        ``health`` maps pair slug -> {"status": "healthy"|"disabled",
        "last_error": ...}. ``samples`` maps format slug -> has a bundled
        sample file. Disabled pairs are hidden from targets_by_input.
        """
        health = health or {}
        pairs_out = []
        for pair in self.pairs:
            entry = dict(pair)
            status = health.get(pair["slug"], {}).get("status", "healthy")
            entry["status"] = status
            entry["last_error"] = health.get(pair["slug"], {}).get("last_error")
            pairs_out.append(entry)
        targets: dict[str, list[str]] = {}
        for pair in pairs_out:
            if pair["status"] == "disabled":
                continue
            targets.setdefault(pair["from"], []).append(pair["to"])
        return {
            "categories": CATEGORIES,
            "formats": self.formats,
            "targets_by_input": targets,
            "pairs": pairs_out,
            "settings_schema": SETTINGS_SCHEMA,
            "presets": PRESETS,
            "defaults": DEFAULT_SETTINGS,
            "samples": samples or {},
        }


# Module-level singleton used by the API and CLI.
CATALOG = Catalog()


def get_catalog() -> Catalog:
    return CATALOG


def count_pairs() -> int:
    return CATALOG.count_pairs()
