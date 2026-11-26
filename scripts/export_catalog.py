"""Export the format catalog for the web app's static generation.

Writes ``web/lib/catalog.json`` (formats, pairs, targets_by_input,
categories, settings schema, presets, defaults) from the single source
of truth, ``api/app/data/formats.json`` + ``api/app/catalog.py``.

Runnable standalone from the repo root:
    python3 api/scripts/export_catalog.py [--out web/lib/catalog.json]

The web app (agent C) reads this file at build time; it never hard-codes
pairs or targets.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
API_DIR = REPO_ROOT / "api"
sys.path.insert(0, str(API_DIR))

from app.catalog import CATALOG  # noqa: E402


def export(out_path: Path | None = None) -> Path:
    out_path = out_path or (REPO_ROOT / "web" / "lib" / "catalog.json")
    payload = CATALOG.formats_response(health={}, samples={})
    payload["pair_count"] = CATALOG.count_pairs()
    payload["generated_from"] = "api/app/data/formats.json + api/app/catalog.py"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return out_path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Export the format catalog for the web app.")
    parser.add_argument("--out", default=None, help="Output path (default: web/lib/catalog.json).")
    args = parser.parse_args(argv)
    out = export(Path(args.out) if args.out else None)
    print(f"wrote {CATALOG.count_pairs()} pairs to {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
