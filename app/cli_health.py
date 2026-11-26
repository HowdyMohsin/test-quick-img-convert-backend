"""Health CLI: count-pairs, verify-engines, health-check, make-sample.

Runnable standalone (``python -m app.cli_health <command>``) and mountable
into the shared CLI (``api/app/cli.py``, owned by the backend-core agent)
via ``register_commands()`` — the shared CLI mounts command modules
defensively, so this module must import cleanly on its own.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .catalog import CATALOG
from .health import (
    JsonPairHealthStore,
    SAMPLES_DIR,
    generate_sample,
    health_check,
    verify_engines_report,
)


def cmd_count_pairs(args) -> int:
    """Compute the pair total from the data files and print it."""
    print(CATALOG.count_pairs())
    return 0


def cmd_verify_engines(args) -> int:
    report = verify_engines_report()
    for name, info in report["engines"].items():
        state = "available" if info["available"] else "MISSING"
        print(f"{name:8} {state:10} {info['detail']}")
        if not info["available"] and info["pairs_affected_count"]:
            print(f"         affects {info['pairs_affected_count']} pairs "
                  f"(e.g. {', '.join(info['pairs_affected'][:3])})")
    print(f"available: {', '.join(report['available']) or 'none'}")
    print(f"missing: {', '.join(report['missing']) or 'none'}")
    return 0


def cmd_health_check(args) -> int:
    """Convert every bundled sample; disable failing pairs.

    Results are written to the pipeline store (the database pair_health
    table via DbStore) so the API and admin read the same health state;
    the JSON file is only a fallback when no database is reachable.
    """
    from .pipeline import MemoryStore, get_default_store

    store = get_default_store()
    if isinstance(store, MemoryStore):
        store = JsonPairHealthStore()
    summary = health_check(store, SAMPLES_DIR)
    print(f"pairs checked: {summary['total']}")
    print(f"healthy: {summary['healthy']}")
    print(f"disabled: {summary['disabled']}")
    print(f"no sample: {summary['no_sample']}")
    for slug, result in summary["pairs"].items():
        if result["status"] == "disabled":
            print(f"  DISABLED {slug}: {result.get('message', '')}")
    return 0


def cmd_make_sample(args) -> int:
    path, reason = generate_sample(args.format, SAMPLES_DIR)
    if path is not None:
        print(str(path))
        return 0
    print(f"cannot generate a sample for {args.format}: {reason}", file=sys.stderr)
    return 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="app.cli_health")
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("count-pairs", help="Print the computed pair total.")
    p.set_defaults(func=cmd_count_pairs)
    p = sub.add_parser("verify-engines", help="Probe every engine and report availability.")
    p.set_defaults(func=cmd_verify_engines)
    p = sub.add_parser("health-check", help="Convert every bundled sample; disable failing pairs.")
    p.set_defaults(func=cmd_health_check)
    p = sub.add_parser("make-sample", help="Generate a real sample file for a format.")
    p.add_argument("--format", required=True, help="Format slug, e.g. jpg, mp3, svg.")
    p.set_defaults(func=cmd_make_sample)
    return parser


def register_commands(subparsers) -> None:
    """Mount these commands into the shared ``app.cli`` parser.

    The shared CLI calls this defensively (try/except ImportError), so
    this function only adds subparsers; it never imports anything else.
    """
    sub = subparsers.add_parser("count-pairs", help="Print the computed pair total.")
    sub.set_defaults(func=cmd_count_pairs)
    sub = subparsers.add_parser("verify-engines", help="Probe every engine and report availability.")
    sub.set_defaults(func=cmd_verify_engines)
    sub = subparsers.add_parser("health-check", help="Convert every bundled sample; disable failing pairs.")
    sub.set_defaults(func=cmd_health_check)
    sub = subparsers.add_parser("make-sample", help="Generate a real sample file for a format.")
    sub.add_argument("--format", required=True)
    sub.set_defaults(func=cmd_make_sample)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
