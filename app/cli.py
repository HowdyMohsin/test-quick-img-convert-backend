"""Unified CLI: ``python -m app.cli <command>`` (v5 section 11).

Mounts the admin commands (``app.cli_admin``: create-admin, seed,
check-config) and the health commands (``app.cli_health``: count-pairs,
verify-engines, health-check, make-sample) under one entry point.
Async commands are run with ``asyncio.run``; sync commands directly.
"""
from __future__ import annotations

import argparse
import asyncio
import sys


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m app.cli",
        description="Quick IMG Convert administration CLI.")
    sub = parser.add_subparsers(dest="command", required=True)

    from .cli_admin import cmd_bootstrap_admin, cmd_check_config, cmd_create_admin, cmd_seed

    p_admin = sub.add_parser("create-admin",
                             help="Create the first admin (CLI only).")
    p_admin.add_argument("--email", required=True)
    p_admin.add_argument("--password", default=None,
                         help="If omitted, prompted securely.")
    p_admin.set_defaults(func=cmd_create_admin)

    p_boot = sub.add_parser(
        "bootstrap-admin",
        help="Create the admin from ADMIN_EMAIL/ADMIN_PASSWORD env vars (idempotent).")
    p_boot.set_defaults(func=cmd_bootstrap_admin)

    p_seed = sub.add_parser(
        "seed", help="Insert default plans/providers/slots/templates.")
    p_seed.set_defaults(func=cmd_seed)

    p_check = sub.add_parser(
        "check-config", help="Validate env + provider configuration.")
    p_check.set_defaults(func=cmd_check_config)

    from .cli_health import register_commands

    register_commands(sub)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    from .deps import reset_engine, reset_settings

    reset_settings()
    reset_engine()
    result = args.func(args)
    if asyncio.iscoroutine(result):
        return asyncio.run(result)
    return result


if __name__ == "__main__":
    raise SystemExit(main())
