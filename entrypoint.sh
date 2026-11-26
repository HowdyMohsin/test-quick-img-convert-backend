#!/bin/sh
# Quick IMG Convert — api entrypoint.
#
# Runs the database migrations before the server starts, so a fresh
# `docker compose up` works on an empty PostgreSQL: the API only
# auto-creates tables on SQLite (see app/main.py), and production
# Postgres must use Alembic migrations. `alembic upgrade head` reads
# DATABASE_URL from the environment and is idempotent — on an
# up-to-date database it is a no-op.
#
# Only the API server applies migrations. The worker shares the same
# database and waits for the API to be healthy (compose depends_on),
# so running Alembic in both containers at once — which can race on
# the version table — is avoided.
set -e

case "$1" in
  uvicorn)
    python -m alembic upgrade head
    # First-run admin (localhost convenience, on the owner's explicit
    # instruction): creates the super_admin from ADMIN_EMAIL /
    # ADMIN_PASSWORD if both are set and the admin does not exist yet.
    # Never blocks the server from starting — a bad admin config is
    # reported by the command itself, and the API still comes up.
    python -m app.cli bootstrap-admin || true
    ;;
esac

exec "$@"
