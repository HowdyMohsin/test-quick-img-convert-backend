FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# ffmpeg + libvips + rsvg-convert are best-effort: if apt cannot fetch
# them the build still succeeds and the engines degrade gracefully
# (pairs needing a missing engine are reported unhealthy, the app stays
# up). Kept MINIMAL on purpose: only what the engines need. The engines
# need nothing else at runtime — Pillow, rawpy, psd-tools, pypdfium2
# and the rest arrive via pip in requirements.txt.
# Deliberately NOT installed (and what degrades without them):
#   - ghostscript / imagemagick: no pairs need them (SVG goes through
#     resvg / rsvg-convert, PDF through pypdfium2, both in this image).
#   - build-essential / python3-dev: wheels only; no compilation step.
# Without ffmpeg, video/audio pairs degrade; without libvips-tools,
# pyvips pairs degrade; without librsvg2-bin, SVG pairs need resvg
# (not in the image) or cairosvg (needs libcairo2, not installed);
# Pillow raster pairs keep working either way.
RUN apt-get update && apt-get install -y --no-install-recommends \
        ffmpeg libvips-tools librsvg2-bin \
    && rm -rf /var/lib/apt/lists/* || echo "ffmpeg/libvips/rsvg install failed - engines will degrade gracefully"

COPY requirements.txt .
RUN pip install -r requirements.txt

# Source is copied ONLY after the install, and .dockerignore keeps host
# artifacts (.venv, __pycache__, .env, *.db, /data) out of this COPY, so
# nothing on the build host can overwrite the installed dependencies.
# /data is root-anchored: it excludes only the runtime api/data/ dir.
# app/data/formats.json is source data and MUST ship in this image —
# the API cannot start without it.
COPY . .

# Migrations run at container start (see entrypoint.sh): a fresh
# `docker compose up` must work on an empty PostgreSQL.
RUN chmod +x /app/entrypoint.sh
ENTRYPOINT ["/app/entrypoint.sh"]

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
