# Bundled sample files

One real sample per input format, used by `python -m app.cli_health
health-check` (run at startup and nightly). Every file here was
generated locally — none is a placeholder.

## How they were made

- Raster images (JPG, PNG, WebP, AVIF, GIF, TIFF, BMP, ICO, TGA): drawn
  with Pillow (400x300 gradient with shapes). GIF is animated (2 frames).
- HEIC: written with pillow-heif.
- PSD: Pillow cannot write PSD (its PSD plugin is read-only), so the
  sample is a minimal valid PSD written by hand in `app/health.py`
  (8BPS, version 1, 8-bit RGB, uncompressed planar channels). It reads
  back correctly in both Pillow and psd-tools.
- SVG: hand-written.
- PDF: 2 pages, written with Pillow.
- Audio (MP3, WAV, FLAC, OGG, M4A, AAC, Opus, AIFF, WMA): 2-second
  440 Hz sine tone via ffmpeg.
- Video (MP4, MKV, MOV, AVI, WebM, WMV, M4V, 3GP): 2-second test pattern
  with a sine tone via ffmpeg.

## Missing samples (9)

Camera RAW samples cannot be generated locally — a RAW file is the
unprocessed sensor dump of a real camera, and there is no local tool
that synthesises one:

- CR2 (Canon), CR3 (Canon), NEF (Nikon), ARW (Sony), ORF (Olympus),
  RAF (Fujifilm), RW2 (Panasonic), DNG (Adobe), PEF (Pentax)

To cover those 54 pairs, drop one real file of each format into this
directory named `<slug>.<extension>` (for example `cr2.cr2`), then
re-run `health-check`. Until then `health-check` reports those pairs
as `no_sample` — never as failed — and never crashes on them.
