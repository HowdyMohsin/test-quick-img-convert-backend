"""Brand constants for Quick IMG Convert (backend copy).

Single source of truth for the API side. The web app keeps its own copy
in ``web/lib/brand.ts`` and the admin app in ``admin/lib/brand.ts``;
never hard-code these strings in components or handlers.
"""

BRAND_NAME = "Quick IMG Convert"
BRAND_TAGLINE = "Convert images, RAW, audio, video and PDF — fast, free and private."
BRAND_HOME_H1 = "Free online file converter"
BRAND_SUPPORT_EMAIL = "support@quickimgconvert.com"
BRAND_FROM_NAME = "Quick IMG Convert"
RECEIPT_PREFIX = "QIC-"

# Design tokens (kept here so transactional email HTML matches the product).
COLOR_PRIMARY = "#4F46E5"
COLOR_INK = "#0F172A"
COLOR_MUTED = "#64748B"
COLOR_SURFACE = "#FFFFFF"
COLOR_SOFT = "#F1F5F9"
COLOR_LINE = "#E2E8F0"
COLOR_SUCCESS = "#16A34A"
COLOR_WARN = "#D97706"
COLOR_DANGER = "#DC2626"
