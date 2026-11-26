"""Seed (v5 section 16): idempotent, real defaults only.

Inserts 3 plans + anonymous rules, 8 payment providers (ALL DISABLED
until configured), default ad slots, 5 popups + announcement, 10 email
templates and default site settings. Creates NO users, NO coupons and
NO demo data. Existing rows are never overwritten, so re-running seed
after an admin edits a value is safe.
"""

from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession

from .models import (
    AdSlot,
    Announcement,
    EmailTemplate,
    PaymentProvider,
    Plan,
    Popup,
    SiteSetting,
)

ANONYMOUS_LIMITS = {
    "daily": 5, "batch": 10, "img_mb": 200, "aud_mb": 100,
    "vid_mb": 500, "vid_min": 30, "parallel": 1, "priority": False, "ads": True,
    "editor": False,
}

PLANS = [
    {
        "id": "free", "name": "Free", "price_cents": 0, "price_yearly_cents": 0,
        "limits": {
            "daily": 25, "batch": 10, "img_mb": 200, "aud_mb": 100,
            "vid_mb": 500, "vid_min": 30, "parallel": 2, "priority": False, "ads": True,
            "editor": False,
        },
        "featured": 0, "sort": 1,
    },
    {
        "id": "basic", "name": "Basic", "price_cents": 400, "price_yearly_cents": 4000,
        "limits": {
            "daily": 100, "batch": 30, "img_mb": 500, "aud_mb": 250,
            "vid_mb": 1024, "vid_min": 60, "parallel": 3, "priority": False, "ads": False,
            "editor": True,
        },
        "featured": 1, "sort": 2,
    },
    {
        "id": "pro", "name": "Pro", "price_cents": 900, "price_yearly_cents": 9000,
        "limits": {
            "daily": 2000, "batch": 100, "img_mb": 2048, "aud_mb": 1024,
            "vid_mb": 4096, "vid_min": 120, "parallel": 6, "priority": True, "ads": False,
            "editor": True,
        },
        "featured": 0, "sort": 3,
    },
]

PROVIDERS = [
    ("manual_jazzcash", "JazzCash", "manual"),
    ("manual_easypaisa", "EasyPaisa", "manual"),
    ("manual_bank", "Bank Transfer", "manual"),
    ("manual_usdt", "USDT (TRC20)", "manual"),
    ("payoneer_link", "Payoneer", "link"),
    ("lemonsqueezy", "Lemon Squeezy", "auto"),
    ("paddle", "Paddle", "auto"),
    ("stripe", "Stripe", "auto"),
]

AD_SLOTS = [
    ("home_top", "Home — top", "home_top", "responsive", "all", True, 1),
    ("home_mid", "Home — middle", "home_mid", "responsive", "all", True, 2),
    ("home_bottom", "Home — bottom", "home_bottom", "responsive", "all", True, 3),
    ("pair_top", "Pair — below tool", "pair_top", "responsive", "all", True, 4),
    ("pair_mid", "Pair — middle", "pair_mid", "responsive", "all", True, 5),
    ("pair_bottom", "Pair — bottom", "pair_bottom", "responsive", "all", True, 6),
    ("mobile_anchor", "Mobile anchor", "mobile_anchor", "320x50", "mobile", False, 7),
    ("pair_sidebar", "Pair — sidebar", "pair_sidebar", "300x250", "all", True, 8),
]

POPUPS = [
    {
        "key": "limit_popup", "title": "Daily limit reached",
        "body": "You have used all your free conversions for today. Upgrade to keep converting without waiting.",
        "cta_text": "See plans", "cta_href": "/pricing",
        "frequency": "once per session", "pages": ["/", "/convert"],
    },
    {
        "key": "batch_popup", "title": "Need to convert more files at once?",
        "body": "Your plan allows a limited number of files per batch. Upgrade to convert up to 100 files in one go.",
        "cta_text": "See plans", "cta_href": "/pricing",
        "frequency": "once per session", "pages": ["/convert"],
    },
    {
        "key": "exit_popup", "title": "Before you go — go ad-free",
        "body": "Upgrade to Pro for unlimited-feeling conversions: 2,000 files a day, no ads, priority queue.",
        "cta_text": "See Pro", "cta_href": "/pricing",
        "frequency": "once per 7 days per visitor", "pages": ["/", "/pricing"],
    },
    {
        "key": "success_toast", "title": "Conversion complete",
        "body": "Enjoying Quick IMG Convert? Go ad-free with Pro.",
        "cta_text": "See Pro", "cta_href": "/pricing",
        "frequency": "once per session", "pages": ["/convert"],
    },
    {
        "key": "announce_bar", "title": "Announcement",
        "body": "Welcome to Quick IMG Convert — fast, free and private file conversion.",
        "cta_text": "", "cta_href": "",
        "frequency": "always while scheduled", "pages": ["/"],
    },
]

EMAIL_TEMPLATES = [
    ("welcome", "Welcome to Quick IMG Convert",
     "Hi {name},\n\nWelcome to Quick IMG Convert. Your account is ready — you get 25 free conversions every day.\n\nHappy converting!"),
    ("verify_email", "Verify your email — Quick IMG Convert",
     "Hi {name},\n\nPlease verify your email by opening this link:\n{link}\n\nThe link works for 24 hours."),
    ("verify_otp", "Your verification code — Quick IMG Convert",
     "Hi {name},\n\nYour verification code is: {code}\n\nIt expires in 10 minutes. If you did not ask for this code, ignore this email."),
    ("reset_password", "Reset your password — Quick IMG Convert",
     "Hi {name},\n\nReset your password by opening this link:\n{link}\n\nThe link works for 60 minutes."),
    ("password_changed", "Your password was changed — Quick IMG Convert",
     "Hi {name},\n\nYour password was changed. All other devices were signed out.\n\nIf this was not you, contact support right away."),
    ("email_change_notice", "Your email address was changed — Quick IMG Convert",
     "Hi {name},\n\nThe email address on your account was changed to {new_email}.\n\nIf this was not you, contact support right away."),
    ("payment_submitted", "We received your payment — Quick IMG Convert",
     "Hi {name},\n\nWe received your payment for the {plan} plan (reference {reference}, amount {amount}). We will review it within 24 hours."),
    ("payment_approved", "Your payment was approved — Quick IMG Convert",
     "Hi {name},\n\nYour payment for the {plan} plan was approved (reference {reference}, amount {amount}). Your receipt is {receipt_no} and your plan is now active."),
    ("payment_rejected", "Your payment could not be approved — Quick IMG Convert",
     "Hi {name},\n\nYour payment for the {plan} plan (reference {reference}) could not be approved. Reason: {reason}\n\nPlease contact support if you need help."),
    ("past_due", "Your subscription payment is past due — Quick IMG Convert",
     "Hi {name},\n\nYour {plan} subscription payment is past due. Please update your payment details within 7 days to keep your plan."),
    ("subscription_ended", "Your subscription has ended — Quick IMG Convert",
     "Hi {name},\n\nYour {plan} subscription has ended. You are now on the Free plan. You can upgrade again any time."),
]

SITE_SETTINGS = {
    "site_name": "Quick IMG Convert",
    "tagline": "Convert images, RAW, audio, video and PDF — fast, free and private.",
    "support_email": "support@quickimgconvert.com",
    "pkr_per_usd": 280,
    "quota_timezone": "Asia/Karachi",
    "approval_window_hours": 24,
    "approval_window_text": "Manual payments are reviewed within 24 hours.",
    "maintenance_mode": False,
    "retention_hours": 24,
    "anonymous_limits": ANONYMOUS_LIMITS,
    "consent_required": True,
    "cmp_configured": False,
}


async def _insert_if_missing(db: AsyncSession, model, key, obj) -> None:
    existing = await db.get(model, key)
    if existing is None:
        db.add(obj)


async def seed(db: AsyncSession) -> dict[str, int]:
    """Insert all defaults that are missing. Returns counts inserted."""
    counts = {"plans": 0, "providers": 0, "ad_slots": 0, "popups": 0,
              "announcements": 0, "email_templates": 0, "site_settings": 0}
    for p in PLANS:
        if await db.get(Plan, p["id"]) is None:
            db.add(Plan(**p))
            counts["plans"] += 1
    # The Stripe row used to be seeded as "stripe-reserved" (test mode
    # only now, key "stripe"). Rename the old row in place so existing
    # databases gain the usable row without a duplicate.
    old_stripe = await db.get(PaymentProvider, "stripe-reserved")
    if old_stripe is not None and await db.get(PaymentProvider, "stripe") is None:
        old_stripe.key = "stripe"
        old_stripe.label = "Stripe"
    for idx, (key, label, flow) in enumerate(PROVIDERS):
        if await db.get(PaymentProvider, key) is None:
            db.add(PaymentProvider(key=key, label=label, flow=flow, enabled=False, sort=idx))
            counts["providers"] += 1
    for key, label, placement, size, device, enabled, sort in AD_SLOTS:
        if await db.get(AdSlot, key) is None:
            db.add(AdSlot(key=key, label=label, placement=placement, size=size,
                          device=device, enabled=enabled, network="custom", sort=sort))
            counts["ad_slots"] += 1
    for pop in POPUPS:
        if await db.get(Popup, pop["key"]) is None:
            db.add(Popup(**pop))
            counts["popups"] += 1
    existing_ann = (await db.execute(
        __import__("sqlalchemy").select(Announcement))).scalars().all()
    if not existing_ann:
        db.add(Announcement(
            text="Welcome to Quick IMG Convert — fast, free and private file conversion.",
            enabled=False,
        ))
        counts["announcements"] += 1
    for key, subject, body in EMAIL_TEMPLATES:
        if await db.get(EmailTemplate, key) is None:
            db.add(EmailTemplate(key=key, subject=subject, body=body))
            counts["email_templates"] += 1
    for key, value in SITE_SETTINGS.items():
        if await db.get(SiteSetting, key) is None:
            db.add(SiteSetting(key=key, value=value))
            counts["site_settings"] += 1
    await db.commit()
    return counts
