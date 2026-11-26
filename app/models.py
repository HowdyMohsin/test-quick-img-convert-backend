"""Database schema (v5 spec section 10) — every table, one revision.

``users.email`` is CITEXT on PostgreSQL. For SQLite dev the custom
:func:`CIText` type compiles to ``VARCHAR`` instead, so SQLite dev
uniqueness is case-SENSITIVE while production (CITEXT) is
case-insensitive. Application code therefore always normalises email
(trim + Unicode NFC + lower-case) before lookups, so behaviour matches
in both environments.

JSON columns use SQLAlchemy ``JSON`` (JSONB on PostgreSQL, TEXT on
SQLite). ``payment_providers.config`` is stored as TEXT holding an
AES-GCM ciphertext blob (see ``app.security``), not as JSONB: the
ciphertext is opaque, and a TEXT column keeps the encrypted value
write-only and never accidentally parsed as a config object.
"""

from __future__ import annotations

import uuid
from datetime import date, datetime, timezone

from sqlalchemy import (
    BigInteger,
    Boolean,
    Date,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    JSON,
    String,
    Text,
    UniqueConstraint,
    types,
)
from sqlalchemy.dialects.postgresql import CITEXT as PG_CITEXT
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _uuid() -> str:
    return str(uuid.uuid4())


# SQLite only autoincrements a PK when the column type is INTEGER
# (the rowid alias); a BIGINT PK gets no autoincrement and inserts
# fail with NULL id on the dev database. PostgreSQL is unaffected
# (BIGSERIAL). So every BigInteger PK uses this variant: BIGINT on
# PostgreSQL, INTEGER on SQLite — autoincrement works on both, and no
# per-insert max(id)+1 shim is needed anywhere (events, ad_events,
# audit_log, auth_attempts).
AutoId = BigInteger().with_variant(Integer, "sqlite")


class CIText(types.TypeDecorator):
    """Case-insensitive text: CITEXT on PostgreSQL, VARCHAR on SQLite.

    See the module docstring for the dev-vs-production difference.
    """

    impl = String
    cache_ok = True

    def load_dialect_impl(self, dialect):
        if dialect.name == "postgresql":
            # Must return the TYPE itself, not its compiled SQL text:
            # returning dialect.type_compiler.process(PG_CITEXT()) gave
            # back the string "CITEXT", and SQLAlchemy then called
            # .dialect_impl() on that string -> AttributeError, which
            # killed `alembic upgrade head` on the first real PostgreSQL
            # run (SQLite never hit this branch, so it stayed hidden).
            return PG_CITEXT()
        return self.impl

    def process_bind_param(self, value, dialect):
        return value


class Base(DeclarativeBase):
    pass


# ---------------------------------------------------------------- accounts

class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    email: Mapped[str] = mapped_column(CIText(255), unique=True, nullable=False)
    email_verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    password_hash: Mapped[str | None] = mapped_column(Text)  # nullable: Google-only
    display_name: Mapped[str] = mapped_column(String(200), nullable=False, default="")
    plan: Mapped[str] = mapped_column(String(50), nullable=False, default="free")
    banned: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    ban_reason: Mapped[str | None] = mapped_column(Text)
    marketing_opt_in: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, nullable=False)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class AuthIdentity(Base):
    __tablename__ = "auth_identities"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id"), nullable=False)
    provider: Mapped[str] = mapped_column(String(50), nullable=False)  # google
    subject: Mapped[str] = mapped_column(String(255), nullable=False)
    email: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, nullable=False)

    __table_args__ = (UniqueConstraint("provider", "subject", name="uq_auth_identities_provider_subject"),)


class Session(Base):
    __tablename__ = "sessions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id"), nullable=False)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    csrf_secret: Mapped[str] = mapped_column(String(64), nullable=False)
    ip: Mapped[str | None] = mapped_column(String(64))
    user_agent: Mapped[str | None] = mapped_column(Text)
    remember: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class EmailToken(Base):
    __tablename__ = "email_tokens"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id"), nullable=False)
    kind: Mapped[str] = mapped_column(String(30), nullable=False)  # verify | reset | change_email
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    new_email: Mapped[str | None] = mapped_column(String(255))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, nullable=False)


class EmailOtp(Base):
    """One-time 6-digit email verification code.

    Only the SHA-256 hash of the code is stored. One active code per user:
    issuing a new code invalidates any earlier unused one. A code expires
    after 10 minutes and is void after 5 failed attempts.
    """
    __tablename__ = "email_otps"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id"), nullable=False)
    code_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, nullable=False)


class AuthAttempt(Base):
    __tablename__ = "auth_attempts"

    id: Mapped[int] = mapped_column(AutoId, primary_key=True, autoincrement=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, nullable=False)
    kind: Mapped[str] = mapped_column(String(30), nullable=False)  # login | register | forgot | resend
    email_hash: Mapped[str | None] = mapped_column(String(64))
    ip: Mapped[str | None] = mapped_column(String(64))
    success: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    __table_args__ = (Index("ix_auth_attempts_ip_ts", "ip", "ts"),
                      Index("ix_auth_attempts_email_ts", "email_hash", "ts"))


# ---------------------------------------------------------------- plans/quota/billing

class Quota(Base):
    __tablename__ = "quotas"

    owner_key: Mapped[str] = mapped_column(String(255), primary_key=True)
    day: Mapped[date] = mapped_column(Date, primary_key=True)
    used: Mapped[int] = mapped_column(Integer, nullable=False, default=0)


class Plan(Base):
    __tablename__ = "plans"

    id: Mapped[str] = mapped_column(String(50), primary_key=True)  # free | basic | pro
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    price_cents: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    price_yearly_cents: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    currency: Mapped[str] = mapped_column(String(10), nullable=False, default="USD")
    trial_days: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    # limits: {daily, batch, img_mb, aud_mb, vid_mb, vid_min, parallel, priority, ads}
    limits: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    featured: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    archived: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    sort: Mapped[int] = mapped_column(Integer, nullable=False, default=0)


class PlanPrice(Base):
    __tablename__ = "plan_prices"

    plan_id: Mapped[str] = mapped_column(String(50), ForeignKey("plans.id"), primary_key=True)
    provider_key: Mapped[str] = mapped_column(String(50), primary_key=True)
    interval: Mapped[str] = mapped_column(String(20), primary_key=True)  # monthly | yearly
    provider_price_id: Mapped[str] = mapped_column(String(255), nullable=False)


class Coupon(Base):
    __tablename__ = "coupons"

    code: Mapped[str] = mapped_column(String(50), primary_key=True)
    type: Mapped[str] = mapped_column(String(20), nullable=False)  # percent | fixed
    value: Mapped[int] = mapped_column(Integer, nullable=False)  # percent 1-100 or fixed cents
    plans: Mapped[list | None] = mapped_column(JSON)  # null/[] = all plans
    intervals: Mapped[list | None] = mapped_column(JSON)  # monthly | yearly | both
    recurring: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    max_uses: Mapped[int | None] = mapped_column(Integer)
    used: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    per_user_limit: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)


class Subscription(Base):
    __tablename__ = "subscriptions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id"), nullable=False)
    plan_id: Mapped[str] = mapped_column(String(50), ForeignKey("plans.id"), nullable=False)
    provider_key: Mapped[str] = mapped_column(String(50), nullable=False)
    provider_sub_id: Mapped[str | None] = mapped_column(String(255))
    interval: Mapped[str] = mapped_column(String(20), nullable=False, default="monthly")
    coupon_code: Mapped[str | None] = mapped_column(String(50))
    status: Mapped[str] = mapped_column(String(30), nullable=False, default="active")
    cancel_at_period_end: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    current_period_end: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    grace_ends_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, nullable=False)


class PaymentProvider(Base):
    __tablename__ = "payment_providers"

    key: Mapped[str] = mapped_column(String(50), primary_key=True)
    label: Mapped[str] = mapped_column(String(100), nullable=False)
    flow: Mapped[str] = mapped_column(String(20), nullable=False)  # manual | auto | link
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    # AES-GCM ciphertext blob (base64), write-only via the admin API.
    config: Mapped[str | None] = mapped_column(Text)
    sort: Mapped[int] = mapped_column(Integer, nullable=False, default=0)


class PaymentRequest(Base):
    __tablename__ = "payment_requests"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id"), nullable=False)
    plan_id: Mapped[str] = mapped_column(String(50), ForeignKey("plans.id"), nullable=False)
    interval: Mapped[str] = mapped_column(String(20), nullable=False, default="monthly")
    provider_key: Mapped[str] = mapped_column(String(50), nullable=False)
    coupon_code: Mapped[str | None] = mapped_column(String(50))
    amount_cents: Mapped[int] = mapped_column(Integer, nullable=False)
    currency: Mapped[str] = mapped_column(String(10), nullable=False, default="USD")
    display_amount: Mapped[str | None] = mapped_column(String(100))
    fx_rate: Mapped[float | None] = mapped_column(Float)
    reference: Mapped[str | None] = mapped_column(String(255))
    note: Mapped[str | None] = mapped_column(Text)
    proof_path: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(30), nullable=False, default="pending")
    admin_note: Mapped[str | None] = mapped_column(Text)
    receipt_no: Mapped[str | None] = mapped_column(String(50))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, nullable=False)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    resolved_by: Mapped[str | None] = mapped_column(String(255))

    __table_args__ = (
        UniqueConstraint("provider_key", "reference", name="uq_payment_requests_provider_reference"),
    )


class WebhookEvent(Base):
    __tablename__ = "webhook_events"

    provider_key: Mapped[str] = mapped_column(String(50), primary_key=True)
    event_id: Mapped[str] = mapped_column(String(255), primary_key=True)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, nullable=False)
    type: Mapped[str | None] = mapped_column(String(100))
    payload: Mapped[dict | None] = mapped_column(JSON)
    status: Mapped[str | None] = mapped_column(String(30))
    error: Mapped[str | None] = mapped_column(Text)


# ---------------------------------------------------------------- pipeline

class Upload(Base):
    __tablename__ = "uploads"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    owner_key: Mapped[str] = mapped_column(String(255), nullable=False)
    filename: Mapped[str] = mapped_column(String(255), nullable=False)
    original_filename: Mapped[str | None] = mapped_column(String(200))
    size: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    detected_format: Mapped[str | None] = mapped_column(String(50))
    category: Mapped[str | None] = mapped_column(String(50))
    path: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Job(Base):
    __tablename__ = "jobs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    batch_id: Mapped[str | None] = mapped_column(String(36))
    owner_key: Mapped[str] = mapped_column(String(255), nullable=False)
    user_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("users.id"))
    upload_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("uploads.id"))
    pair_slug: Mapped[str | None] = mapped_column(String(100))
    from_slug: Mapped[str | None] = mapped_column(String(50))
    to_slug: Mapped[str | None] = mapped_column(String(50))
    category: Mapped[str | None] = mapped_column(String(50))
    route: Mapped[str | None] = mapped_column(String(50))
    settings: Mapped[dict | None] = mapped_column(JSON)
    plan: Mapped[str | None] = mapped_column(String(50))
    status: Mapped[str] = mapped_column(String(30), nullable=False, default="queued")
    progress: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    # Set by the cancel endpoint while a job is running; the worker checks
    # it after the conversion finishes (a separate process cannot see an
    # in-memory flag, so it must be persisted).
    cancel_requested: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    # Quota counters this job consumed (owner key plus, for anonymous users,
    # the IP-HMAC key); refunds decrement every key in this list.
    quota_keys: Mapped[list | None] = mapped_column(JSON, nullable=True)
    error_code: Mapped[str | None] = mapped_column(String(100))
    error_message: Mapped[str | None] = mapped_column(Text)
    out_name: Mapped[str | None] = mapped_column(String(255))
    out_path: Mapped[str | None] = mapped_column(Text)
    out_size: Mapped[int | None] = mapped_column(BigInteger)
    in_size: Mapped[int | None] = mapped_column(BigInteger)
    out_info: Mapped[dict | None] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class PairHealth(Base):
    __tablename__ = "pair_health"

    pair_slug: Mapped[str] = mapped_column(String(100), primary_key=True)
    status: Mapped[str] = mapped_column(String(30), nullable=False, default="healthy")
    last_checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error: Mapped[str | None] = mapped_column(Text)


class Event(Base):
    __tablename__ = "events"

    id: Mapped[int] = mapped_column(AutoId, primary_key=True, autoincrement=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, nullable=False)
    owner_type: Mapped[str | None] = mapped_column(String(30))
    plan: Mapped[str | None] = mapped_column(String(50))
    pair_slug: Mapped[str | None] = mapped_column(String(100))
    category: Mapped[str | None] = mapped_column(String(50))
    status: Mapped[str | None] = mapped_column(String(30))
    bytes_in: Mapped[int | None] = mapped_column(BigInteger)
    bytes_out: Mapped[int | None] = mapped_column(BigInteger)
    duration_ms: Mapped[int | None] = mapped_column(Integer)


# ---------------------------------------------------------------- ads/marketing/content

class AdSlot(Base):
    __tablename__ = "ad_slots"

    key: Mapped[str] = mapped_column(String(100), primary_key=True)
    label: Mapped[str] = mapped_column(String(200), nullable=False)
    placement: Mapped[str] = mapped_column(String(100), nullable=False)
    size: Mapped[str] = mapped_column(String(50), nullable=False, default="responsive")
    device: Mapped[str] = mapped_column(String(20), nullable=False, default="all")
    freq_cap: Mapped[int | None] = mapped_column(Integer)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    network: Mapped[str] = mapped_column(String(50), nullable=False, default="custom")
    unit_id: Mapped[str | None] = mapped_column(String(255))
    code: Mapped[str | None] = mapped_column(Text)
    sort: Mapped[int] = mapped_column(Integer, nullable=False, default=0)


class AdEvent(Base):
    __tablename__ = "ad_events"

    id: Mapped[int] = mapped_column(AutoId, primary_key=True, autoincrement=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, nullable=False)
    slot: Mapped[str | None] = mapped_column(String(100))
    plan: Mapped[str | None] = mapped_column(String(50))
    page: Mapped[str | None] = mapped_column(String(255))
    device: Mapped[str | None] = mapped_column(String(20))


class AdRevenue(Base):
    __tablename__ = "ad_revenue"

    day: Mapped[date] = mapped_column(Date, primary_key=True)
    network: Mapped[str] = mapped_column(String(50), primary_key=True)
    amount_cents: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    currency: Mapped[str] = mapped_column(String(10), nullable=False, default="USD")


class Popup(Base):
    __tablename__ = "popups"

    key: Mapped[str] = mapped_column(String(100), primary_key=True)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    body: Mapped[str] = mapped_column(Text, nullable=False, default="")
    cta_text: Mapped[str | None] = mapped_column(String(100))
    cta_href: Mapped[str | None] = mapped_column(String(255))
    frequency: Mapped[str | None] = mapped_column(String(100))
    schedule: Mapped[dict | None] = mapped_column(JSON)
    pages: Mapped[list | None] = mapped_column(JSON)


class Announcement(Base):
    __tablename__ = "announcements"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    text: Mapped[str] = mapped_column(Text, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    starts_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    ends_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Notification(Base):
    __tablename__ = "notifications"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id"), nullable=False)
    kind: Mapped[str] = mapped_column(String(50), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    body: Mapped[str | None] = mapped_column(Text)
    href: Mapped[str | None] = mapped_column(String(255))
    read: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, nullable=False)


class EmailTemplate(Base):
    __tablename__ = "email_templates"

    key: Mapped[str] = mapped_column(String(100), primary_key=True)
    subject: Mapped[str] = mapped_column(String(255), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)


class SiteSetting(Base):
    __tablename__ = "site_settings"

    key: Mapped[str] = mapped_column(String(100), primary_key=True)
    value: Mapped[dict | list | str | int | float | bool | None] = mapped_column(JSON)


# ---------------------------------------------------------------- admin

class AdminUser(Base):
    __tablename__ = "admin_users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    email: Mapped[str] = mapped_column(CIText(255), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(Text, nullable=False)
    role: Mapped[str] = mapped_column(String(30), nullable=False, default="staff")
    permissions: Mapped[dict | None] = mapped_column(JSON)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    must_change_password: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    totp_secret: Mapped[str | None] = mapped_column(Text)  # encrypted when set
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class AdminSession(Base):
    __tablename__ = "admin_sessions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    admin_id: Mapped[str] = mapped_column(String(36), ForeignKey("admin_users.id"), nullable=False)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    ip: Mapped[str | None] = mapped_column(String(64))
    user_agent: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class AuditLog(Base):
    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(AutoId, primary_key=True, autoincrement=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, nullable=False)
    admin_email: Mapped[str | None] = mapped_column(String(255))
    action: Mapped[str] = mapped_column(String(100), nullable=False)
    target: Mapped[str | None] = mapped_column(String(255))
    before: Mapped[dict | None] = mapped_column(JSON)
    after: Mapped[dict | None] = mapped_column(JSON)
    ip: Mapped[str | None] = mapped_column(String(64))
