"""Add purpose to email_otps (verify vs reset).

The 8-digit password-reset codes (owner order 2026-11-27) live in the
same table as the 6-digit email-verification codes; the purpose column
keeps the two flows from colliding — issuing / verifying a code only
ever touches rows of its own purpose. Existing rows are verification
codes, so they default to "verify". See app/auth.py and
app/models.py EmailOtp.
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "email_otps",
        sa.Column("purpose", sa.String(30), nullable=False,
                  server_default="verify"),
    )
    op.create_index(
        "ix_email_otps_user_purpose", "email_otps", ["user_id", "purpose"]
    )


def downgrade() -> None:
    op.drop_index("ix_email_otps_user_purpose", table_name="email_otps")
    op.drop_column("email_otps", "purpose")
