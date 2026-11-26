"""Add display_name to admin_users.

The admin Team page has a Name field when creating an admin, but the
column did not exist: the name was silently dropped and the list always
fell back to the email. Nullable, so existing rows are unaffected.
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "admin_users",
        sa.Column("display_name", sa.String(255), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("admin_users", "display_name")
