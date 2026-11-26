"""Add jobs.cancel_requested, jobs.quota_keys, uploads.original_filename.

Integration (2026-11-24): the pipeline store is database-backed, so the
worker (a separate process/container) must see cancel flags and the quota
counters a job consumed. ``cancel_requested`` lets the cancel endpoint
flag a running job; ``quota_keys`` lists every quota counter the job
consumed (owner key plus, for anonymous users, the IP-HMAC key) so a
refund decrements all of them. ``original_filename`` preserves the
client-supplied name alongside the sanitized stored filename.
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("jobs") as batch_op:
        batch_op.add_column(
            sa.Column("cancel_requested", sa.Boolean(), nullable=False,
                      server_default=sa.false()))
        batch_op.add_column(sa.Column("quota_keys", sa.JSON(), nullable=True))
    with op.batch_alter_table("uploads") as batch_op:
        batch_op.add_column(
            sa.Column("original_filename", sa.String(200), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("uploads") as batch_op:
        batch_op.drop_column("original_filename")
    with op.batch_alter_table("jobs") as batch_op:
        batch_op.drop_column("quota_keys")
        batch_op.drop_column("cancel_requested")
