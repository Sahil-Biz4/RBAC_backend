"""008 drop refresh_tokens table

Revision ID: 008
Revises: 482ca40976d7
Create Date: 2026-05-13 00:00:00

Refresh tokens are stored in Redis (keyed by user_id) — the database table
is no longer used and can be dropped.
"""

import sqlalchemy as sa
from alembic import op

revision = "008"
down_revision = "482ca40976d7"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.drop_index("ix_refresh_tokens_jti", table_name="refresh_tokens")
    op.drop_index("ix_refresh_tokens_user_id", table_name="refresh_tokens")
    op.drop_table("refresh_tokens")


def downgrade() -> None:
    op.create_table(
        "refresh_tokens",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("user_id", sa.Integer, sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("jti", sa.String(36), nullable=False, unique=True),
        sa.Column("is_revoked", sa.Boolean, default=False, nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_refresh_tokens_user_id", "refresh_tokens", ["user_id"])
    op.create_index("ix_refresh_tokens_jti", "refresh_tokens", ["jti"])
