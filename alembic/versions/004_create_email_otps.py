"""004 create email_otps table

Revision ID: 004
Revises: 003
Create Date: 2025-01-01 00:04:00
"""

import sqlalchemy as sa
from alembic import op

revision = "004"
down_revision = "003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "email_otps",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("user_id", sa.Integer, sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("otp_hash", sa.String(64), nullable=False),
        sa.Column("purpose", sa.String(50), nullable=False),
        sa.Column("attempts", sa.Integer, default=0, nullable=False),
        sa.Column("is_used", sa.Boolean, default=False, nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_email_otps_user_id", "email_otps", ["user_id"])
    op.create_index("ix_email_otps_purpose", "email_otps", ["purpose"])


def downgrade() -> None:
    op.drop_index("ix_email_otps_purpose", table_name="email_otps")
    op.drop_index("ix_email_otps_user_id", table_name="email_otps")
    op.drop_table("email_otps")
