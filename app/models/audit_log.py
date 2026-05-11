"""AuditLog SQLAlchemy model — immutable record of security-relevant events.

Audit logs are append-only; no UPDATE or DELETE operations should ever be
performed on this table. Retention and archival policies are handled
outside the application layer.

Captured events include:
  - Successful logins / logouts
  - Failed login attempts (brute-force tracking)
  - Password changes and resets
  - Email verification
  - Session revocation
  - Role / permission changes (admin actions)
"""

from sqlalchemy import ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin, UUIDMixin


class AuditLog(UUIDMixin, TimestampMixin, Base):
    """Immutable audit record for a security-relevant application event.

    Attributes:
        user_id:    FK to the actor user (nullable for unauthenticated events
                    such as failed login with unknown email).
        event:      Machine-readable event code (e.g. ``LOGIN_SUCCESS``).
        ip_address: Client IP address at the time of the event.
        user_agent: HTTP User-Agent header at the time of the event.
        meta:       Optional JSON string with event-specific context.
    """

    __tablename__ = "audit_logs"

    user_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    event: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(Text, nullable=True)
    meta: Mapped[str | None] = mapped_column(Text, nullable=True)
