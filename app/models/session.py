"""UserSession SQLAlchemy model — replaces the flat refresh_tokens table.

Design goals:
  - Each session owns exactly one active refresh token (JTI-based).
  - ``token_family`` groups all rotation descendants from a single login — if a
    revoked token is replayed, the entire family is invalidated (replay attack defence).
  - Optional metadata (device_info, user_agent, ip_address) allows future
    per-device session management without schema changes.
  - ``is_active`` flag enables instant session revocation without touching tokens.
  - Single-device enforcement: the service layer calls ``revoke_all_user_sessions()``
    before creating a new session. To enable multi-device login in the future,
    simply remove that call — the data model supports multiple sessions natively.
"""

from sqlalchemy import Boolean, DateTime, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin, UUIDMixin


class UserSession(UUIDMixin, TimestampMixin, Base):
    """Tracks an active authenticated session for a user.

    Attributes:
        user_id:       FK to the owning user.
        jti:           JWT ID of the *current* valid refresh token for this session.
        token_family:  UUID shared across all tokens in a rotation chain.
                       Used to detect and respond to refresh token replay attacks.
        is_active:     False means this session has been explicitly revoked.
        expires_at:    Wall-clock expiry of the refresh token (matches JWT 'exp').
        last_active_at: Updated on every successful token refresh.
        device_info:   Optional client-supplied device descriptor (e.g. "iPhone 15").
        user_agent:    HTTP User-Agent header captured at login time.
        ip_address:    Client IP address captured at login time.
    """

    __tablename__ = "user_sessions"

    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    jti: Mapped[str] = mapped_column(String(36), unique=True, nullable=False, index=True)
    token_family: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    expires_at: Mapped[DateTime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_active_at: Mapped[DateTime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Optional metadata — safe to leave NULL; never required for auth logic
    device_info: Mapped[str | None] = mapped_column(String(255), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(Text, nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)

    user: Mapped["User"] = relationship("User", back_populates="sessions")  # noqa: F821
