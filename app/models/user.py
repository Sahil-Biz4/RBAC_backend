"""User SQLAlchemy model."""

from sqlalchemy import Boolean, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, SoftDeleteMixin, TimestampMixin


class User(TimestampMixin, SoftDeleteMixin, Base):
    """Represents an application user account."""

    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    password_hash: Mapped[str | None] = mapped_column(String(255), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    is_email_verified: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    perms_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1, server_default="1")

    user_roles: Mapped[list["UserRole"]] = relationship(  # noqa: F821
        "UserRole", back_populates="user", cascade="all, delete-orphan", lazy="selectin"
    )
    email_otps: Mapped[list["EmailOtp"]] = relationship(  # noqa: F821
        "EmailOtp", back_populates="user", cascade="all, delete-orphan"
    )
