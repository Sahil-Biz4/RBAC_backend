"""Role SQLAlchemy model."""

from sqlalchemy import Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin


class Role(TimestampMixin, Base):
    """Represents a named role that groups a set of permissions."""

    __tablename__ = "roles"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(50), unique=True, nullable=False, index=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    role_permissions: Mapped[list["RolePermission"]] = relationship(  # noqa: F821
        "RolePermission", back_populates="role", cascade="all, delete-orphan", lazy="selectin"
    )
    user_roles: Mapped[list["UserRole"]] = relationship(  # noqa: F821
        "UserRole", back_populates="role", cascade="all, delete-orphan"
    )
