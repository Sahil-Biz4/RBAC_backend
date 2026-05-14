"""Shared SQLAlchemy model base classes and mixins.

All ORM models use integer autoincrement primary keys. Mix in ``TimestampMixin``
for ``created_at`` / ``updated_at`` and ``SoftDeleteMixin`` for ``deleted_at``.
"""

from datetime import datetime

from sqlalchemy import DateTime, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    """Declarative base shared by all SQLAlchemy ORM models.

    Imported by ``app.core.database`` so the engine can discover all tables.
    """


class TimestampMixin:
    """Adds ``created_at`` and ``updated_at`` columns (timezone-aware)."""

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    updated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        onupdate=func.now(),
        nullable=True,
    )


class SoftDeleteMixin:
    """Adds a ``deleted_at`` nullable timestamp for soft-delete support."""

    deleted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
