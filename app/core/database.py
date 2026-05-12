"""Async SQLAlchemy engine, session factory, and declarative base.

``Base`` is imported from ``app.models.base`` so all models share a single
metadata object. This module re-exports ``Base`` for backward compatibility —
existing code that does ``from app.core.database import Base`` continues to work.
"""

import logging
from collections.abc import AsyncGenerator

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.core.config.settings import settings
from app.models.base import Base  # re-exported for backward compatibility


logger = logging.getLogger(__name__)

__all__ = ["Base", "engine", "AsyncSessionLocal", "get_db"]


def _normalize_database_url(url: str) -> str:
    """Normalise a DATABASE_URL to an async-compatible SQLAlchemy dialect.

    Handles:
        - postgres:// → postgresql+psycopg://   (Heroku-style shorthand)
        - postgresql:// → postgresql+psycopg://  (sync dialect → async)
        - postgresql+asyncpg:// → kept as-is when asyncpg is installed
    """
    if not url:
        return url
    if url.startswith("postgres://"):
        url = "postgresql://" + url.removeprefix("postgres://")
    if url.startswith("postgresql+asyncpg://"):
        try:
            import asyncpg  # noqa: F401

            return url
        except ImportError:
            return url.replace("postgresql+asyncpg://", "postgresql+psycopg://", 1)
    if url.startswith("postgresql://"):
        return url.replace("postgresql://", "postgresql+psycopg://", 1)
    return url


_db_url = _normalize_database_url(settings.database_url)
if not _db_url:
    raise RuntimeError(
        "DATABASE_URL is not configured. "
        "Set DATABASE_URL in your .env file or environment variables."
    )

engine = create_async_engine(_db_url, pool_pre_ping=True)

AsyncSessionLocal = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency that yields an async database session.

    Automatically rolls back on unhandled exceptions and always closes the session.
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise
