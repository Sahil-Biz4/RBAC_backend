"""Users feature database operations."""

from datetime import UTC, datetime

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models.associations import UserRole
from app.models.role import Role
from app.models.user import User


async def get_all_users(db: AsyncSession, skip: int = 0, limit: int = 50) -> tuple[list[User], int]:
    """Return a paginated list of users and the total count."""
    count_result = await db.execute(select(func.count()).select_from(User).where(User.deleted_at.is_(None)))
    total = count_result.scalar_one()

    result = await db.execute(
        select(User)
        .where(User.deleted_at.is_(None))
        .options(selectinload(User.user_roles).selectinload(UserRole.role))
        .order_by(User.created_at.desc())
        .offset(skip)
        .limit(limit)
    )
    return result.scalars().all(), total


async def get_user_by_id(db: AsyncSession, user_id: int) -> User | None:
    """Fetch a user by primary key with roles loaded."""
    result = await db.execute(
        select(User)
        .where(User.id == user_id, User.deleted_at.is_(None))
        .options(selectinload(User.user_roles).selectinload(UserRole.role).selectinload(Role.role_permissions))
    )
    return result.scalars().first()


async def update_user_name(db: AsyncSession, user: User, name: str) -> User:
    """Update a user's display name."""
    user.name = name
    await db.commit()
    await db.refresh(user)
    return user


async def soft_delete_user(db: AsyncSession, user: User) -> None:
    """Soft-delete a user by setting deleted_at and deactivating the account."""
    user.deleted_at = datetime.now(UTC)
    user.is_active = False
    await db.commit()
