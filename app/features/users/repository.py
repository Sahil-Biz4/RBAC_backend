"""Users feature database operations."""

from datetime import UTC, datetime

from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models.associations import UserRole
from app.models.role import Role
from app.models.user import User


async def get_all_users(
    db: AsyncSession,
    skip: int = 0,
    limit: int = 50,
    search: str | None = None,
) -> tuple[list[User], int]:
    """Return a paginated list of users and the total count, optionally filtered by search term."""
    base_filter = User.deleted_at.is_(None)
    if search:
        _term = f"%{search.strip()}%"
        search_filter = or_(User.name.ilike(_term), User.email.ilike(_term))
        where_clause = (base_filter, search_filter)
    else:
        where_clause = (base_filter,)

    count_result = await db.execute(select(func.count()).select_from(User).where(*where_clause))
    total = count_result.scalar_one()

    result = await db.execute(
        select(User)
        .where(*where_clause)
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


async def update_user_password(db: AsyncSession, user: User, new_hash: str) -> None:
    """Update the stored password hash for a user."""
    user.password_hash = new_hash
    await db.commit()


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


async def get_user_by_email(db: AsyncSession, email: str) -> User | None:
    """Fetch a user by email address."""
    result = await db.execute(select(User).where(User.email == email, User.deleted_at.is_(None)))
    return result.scalars().first()


async def create_user(
    db: AsyncSession,
    name: str,
    email: str,
    password_hash: str,
    is_active: bool = True,
    is_email_verified: bool = False,
) -> User:
    """Create a new user. Flushes to obtain the primary key; caller is responsible for commit."""
    user = User(
        name=name,
        email=email,
        password_hash=password_hash,
        is_active=is_active,
        is_email_verified=is_email_verified,
    )
    db.add(user)
    await db.flush()
    await db.refresh(user, attribute_names=["user_roles"])
    return user


async def update_user(
    db: AsyncSession, user: User, name: str | None = None, email: str | None = None, is_active: bool | None = None
) -> User:
    """Update user details."""
    if name is not None:
        user.name = name
    if email is not None:
        user.email = email
    if is_active is not None:
        user.is_active = is_active
    await db.commit()
    await db.refresh(user)
    return user
