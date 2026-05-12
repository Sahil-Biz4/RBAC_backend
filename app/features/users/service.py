"""Users feature business logic.

All service functions raise domain exceptions so HTTP concerns stay out of
this layer. Routes catch ``AppError`` and call ``.as_http_exception()``.
"""

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth.password import hash_password
from app.core.exceptions import ConflictError, ForbiddenError, NotFoundError
from app.features.users import repository as repo
from app.utils.constants import ErrorCodes, ResponseCodes, ResponseMessages


async def get_current_user_profile(db: AsyncSession, user_id: int) -> dict:
    """Return the authenticated user's profile data.

    Raises:
        NotFoundError: User no longer exists (e.g. deleted after token issued).
    """
    user = await repo.get_user_by_id(db=db, user_id=user_id)
    if not user:
        raise NotFoundError(ErrorCodes.USER_NOT_FOUND, ResponseMessages.USER_NOT_FOUND)
    return user


async def update_current_user_profile(db: AsyncSession, user_id: int, name: str) -> dict:
    """Update the authenticated user's display name.

    Raises:
        NotFoundError: User not found.
    """
    user = await repo.get_user_by_id(db=db, user_id=user_id)
    if not user:
        raise NotFoundError(ErrorCodes.USER_NOT_FOUND, ResponseMessages.USER_NOT_FOUND)
    updated = await repo.update_user_name(db=db, user=user, name=name)
    return updated


async def list_users(db: AsyncSession, skip: int = 0, limit: int = 20) -> dict:
    """Return a paginated list of all users (admin-only)."""
    users, total = await repo.get_all_users(db=db, skip=skip, limit=limit)
    return {
        "users": users,
        "total": total,
        "skip": skip,
        "limit": limit,
        "has_next": (skip + limit) < total,
    }


async def get_user_by_id(db: AsyncSession, user_id: int) -> dict:
    """Return a single user by ID (admin-only).

    Raises:
        NotFoundError: User not found.
    """
    user = await repo.get_user_by_id(db=db, user_id=user_id)
    if not user:
        raise NotFoundError(ErrorCodes.USER_NOT_FOUND, ResponseMessages.USER_NOT_FOUND)
    return user


async def delete_user(db: AsyncSession, user_id: int, requesting_user_id: int) -> dict:
    """Soft-delete a user by ID (admin-only).

    Raises:
        ConflictError: Admin attempted to delete their own account.
        NotFoundError: User not found or already deleted.
    """
    if user_id == requesting_user_id:
        raise ForbiddenError(ErrorCodes.FORBIDDEN, ResponseMessages.CANNOT_DELETE_SELF)

    user = await repo.get_user_by_id(db=db, user_id=user_id)
    if not user:
        raise NotFoundError(ErrorCodes.USER_NOT_FOUND, ResponseMessages.USER_NOT_FOUND)

    await repo.soft_delete_user(db=db, user=user)
    return {"success": True, "success_code": ResponseCodes.USER_DELETED}


async def create_user(
    db: AsyncSession, name: str, email: str, password: str, is_active: bool = True
) -> dict:
    """Create a new user (admin-only).
    
    Raises:
        ConflictError: Email already exists.
    """
    existing = await repo.get_user_by_email(db=db, email=email)
    if existing:
        raise ConflictError(ErrorCodes.EMAIL_EXISTS, ResponseMessages.EMAIL_ALREADY_EXISTS)
    
    password_hash = hash_password(password)
    user = await repo.create_user(
        db=db, name=name, email=email, password_hash=password_hash, is_active=is_active
    )
    return user


async def update_user(
    db: AsyncSession, user_id: int, name: str | None = None, 
    email: str | None = None, is_active: bool | None = None
) -> dict:
    """Update user details (admin-only).
    
    Raises:
        NotFoundError: User not found.
        ConflictError: Email already exists.
    """
    user = await repo.get_user_by_id(db=db, user_id=user_id)
    if not user:
        raise NotFoundError(ErrorCodes.USER_NOT_FOUND, ResponseMessages.USER_NOT_FOUND)
    
    if email and email != user.email:
        existing = await repo.get_user_by_email(db=db, email=email)
        if existing:
            raise ConflictError(ErrorCodes.EMAIL_EXISTS, ResponseMessages.EMAIL_ALREADY_EXISTS)
    
    updated = await repo.update_user(
        db=db, user=user, name=name, email=email, is_active=is_active
    )
    return updated
