"""Users feature business logic.

All service functions raise domain exceptions so HTTP concerns stay out of
this layer. Routes catch ``AppError`` and call ``.as_http_exception()``.
"""

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth.password import hash_password, verify_password
from app.core.exceptions import AuthError, ConflictError, ForbiddenError, NotFoundError
from app.features.users import repository as repo
from app.models.user import User
from app.utils.constants import ErrorCodes, ResponseCodes, ResponseMessages, RoleNames


async def change_my_password(db: AsyncSession, user: User, current_password: str, new_password: str) -> dict:
    """Allow the authenticated user to change their own password.

    Raises:
        AuthError: Current password is incorrect, or no password is set.
    """
    if not user.password_hash or not verify_password(current_password, user.password_hash):
        raise AuthError(ErrorCodes.INCORRECT_CURRENT_PASSWORD, ResponseMessages.INCORRECT_CURRENT_PASSWORD)

    if verify_password(new_password, user.password_hash):
        raise AuthError(ErrorCodes.SAME_PASSWORD, ResponseMessages.SAME_PASSWORD)

    await repo.update_user_password(db=db, user=user, new_hash=hash_password(new_password))
    return {"success": True, "success_code": ResponseCodes.PASSWORD_CHANGED}


async def update_my_profile(db: AsyncSession, user: User, name: str | None) -> User:
    """Update the authenticated user's display name. Returns the updated User."""
    if name:
        user = await repo.update_user_name(db=db, user=user, name=name)
    return user


async def list_users(
    db: AsyncSession,
    skip: int = 0,
    limit: int = 20,
    search: str | None = None,
) -> dict:
    """Return a paginated list of all users (admin-only), optionally filtered by name or email."""
    users, total = await repo.get_all_users(db=db, skip=skip, limit=limit, search=search)
    return {
        "users": users,
        "total": total,
        "skip": skip,
        "limit": limit,
        "has_next": (skip + limit) < total,
    }


async def get_user_by_id(db: AsyncSession, user_id: int) -> User:
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
        ForbiddenError: Admin attempted to delete their own account.
        NotFoundError:  User not found or already deleted.
    """
    if user_id == requesting_user_id:
        raise ForbiddenError(ErrorCodes.FORBIDDEN, ResponseMessages.CANNOT_DELETE_SELF)

    user = await repo.get_user_by_id(db=db, user_id=user_id)
    if not user:
        raise NotFoundError(ErrorCodes.USER_NOT_FOUND, ResponseMessages.USER_NOT_FOUND)

    await repo.soft_delete_user(db=db, user=user)
    return {"success": True, "success_code": ResponseCodes.USER_DELETED}


async def create_user(db: AsyncSession, name: str, email: str, password: str, is_active: bool = True) -> User:
    """Create a new verified user with the default role (admin-only).

    Admin-created accounts are marked email-verified and assigned the USER role
    so they can log in immediately.

    Raises:
        ConflictError: Email already exists.
    """
    from app.features.auth import repository as auth_repo

    existing = await repo.get_user_by_email(db=db, email=email)
    if existing:
        raise ConflictError(ErrorCodes.EMAIL_EXISTS, ResponseMessages.EMAIL_ALREADY_EXISTS)

    password_hash = hash_password(password)
    user = await repo.create_user(
        db=db,
        name=name,
        email=email,
        password_hash=password_hash,
        is_active=is_active,
        is_email_verified=True,
    )
    await auth_repo.assign_role_to_user(db=db, user_id=user.id, role_name=RoleNames.DEFAULT)
    await db.commit()
    return user


async def update_user(
    db: AsyncSession, user_id: int, name: str | None = None, email: str | None = None, is_active: bool | None = None
) -> User:
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

    return await repo.update_user(db=db, user=user, name=name, email=email, is_active=is_active)
