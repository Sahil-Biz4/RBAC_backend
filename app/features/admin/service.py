"""Admin feature business logic — roles, permissions, and assignments."""

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import BadRequestError, ConflictError, NotFoundError
from app.features.admin import repository as repo
from app.models.permission import Permission
from app.models.role import Role
from app.models.user import User
from app.utils.constants import ErrorCodes, ResponseMessages, RoleNames


async def list_roles(db: AsyncSession, skip: int, limit: int, search: str | None = None) -> tuple[list[Role], int]:
    return await repo.get_roles_paginated(db=db, skip=skip, limit=limit, search=search)


async def create_role(db: AsyncSession, name: str, description: str | None) -> Role:
    """Raises ConflictError if a role with the given name already exists."""
    existing = await repo.get_role_by_name(db=db, name=name)
    if existing:
        raise ConflictError(ErrorCodes.ROLE_EXISTS, ResponseMessages.ROLE_ALREADY_EXISTS)
    return await repo.create_role(db=db, name=name, description=description)


async def update_role(db: AsyncSession, role_id: int, name: str | None, description: str | None) -> Role:
    """Raises NotFoundError or BadRequestError (for default roles)."""
    role = await repo.get_role_by_id(db=db, role_id=role_id)
    if not role:
        raise NotFoundError(ErrorCodes.ROLE_NOT_FOUND, ResponseMessages.ROLE_NOT_FOUND)
    if role.name in RoleNames.ALL:
        raise BadRequestError(ErrorCodes.FORBIDDEN, ResponseMessages.CANNOT_DELETE_DEFAULT_ROLE)
    return await repo.update_role(db=db, role=role, name=name, description=description)


async def delete_role(db: AsyncSession, role_id: int) -> None:
    """Raises NotFoundError or BadRequestError (for default roles)."""
    role = await repo.get_role_by_id(db=db, role_id=role_id)
    if not role:
        raise NotFoundError(ErrorCodes.ROLE_NOT_FOUND, ResponseMessages.ROLE_NOT_FOUND)
    if role.name in RoleNames.ALL:
        raise BadRequestError(ErrorCodes.FORBIDDEN, ResponseMessages.CANNOT_DELETE_DEFAULT_ROLE)
    await repo.delete_role(db=db, role=role)


async def assign_permission_to_role(db: AsyncSession, role_id: int, permission_id: int) -> None:
    """Raises NotFoundError for missing role/permission, ConflictError if already assigned."""
    role = await repo.get_role_by_id(db=db, role_id=role_id)
    if not role:
        raise NotFoundError(ErrorCodes.ROLE_NOT_FOUND, ResponseMessages.ROLE_NOT_FOUND)
    permission = await repo.get_permission_by_id(db=db, permission_id=permission_id)
    if not permission:
        raise NotFoundError(ErrorCodes.PERMISSION_NOT_FOUND, ResponseMessages.PERMISSION_NOT_FOUND)
    assigned = await repo.assign_permission_to_role(db=db, role_id=role_id, permission_id=permission_id)
    if not assigned:
        raise ConflictError(ErrorCodes.PERMISSION_ALREADY_ASSIGNED, ResponseMessages.PERMISSION_ALREADY_ASSIGNED)


async def revoke_permission_from_role(db: AsyncSession, role_id: int, permission_id: int) -> None:
    """Raises NotFoundError if the assignment does not exist."""
    removed = await repo.revoke_permission_from_role(db=db, role_id=role_id, permission_id=permission_id)
    if not removed:
        raise NotFoundError(ErrorCodes.PERMISSION_NOT_FOUND, ResponseMessages.PERMISSION_NOT_ASSIGNED)


async def list_permissions(db: AsyncSession, skip: int, limit: int) -> tuple[list[Permission], int]:
    return await repo.get_permissions_paginated(db=db, skip=skip, limit=limit)


async def create_permission(
    db: AsyncSession, name: str, resource: str, action: str, description: str | None
) -> Permission:
    """Raises ConflictError if a permission with the given name already exists."""
    existing = await repo.get_permission_by_name(db=db, name=name)
    if existing:
        raise ConflictError(ErrorCodes.PERMISSION_EXISTS, ResponseMessages.PERMISSION_ALREADY_EXISTS)
    return await repo.create_permission(db=db, name=name, resource=resource, action=action, description=description)


async def delete_permission(db: AsyncSession, permission_id: int) -> None:
    """Raises NotFoundError if the permission does not exist."""
    permission = await repo.get_permission_by_id(db=db, permission_id=permission_id)
    if not permission:
        raise NotFoundError(ErrorCodes.PERMISSION_NOT_FOUND, ResponseMessages.PERMISSION_NOT_FOUND)
    await repo.delete_permission(db=db, permission=permission)


async def get_user_roles(db: AsyncSession, user_id: int) -> User:
    """Raises NotFoundError if the user does not exist."""
    user = await repo.get_user_with_roles(db=db, user_id=user_id)
    if not user:
        raise NotFoundError(ErrorCodes.USER_NOT_FOUND, ResponseMessages.USER_NOT_FOUND)
    return user


async def assign_role_to_user(db: AsyncSession, user_id: int, role_id: int) -> None:
    """Raises NotFoundError for missing user/role, ConflictError if already assigned."""
    user = await repo.get_user_with_roles(db=db, user_id=user_id)
    if not user:
        raise NotFoundError(ErrorCodes.USER_NOT_FOUND, ResponseMessages.USER_NOT_FOUND)
    role = await repo.get_role_by_id(db=db, role_id=role_id)
    if not role:
        raise NotFoundError(ErrorCodes.ROLE_NOT_FOUND, ResponseMessages.ROLE_NOT_FOUND)
    assigned = await repo.assign_role_to_user(db=db, user_id=user_id, role_id=role_id)
    if not assigned:
        raise ConflictError(ErrorCodes.ROLE_ALREADY_ASSIGNED, ResponseMessages.ROLE_ALREADY_ASSIGNED)


async def revoke_role_from_user(db: AsyncSession, user_id: int, role_id: int) -> None:
    """Raises NotFoundError if the assignment does not exist."""
    removed = await repo.revoke_role_from_user(db=db, user_id=user_id, role_id=role_id)
    if not removed:
        raise NotFoundError(ErrorCodes.ROLE_NOT_FOUND, ResponseMessages.ROLE_NOT_ASSIGNED)
