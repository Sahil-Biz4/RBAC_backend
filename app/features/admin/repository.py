"""Admin feature database operations — roles, permissions, and assignments."""

from sqlalchemy import and_, func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models.associations import RolePermission, UserRole
from app.models.permission import Permission
from app.models.role import Role
from app.models.user import User


# ── Roles ──────────────────────────────────────────────────────────────────


async def get_roles_paginated(
    db: AsyncSession,
    skip: int,
    limit: int,
    search: str | None = None,
) -> tuple[list[Role], int]:
    """Return a paginated list of roles and the total count, optionally filtered by search term."""
    if search:
        _term = f"%{search.strip()}%"
        where_clause = (or_(Role.name.ilike(_term), Role.description.ilike(_term)),)
    else:
        where_clause = ()

    total_result = await db.execute(select(func.count()).select_from(Role).where(*where_clause))
    total = total_result.scalar_one()

    result = await db.execute(
        select(Role)
        .where(*where_clause)
        .options(selectinload(Role.role_permissions).selectinload(RolePermission.permission))
        .order_by(Role.name)
        .offset(skip)
        .limit(limit)
    )
    return result.scalars().all(), total


async def get_role_by_id(db: AsyncSession, role_id: int) -> Role | None:
    result = await db.execute(
        select(Role)
        .where(Role.id == role_id)
        .options(selectinload(Role.role_permissions).selectinload(RolePermission.permission))
    )
    return result.scalars().first()


async def get_role_by_name(db: AsyncSession, name: str) -> Role | None:
    result = await db.execute(select(Role).where(Role.name == name))
    return result.scalars().first()


async def create_role(db: AsyncSession, name: str, description: str | None) -> Role:
    role = Role(name=name, description=description)
    db.add(role)
    await db.commit()
    await db.refresh(role)
    return role


async def update_role(db: AsyncSession, role: Role, name: str | None, description: str | None) -> Role:
    if name is not None:
        role.name = name
    if description is not None:
        role.description = description
    await db.commit()
    await db.refresh(role)
    return role


async def delete_role(db: AsyncSession, role: Role) -> None:
    await db.delete(role)
    await db.commit()


# ── Permissions ────────────────────────────────────────────────────────────


async def get_permissions_paginated(db: AsyncSession, skip: int, limit: int) -> tuple[list[Permission], int]:
    """Return a paginated list of permissions and the total count."""
    total_result = await db.execute(select(func.count()).select_from(Permission))
    total = total_result.scalar_one()
    result = await db.execute(select(Permission).order_by(Permission.name).offset(skip).limit(limit))
    return result.scalars().all(), total


async def get_permission_by_id(db: AsyncSession, permission_id: int) -> Permission | None:
    result = await db.execute(select(Permission).where(Permission.id == permission_id))
    return result.scalars().first()


async def get_permission_by_name(db: AsyncSession, name: str) -> Permission | None:
    result = await db.execute(select(Permission).where(Permission.name == name))
    return result.scalars().first()


async def create_permission(
    db: AsyncSession, name: str, resource: str, action: str, description: str | None
) -> Permission:
    permission = Permission(name=name, resource=resource, action=action, description=description)
    db.add(permission)
    await db.commit()
    await db.refresh(permission)
    return permission


async def delete_permission(db: AsyncSession, permission: Permission) -> None:
    await db.delete(permission)
    await db.commit()


# ── Role ↔ Permission assignments ─────────────────────────────────────────


async def assign_permission_to_role(db: AsyncSession, role_id: int, permission_id: int) -> bool:
    """Assign a permission to a role. Returns False if already assigned."""
    existing = await db.execute(
        select(RolePermission).where(
            and_(RolePermission.role_id == role_id, RolePermission.permission_id == permission_id)
        )
    )
    if existing.scalars().first():
        return False
    db.add(RolePermission(role_id=role_id, permission_id=permission_id))
    subq = select(UserRole.user_id).where(UserRole.role_id == role_id).scalar_subquery()
    await db.execute(update(User).where(User.id.in_(subq)).values(perms_version=User.perms_version + 1))
    await db.commit()
    return True


async def revoke_permission_from_role(db: AsyncSession, role_id: int, permission_id: int) -> bool:
    """Remove a permission from a role. Returns False if not assigned."""
    result = await db.execute(
        select(RolePermission).where(
            and_(RolePermission.role_id == role_id, RolePermission.permission_id == permission_id)
        )
    )
    rp = result.scalars().first()
    if not rp:
        return False
    await db.delete(rp)
    subq = select(UserRole.user_id).where(UserRole.role_id == role_id).scalar_subquery()
    await db.execute(update(User).where(User.id.in_(subq)).values(perms_version=User.perms_version + 1))
    await db.commit()
    return True


# ── User ↔ Role assignments ────────────────────────────────────────────────


async def get_user_with_roles(db: AsyncSession, user_id: int) -> User | None:
    result = await db.execute(
        select(User).where(User.id == user_id).options(selectinload(User.user_roles).selectinload(UserRole.role))
    )
    return result.scalars().first()


async def assign_role_to_user(db: AsyncSession, user_id: int, role_id: int) -> bool:
    """Assign a role to a user. Returns False if already assigned."""
    existing = await db.execute(select(UserRole).where(and_(UserRole.user_id == user_id, UserRole.role_id == role_id)))
    if existing.scalars().first():
        return False
    db.add(UserRole(user_id=user_id, role_id=role_id))
    await db.execute(update(User).where(User.id == user_id).values(perms_version=User.perms_version + 1))
    await db.commit()
    return True


async def revoke_role_from_user(db: AsyncSession, user_id: int, role_id: int) -> bool:
    """Remove a role from a user. Returns False if not assigned."""
    result = await db.execute(select(UserRole).where(and_(UserRole.user_id == user_id, UserRole.role_id == role_id)))
    ur = result.scalars().first()
    if not ur:
        return False
    await db.delete(ur)
    await db.execute(update(User).where(User.id == user_id).values(perms_version=User.perms_version + 1))
    await db.commit()
    return True
