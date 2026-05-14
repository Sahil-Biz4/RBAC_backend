"""Unit tests for app/features/admin/repository.py.

Tests cover CRUD operations, pagination, and the perms_version increment
side-effect that fires whenever role↔permission or user↔role assignments change.
"""

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth.password import hash_password
from app.features.admin import repository as repo
from app.models.permission import Permission
from app.models.role import Role
from app.models.user import User


# ── Helpers ────────────────────────────────────────────────────────────────


async def _make_role(db: AsyncSession, name: str = "tester") -> Role:
    return await repo.create_role(db=db, name=name, description=f"{name} role")


async def _make_permission(db: AsyncSession, resource: str = "users", action: str = "read") -> Permission:
    return await repo.create_permission(
        db=db,
        name=f"{resource}:{action}",
        resource=resource,
        action=action,
        description=None,
    )


async def _make_user(db: AsyncSession, email: str = "x@example.com") -> User:
    user = User(
        name="Test",
        email=email,
        password_hash=hash_password("Password1!"),
        is_active=True,
        is_email_verified=True,
    )
    db.add(user)
    await db.flush()
    await db.refresh(user)
    return user


# ── Role CRUD ──────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_create_role(db: AsyncSession) -> None:
    role = await _make_role(db, name="editor")
    assert role.id is not None
    assert role.name == "editor"
    assert role.description == "editor role"


@pytest.mark.asyncio
async def test_get_role_by_id_returns_role(db: AsyncSession) -> None:
    role = await _make_role(db)
    fetched = await repo.get_role_by_id(db=db, role_id=role.id)
    assert fetched is not None
    assert fetched.id == role.id


@pytest.mark.asyncio
async def test_get_role_by_id_returns_none_for_missing(db: AsyncSession) -> None:
    result = await repo.get_role_by_id(db=db, role_id=99999)
    assert result is None


@pytest.mark.asyncio
async def test_get_role_by_name(db: AsyncSession) -> None:
    await _make_role(db, name="viewer")
    found = await repo.get_role_by_name(db=db, name="viewer")
    assert found is not None
    assert found.name == "viewer"


@pytest.mark.asyncio
async def test_get_role_by_name_missing(db: AsyncSession) -> None:
    result = await repo.get_role_by_name(db=db, name="nonexistent")
    assert result is None


@pytest.mark.asyncio
async def test_update_role(db: AsyncSession) -> None:
    role = await _make_role(db, name="old_name")
    updated = await repo.update_role(db=db, role=role, name="new_name", description="new desc")
    assert updated.name == "new_name"
    assert updated.description == "new desc"


@pytest.mark.asyncio
async def test_delete_role(db: AsyncSession) -> None:
    role = await _make_role(db)
    await repo.delete_role(db=db, role=role)
    assert await repo.get_role_by_id(db=db, role_id=role.id) is None


# ── Roles pagination ───────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_get_roles_paginated_returns_all(db: AsyncSession) -> None:
    for i in range(5):
        await _make_role(db, name=f"role_{i}")
    roles, total = await repo.get_roles_paginated(db=db, skip=0, limit=10)
    assert total == 5
    assert len(roles) == 5


@pytest.mark.asyncio
async def test_get_roles_paginated_respects_limit(db: AsyncSession) -> None:
    for i in range(5):
        await _make_role(db, name=f"r{i}")
    roles, total = await repo.get_roles_paginated(db=db, skip=0, limit=3)
    assert total == 5
    assert len(roles) == 3


@pytest.mark.asyncio
async def test_get_roles_paginated_second_page(db: AsyncSession) -> None:
    for i in range(5):
        await _make_role(db, name=f"pg{i}")
    roles, total = await repo.get_roles_paginated(db=db, skip=3, limit=3)
    assert total == 5
    assert len(roles) == 2


@pytest.mark.asyncio
async def test_get_roles_paginated_empty(db: AsyncSession) -> None:
    roles, total = await repo.get_roles_paginated(db=db, skip=0, limit=10)
    assert total == 0
    assert roles == []


# ── Permission CRUD ────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_create_permission(db: AsyncSession) -> None:
    perm = await _make_permission(db, resource="reports", action="read")
    assert perm.id is not None
    assert perm.name == "reports:read"
    assert perm.resource == "reports"
    assert perm.action == "read"


@pytest.mark.asyncio
async def test_get_permission_by_id(db: AsyncSession) -> None:
    perm = await _make_permission(db)
    fetched = await repo.get_permission_by_id(db=db, permission_id=perm.id)
    assert fetched is not None
    assert fetched.id == perm.id


@pytest.mark.asyncio
async def test_get_permission_by_id_missing(db: AsyncSession) -> None:
    result = await repo.get_permission_by_id(db=db, permission_id=99999)
    assert result is None


@pytest.mark.asyncio
async def test_get_permission_by_name(db: AsyncSession) -> None:
    await _make_permission(db, resource="posts", action="write")
    found = await repo.get_permission_by_name(db=db, name="posts:write")
    assert found is not None
    assert found.name == "posts:write"


@pytest.mark.asyncio
async def test_delete_permission(db: AsyncSession) -> None:
    perm = await _make_permission(db)
    await repo.delete_permission(db=db, permission=perm)
    assert await repo.get_permission_by_id(db=db, permission_id=perm.id) is None


# ── Permissions pagination ─────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_get_permissions_paginated_returns_all(db: AsyncSession) -> None:
    for i in range(4):
        await _make_permission(db, resource=f"res{i}", action="read")
    perms, total = await repo.get_permissions_paginated(db=db, skip=0, limit=10)
    assert total == 4
    assert len(perms) == 4


@pytest.mark.asyncio
async def test_get_permissions_paginated_respects_limit(db: AsyncSession) -> None:
    for i in range(4):
        await _make_permission(db, resource=f"res{i}", action="read")
    perms, total = await repo.get_permissions_paginated(db=db, skip=0, limit=2)
    assert total == 4
    assert len(perms) == 2


@pytest.mark.asyncio
async def test_get_permissions_paginated_empty(db: AsyncSession) -> None:
    perms, total = await repo.get_permissions_paginated(db=db, skip=0, limit=10)
    assert total == 0
    assert perms == []


# ── Role ↔ Permission assignments ─────────────────────────────────────────


@pytest.mark.asyncio
async def test_assign_permission_to_role_success(db: AsyncSession) -> None:
    role = await _make_role(db)
    perm = await _make_permission(db)
    result = await repo.assign_permission_to_role(db=db, role_id=role.id, permission_id=perm.id)
    assert result is True


@pytest.mark.asyncio
async def test_assign_permission_to_role_duplicate_returns_false(db: AsyncSession) -> None:
    role = await _make_role(db)
    perm = await _make_permission(db)
    await repo.assign_permission_to_role(db=db, role_id=role.id, permission_id=perm.id)
    result = await repo.assign_permission_to_role(db=db, role_id=role.id, permission_id=perm.id)
    assert result is False


@pytest.mark.asyncio
async def test_assign_permission_increments_perms_version(db: AsyncSession) -> None:
    role = await _make_role(db)
    perm = await _make_permission(db)
    user = await _make_user(db)
    initial_version = user.perms_version

    await repo.assign_role_to_user(db=db, user_id=user.id, role_id=role.id)
    await repo.assign_permission_to_role(db=db, role_id=role.id, permission_id=perm.id)

    await db.refresh(user)
    assert user.perms_version == initial_version + 2


@pytest.mark.asyncio
async def test_revoke_permission_from_role_success(db: AsyncSession) -> None:
    role = await _make_role(db)
    perm = await _make_permission(db)
    await repo.assign_permission_to_role(db=db, role_id=role.id, permission_id=perm.id)
    result = await repo.revoke_permission_from_role(db=db, role_id=role.id, permission_id=perm.id)
    assert result is True


@pytest.mark.asyncio
async def test_revoke_permission_not_assigned_returns_false(db: AsyncSession) -> None:
    role = await _make_role(db)
    perm = await _make_permission(db)
    result = await repo.revoke_permission_from_role(db=db, role_id=role.id, permission_id=perm.id)
    assert result is False


@pytest.mark.asyncio
async def test_revoke_permission_decrements_perms_version(db: AsyncSession) -> None:
    role = await _make_role(db)
    perm = await _make_permission(db)
    user = await _make_user(db)

    await repo.assign_role_to_user(db=db, user_id=user.id, role_id=role.id)
    await repo.assign_permission_to_role(db=db, role_id=role.id, permission_id=perm.id)
    await db.refresh(user)
    version_after_assign = user.perms_version

    await repo.revoke_permission_from_role(db=db, role_id=role.id, permission_id=perm.id)
    await db.refresh(user)
    assert user.perms_version == version_after_assign + 1


# ── User ↔ Role assignments ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_assign_role_to_user_success(db: AsyncSession) -> None:
    role = await _make_role(db)
    user = await _make_user(db)
    result = await repo.assign_role_to_user(db=db, user_id=user.id, role_id=role.id)
    assert result is True


@pytest.mark.asyncio
async def test_assign_role_to_user_duplicate_returns_false(db: AsyncSession) -> None:
    role = await _make_role(db)
    user = await _make_user(db)
    await repo.assign_role_to_user(db=db, user_id=user.id, role_id=role.id)
    result = await repo.assign_role_to_user(db=db, user_id=user.id, role_id=role.id)
    assert result is False


@pytest.mark.asyncio
async def test_assign_role_increments_perms_version(db: AsyncSession) -> None:
    role = await _make_role(db)
    user = await _make_user(db)
    initial_version = user.perms_version

    await repo.assign_role_to_user(db=db, user_id=user.id, role_id=role.id)
    await db.refresh(user)
    assert user.perms_version == initial_version + 1


@pytest.mark.asyncio
async def test_revoke_role_from_user_success(db: AsyncSession) -> None:
    role = await _make_role(db)
    user = await _make_user(db)
    await repo.assign_role_to_user(db=db, user_id=user.id, role_id=role.id)
    result = await repo.revoke_role_from_user(db=db, user_id=user.id, role_id=role.id)
    assert result is True


@pytest.mark.asyncio
async def test_revoke_role_not_assigned_returns_false(db: AsyncSession) -> None:
    role = await _make_role(db)
    user = await _make_user(db)
    result = await repo.revoke_role_from_user(db=db, user_id=user.id, role_id=role.id)
    assert result is False


@pytest.mark.asyncio
async def test_revoke_role_increments_perms_version(db: AsyncSession) -> None:
    role = await _make_role(db)
    user = await _make_user(db)
    await repo.assign_role_to_user(db=db, user_id=user.id, role_id=role.id)
    await db.refresh(user)
    version_after_assign = user.perms_version

    await repo.revoke_role_from_user(db=db, user_id=user.id, role_id=role.id)
    await db.refresh(user)
    assert user.perms_version == version_after_assign + 1


@pytest.mark.asyncio
async def test_get_user_with_roles(db: AsyncSession) -> None:
    role = await _make_role(db)
    user = await _make_user(db)
    user_id = user.id
    role_name = role.name
    await repo.assign_role_to_user(db=db, user_id=user_id, role_id=role.id)

    db.expire_all()
    fetched = await repo.get_user_with_roles(db=db, user_id=user_id)
    assert fetched is not None
    assert len(fetched.user_roles) == 1
    assert fetched.user_roles[0].role.name == role_name


@pytest.mark.asyncio
async def test_get_user_with_roles_missing(db: AsyncSession) -> None:
    result = await repo.get_user_with_roles(db=db, user_id=99999)
    assert result is None
