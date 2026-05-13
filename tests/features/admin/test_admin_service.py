"""Unit tests for app/features/admin/service.py.

All tests bypass HTTP and work directly against the service layer so the
domain-exception logic is exercised without route or serialisation concerns.
"""

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth.password import hash_password
from app.core.exceptions import BadRequestError, ConflictError, NotFoundError
from app.features.admin import repository as repo
from app.features.admin import service
from app.models.role import Role
from app.models.user import User
from app.utils.constants import RoleNames


# ── Helpers ────────────────────────────────────────────────────────────────


async def _make_role(db: AsyncSession, name: str = "tester") -> Role:
    return await repo.create_role(db=db, name=name, description=f"{name} role")


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


# ── list_roles ─────────────────────────────────────────────────────────────


class TestListRoles:
    async def test_returns_empty_when_no_roles(self, db: AsyncSession) -> None:
        roles, total = await service.list_roles(db=db, skip=0, limit=10)
        assert roles == []
        assert total == 0

    async def test_returns_all_roles(self, db: AsyncSession) -> None:
        await _make_role(db, "alpha")
        await _make_role(db, "beta")
        roles, total = await service.list_roles(db=db, skip=0, limit=10)
        assert total == 2
        assert len(roles) == 2

    async def test_search_filters_by_name(self, db: AsyncSession) -> None:
        await _make_role(db, "viewer")
        await _make_role(db, "editor")
        roles, total = await service.list_roles(db=db, skip=0, limit=10, search="view")
        assert total == 1
        assert roles[0].name == "viewer"


# ── create_role ────────────────────────────────────────────────────────────


class TestCreateRole:
    async def test_creates_new_role(self, db: AsyncSession) -> None:
        role = await service.create_role(db=db, name="moderator", description="Moderator role")
        assert role.id is not None
        assert role.name == "moderator"

    async def test_duplicate_name_raises_conflict(self, db: AsyncSession) -> None:
        await service.create_role(db=db, name="duplicate", description=None)
        with pytest.raises(ConflictError):
            await service.create_role(db=db, name="duplicate", description=None)


# ── update_role ────────────────────────────────────────────────────────────


class TestUpdateRole:
    async def test_updates_role_name(self, db: AsyncSession) -> None:
        role = await _make_role(db, "old")
        updated = await service.update_role(db=db, role_id=role.id, name="new", description=None)
        assert updated.name == "new"

    async def test_missing_role_raises_not_found(self, db: AsyncSession) -> None:
        with pytest.raises(NotFoundError):
            await service.update_role(db=db, role_id=99999, name="x", description=None)

    async def test_default_role_raises_bad_request(self, db: AsyncSession) -> None:
        role = await _make_role(db, RoleNames.USER)
        with pytest.raises(BadRequestError):
            await service.update_role(db=db, role_id=role.id, name="renamed", description=None)


# ── delete_role ────────────────────────────────────────────────────────────


class TestDeleteRole:
    async def test_deletes_custom_role(self, db: AsyncSession) -> None:
        role = await _make_role(db, "temp")
        await service.delete_role(db=db, role_id=role.id)
        roles, total = await service.list_roles(db=db, skip=0, limit=10)
        assert total == 0

    async def test_missing_role_raises_not_found(self, db: AsyncSession) -> None:
        with pytest.raises(NotFoundError):
            await service.delete_role(db=db, role_id=99999)

    async def test_default_role_raises_bad_request(self, db: AsyncSession) -> None:
        role = await _make_role(db, RoleNames.ADMIN)
        with pytest.raises(BadRequestError):
            await service.delete_role(db=db, role_id=role.id)


# ── list_permissions ───────────────────────────────────────────────────────


class TestListPermissions:
    async def test_returns_empty_when_no_permissions(self, db: AsyncSession) -> None:
        perms, total = await service.list_permissions(db=db, skip=0, limit=10)
        assert perms == []
        assert total == 0


# ── create_permission ──────────────────────────────────────────────────────


class TestCreatePermission:
    async def test_creates_permission(self, db: AsyncSession) -> None:
        perm = await service.create_permission(
            db=db, name="reports:read", resource="reports", action="read", description=None
        )
        assert perm.id is not None
        assert perm.name == "reports:read"

    async def test_duplicate_name_raises_conflict(self, db: AsyncSession) -> None:
        await service.create_permission(db=db, name="dup:read", resource="dup", action="read", description=None)
        with pytest.raises(ConflictError):
            await service.create_permission(db=db, name="dup:read", resource="dup", action="read", description=None)


# ── delete_permission ──────────────────────────────────────────────────────


class TestDeletePermission:
    async def test_deletes_existing_permission(self, db: AsyncSession) -> None:
        perm = await service.create_permission(
            db=db, name="del:write", resource="del", action="write", description=None
        )
        await service.delete_permission(db=db, permission_id=perm.id)
        perms, total = await service.list_permissions(db=db, skip=0, limit=10)
        assert total == 0

    async def test_missing_permission_raises_not_found(self, db: AsyncSession) -> None:
        with pytest.raises(NotFoundError):
            await service.delete_permission(db=db, permission_id=99999)


# ── assign_permission_to_role ──────────────────────────────────────────────


class TestAssignPermissionToRole:
    async def test_assigns_successfully(self, db: AsyncSession) -> None:
        role = await _make_role(db)
        perm = await service.create_permission(db=db, name="x:read", resource="x", action="read", description=None)
        await service.assign_permission_to_role(db=db, role_id=role.id, permission_id=perm.id)

    async def test_missing_role_raises_not_found(self, db: AsyncSession) -> None:
        perm = await service.create_permission(db=db, name="y:read", resource="y", action="read", description=None)
        with pytest.raises(NotFoundError):
            await service.assign_permission_to_role(db=db, role_id=99999, permission_id=perm.id)

    async def test_missing_permission_raises_not_found(self, db: AsyncSession) -> None:
        role = await _make_role(db, "role_a")
        with pytest.raises(NotFoundError):
            await service.assign_permission_to_role(db=db, role_id=role.id, permission_id=99999)

    async def test_duplicate_raises_conflict(self, db: AsyncSession) -> None:
        role = await _make_role(db, "role_b")
        perm = await service.create_permission(db=db, name="z:read", resource="z", action="read", description=None)
        await service.assign_permission_to_role(db=db, role_id=role.id, permission_id=perm.id)
        with pytest.raises(ConflictError):
            await service.assign_permission_to_role(db=db, role_id=role.id, permission_id=perm.id)


# ── revoke_permission_from_role ────────────────────────────────────────────


class TestRevokePermissionFromRole:
    async def test_revokes_successfully(self, db: AsyncSession) -> None:
        role = await _make_role(db, "role_c")
        perm = await service.create_permission(db=db, name="c:read", resource="c", action="read", description=None)
        await service.assign_permission_to_role(db=db, role_id=role.id, permission_id=perm.id)
        await service.revoke_permission_from_role(db=db, role_id=role.id, permission_id=perm.id)

    async def test_not_assigned_raises_not_found(self, db: AsyncSession) -> None:
        role = await _make_role(db, "role_d")
        perm = await service.create_permission(db=db, name="d:write", resource="d", action="write", description=None)
        with pytest.raises(NotFoundError):
            await service.revoke_permission_from_role(db=db, role_id=role.id, permission_id=perm.id)


# ── get_user_roles ─────────────────────────────────────────────────────────


class TestGetUserRoles:
    async def test_returns_user_with_empty_roles(self, db: AsyncSession) -> None:
        user = await _make_user(db)
        result = await service.get_user_roles(db=db, user_id=user.id)
        assert result.id == user.id
        assert result.user_roles == []

    async def test_missing_user_raises_not_found(self, db: AsyncSession) -> None:
        with pytest.raises(NotFoundError):
            await service.get_user_roles(db=db, user_id=99999)


# ── assign_role_to_user ────────────────────────────────────────────────────


class TestAssignRoleToUser:
    async def test_assigns_successfully(self, db: AsyncSession) -> None:
        user = await _make_user(db, "assign@example.com")
        role = await _make_role(db, "assignable")
        await service.assign_role_to_user(db=db, user_id=user.id, role_id=role.id)

    async def test_missing_user_raises_not_found(self, db: AsyncSession) -> None:
        role = await _make_role(db, "orphan")
        with pytest.raises(NotFoundError):
            await service.assign_role_to_user(db=db, user_id=99999, role_id=role.id)

    async def test_missing_role_raises_not_found(self, db: AsyncSession) -> None:
        user = await _make_user(db, "norole@example.com")
        with pytest.raises(NotFoundError):
            await service.assign_role_to_user(db=db, user_id=user.id, role_id=99999)

    async def test_duplicate_raises_conflict(self, db: AsyncSession) -> None:
        user = await _make_user(db, "dup_role@example.com")
        role = await _make_role(db, "once_only")
        await service.assign_role_to_user(db=db, user_id=user.id, role_id=role.id)
        with pytest.raises(ConflictError):
            await service.assign_role_to_user(db=db, user_id=user.id, role_id=role.id)


# ── revoke_role_from_user ──────────────────────────────────────────────────


class TestRevokeRoleFromUser:
    async def test_revokes_successfully(self, db: AsyncSession) -> None:
        user = await _make_user(db, "revoke@example.com")
        role = await _make_role(db, "revokable")
        await service.assign_role_to_user(db=db, user_id=user.id, role_id=role.id)
        await service.revoke_role_from_user(db=db, user_id=user.id, role_id=role.id)

    async def test_not_assigned_raises_not_found(self, db: AsyncSession) -> None:
        user = await _make_user(db, "noassign@example.com")
        role = await _make_role(db, "ghost_role")
        with pytest.raises(NotFoundError):
            await service.revoke_role_from_user(db=db, user_id=user.id, role_id=role.id)
