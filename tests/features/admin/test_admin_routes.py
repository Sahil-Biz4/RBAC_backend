"""Integration tests for admin feature routes — roles, permissions, user assignments."""

import pytest
from fastapi import status
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth.jwt_handler import create_access_token
from app.models.permission import Permission
from app.models.role import Role
from app.models.user import User
from app.utils.constants import Permissions, RoleNames


# ── Helpers ────────────────────────────────────────────────────────────────

def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


async def _make_role(db: AsyncSession, name: str = "testrole") -> Role:
    from app.features.admin import repository as repo
    return await repo.create_role(db=db, name=name, description="test")


async def _make_permission(
    db: AsyncSession, name: str = "users:create", resource: str = "users", action: str = "create"
) -> Permission:
    from app.features.admin import repository as repo
    return await repo.create_permission(db=db, name=name, resource=resource, action=action, description=None)


# ── List Roles ─────────────────────────────────────────────────────────────

class TestListRoles:
    async def test_with_roles_read_permission_returns_200(
        self, client: AsyncClient, admin_full_token: str
    ):
        resp = await client.get("/api/v1/admin/roles", headers=_auth(admin_full_token))
        assert resp.status_code == status.HTTP_200_OK
        assert resp.json()["success"] is True
        assert "roles" in resp.json()

    async def test_without_permission_returns_403(
        self, client: AsyncClient, user_token: str
    ):
        resp = await client.get("/api/v1/admin/roles", headers=_auth(user_token))
        assert resp.status_code == status.HTTP_403_FORBIDDEN

    async def test_without_auth_returns_401(self, client: AsyncClient):
        resp = await client.get("/api/v1/admin/roles")
        assert resp.status_code == status.HTTP_401_UNAUTHORIZED


# ── Create Role ────────────────────────────────────────────────────────────

class TestCreateRole:
    async def test_create_role_returns_201(
        self, client: AsyncClient, admin_full_token: str
    ):
        resp = await client.post(
            "/api/v1/admin/roles",
            headers=_auth(admin_full_token),
            json={"name": "editor", "description": "Can edit content"},
        )
        assert resp.status_code == status.HTTP_201_CREATED
        data = resp.json()
        assert data["success"] is True
        assert data["role"]["name"] == "editor"

    async def test_duplicate_role_returns_409(
        self, client: AsyncClient, db: AsyncSession, admin_full_token: str
    ):
        await _make_role(db, "duplicaterole")
        resp = await client.post(
            "/api/v1/admin/roles",
            headers=_auth(admin_full_token),
            json={"name": "duplicaterole"},
        )
        assert resp.status_code == status.HTTP_409_CONFLICT

    async def test_without_roles_create_permission_returns_403(
        self, client: AsyncClient, user_token: str
    ):
        resp = await client.post(
            "/api/v1/admin/roles",
            headers=_auth(user_token),
            json={"name": "newrole"},
        )
        assert resp.status_code == status.HTTP_403_FORBIDDEN

    async def test_name_too_short_returns_422(
        self, client: AsyncClient, admin_full_token: str
    ):
        resp = await client.post(
            "/api/v1/admin/roles",
            headers=_auth(admin_full_token),
            json={"name": "x"},
        )
        assert resp.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


# ── Update Role ────────────────────────────────────────────────────────────

class TestUpdateRole:
    async def test_update_role_returns_200(
        self, client: AsyncClient, db: AsyncSession, admin_full_token: str
    ):
        role = await _make_role(db, "oldrole")
        resp = await client.put(
            f"/api/v1/admin/roles/{role.id}",
            headers=_auth(admin_full_token),
            json={"name": "oldrole", "description": "Updated desc"},
        )
        assert resp.status_code == status.HTTP_200_OK
        assert resp.json()["success"] is True

    async def test_update_nonexistent_role_returns_404(
        self, client: AsyncClient, admin_full_token: str
    ):
        resp = await client.put(
            "/api/v1/admin/roles/99999",
            headers=_auth(admin_full_token),
            json={"name": "ghost", "description": None},
        )
        assert resp.status_code == status.HTTP_404_NOT_FOUND

    async def test_rename_default_role_returns_400(
        self, client: AsyncClient, db: AsyncSession, admin_full_token: str, sample_user_role: Role
    ):
        """Renaming a default system role should be forbidden."""
        resp = await client.put(
            f"/api/v1/admin/roles/{sample_user_role.id}",
            headers=_auth(admin_full_token),
            json={"name": "renamed_user", "description": None},
        )
        assert resp.status_code == status.HTTP_400_BAD_REQUEST

    async def test_without_permission_returns_403(
        self, client: AsyncClient, db: AsyncSession, user_token: str
    ):
        role = await _make_role(db, "somerole")
        resp = await client.put(
            f"/api/v1/admin/roles/{role.id}",
            headers=_auth(user_token),
            json={"name": "somerole"},
        )
        assert resp.status_code == status.HTTP_403_FORBIDDEN


# ── Delete Role ────────────────────────────────────────────────────────────

class TestDeleteRole:
    async def test_delete_custom_role_returns_200(
        self, client: AsyncClient, db: AsyncSession, admin_full_token: str
    ):
        role = await _make_role(db, "customrole")
        resp = await client.delete(
            f"/api/v1/admin/roles/{role.id}",
            headers=_auth(admin_full_token),
        )
        assert resp.status_code == status.HTTP_200_OK
        assert resp.json()["success"] is True

    async def test_delete_nonexistent_role_returns_404(
        self, client: AsyncClient, admin_full_token: str
    ):
        resp = await client.delete(
            "/api/v1/admin/roles/99999",
            headers=_auth(admin_full_token),
        )
        assert resp.status_code == status.HTTP_404_NOT_FOUND

    async def test_delete_default_role_returns_400(
        self, client: AsyncClient, sample_user_role: Role, admin_full_token: str
    ):
        """Default system roles must be protected from deletion."""
        resp = await client.delete(
            f"/api/v1/admin/roles/{sample_user_role.id}",
            headers=_auth(admin_full_token),
        )
        assert resp.status_code == status.HTTP_400_BAD_REQUEST

    async def test_without_permission_returns_403(
        self, client: AsyncClient, db: AsyncSession, user_token: str
    ):
        role = await _make_role(db, "toberemovedXX")
        resp = await client.delete(
            f"/api/v1/admin/roles/{role.id}",
            headers=_auth(user_token),
        )
        assert resp.status_code == status.HTTP_403_FORBIDDEN


# ── List Permissions ───────────────────────────────────────────────────────

class TestListPermissions:
    async def test_with_permission_returns_200(
        self, client: AsyncClient, admin_full_token: str
    ):
        resp = await client.get("/api/v1/admin/permissions", headers=_auth(admin_full_token))
        assert resp.status_code == status.HTTP_200_OK
        assert "permissions" in resp.json()

    async def test_without_auth_returns_401(self, client: AsyncClient):
        resp = await client.get("/api/v1/admin/permissions")
        assert resp.status_code == status.HTTP_401_UNAUTHORIZED


# ── Create Permission ──────────────────────────────────────────────────────

class TestCreatePermission:
    async def test_create_valid_permission_returns_201(
        self, client: AsyncClient, admin_full_token: str
    ):
        resp = await client.post(
            "/api/v1/admin/permissions",
            headers=_auth(admin_full_token),
            json={"name": "users:create", "resource": "users", "action": "create"},
        )
        assert resp.status_code == status.HTTP_201_CREATED
        data = resp.json()
        assert data["permission"]["name"] == "users:create"

    async def test_duplicate_permission_returns_409(
        self, client: AsyncClient, db: AsyncSession, admin_full_token: str
    ):
        await _make_permission(db, "roles:read", "roles", "read")
        resp = await client.post(
            "/api/v1/admin/permissions",
            headers=_auth(admin_full_token),
            json={"name": "roles:read", "resource": "roles", "action": "read"},
        )
        assert resp.status_code == status.HTTP_409_CONFLICT

    async def test_disallowed_resource_returns_422(
        self, client: AsyncClient, admin_full_token: str
    ):
        resp = await client.post(
            "/api/v1/admin/permissions",
            headers=_auth(admin_full_token),
            json={"name": "payments:read", "resource": "payments", "action": "read"},
        )
        assert resp.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    async def test_disallowed_action_returns_422(
        self, client: AsyncClient, admin_full_token: str
    ):
        resp = await client.post(
            "/api/v1/admin/permissions",
            headers=_auth(admin_full_token),
            json={"name": "users:export", "resource": "users", "action": "export"},
        )
        assert resp.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    async def test_name_resource_mismatch_returns_422(
        self, client: AsyncClient, admin_full_token: str
    ):
        """name field resource part must match the resource field."""
        resp = await client.post(
            "/api/v1/admin/permissions",
            headers=_auth(admin_full_token),
            json={"name": "roles:read", "resource": "users", "action": "read"},
        )
        assert resp.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    async def test_without_permission_returns_403(
        self, client: AsyncClient, user_token: str
    ):
        resp = await client.post(
            "/api/v1/admin/permissions",
            headers=_auth(user_token),
            json={"name": "users:create", "resource": "users", "action": "create"},
        )
        assert resp.status_code == status.HTTP_403_FORBIDDEN


# ── Delete Permission ──────────────────────────────────────────────────────

class TestDeletePermission:
    async def test_delete_permission_returns_200(
        self, client: AsyncClient, db: AsyncSession, admin_full_token: str
    ):
        perm = await _make_permission(db, "profile:delete", "profile", "delete")
        resp = await client.delete(
            f"/api/v1/admin/permissions/{perm.id}",
            headers=_auth(admin_full_token),
        )
        assert resp.status_code == status.HTTP_200_OK
        assert resp.json()["success"] is True

    async def test_delete_nonexistent_permission_returns_404(
        self, client: AsyncClient, admin_full_token: str
    ):
        resp = await client.delete(
            "/api/v1/admin/permissions/99999",
            headers=_auth(admin_full_token),
        )
        assert resp.status_code == status.HTTP_404_NOT_FOUND

    async def test_without_permission_returns_403(
        self, client: AsyncClient, db: AsyncSession, user_token: str
    ):
        perm = await _make_permission(db, "users:update", "users", "update")
        resp = await client.delete(
            f"/api/v1/admin/permissions/{perm.id}",
            headers=_auth(user_token),
        )
        assert resp.status_code == status.HTTP_403_FORBIDDEN


# ── Assign Permission to Role ──────────────────────────────────────────────

class TestAssignPermissionToRole:
    async def test_assign_permission_returns_200(
        self, client: AsyncClient, db: AsyncSession, admin_full_token: str
    ):
        role = await _make_role(db, "roleA")
        perm = await _make_permission(db, "profile:read", "profile", "read")
        resp = await client.post(
            f"/api/v1/admin/roles/{role.id}/permissions",
            headers=_auth(admin_full_token),
            json={"permission_id": perm.id},
        )
        assert resp.status_code == status.HTTP_200_OK
        assert resp.json()["success"] is True

    async def test_assign_already_assigned_returns_409(
        self, client: AsyncClient, db: AsyncSession, admin_full_token: str
    ):
        from tests.conftest import _assign_permission
        role = await _make_role(db, "roleB")
        perm = await _make_permission(db, "profile:update", "profile", "update")
        await _assign_permission(db, role.id, perm.id)
        resp = await client.post(
            f"/api/v1/admin/roles/{role.id}/permissions",
            headers=_auth(admin_full_token),
            json={"permission_id": perm.id},
        )
        assert resp.status_code == status.HTTP_409_CONFLICT

    async def test_role_not_found_returns_404(
        self, client: AsyncClient, db: AsyncSession, admin_full_token: str
    ):
        perm = await _make_permission(db, "roles:delete", "roles", "delete")
        resp = await client.post(
            "/api/v1/admin/roles/99999/permissions",
            headers=_auth(admin_full_token),
            json={"permission_id": perm.id},
        )
        assert resp.status_code == status.HTTP_404_NOT_FOUND

    async def test_permission_not_found_returns_404(
        self, client: AsyncClient, db: AsyncSession, admin_full_token: str
    ):
        role = await _make_role(db, "roleC")
        resp = await client.post(
            f"/api/v1/admin/roles/{role.id}/permissions",
            headers=_auth(admin_full_token),
            json={"permission_id": 99999},
        )
        assert resp.status_code == status.HTTP_404_NOT_FOUND

    async def test_without_permission_returns_403(
        self, client: AsyncClient, db: AsyncSession, user_token: str
    ):
        role = await _make_role(db, "roleD")
        perm = await _make_permission(db, "profile:create", "profile", "create")
        resp = await client.post(
            f"/api/v1/admin/roles/{role.id}/permissions",
            headers=_auth(user_token),
            json={"permission_id": perm.id},
        )
        assert resp.status_code == status.HTTP_403_FORBIDDEN


# ── Revoke Permission from Role ────────────────────────────────────────────

class TestRevokePermissionFromRole:
    async def test_revoke_permission_returns_200(
        self, client: AsyncClient, db: AsyncSession, admin_full_token: str
    ):
        from tests.conftest import _assign_permission
        role = await _make_role(db, "roleE")
        perm = await _make_permission(db, "profile:create", "profile", "create")
        await _assign_permission(db, role.id, perm.id)
        resp = await client.delete(
            f"/api/v1/admin/roles/{role.id}/permissions/{perm.id}",
            headers=_auth(admin_full_token),
        )
        assert resp.status_code == status.HTTP_200_OK
        assert resp.json()["success"] is True

    async def test_revoke_unassigned_permission_returns_404(
        self, client: AsyncClient, db: AsyncSession, admin_full_token: str
    ):
        role = await _make_role(db, "roleF")
        perm = await _make_permission(db, "profile:update", "profile", "update")
        resp = await client.delete(
            f"/api/v1/admin/roles/{role.id}/permissions/{perm.id}",
            headers=_auth(admin_full_token),
        )
        assert resp.status_code == status.HTTP_404_NOT_FOUND

    async def test_without_permission_returns_403(
        self, client: AsyncClient, db: AsyncSession, user_token: str
    ):
        role = await _make_role(db, "roleG")
        resp = await client.delete(
            f"/api/v1/admin/roles/{role.id}/permissions/1",
            headers=_auth(user_token),
        )
        assert resp.status_code == status.HTTP_403_FORBIDDEN


# ── Get User Roles ─────────────────────────────────────────────────────────

class TestGetUserRoles:
    async def test_get_user_roles_returns_200(
        self, client: AsyncClient, sample_user: User, admin_full_token: str
    ):
        resp = await client.get(
            f"/api/v1/admin/users/{sample_user.id}/roles",
            headers=_auth(admin_full_token),
        )
        assert resp.status_code == status.HTTP_200_OK
        data = resp.json()
        assert "roles" in data
        assert any(r["name"] == RoleNames.USER for r in data["roles"])

    async def test_nonexistent_user_returns_404(
        self, client: AsyncClient, admin_full_token: str
    ):
        resp = await client.get(
            "/api/v1/admin/users/99999/roles",
            headers=_auth(admin_full_token),
        )
        assert resp.status_code == status.HTTP_404_NOT_FOUND

    async def test_without_permission_returns_403(
        self, client: AsyncClient, sample_user: User, user_token: str
    ):
        resp = await client.get(
            f"/api/v1/admin/users/{sample_user.id}/roles",
            headers=_auth(user_token),
        )
        assert resp.status_code == status.HTTP_403_FORBIDDEN


# ── Assign Role to User ────────────────────────────────────────────────────

class TestAssignRoleToUser:
    async def test_assign_role_returns_200(
        self, client: AsyncClient, db: AsyncSession, sample_user: User, admin_full_token: str
    ):
        new_role = await _make_role(db, "newroleXY")
        resp = await client.post(
            f"/api/v1/admin/users/{sample_user.id}/roles",
            headers=_auth(admin_full_token),
            json={"role_id": new_role.id},
        )
        assert resp.status_code == status.HTTP_200_OK
        assert resp.json()["success"] is True

    async def test_assign_already_assigned_role_returns_409(
        self, client: AsyncClient, sample_user: User, sample_user_role: Role, admin_full_token: str
    ):
        """sample_user already has the user role — re-assigning must return 409."""
        resp = await client.post(
            f"/api/v1/admin/users/{sample_user.id}/roles",
            headers=_auth(admin_full_token),
            json={"role_id": sample_user_role.id},
        )
        assert resp.status_code == status.HTTP_409_CONFLICT

    async def test_user_not_found_returns_404(
        self, client: AsyncClient, db: AsyncSession, admin_full_token: str
    ):
        new_role = await _make_role(db, "roleXYZ")
        resp = await client.post(
            "/api/v1/admin/users/99999/roles",
            headers=_auth(admin_full_token),
            json={"role_id": new_role.id},
        )
        assert resp.status_code == status.HTTP_404_NOT_FOUND

    async def test_role_not_found_returns_404(
        self, client: AsyncClient, sample_user: User, admin_full_token: str
    ):
        resp = await client.post(
            f"/api/v1/admin/users/{sample_user.id}/roles",
            headers=_auth(admin_full_token),
            json={"role_id": 99999},
        )
        assert resp.status_code == status.HTTP_404_NOT_FOUND

    async def test_without_permission_returns_403(
        self, client: AsyncClient, db: AsyncSession, sample_user: User, user_token: str
    ):
        new_role = await _make_role(db, "roleABC")
        resp = await client.post(
            f"/api/v1/admin/users/{sample_user.id}/roles",
            headers=_auth(user_token),
            json={"role_id": new_role.id},
        )
        assert resp.status_code == status.HTTP_403_FORBIDDEN


# ── Revoke Role from User ──────────────────────────────────────────────────

class TestRevokeRoleFromUser:
    async def test_revoke_role_returns_200(
        self, client: AsyncClient, sample_user: User, sample_user_role: Role, admin_full_token: str
    ):
        resp = await client.delete(
            f"/api/v1/admin/users/{sample_user.id}/roles/{sample_user_role.id}",
            headers=_auth(admin_full_token),
        )
        assert resp.status_code == status.HTTP_200_OK
        assert resp.json()["success"] is True

    async def test_revoke_unassigned_role_returns_404(
        self, client: AsyncClient, db: AsyncSession, sample_user: User, admin_full_token: str
    ):
        unassigned_role = await _make_role(db, "notassigned")
        resp = await client.delete(
            f"/api/v1/admin/users/{sample_user.id}/roles/{unassigned_role.id}",
            headers=_auth(admin_full_token),
        )
        assert resp.status_code == status.HTTP_404_NOT_FOUND

    async def test_without_permission_returns_403(
        self, client: AsyncClient, sample_user: User, sample_user_role: Role, user_token: str
    ):
        resp = await client.delete(
            f"/api/v1/admin/users/{sample_user.id}/roles/{sample_user_role.id}",
            headers=_auth(user_token),
        )
        assert resp.status_code == status.HTTP_403_FORBIDDEN
