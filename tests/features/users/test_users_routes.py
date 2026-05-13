"""Integration tests for users feature routes."""

from fastapi import status
from httpx import AsyncClient

from app.models.user import User
from app.utils.constants import RoleNames


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


# ── GET /me ────────────────────────────────────────────────────────────────


class TestGetMe:
    async def test_returns_current_user_profile(self, client: AsyncClient, sample_user: User, user_token: str):
        resp = await client.get("/api/v1/users/me", headers=_auth(user_token))
        assert resp.status_code == status.HTTP_200_OK
        data = resp.json()
        assert data["success"] is True
        assert data["user"]["email"] == sample_user.email
        assert data["user"]["name"] == sample_user.name

    async def test_response_includes_roles(self, client: AsyncClient, sample_user: User, user_token: str):
        resp = await client.get("/api/v1/users/me", headers=_auth(user_token))
        assert resp.status_code == status.HTTP_200_OK
        roles = resp.json()["user"]["roles"]
        assert any(r["name"] == RoleNames.USER for r in roles)

    async def test_without_auth_returns_401(self, client: AsyncClient):
        resp = await client.get("/api/v1/users/me")
        assert resp.status_code == status.HTTP_401_UNAUTHORIZED

    async def test_invalid_token_returns_401(self, client: AsyncClient):
        resp = await client.get("/api/v1/users/me", headers={"Authorization": "Bearer garbage"})
        assert resp.status_code == status.HTTP_401_UNAUTHORIZED


# ── PUT /me ────────────────────────────────────────────────────────────────


class TestUpdateMe:
    async def test_update_name_returns_200(self, client: AsyncClient, sample_user: User, user_token: str):
        resp = await client.put(
            "/api/v1/users/me",
            headers=_auth(user_token),
            json={"name": "Updated Name"},
        )
        assert resp.status_code == status.HTTP_200_OK
        assert resp.json()["user"]["name"] == "Updated Name"

    async def test_name_too_short_returns_422(self, client: AsyncClient, sample_user: User, user_token: str):
        resp = await client.put(
            "/api/v1/users/me",
            headers=_auth(user_token),
            json={"name": "X"},
        )
        assert resp.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    async def test_null_name_is_no_op_and_returns_200(self, client: AsyncClient, sample_user: User, user_token: str):
        """Omitting name should succeed without changing anything."""
        resp = await client.put(
            "/api/v1/users/me",
            headers=_auth(user_token),
            json={"name": None},
        )
        assert resp.status_code == status.HTTP_200_OK

    async def test_without_auth_returns_401(self, client: AsyncClient):
        resp = await client.put("/api/v1/users/me", json={"name": "Hacker"})
        assert resp.status_code == status.HTTP_401_UNAUTHORIZED


# ── GET /users (list) ──────────────────────────────────────────────────────


class TestListUsers:
    async def test_admin_with_users_read_returns_paginated_list(
        self, client: AsyncClient, sample_user: User, admin_token: str
    ):
        resp = await client.get("/api/v1/users", headers=_auth(admin_token))
        assert resp.status_code == status.HTTP_200_OK
        data = resp.json()
        assert "users" in data
        assert "total" in data
        assert data["total"] >= 1

    async def test_regular_user_without_permission_returns_403(self, client: AsyncClient, user_token: str):
        resp = await client.get("/api/v1/users", headers=_auth(user_token))
        assert resp.status_code == status.HTTP_403_FORBIDDEN

    async def test_without_auth_returns_401(self, client: AsyncClient):
        resp = await client.get("/api/v1/users")
        assert resp.status_code == status.HTTP_401_UNAUTHORIZED

    async def test_pagination_params_are_respected(self, client: AsyncClient, admin_token: str):
        resp = await client.get("/api/v1/users", headers=_auth(admin_token), params={"skip": 0, "limit": 1})
        assert resp.status_code == status.HTTP_200_OK
        assert len(resp.json()["users"]) <= 1

    async def test_search_by_name_returns_matching_users(
        self, client: AsyncClient, sample_user: User, admin_token: str
    ):
        resp = await client.get("/api/v1/users", headers=_auth(admin_token), params={"search": sample_user.name})
        assert resp.status_code == status.HTTP_200_OK
        data = resp.json()
        assert data["total"] >= 1
        assert any(u["name"] == sample_user.name for u in data["users"])

    async def test_search_by_email_returns_matching_users(
        self, client: AsyncClient, sample_user: User, admin_token: str
    ):
        resp = await client.get("/api/v1/users", headers=_auth(admin_token), params={"search": sample_user.email})
        assert resp.status_code == status.HTTP_200_OK
        data = resp.json()
        assert data["total"] >= 1
        assert any(u["email"] == sample_user.email for u in data["users"])

    async def test_search_partial_match_returns_results(self, client: AsyncClient, sample_user: User, admin_token: str):
        partial = sample_user.name[:4]
        resp = await client.get("/api/v1/users", headers=_auth(admin_token), params={"search": partial})
        assert resp.status_code == status.HTTP_200_OK
        assert resp.json()["total"] >= 1

    async def test_search_no_match_returns_empty(self, client: AsyncClient, admin_token: str):
        resp = await client.get(
            "/api/v1/users",
            headers=_auth(admin_token),
            params={"search": "zzznomatchzzz"},
        )
        assert resp.status_code == status.HTTP_200_OK
        data = resp.json()
        assert data["total"] == 0
        assert data["users"] == []

    async def test_search_echoed_in_response(self, client: AsyncClient, admin_token: str):
        resp = await client.get("/api/v1/users", headers=_auth(admin_token), params={"search": "test"})
        assert resp.status_code == status.HTTP_200_OK
        assert resp.json()["search"] == "test"

    async def test_search_none_when_omitted(self, client: AsyncClient, admin_token: str):
        resp = await client.get("/api/v1/users", headers=_auth(admin_token))
        assert resp.status_code == status.HTTP_200_OK
        assert resp.json()["search"] is None

    async def test_search_exceeds_max_length_returns_422(self, client: AsyncClient, admin_token: str):
        resp = await client.get(
            "/api/v1/users",
            headers=_auth(admin_token),
            params={"search": "x" * 101},
        )
        assert resp.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


# ── GET /users/{id} ────────────────────────────────────────────────────────


class TestGetUser:
    async def test_get_existing_user_returns_200(self, client: AsyncClient, sample_user: User, admin_token: str):
        resp = await client.get(f"/api/v1/users/{sample_user.id}", headers=_auth(admin_token))
        assert resp.status_code == status.HTTP_200_OK
        assert resp.json()["user"]["email"] == sample_user.email

    async def test_get_nonexistent_user_returns_404(self, client: AsyncClient, admin_token: str):
        resp = await client.get("/api/v1/users/99999", headers=_auth(admin_token))
        assert resp.status_code == status.HTTP_404_NOT_FOUND

    async def test_without_permission_returns_403(self, client: AsyncClient, sample_user: User, user_token: str):
        resp = await client.get(f"/api/v1/users/{sample_user.id}", headers=_auth(user_token))
        assert resp.status_code == status.HTTP_403_FORBIDDEN

    async def test_without_auth_returns_401(self, client: AsyncClient):
        resp = await client.get("/api/v1/users/1")
        assert resp.status_code == status.HTTP_401_UNAUTHORIZED


# ── DELETE /users/{id} ─────────────────────────────────────────────────────


class TestDeleteUser:
    async def test_admin_can_delete_other_user(self, client: AsyncClient, sample_user: User, admin_token: str):
        resp = await client.delete(f"/api/v1/users/{sample_user.id}", headers=_auth(admin_token))
        assert resp.status_code == status.HTTP_200_OK
        assert resp.json()["success"] is True

    async def test_cannot_delete_self_returns_403(self, client: AsyncClient, sample_admin_user: User, admin_token: str):
        """Admin trying to delete their own account must be rejected."""
        resp = await client.delete(f"/api/v1/users/{sample_admin_user.id}", headers=_auth(admin_token))
        assert resp.status_code == status.HTTP_403_FORBIDDEN

    async def test_delete_nonexistent_user_returns_404(self, client: AsyncClient, admin_token: str):
        resp = await client.delete("/api/v1/users/99999", headers=_auth(admin_token))
        assert resp.status_code == status.HTTP_404_NOT_FOUND

    async def test_without_permission_returns_403(self, client: AsyncClient, sample_user: User, user_token: str):
        resp = await client.delete(f"/api/v1/users/{sample_user.id}", headers=_auth(user_token))
        assert resp.status_code == status.HTTP_403_FORBIDDEN

    async def test_without_auth_returns_401(self, client: AsyncClient):
        resp = await client.delete("/api/v1/users/1")
        assert resp.status_code == status.HTTP_401_UNAUTHORIZED


# ── POST /me/change-password ───────────────────────────────────────────────


class TestChangeMyPassword:
    async def test_correct_password_returns_200(self, client: AsyncClient, sample_user: User, user_token: str):
        resp = await client.post(
            "/api/v1/users/me/change-password",
            headers=_auth(user_token),
            json={
                "current_password": "Password1!",
                "new_password": "NewPassword2@",
                "confirm_password": "NewPassword2@",
            },
        )
        assert resp.status_code == status.HTTP_200_OK
        assert resp.json()["success"] is True

    async def test_wrong_current_password_returns_401(self, client: AsyncClient, sample_user: User, user_token: str):
        resp = await client.post(
            "/api/v1/users/me/change-password",
            headers=_auth(user_token),
            json={
                "current_password": "WrongPass1!",
                "new_password": "NewPassword2@",
                "confirm_password": "NewPassword2@",
            },
        )
        assert resp.status_code == status.HTTP_401_UNAUTHORIZED

    async def test_passwords_mismatch_returns_422(self, client: AsyncClient, sample_user: User, user_token: str):
        resp = await client.post(
            "/api/v1/users/me/change-password",
            headers=_auth(user_token),
            json={
                "current_password": "Password1!",
                "new_password": "NewPassword2@",
                "confirm_password": "Different1!",
            },
        )
        assert resp.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    async def test_same_password_returns_422(self, client: AsyncClient, sample_user: User, user_token: str):
        resp = await client.post(
            "/api/v1/users/me/change-password",
            headers=_auth(user_token),
            json={
                "current_password": "Password1!",
                "new_password": "Password1!",
                "confirm_password": "Password1!",
            },
        )
        assert resp.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    async def test_without_auth_returns_401(self, client: AsyncClient):
        resp = await client.post(
            "/api/v1/users/me/change-password",
            json={
                "current_password": "Password1!",
                "new_password": "NewPassword2@",
                "confirm_password": "NewPassword2@",
            },
        )
        assert resp.status_code == status.HTTP_401_UNAUTHORIZED


# ── POST /users (admin create) ─────────────────────────────────────────────


class TestCreateUser:
    async def test_admin_can_create_user(self, client: AsyncClient, admin_full_token: str):
        resp = await client.post(
            "/api/v1/users",
            headers=_auth(admin_full_token),
            json={"name": "Created User", "email": "created_route@example.com", "password": "Password1!"},
        )
        assert resp.status_code == status.HTTP_201_CREATED
        assert resp.json()["success"] is True
        assert resp.json()["user"]["email"] == "created_route@example.com"

    async def test_duplicate_email_returns_409(self, client: AsyncClient, sample_user: User, admin_full_token: str):
        resp = await client.post(
            "/api/v1/users",
            headers=_auth(admin_full_token),
            json={"name": "Dup", "email": sample_user.email, "password": "Password1!"},
        )
        assert resp.status_code == status.HTTP_409_CONFLICT

    async def test_without_permission_returns_403(self, client: AsyncClient, user_token: str):
        resp = await client.post(
            "/api/v1/users",
            headers=_auth(user_token),
            json={"name": "User", "email": "unauth@example.com", "password": "Password1!"},
        )
        assert resp.status_code == status.HTTP_403_FORBIDDEN

    async def test_missing_email_returns_422(self, client: AsyncClient, admin_full_token: str):
        resp = await client.post(
            "/api/v1/users",
            headers=_auth(admin_full_token),
            json={"name": "No Email", "password": "Password1!"},
        )
        assert resp.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    async def test_without_auth_returns_401(self, client: AsyncClient):
        resp = await client.post(
            "/api/v1/users",
            json={"name": "NoAuth", "email": "noauth@example.com", "password": "Password1!"},
        )
        assert resp.status_code == status.HTTP_401_UNAUTHORIZED


# ── PUT /users/{id} (admin update) ────────────────────────────────────────


class TestUpdateUser:
    async def test_admin_can_update_name(self, client: AsyncClient, sample_user: User, admin_token: str):
        resp = await client.put(
            f"/api/v1/users/{sample_user.id}",
            headers=_auth(admin_token),
            json={"name": "Admin Updated"},
        )
        assert resp.status_code == status.HTTP_200_OK
        assert resp.json()["user"]["name"] == "Admin Updated"

    async def test_admin_can_deactivate_user(self, client: AsyncClient, sample_user: User, admin_token: str):
        resp = await client.put(
            f"/api/v1/users/{sample_user.id}",
            headers=_auth(admin_token),
            json={"is_active": False},
        )
        assert resp.status_code == status.HTTP_200_OK
        assert resp.json()["user"]["is_active"] is False

    async def test_duplicate_email_returns_409(
        self, client: AsyncClient, sample_user: User, sample_admin_user: User, admin_token: str
    ):
        resp = await client.put(
            f"/api/v1/users/{sample_user.id}",
            headers=_auth(admin_token),
            json={"email": sample_admin_user.email},
        )
        assert resp.status_code == status.HTTP_409_CONFLICT

    async def test_nonexistent_user_returns_404(self, client: AsyncClient, admin_token: str):
        resp = await client.put(
            "/api/v1/users/99999",
            headers=_auth(admin_token),
            json={"name": "Ghost"},
        )
        assert resp.status_code == status.HTTP_404_NOT_FOUND

    async def test_without_permission_returns_403(self, client: AsyncClient, sample_user: User, user_token: str):
        resp = await client.put(
            f"/api/v1/users/{sample_user.id}",
            headers=_auth(user_token),
            json={"name": "Hacker"},
        )
        assert resp.status_code == status.HTTP_403_FORBIDDEN

    async def test_without_auth_returns_401(self, client: AsyncClient, sample_user: User):
        resp = await client.put(
            f"/api/v1/users/{sample_user.id}",
            json={"name": "Anon"},
        )
        assert resp.status_code == status.HTTP_401_UNAUTHORIZED


# ── GET /users/perms-version ───────────────────────────────────────────────


class TestPermsVersion:
    async def test_returns_current_perms_version(self, client: AsyncClient, sample_user: User, user_token: str):
        resp = await client.get("/api/v1/users/perms-version", headers=_auth(user_token))
        assert resp.status_code == status.HTTP_200_OK
        data = resp.json()
        assert data["success"] is True
        assert "perms_version" in data
        assert data["perms_version"] == sample_user.perms_version

    async def test_without_auth_returns_401(self, client: AsyncClient):
        resp = await client.get("/api/v1/users/perms-version")
        assert resp.status_code == status.HTTP_401_UNAUTHORIZED
