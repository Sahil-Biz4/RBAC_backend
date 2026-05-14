"""Integration tests for AuthMiddleware — JWT validation, JTI checks, and excluded paths."""

from unittest.mock import patch

from fastapi import status
from httpx import AsyncClient

from app.core.auth.jwt_handler import create_access_token
from app.models.user import User
from app.utils.constants import Permissions, RoleNames


# ── No Authorization header ────────────────────────────────────────────────


class TestNoAuthHeader:
    async def test_protected_route_without_token_returns_401(self, client: AsyncClient):
        resp = await client.get("/api/v1/users/me")
        assert resp.status_code == status.HTTP_401_UNAUTHORIZED

    async def test_excluded_health_path_without_token_returns_200(self, client: AsyncClient):
        resp = await client.get("/health")
        assert resp.status_code == status.HTTP_200_OK

    async def test_excluded_auth_register_without_token_returns_422_not_401(self, client: AsyncClient):
        resp = await client.post("/api/v1/auth/register", json={})
        assert resp.status_code != status.HTTP_401_UNAUTHORIZED


# ── Malformed / invalid tokens ─────────────────────────────────────────────


class TestInvalidToken:
    async def test_garbage_token_returns_401(self, client: AsyncClient):
        resp = await client.get("/api/v1/users/me", headers={"Authorization": "Bearer not.a.jwt"})
        assert resp.status_code == status.HTTP_401_UNAUTHORIZED

    async def test_missing_bearer_prefix_returns_401(self, client: AsyncClient):
        resp = await client.get("/api/v1/users/me", headers={"Authorization": "Token some-token"})
        assert resp.status_code == status.HTTP_401_UNAUTHORIZED

    async def test_empty_bearer_returns_401(self, client: AsyncClient):
        resp = await client.get("/api/v1/users/me", headers={"Authorization": "Bearer "})
        assert resp.status_code == status.HTTP_401_UNAUTHORIZED


# ── Wrong scope ────────────────────────────────────────────────────────────


class TestWrongScope:
    async def test_refresh_token_used_as_access_token_returns_401(
        self, client: AsyncClient, sample_user: User, mock_redis
    ):
        from app.core.auth.jwt_handler import create_refresh_token

        refresh_token, _ = create_refresh_token(subject=sample_user.id, email=sample_user.email)
        resp = await client.get("/api/v1/users/me", headers={"Authorization": f"Bearer {refresh_token}"})
        assert resp.status_code == status.HTTP_401_UNAUTHORIZED

    async def test_password_reset_token_used_as_access_token_returns_401(self, client: AsyncClient, sample_user: User):
        from app.core.auth.jwt_handler import create_password_reset_token

        reset_token = create_password_reset_token(subject=sample_user.id, email=sample_user.email)
        resp = await client.get("/api/v1/users/me", headers={"Authorization": f"Bearer {reset_token}"})
        assert resp.status_code == status.HTTP_401_UNAUTHORIZED


# ── Revoked JTI ────────────────────────────────────────────────────────────


class TestRevokedJti:
    async def test_token_with_unknown_jti_returns_401(self, client: AsyncClient, sample_user: User, mock_redis):
        token, _ = create_access_token(
            subject=sample_user.id,
            email=sample_user.email,
            roles=[RoleNames.USER],
            permissions=[Permissions.PROFILE_READ],
            perms_version=sample_user.perms_version,
        )
        resp = await client.get("/api/v1/users/me", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == status.HTTP_401_UNAUTHORIZED


# ── Redis unavailable ──────────────────────────────────────────────────────


class TestRedisUnavailable:
    async def test_redis_down_returns_503(self, client: AsyncClient, sample_user: User):
        token, _ = create_access_token(
            subject=sample_user.id,
            email=sample_user.email,
            roles=[RoleNames.USER],
            permissions=[Permissions.PROFILE_READ],
            perms_version=sample_user.perms_version,
        )
        with patch(
            "app.core.services.redis_service.redis_service.verify_access_jti",
            side_effect=RuntimeError("Redis not connected"),
        ):
            resp = await client.get("/api/v1/users/me", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == status.HTTP_503_SERVICE_UNAVAILABLE


# ── Valid token passes through ─────────────────────────────────────────────


class TestValidToken:
    async def test_valid_token_with_jti_in_redis_passes(self, client: AsyncClient, user_token: str, sample_user: User):
        resp = await client.get("/api/v1/users/me", headers={"Authorization": f"Bearer {user_token}"})
        assert resp.status_code == status.HTTP_200_OK

    async def test_payload_contains_correct_user(self, client: AsyncClient, user_token: str, sample_user: User):
        resp = await client.get("/api/v1/users/me", headers={"Authorization": f"Bearer {user_token}"})
        assert resp.status_code == status.HTTP_200_OK
        data = resp.json()
        assert data["user"]["email"] == sample_user.email
