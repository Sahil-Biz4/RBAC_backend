"""Unit tests for RBAC dependency factories."""

import pytest
from fastapi import Depends, FastAPI, status
from httpx import ASGITransport, AsyncClient

from app.core.auth.jwt_handler import create_access_token
from app.core.auth.rbac import require_all_permissions, require_any_permission, require_any_role, require_permission, require_role
from app.core.config.settings import settings
from app.core.middleware.auth import AuthMiddleware


def _make_app(dependency) -> FastAPI:
    """Helper — build a minimal FastAPI app with a single protected route."""
    _app = FastAPI()
    _app.add_middleware(AuthMiddleware, excluded_prefixes=[])

    @_app.get("/protected", dependencies=[dependency])
    async def _protected():
        return {"ok": True}

    return _app


def _token(roles: list[str], permissions: list[str]) -> str:
    token, _ = create_access_token(subject=1, email="t@t.com", roles=roles, permissions=permissions, perms_version=1)
    return token


class TestRequireRole:
    async def test_passes_with_correct_role(self):
        _app = _make_app(Depends(require_role("admin")))
        async with AsyncClient(transport=ASGITransport(_app), base_url="http://test") as ac:
            resp = await ac.get("/protected", headers={"Authorization": f"Bearer {_token(['admin'], [])}"})
        assert resp.status_code == status.HTTP_200_OK

    async def test_forbidden_with_wrong_role(self):
        _app = _make_app(Depends(require_role("admin")))
        async with AsyncClient(transport=ASGITransport(_app), base_url="http://test") as ac:
            resp = await ac.get("/protected", headers={"Authorization": f"Bearer {_token(['user'], [])}"})
        assert resp.status_code == status.HTTP_403_FORBIDDEN

    async def test_unauthorized_without_token(self):
        _app = _make_app(Depends(require_role("admin")))
        async with AsyncClient(transport=ASGITransport(_app), base_url="http://test") as ac:
            resp = await ac.get("/protected")
        assert resp.status_code == status.HTTP_401_UNAUTHORIZED


class TestRequireAnyRole:
    async def test_passes_with_one_of_the_roles(self):
        _app = _make_app(Depends(require_any_role(["admin", "manager"])))
        async with AsyncClient(transport=ASGITransport(_app), base_url="http://test") as ac:
            resp = await ac.get("/protected", headers={"Authorization": f"Bearer {_token(['manager'], [])}"})
        assert resp.status_code == status.HTTP_200_OK

    async def test_forbidden_with_none_of_the_roles(self):
        _app = _make_app(Depends(require_any_role(["admin", "manager"])))
        async with AsyncClient(transport=ASGITransport(_app), base_url="http://test") as ac:
            resp = await ac.get("/protected", headers={"Authorization": f"Bearer {_token(['user'], [])}"})
        assert resp.status_code == status.HTTP_403_FORBIDDEN


class TestRequirePermission:
    async def test_passes_with_correct_permission(self):
        _app = _make_app(Depends(require_permission("users:read")))
        async with AsyncClient(transport=ASGITransport(_app), base_url="http://test") as ac:
            resp = await ac.get("/protected", headers={"Authorization": f"Bearer {_token([], ['users:read'])}"})
        assert resp.status_code == status.HTTP_200_OK

    async def test_forbidden_without_permission(self):
        _app = _make_app(Depends(require_permission("users:read")))
        async with AsyncClient(transport=ASGITransport(_app), base_url="http://test") as ac:
            resp = await ac.get("/protected", headers={"Authorization": f"Bearer {_token([], ['profile:read'])}"})
        assert resp.status_code == status.HTTP_403_FORBIDDEN


class TestRequireAnyPermission:
    async def test_passes_with_one_matching(self):
        _app = _make_app(Depends(require_any_permission(["users:read", "reports:read"])))
        async with AsyncClient(transport=ASGITransport(_app), base_url="http://test") as ac:
            resp = await ac.get("/protected", headers={"Authorization": f"Bearer {_token([], ['users:read'])}"})
        assert resp.status_code == status.HTTP_200_OK


class TestRequireAllPermissions:
    async def test_passes_when_all_present(self):
        _app = _make_app(Depends(require_all_permissions(["users:read", "users:write"])))
        async with AsyncClient(transport=ASGITransport(_app), base_url="http://test") as ac:
            resp = await ac.get(
                "/protected",
                headers={"Authorization": f"Bearer {_token([], ['users:read', 'users:write'])}"},
            )
        assert resp.status_code == status.HTTP_200_OK

    async def test_forbidden_when_one_missing(self):
        _app = _make_app(Depends(require_all_permissions(["users:read", "users:write"])))
        async with AsyncClient(transport=ASGITransport(_app), base_url="http://test") as ac:
            resp = await ac.get("/protected", headers={"Authorization": f"Bearer {_token([], ['users:read'])}"})
        assert resp.status_code == status.HTTP_403_FORBIDDEN
