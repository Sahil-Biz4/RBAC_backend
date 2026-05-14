"""Tests for app/main.py — health check and global exception handler."""

import json
from unittest.mock import AsyncMock, MagicMock

from fastapi import status
from httpx import AsyncClient

from app.main import app


class TestHealthCheck:
    async def test_healthy_returns_200(self, client: AsyncClient):
        resp = await client.get("/health")
        assert resp.status_code == status.HTTP_200_OK
        data = resp.json()
        assert data["status"] == "healthy"
        assert data["service"] == "ok"
        assert data["database"] == "ok"

    async def test_db_failure_returns_503(self, client: AsyncClient):
        """When the DB is unreachable, health check must return 503 with unhealthy status."""
        from app.core.database import get_db

        broken_db = AsyncMock()
        broken_db.execute.side_effect = Exception("DB connection refused")

        # Save original override set by the client fixture.
        original_override = app.dependency_overrides.get(get_db)

        async def _broken_get_db():
            yield broken_db

        app.dependency_overrides[get_db] = _broken_get_db
        try:
            resp = await client.get("/health")
        finally:
            if original_override is not None:
                app.dependency_overrides[get_db] = original_override
            else:
                app.dependency_overrides.pop(get_db, None)

        assert resp.status_code == status.HTTP_503_SERVICE_UNAVAILABLE
        data = resp.json()
        assert data["status"] == "unhealthy"
        assert data["database"] == "unreachable"


class TestGlobalExceptionHandler:
    async def test_unhandled_exception_returns_500_json(self):
        """The global exception handler must return a well-formed 500 JSON body."""
        handler = app.exception_handlers.get(Exception)
        assert handler is not None, "Global exception handler not registered on app"

        mock_request = MagicMock()
        response = await handler(mock_request, RuntimeError("forced test error"))

        assert response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
        body = json.loads(response.body)
        assert body["success"] is False
        assert "message" in body
