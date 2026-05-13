"""Unit tests for FastAPI dependency functions — called directly, not via HTTP."""

from unittest.mock import MagicMock, patch

import pytest
from fastapi import HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth.dependencies import (
    get_current_user,
    get_current_user_payload,
    get_password_reset_user,
)
from app.core.auth.jwt_handler import create_password_reset_token
from app.models.user import User


class TestGetCurrentUserPayload:
    async def test_raises_401_when_no_payload(self):
        request = MagicMock()
        request.state.token_payload = None
        with pytest.raises(HTTPException) as exc_info:
            await get_current_user_payload(request=request)
        assert exc_info.value.status_code == 401

    async def test_returns_payload_when_set(self):
        payload = {"sub": "1", "email": "t@t.com"}
        request = MagicMock()
        request.state.token_payload = payload
        result = await get_current_user_payload(request=request)
        assert result == payload

    async def test_raises_401_for_empty_dict_payload(self):
        request = MagicMock()
        request.state.token_payload = {}
        with pytest.raises(HTTPException) as exc_info:
            await get_current_user_payload(request=request)
        assert exc_info.value.status_code == 401


class TestGetCurrentUser:
    async def test_raises_401_when_no_sub_in_payload(self, db: AsyncSession):
        with pytest.raises(HTTPException) as exc_info:
            await get_current_user(payload={}, db=db)
        assert exc_info.value.status_code == 401

    async def test_raises_401_for_inactive_user(self, db: AsyncSession, inactive_user: User):
        payload = {"sub": str(inactive_user.id)}
        with pytest.raises(HTTPException) as exc_info:
            await get_current_user(payload=payload, db=db)
        assert exc_info.value.status_code == 401

    async def test_raises_401_for_nonexistent_user(self, db: AsyncSession):
        payload = {"sub": "99999"}
        with pytest.raises(HTTPException) as exc_info:
            await get_current_user(payload=payload, db=db)
        assert exc_info.value.status_code == 401

    async def test_raises_401_for_stale_perms_version(self, db: AsyncSession, sample_user: User):
        payload = {"sub": str(sample_user.id), "perms_version": sample_user.perms_version + 99}
        with pytest.raises(HTTPException) as exc_info:
            await get_current_user(payload=payload, db=db)
        assert exc_info.value.status_code == 401

    async def test_returns_user_for_valid_payload(self, db: AsyncSession, sample_user: User):
        payload = {"sub": str(sample_user.id), "perms_version": sample_user.perms_version}
        result = await get_current_user(payload=payload, db=db)
        assert result.id == sample_user.id

    async def test_returns_user_when_perms_version_not_in_payload(self, db: AsyncSession, sample_user: User):
        payload = {"sub": str(sample_user.id)}
        result = await get_current_user(payload=payload, db=db)
        assert result.id == sample_user.id


class TestGetPasswordResetUser:
    async def test_raises_400_for_invalid_token(self, db: AsyncSession):
        with pytest.raises(HTTPException) as exc_info:
            await get_password_reset_user(token="not.a.valid.token", db=db)
        assert exc_info.value.status_code == 400

    async def test_raises_400_when_token_missing_sub(self, db: AsyncSession):
        with (
            patch("app.core.auth.dependencies.decode_password_reset_token", return_value={}),
            pytest.raises(HTTPException) as exc_info,
        ):
            await get_password_reset_user(token="fake", db=db)
        assert exc_info.value.status_code == 400

    async def test_raises_400_when_user_not_found(self, db: AsyncSession):
        with (
            patch(
                "app.core.auth.dependencies.decode_password_reset_token",
                return_value={"sub": "99999"},
            ),
            pytest.raises(HTTPException) as exc_info,
        ):
            await get_password_reset_user(token="fake", db=db)
        assert exc_info.value.status_code == 400

    async def test_returns_user_for_valid_token(self, db: AsyncSession, sample_user: User):
        token = create_password_reset_token(subject=sample_user.id, email=sample_user.email)
        result = await get_password_reset_user(token=token, db=db)
        assert result.id == sample_user.id
