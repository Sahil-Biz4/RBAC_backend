"""Unit tests for JWT token creation and decoding."""

import time

import jwt
import pytest

from app.core.auth.jwt_handler import (
    create_access_token,
    create_password_reset_token,
    create_refresh_token,
    decode_refresh_token,
    decode_token,
)
from app.core.config.settings import settings
from app.core.constants import JWT_SCOPE_ACCESS, JWT_SCOPE_PASSWORD_RESET, JWT_SCOPE_REFRESH


class TestCreateAccessToken:
    def test_returns_token_and_jti(self):
        token, jti = create_access_token(
            subject=1, email="test@example.com", roles=["user"], permissions=["profile:read"], perms_version=1
        )
        assert isinstance(token, str)
        assert isinstance(jti, str)
        assert len(jti) == 36

    def test_payload_contains_correct_claims(self):
        roles = ["admin"]
        permissions = ["users:read", "users:write"]
        token, jti = create_access_token(
            subject=42, email="admin@example.com", roles=roles, permissions=permissions, perms_version=3
        )
        payload = jwt.decode(token, settings.jwt_secret_key, algorithms=[settings.jwt_algorithm])
        assert payload["sub"] == "42"
        assert payload["email"] == "admin@example.com"
        assert payload["roles"] == roles
        assert payload["permissions"] == permissions
        assert payload["scope"] == JWT_SCOPE_ACCESS
        assert payload["jti"] == jti
        assert payload["perms_version"] == 3

    def test_custom_expiry_is_respected(self):
        token, _ = create_access_token(
            subject=1, email="t@t.com", roles=[], permissions=[], perms_version=1, expires_minutes=60
        )
        payload = jwt.decode(token, settings.jwt_secret_key, algorithms=[settings.jwt_algorithm])
        assert payload["exp"] > int(time.time()) + 3500

    def test_each_token_has_unique_jti(self):
        _, jti1 = create_access_token(subject=1, email="a@a.com", roles=[], permissions=[], perms_version=1)
        _, jti2 = create_access_token(subject=1, email="a@a.com", roles=[], permissions=[], perms_version=1)
        assert jti1 != jti2


class TestCreateRefreshToken:
    def test_scope_is_refresh(self):
        token, _ = create_refresh_token(subject=1, email="t@t.com")
        payload = jwt.decode(token, settings.jwt_secret_key, algorithms=[settings.jwt_algorithm])
        assert payload["scope"] == JWT_SCOPE_REFRESH

    def test_does_not_contain_permissions(self):
        token, _ = create_refresh_token(subject=1, email="t@t.com")
        payload = jwt.decode(token, settings.jwt_secret_key, algorithms=[settings.jwt_algorithm])
        assert "permissions" not in payload
        assert "roles" not in payload


class TestCreatePasswordResetToken:
    def test_scope_is_password_reset(self):
        token = create_password_reset_token(subject=1, email="t@t.com")
        payload = jwt.decode(token, settings.jwt_secret_key, algorithms=[settings.jwt_algorithm])
        assert payload["scope"] == JWT_SCOPE_PASSWORD_RESET

    def test_expires_within_configured_minutes(self):
        token = create_password_reset_token(subject=1, email="t@t.com")
        payload = jwt.decode(token, settings.jwt_secret_key, algorithms=[settings.jwt_algorithm])
        remaining = payload["exp"] - int(time.time())
        assert remaining <= settings.password_reset_token_expire_minutes * 60
        assert remaining > 0


class TestDecodeToken:
    def test_valid_access_token_decoded(self):
        token, jti = create_access_token(subject=7, email="x@x.com", roles=["user"], permissions=[], perms_version=2)
        payload = decode_token(token)
        assert payload["sub"] == "7"
        assert payload["jti"] == jti

    def test_expired_token_raises(self):
        token, _ = create_access_token(
            subject=1, email="t@t.com", roles=[], permissions=[], perms_version=1, expires_minutes=-1
        )
        with pytest.raises(jwt.PyJWTError):
            decode_token(token)


class TestDecodeRefreshToken:
    def test_valid_refresh_token_is_decoded(self):
        token, jti = create_refresh_token(subject=5, email="user@example.com")
        payload = decode_refresh_token(token)
        assert payload["sub"] == "5"
        assert payload["jti"] == jti

    def test_access_token_raises_invalid_scope(self):
        token, _ = create_access_token(subject=1, email="t@t.com", roles=[], permissions=[], perms_version=1)
        with pytest.raises(jwt.InvalidTokenError):
            decode_refresh_token(token)

    def test_tampered_token_raises(self):
        token, _ = create_refresh_token(subject=1, email="t@t.com")
        tampered = token + "x"
        with pytest.raises(jwt.InvalidTokenError):
            decode_refresh_token(tampered)
