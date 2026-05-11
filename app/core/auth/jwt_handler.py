"""JWT token creation and decoding utilities for access, refresh, and password-reset tokens."""

import uuid
from datetime import UTC, datetime, timedelta

import jwt
from jwt.exceptions import PyJWTError

from app.core.config.settings import settings
from app.core.constants import (
    JWT_SCOPE_ACCESS,
    JWT_SCOPE_PASSWORD_RESET,
    JWT_SCOPE_REFRESH,
)
from app.utils.constants import ResponseMessages


def create_access_token(
    *,
    subject: int | str,
    email: str,
    roles: list[str],
    permissions: list[str],
    expires_minutes: int | None = None,
) -> tuple[str, str]:
    """Create a signed JWT access token embedding roles and permissions.

    Roles and permissions are cached in the token so every request avoids
    a DB round-trip for authorization checks. They are refreshed on token renewal.

    Args:
        subject: User ID stored in the 'sub' claim.
        email: User email stored in the 'email' claim.
        roles: List of role names assigned to the user.
        permissions: Flattened list of all permission strings for those roles.
        expires_minutes: Optional override for expiry. Defaults to settings value.

    Returns:
        Tuple of (encoded JWT string, JTI string).
    """
    expire_minutes = expires_minutes if expires_minutes is not None else settings.jwt_access_token_expire_minutes
    expire = datetime.now(UTC) + timedelta(minutes=expire_minutes)
    jti = str(uuid.uuid4())

    payload = {
        "sub": str(subject),
        "email": email,
        "roles": roles,
        "permissions": permissions,
        "jti": jti,
        "scope": JWT_SCOPE_ACCESS,
        "exp": int(expire.timestamp()),
    }
    token = jwt.encode(payload, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)
    return token, jti


def create_refresh_token(
    *,
    subject: int | str,
    email: str,
    expires_minutes: int | None = None,
) -> tuple[str, str]:
    """Create a signed JWT refresh token.

    Refresh tokens do NOT carry roles/permissions — a fresh DB lookup happens
    when the client exchanges the refresh token for a new access token.

    Args:
        subject: User ID stored in the 'sub' claim.
        email: User email stored in the 'email' claim.
        expires_minutes: Optional override. Defaults to settings value.

    Returns:
        Tuple of (encoded JWT string, JTI string).
    """
    expire_minutes = expires_minutes if expires_minutes is not None else settings.jwt_refresh_token_expire_minutes
    expire = datetime.now(UTC) + timedelta(minutes=expire_minutes)
    jti = str(uuid.uuid4())

    payload = {
        "sub": str(subject),
        "email": email,
        "jti": jti,
        "scope": JWT_SCOPE_REFRESH,
        "exp": int(expire.timestamp()),
    }
    token = jwt.encode(payload, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)
    return token, jti


def create_password_reset_token(*, subject: int | str, email: str) -> str:
    """Create a short-lived JWT scoped to password reset only.

    Args:
        subject: User ID stored in the 'sub' claim.
        email: User email stored in the 'email' claim.

    Returns:
        Encoded JWT string with scope='password_reset'.
    """
    expire = datetime.now(UTC) + timedelta(minutes=settings.password_reset_token_expire_minutes)
    payload = {
        "sub": str(subject),
        "email": email,
        "scope": JWT_SCOPE_PASSWORD_RESET,
        "exp": int(expire.timestamp()),
    }
    return jwt.encode(payload, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)


def decode_token(token: str) -> dict:
    """Decode and verify any JWT token issued by this application.

    Raises:
        jwt.PyJWTError: If the token is invalid, expired, or tampered with.
    """
    return jwt.decode(token, settings.jwt_secret_key, algorithms=[settings.jwt_algorithm])


def decode_refresh_token(token: str) -> dict:
    """Decode and verify a refresh token, enforcing the correct scope.

    Raises:
        jwt.InvalidTokenError: If token is invalid, expired, or scope is not 'refresh'.
    """
    try:
        payload = decode_token(token)
    except PyJWTError as exc:
        raise jwt.InvalidTokenError(ResponseMessages.REFRESH_TOKEN_INVALID) from exc

    if payload.get("scope") != JWT_SCOPE_REFRESH:
        raise jwt.InvalidTokenError(ResponseMessages.INVALID_TOKEN_SCOPE)

    return payload


def decode_password_reset_token(token: str) -> dict:
    """Decode and verify a password-reset token, enforcing the correct scope.

    Raises:
        jwt.InvalidTokenError: If token is invalid, expired, or scope is not 'password_reset'.
    """
    try:
        payload = decode_token(token)
    except PyJWTError as exc:
        raise jwt.InvalidTokenError(ResponseMessages.INVALID_TOKEN) from exc

    if payload.get("scope") != JWT_SCOPE_PASSWORD_RESET:
        raise jwt.InvalidTokenError(ResponseMessages.INVALID_TOKEN_SCOPE)

    return payload
