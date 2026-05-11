"""FastAPI dependency functions for extracting and validating the current user from JWT tokens."""

from __future__ import annotations

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jwt.exceptions import PyJWTError
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.requests import Request

from app.core.auth.jwt_handler import decode_password_reset_token
from app.core.config.settings import settings
from app.core.database import get_db
from app.models.user import User
from app.utils.constants import ErrorCodes, ResponseMessages


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")


async def get_current_user_payload(request: Request) -> dict:
    """Extract the pre-validated JWT payload attached by AuthMiddleware.

    Raises:
        HTTPException 401: If the token payload is absent from request state.
    """
    payload = getattr(request.state, "token_payload", None)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"success": False, "message": ResponseMessages.INVALID_TOKEN},
        )
    return payload


async def get_current_user(
    payload: dict = Depends(get_current_user_payload),
    db: AsyncSession = Depends(get_db),
) -> User:
    """Resolve the authenticated User record from the database.

    Uses the 'sub' claim from the JWT payload to look up the user.

    Raises:
        HTTPException 401: If no active user exists for the token's subject.
    """
    from app.features.auth.repository import get_user_by_id

    user_id_str = payload.get("sub")
    if not user_id_str:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"success": False, "message": ResponseMessages.INVALID_TOKEN},
        )

    user = await get_user_by_id(db=db, user_id=int(user_id_str))
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"success": False, "message": ResponseMessages.INVALID_TOKEN},
        )

    token_version = payload.get("perms_version")
    if token_version is not None and token_version != user.perms_version:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "success": False,
                "message": ResponseMessages.PERMISSIONS_CHANGED,
                "error_code": ErrorCodes.PERMISSIONS_CHANGED,
            },
        )

    return user


async def get_current_admin_user(
    current_user: User = Depends(get_current_user),
    payload: dict = Depends(get_current_user_payload),
) -> User:
    """Ensure the current user holds an admin-level role.

    Checks the 'roles' claim in the JWT for 'admin' or 'super_admin'.

    Raises:
        HTTPException 403: If the user does not have an admin role.
    """
    from app.utils.constants import RoleNames

    roles: list[str] = payload.get("roles", [])
    if not any(r in roles for r in RoleNames.ADMIN_ROLES):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"success": False, "message": ResponseMessages.ADMIN_ONLY},
        )
    return current_user


async def get_password_reset_user(
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db),
) -> User:
    """Decode a password-reset JWT and return the corresponding User.

    Raises:
        HTTPException 400: If the token is invalid, expired, wrong scope, or user not found.
    """
    from app.features.auth.repository import get_user_by_id

    try:
        payload = decode_password_reset_token(token)
    except (PyJWTError, jwt.InvalidTokenError) as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"success": False, "message": ResponseMessages.INVALID_TOKEN},
        ) from exc

    user_id_str = payload.get("sub")
    if not user_id_str:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"success": False, "message": ResponseMessages.INVALID_TOKEN},
        )

    user = await get_user_by_id(db=db, user_id=int(user_id_str))
    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"success": False, "message": ResponseMessages.INVALID_TOKEN},
        )
    return user
