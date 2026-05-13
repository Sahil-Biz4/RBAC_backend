"""Session management — login, token refresh, and logout operations."""

import asyncio
import logging

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth.jwt_handler import (
    ACCESS_TOKEN_TTL,
    REFRESH_TOKEN_TTL,
    create_access_token,
    create_refresh_token,
    decode_refresh_token,
)
from app.core.auth.password import hash_password, needs_rehash, verify_password
from app.core.config.settings import settings
from app.core.constants import OtpPurpose
from app.core.exceptions import AuthError, ForbiddenError
from app.core.services.email_service import send_otp_email
from app.core.services.redis_service import redis_service
from app.features.auth import repository as repo
from app.features.auth._response import build_token_response
from app.utils.constants import ErrorCodes, ResponseCodes, ResponseMessages
from app.utils.helpers import generate_numeric_otp, hash_otp


logger = logging.getLogger(__name__)


async def login_user(db: AsyncSession, email: str, password: str) -> dict:
    """Authenticate credentials and return JWT access + refresh tokens.

    Raises:
        AuthError:      Invalid credentials.
        ForbiddenError: Account inactive or email not verified.
    """
    user = await repo.get_user_by_email(db=db, email=email)
    if not user or not user.password_hash or not verify_password(password, user.password_hash):
        raise AuthError(ErrorCodes.INVALID_CREDENTIALS, ResponseMessages.INVALID_CREDENTIALS)

    if not user.is_email_verified:
        await repo.invalidate_user_otps(db=db, user_id=user.id, purpose=OtpPurpose.EMAIL_VERIFICATION)
        otp = generate_numeric_otp()
        await repo.create_email_otp(
            db=db,
            user_id=user.id,
            otp_hash=hash_otp(otp),
            purpose=OtpPurpose.EMAIL_VERIFICATION,
            expire_minutes=settings.otp_expire_minutes,
        )
        await db.commit()
        await send_otp_email(to_email=email, otp=otp, purpose="email verification")
        return {
            "success": False,
            "error_code": ErrorCodes.EMAIL_NOT_VERIFIED,
            "message": ResponseMessages.EMAIL_NOT_VERIFIED,
            "email_verification_required": True,
            "email": email,
        }

    if not user.is_active:
        raise ForbiddenError(ErrorCodes.ACCOUNT_INACTIVE, ResponseMessages.ACCOUNT_INACTIVE)

    if user.password_hash and needs_rehash(user.password_hash):
        await repo.update_user_password(db=db, user=user, new_hash=hash_password(password))

    roles, permissions = repo.extract_roles_and_permissions(user)

    access_token, access_jti = create_access_token(
        subject=user.id,
        email=user.email,
        roles=roles,
        permissions=permissions,
        perms_version=user.perms_version,
    )
    refresh_token, _ = create_refresh_token(subject=user.id, email=user.email)

    await redis_service.store_refresh_token(user.id, refresh_token, REFRESH_TOKEN_TTL)
    await redis_service.store_access_jti(user.id, access_jti, ACCESS_TOKEN_TTL)

    return build_token_response(access_token, refresh_token, ResponseCodes.LOGIN_SUCCESS)


async def refresh_tokens(db: AsyncSession, user_id: int, refresh_token: str) -> dict:
    """Issue new access + refresh tokens by verifying the stored Redis token (rotation).

    Raises:
        AuthError: Token missing in Redis, invalid JWT, or user not found/inactive.
    """
    is_valid = await redis_service.verify_refresh_token(user_id, refresh_token)
    if not is_valid:
        raise AuthError(ErrorCodes.INVALID_TOKEN, ResponseMessages.REFRESH_TOKEN_INVALID)

    try:
        decode_refresh_token(refresh_token)
    except Exception as exc:
        raise AuthError(ErrorCodes.INVALID_TOKEN, ResponseMessages.REFRESH_TOKEN_INVALID) from exc

    user = await repo.get_user_by_id(db=db, user_id=user_id)
    if not user or not user.is_active:
        raise AuthError(ErrorCodes.INVALID_TOKEN, ResponseMessages.INVALID_TOKEN)

    roles, permissions = repo.extract_roles_and_permissions(user)

    new_access, new_access_jti = create_access_token(
        subject=user.id,
        email=user.email,
        roles=roles,
        permissions=permissions,
        perms_version=user.perms_version,
    )
    new_refresh, _ = create_refresh_token(subject=user.id, email=user.email)

    await redis_service.store_refresh_token(user.id, new_refresh, REFRESH_TOKEN_TTL)
    await redis_service.store_access_jti(user.id, new_access_jti, ACCESS_TOKEN_TTL)

    return build_token_response(new_access, new_refresh, ResponseCodes.TOKEN_REFRESHED)


async def logout_user(user_id: int) -> dict:
    """Delete the Redis refresh token and access JTI. Intentionally lenient — always returns success."""
    try:
        await asyncio.gather(
            redis_service.delete_refresh_token(user_id),
            redis_service.delete_access_jti(user_id),
        )
    except Exception as exc:
        logger.warning("logout_user: token deletion failed — %s", exc)

    return {"success": True, "success_code": ResponseCodes.LOGOUT_SUCCESS}
