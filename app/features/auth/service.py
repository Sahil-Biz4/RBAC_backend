"""Auth business logic — orchestrates repository, JWT, password, and email operations.

Services raise domain exceptions (from ``app.core.exceptions``) rather than
``HTTPException``. Routes catch ``AppError`` and call ``.as_http_exception()``
to convert them, keeping HTTP concerns out of this layer.
"""

import logging

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth.jwt_handler import (
    create_access_token,
    create_password_reset_token,
    create_refresh_token,
    decode_refresh_token,
)
from app.core.auth.password import hash_password, needs_rehash, verify_password
from app.core.config.settings import settings
from app.core.constants import OtpPurpose
from app.core.exceptions import AuthError, ConflictError, ForbiddenError, NotFoundError, RateLimitError
from app.core.services.email_service import send_otp_email
from app.core.services.redis_service import redis_service
from app.features.auth import repository as repo
from app.utils.constants import ErrorCodes, ResponseCodes, ResponseMessages, RoleNames
from app.utils.helpers import generate_numeric_otp, hash_otp, verify_otp_hash

logger = logging.getLogger(__name__)


async def register_user(db: AsyncSession, name: str, email: str, password: str) -> dict:
    """Create a new user account, assign the default role, and send verification OTP.

    Raises:
        ConflictError: Email is already registered.
    """
    existing = await repo.get_user_by_email(db=db, email=email)
    if existing:
        raise ConflictError(ErrorCodes.EMAIL_EXISTS, ResponseMessages.EMAIL_ALREADY_EXISTS)

    pw_hash = hash_password(password)
    user = await repo.create_user(db=db, name=name, email=email, password_hash=pw_hash, commit=False)

    await repo.assign_role_to_user(db=db, user_id=user.id, role_name=RoleNames.DEFAULT, commit=False)

    otp = generate_numeric_otp()
    await repo.create_email_otp(
        db=db,
        user_id=user.id,
        otp_hash=hash_otp(otp),
        purpose=OtpPurpose.EMAIL_VERIFICATION,
        expire_minutes=settings.otp_expire_minutes,
    )

    await send_otp_email(to_email=email, otp=otp, purpose="email verification")

    return {"success": True, "success_code": ResponseCodes.REGISTER_SUCCESS}


async def register_admin(db: AsyncSession, name: str, email: str, password: str, secret_key: str) -> dict:
    """Create an admin user account protected by the admin secret key.

    Raises:
        ForbiddenError: Admin secret key does not match.
        ConflictError:  Email is already registered.
    """
    if secret_key != settings.admin_secret_key:
        raise ForbiddenError(ErrorCodes.FORBIDDEN, ResponseMessages.INVALID_ADMIN_SECRET)

    existing = await repo.get_user_by_email(db=db, email=email)
    if existing:
        raise ConflictError(ErrorCodes.EMAIL_EXISTS, ResponseMessages.EMAIL_ALREADY_EXISTS)

    pw_hash = hash_password(password)
    user = await repo.create_user(db=db, name=name, email=email, password_hash=pw_hash, commit=False)
    user.is_email_verified = True

    await repo.assign_role_to_user(db=db, user_id=user.id, role_name=RoleNames.ADMIN)

    return {"success": True, "success_code": ResponseCodes.REGISTER_SUCCESS}


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
        raise ForbiddenError(ErrorCodes.EMAIL_NOT_VERIFIED, ResponseMessages.EMAIL_NOT_VERIFIED)

    if not user.is_active:
        raise ForbiddenError(ErrorCodes.ACCOUNT_INACTIVE, ResponseMessages.ACCOUNT_INACTIVE)

    if user.password_hash and needs_rehash(user.password_hash):
        await repo.update_user_password(db=db, user=user, new_hash=hash_password(password))

    roles, permissions = await repo.get_user_roles_and_permissions(db=db, user_id=user.id)

    access_token, _ = create_access_token(
        subject=user.id, email=user.email, roles=roles, permissions=permissions,
        perms_version=user.perms_version,
    )
    refresh_token, _ = create_refresh_token(subject=user.id, email=user.email)

    ttl = settings.jwt_refresh_token_expire_minutes * 60
    await redis_service.store_refresh_token(user.id, refresh_token, ttl)

    return {
        "success": True,
        "success_code": ResponseCodes.LOGIN_SUCCESS,
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
    }


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

    roles, permissions = await repo.get_user_roles_and_permissions(db=db, user_id=user.id)

    new_access, _ = create_access_token(
        subject=user.id, email=user.email, roles=roles, permissions=permissions,
        perms_version=user.perms_version,
    )
    new_refresh, _ = create_refresh_token(subject=user.id, email=user.email)

    ttl = settings.jwt_refresh_token_expire_minutes * 60
    await redis_service.store_refresh_token(user.id, new_refresh, ttl)

    return {
        "success": True,
        "success_code": ResponseCodes.TOKEN_REFRESHED,
        "access_token": new_access,
        "refresh_token": new_refresh,
        "token_type": "bearer",
    }


async def logout_user(user_id: int) -> dict:
    """Delete the Redis refresh token. Intentionally lenient — always returns success."""
    try:
        await redis_service.delete_refresh_token(user_id)
    except Exception as exc:
        logger.warning("logout_user: token deletion failed — %s", exc)

    return {"success": True, "success_code": ResponseCodes.LOGOUT_SUCCESS}


async def verify_otp(db: AsyncSession, email: str, otp: str, purpose: str) -> dict:
    """Verify an OTP for a given purpose.

    On success:
        - email_verification → marks email as verified, returns token pair.
        - password_reset     → returns a short-lived password-reset token.
    """
    user = await repo.get_user_by_email(db=db, email=email)
    if not user:
        raise AuthError(ErrorCodes.INVALID_OTP, ResponseMessages.INVALID_OTP)

    active_otp = await repo.get_active_otp(db=db, user_id=user.id, purpose=purpose)
    if not active_otp:
        raise AuthError(ErrorCodes.INVALID_OTP, ResponseMessages.INVALID_OTP)

    if active_otp.attempts >= settings.otp_max_verify_attempts:
        raise RateLimitError(ErrorCodes.OTP_MAX_ATTEMPTS, ResponseMessages.OTP_MAX_ATTEMPTS)

    if not verify_otp_hash(otp, active_otp.otp_hash):
        await repo.increment_otp_attempts(db=db, otp=active_otp)
        raise AuthError(ErrorCodes.INVALID_OTP, ResponseMessages.INVALID_OTP)

    await repo.mark_otp_used(db=db, otp=active_otp)

    # Mark email as verified for both purposes - user proved they own the email
    if not user.is_email_verified:
        await repo.verify_user_email(db=db, user=user)

    if purpose == OtpPurpose.EMAIL_VERIFICATION:
        roles, permissions = await repo.get_user_roles_and_permissions(db=db, user_id=user.id)
        access_token, _ = create_access_token(
            subject=user.id, email=user.email, roles=roles, permissions=permissions,
            perms_version=user.perms_version,
        )
        refresh_token, _ = create_refresh_token(subject=user.id, email=user.email)

        ttl = settings.jwt_refresh_token_expire_minutes * 60
        await redis_service.store_refresh_token(user.id, refresh_token, ttl)

        return {
            "success": True,
            "success_code": ResponseCodes.OTP_VERIFIED,
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
        }

    reset_token = create_password_reset_token(subject=user.id, email=user.email)
    return {
        "success": True,
        "success_code": ResponseCodes.OTP_VERIFIED,
        "reset_token": reset_token,
    }


async def resend_otp(db: AsyncSession, email: str, purpose: str) -> dict:
    """Invalidate previous OTPs and issue a fresh one, subject to rate limits.

    Intentionally lenient on unknown email: always returns success to prevent
    user enumeration via the resend endpoint.

    Raises:
        RateLimitError: Resend limit exceeded within the configured window.
    """
    user = await repo.get_user_by_email(db=db, email=email)
    if not user:
        return {"success": True, "success_code": ResponseCodes.OTP_RESENT}

    resend_count = await repo.count_recent_resends(
        db=db,
        user_id=user.id,
        purpose=purpose,
        window_minutes=settings.otp_resend_window_minutes,
    )
    if resend_count >= settings.otp_max_resends:
        raise RateLimitError(ErrorCodes.OTP_RESEND_LIMIT, ResponseMessages.OTP_RESEND_LIMIT)

    await repo.invalidate_user_otps(db=db, user_id=user.id, purpose=purpose)

    otp = generate_numeric_otp()
    await repo.create_email_otp(
        db=db,
        user_id=user.id,
        otp_hash=hash_otp(otp),
        purpose=purpose,
        expire_minutes=settings.otp_expire_minutes,
    )
    await send_otp_email(to_email=email, otp=otp, purpose=purpose.replace("_", " "))

    return {"success": True, "success_code": ResponseCodes.OTP_RESENT}


async def forgot_password(db: AsyncSession, email: str) -> dict:
    """Send a password-reset OTP. Always returns success to prevent email enumeration."""
    user = await repo.get_user_by_email(db=db, email=email)
    if user and user.is_active:
        resend_count = await repo.count_recent_resends(
            db=db,
            user_id=user.id,
            purpose=OtpPurpose.PASSWORD_RESET,
            window_minutes=settings.otp_resend_window_minutes,
        )
        if resend_count < settings.otp_max_resends:
            await repo.invalidate_user_otps(db=db, user_id=user.id, purpose=OtpPurpose.PASSWORD_RESET)
            otp = generate_numeric_otp()
            await repo.create_email_otp(
                db=db,
                user_id=user.id,
                otp_hash=hash_otp(otp),
                purpose=OtpPurpose.PASSWORD_RESET,
                expire_minutes=settings.otp_expire_minutes,
            )
            await send_otp_email(to_email=email, otp=otp, purpose="password reset")

    return {"success": True, "success_code": ResponseCodes.PASSWORD_RESET_EMAIL_SENT}


async def change_password(db: AsyncSession, user_id: int, new_password: str) -> dict:
    """Update the user's password hash and revoke all active sessions.

    Called after password-reset token validation. Revoking all sessions
    forces re-authentication on all devices after a password change.

    Raises:
        NotFoundError: User not found (should not happen in normal flow).
    """
    user = await repo.get_user_by_id(db=db, user_id=user_id)
    if not user:
        raise NotFoundError(ErrorCodes.USER_NOT_FOUND, ResponseMessages.USER_NOT_FOUND)

    await repo.update_user_password(db=db, user=user, new_hash=hash_password(new_password))
    await redis_service.delete_all_user_sessions(user_id=user_id)

    return {"success": True, "success_code": ResponseCodes.PASSWORD_CHANGED}
