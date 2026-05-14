"""OTP workflow — verification, resend, forgot-password, and password-change operations."""

import logging

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth.jwt_handler import (
    ACCESS_TOKEN_TTL,
    REFRESH_TOKEN_TTL,
    create_access_token,
    create_password_reset_token,
    create_refresh_token,
)
from app.core.auth.password import hash_password
from app.core.config.settings import settings
from app.core.constants import OtpPurpose
from app.core.exceptions import AuthError, NotFoundError, RateLimitError
from app.core.services.email_service import send_otp_email
from app.core.services.redis_service import redis_service
from app.features.auth import repository as repo
from app.features.auth._response import build_token_response
from app.utils.constants import ErrorCodes, ResponseCodes, ResponseMessages
from app.utils.helpers import generate_numeric_otp, hash_otp, verify_otp_hash


logger = logging.getLogger(__name__)


async def _issue_otp(db: AsyncSession, user_id: int, email: str, purpose: str) -> None:
    """Invalidate existing OTPs, generate a fresh one, persist, commit, and send."""
    await repo.invalidate_user_otps(db=db, user_id=user_id, purpose=purpose)
    otp = generate_numeric_otp()
    await repo.create_email_otp(
        db=db,
        user_id=user_id,
        otp_hash=hash_otp(otp),
        purpose=purpose,
        expire_minutes=settings.otp_expire_minutes,
    )
    await db.commit()
    await send_otp_email(to_email=email, otp=otp, purpose=purpose.replace("_", " "))


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

    if not user.is_email_verified:
        await repo.verify_user_email(db=db, user=user)

    if purpose == OtpPurpose.EMAIL_VERIFICATION:
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

        return build_token_response(access_token, refresh_token, ResponseCodes.OTP_VERIFIED)

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

    await _issue_otp(db, user.id, email, purpose)
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
            await _issue_otp(db, user.id, email, OtpPurpose.PASSWORD_RESET)

    return {"success": True, "success_code": ResponseCodes.PASSWORD_RESET_EMAIL_SENT}


async def change_password(db: AsyncSession, user_id: int, new_password: str) -> dict:
    """Update the user's password hash and revoke all active sessions.

    Raises:
        NotFoundError: User not found (should not happen in normal flow).
    """
    user = await repo.get_user_by_id(db=db, user_id=user_id)
    if not user:
        raise NotFoundError(ErrorCodes.USER_NOT_FOUND, ResponseMessages.USER_NOT_FOUND)

    await repo.update_user_password(db=db, user=user, new_hash=hash_password(new_password))
    await redis_service.delete_all_user_sessions(user_id=user_id)

    return {"success": True, "success_code": ResponseCodes.PASSWORD_CHANGED}
