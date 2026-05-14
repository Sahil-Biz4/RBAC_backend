"""Account management — user registration operations."""

import contextlib
import logging

from sqlalchemy.ext.asyncio import AsyncSession

from app.core import constants
from app.core.auth.password import hash_password
from app.core.config.settings import settings
from app.core.constants import OtpPurpose
from app.core.exceptions import ConflictError, ForbiddenError, RateLimitError
from app.core.services.email_service import send_otp_email
from app.core.services.redis_service import redis_service
from app.features.auth import repository as repo
from app.utils.constants import ErrorCodes, ResponseCodes, ResponseMessages, RoleNames
from app.utils.helpers import generate_numeric_otp, hash_otp


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
    user = await repo.create_user(db=db, name=name, email=email, password_hash=pw_hash)

    await repo.assign_role_to_user(db=db, user_id=user.id, role_name=RoleNames.DEFAULT)

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

    return {"success": True, "success_code": ResponseCodes.REGISTER_SUCCESS}


async def register_admin(
    db: AsyncSession,
    name: str,
    email: str,
    password: str,
    secret_key: str,
    ip_address: str = "",
) -> dict:
    """Create an admin user account protected by the admin secret key.

    When ``ip_address`` is provided, failed secret-key attempts are counted in
    Redis and the IP is locked out after ``settings.admin_register_max_failures``
    failures for ``settings.admin_register_lockout_minutes`` minutes.
    Redis errors are treated as fail-open so a Redis outage does not block the
    endpoint — the secret key remains the primary gate.

    Raises:
        RateLimitError: IP has exceeded the maximum allowed failures.
        ForbiddenError: Admin secret key does not match.
        ConflictError:  Email is already registered.
    """
    lockout_seconds = settings.admin_register_lockout_minutes * 60

    if ip_address:
        try:
            failures = await redis_service.get_ip_failures(constants.ADMIN_REGISTER_FAILURE_KEY_PREFIX, ip_address)
            if failures >= settings.admin_register_max_failures:
                raise RateLimitError(ErrorCodes.ADMIN_IP_LOCKED, ResponseMessages.ADMIN_IP_LOCKED)
        except RateLimitError:
            raise
        except RuntimeError:
            logger.warning("Redis unavailable — skipping IP lockout check for admin registration")

    if secret_key != settings.admin_secret_key:
        if ip_address:
            try:
                await redis_service.increment_ip_failures(
                    constants.ADMIN_REGISTER_FAILURE_KEY_PREFIX, ip_address, lockout_seconds
                )
            except RuntimeError:
                logger.warning("Redis unavailable — could not record admin registration failure for IP %s", ip_address)
        raise ForbiddenError(ErrorCodes.FORBIDDEN, ResponseMessages.INVALID_ADMIN_SECRET)

    existing = await repo.get_user_by_email(db=db, email=email)
    if existing:
        raise ConflictError(ErrorCodes.EMAIL_EXISTS, ResponseMessages.EMAIL_ALREADY_EXISTS)

    pw_hash = hash_password(password)
    user = await repo.create_user(db=db, name=name, email=email, password_hash=pw_hash)
    user.is_email_verified = True

    await repo.assign_role_to_user(db=db, user_id=user.id, role_name=RoleNames.ADMIN)
    await db.commit()

    if ip_address:
        with contextlib.suppress(RuntimeError):
            await redis_service.clear_ip_failures(constants.ADMIN_REGISTER_FAILURE_KEY_PREFIX, ip_address)

    return {"success": True, "success_code": ResponseCodes.REGISTER_SUCCESS}
