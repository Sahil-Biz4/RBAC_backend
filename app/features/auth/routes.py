"""Auth feature HTTP routes."""

from fastapi import APIRouter, Depends, status
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth.dependencies import get_current_user, get_password_reset_user
from app.core.auth.jwt_handler import decode_refresh_token
from app.core.constants import APITags
from app.core.database import get_db
from app.core.exceptions import AppError
from app.features.auth import service
from app.features.auth.routes_definition import routes as r
from app.features.auth.schemas import (
    ChangePasswordIn,
    ForgotPasswordIn,
    LoginIn,
    RefreshIn,
    RegisterAdminIn,
    RegisterIn,
    ResendOtpIn,
    VerifyOtpIn,
)
from app.models.user import User


router = APIRouter(prefix=r.BASE, tags=[APITags.AUTH])


@router.post(r.REGISTER, status_code=status.HTTP_201_CREATED, summary="Register a new user")
async def register(body: RegisterIn, db: AsyncSession = Depends(get_db)) -> JSONResponse:
    """Register a user account and send an email verification OTP."""
    try:
        result = await service.register_user(db=db, name=body.name, email=body.email, password=body.password)
    except AppError as exc:
        raise exc.as_http_exception()
    return JSONResponse(status_code=status.HTTP_201_CREATED, content=result)


@router.post(r.REGISTER_ADMIN, status_code=status.HTTP_201_CREATED, summary="Register an admin user")
async def register_admin(body: RegisterAdminIn, db: AsyncSession = Depends(get_db)) -> JSONResponse:
    """Create an admin account — requires the ADMIN_SECRET_KEY."""
    try:
        result = await service.register_admin(
            db=db,
            name=body.name,
            email=body.email,
            password=body.password,
            secret_key=body.admin_secret_key,
        )
    except AppError as exc:
        raise exc.as_http_exception()
    return JSONResponse(status_code=status.HTTP_201_CREATED, content=result)


@router.post(r.LOGIN, summary="Login with email and password")
async def login(body: LoginIn, db: AsyncSession = Depends(get_db)) -> JSONResponse:
    """Authenticate and return access + refresh tokens; refresh token stored in Redis."""
    try:
        result = await service.login_user(db=db, email=body.email, password=body.password)
    except AppError as exc:
        raise exc.as_http_exception()
    return JSONResponse(status_code=status.HTTP_200_OK, content=result)


@router.post(r.REFRESH, summary="Refresh access token")
async def refresh(body: RefreshIn, db: AsyncSession = Depends(get_db)) -> JSONResponse:
    """Verify the refresh token against Redis and issue a new token pair (rotation)."""
    from app.core.exceptions import AuthError
    from app.utils.constants import ErrorCodes, ResponseMessages
    try:
        payload = decode_refresh_token(body.refresh_token)
        user_id = int(payload["sub"])
    except Exception as exc:
        raise AuthError(ErrorCodes.INVALID_TOKEN, ResponseMessages.REFRESH_TOKEN_INVALID).as_http_exception() from exc
    try:
        result = await service.refresh_tokens(db=db, user_id=user_id, refresh_token=body.refresh_token)
    except AppError as exc:
        raise exc.as_http_exception()
    return JSONResponse(status_code=status.HTTP_200_OK, content=result)


@router.post(r.LOGOUT, summary="Logout — revoke refresh token")
async def logout(
    current_user: User = Depends(get_current_user),
) -> JSONResponse:
    """Delete the Redis refresh token for the current user."""
    result = await service.logout_user(user_id=current_user.id)
    return JSONResponse(status_code=status.HTTP_200_OK, content=result)


@router.post(r.VERIFY_OTP, summary="Verify email OTP")
async def verify_otp(body: VerifyOtpIn, db: AsyncSession = Depends(get_db)) -> JSONResponse:
    """Verify an OTP for email verification or password reset."""
    try:
        result = await service.verify_otp(db=db, email=body.email, otp=body.otp, purpose=body.purpose.value)
    except AppError as exc:
        raise exc.as_http_exception()
    return JSONResponse(status_code=status.HTTP_200_OK, content=result)


@router.post(r.RESEND_OTP, summary="Resend OTP")
async def resend_otp(body: ResendOtpIn, db: AsyncSession = Depends(get_db)) -> JSONResponse:
    """Invalidate the current OTP and send a fresh one."""
    try:
        result = await service.resend_otp(db=db, email=body.email, purpose=body.purpose.value)
    except AppError as exc:
        raise exc.as_http_exception()
    return JSONResponse(status_code=status.HTTP_200_OK, content=result)


@router.post(r.FORGOT_PASSWORD, summary="Request a password reset OTP")
async def forgot_password(body: ForgotPasswordIn, db: AsyncSession = Depends(get_db)) -> JSONResponse:
    """Send a password-reset OTP. Always returns success to prevent email enumeration."""
    result = await service.forgot_password(db=db, email=body.email)
    return JSONResponse(status_code=status.HTTP_200_OK, content=result)


@router.post(r.CHANGE_PASSWORD, summary="Change password using reset token")
async def change_password(
    body: ChangePasswordIn,
    current_user: User = Depends(get_password_reset_user),
    db: AsyncSession = Depends(get_db),
) -> JSONResponse:
    """Update password after verifying the password-reset JWT."""
    try:
        result = await service.change_password(
            db=db, user_id=current_user.id, new_password=body.new_password
        )
    except AppError as exc:
        raise exc.as_http_exception()
    return JSONResponse(status_code=status.HTTP_200_OK, content=result)
