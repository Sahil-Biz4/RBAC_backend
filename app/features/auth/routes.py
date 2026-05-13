"""Auth feature HTTP routes."""

from fastapi import APIRouter, Depends, Request, status
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth.dependencies import get_current_user, get_password_reset_user
from app.core.auth.jwt_handler import decode_refresh_token
from app.core.constants import APITags
from app.core.database import get_db
from app.core.exceptions import AppError, AuthError
from app.core.limiter import limiter
from app.features.auth import service
from app.features.auth.routes_definition import routes as r
from app.features.auth.schemas import (
    ChangePasswordIn,
    ForgotPasswordIn,
    LoginIn,
    RegisterAdminIn,
    RegisterIn,
    ResendOtpIn,
    VerifyOtpIn,
)
from app.models.user import User
from app.utils.constants import ErrorCodes, ResponseMessages


_REFRESH_COOKIE_NAME = "refresh_token"
# Intentionally scoped to /api/v1/auth so the cookie is only sent on auth
# endpoints (refresh/logout), never on every API request.
_REFRESH_COOKIE_PATH = "/api/v1/auth"


def _set_refresh_cookie(response: JSONResponse, token: str) -> None:
    """Attach the refresh token as an httpOnly cookie scoped to the auth path."""
    from app.core.config.settings import settings

    response.set_cookie(
        key=_REFRESH_COOKIE_NAME,
        value=token,
        httponly=True,
        secure=settings.environment not in ("local", "development"),
        samesite="lax",
        path=_REFRESH_COOKIE_PATH,
        max_age=settings.jwt_refresh_token_expire_minutes * 60,
    )


def _clear_refresh_cookie(response: JSONResponse) -> None:
    """Expire the refresh token cookie immediately."""
    response.delete_cookie(key=_REFRESH_COOKIE_NAME, path=_REFRESH_COOKIE_PATH)


router = APIRouter(prefix=r.BASE, tags=[APITags.AUTH])


@router.post(r.REGISTER, status_code=status.HTTP_201_CREATED, summary="Register a new user")
@limiter.limit("5/minute")
async def register(request: Request, body: RegisterIn, db: AsyncSession = Depends(get_db)) -> JSONResponse:
    """Register a user account and send an email verification OTP."""
    try:
        result = await service.register_user(db=db, name=body.name, email=body.email, password=body.password)
    except AppError as exc:
        raise exc.as_http_exception() from exc
    return JSONResponse(status_code=status.HTTP_201_CREATED, content=result)


@router.post(r.REGISTER_ADMIN, status_code=status.HTTP_201_CREATED, summary="Register an admin user")
@limiter.limit("5/minute")
async def register_admin(request: Request, body: RegisterAdminIn, db: AsyncSession = Depends(get_db)) -> JSONResponse:
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
        raise exc.as_http_exception() from exc
    return JSONResponse(status_code=status.HTTP_201_CREATED, content=result)


@router.post(r.LOGIN, summary="Login with email and password")
@limiter.limit("10/minute")
async def login(request: Request, body: LoginIn, db: AsyncSession = Depends(get_db)) -> JSONResponse:
    """Authenticate and return access token; refresh token is set as an httpOnly cookie."""
    try:
        result = await service.login_user(db=db, email=body.email, password=body.password)
    except AppError as exc:
        raise exc.as_http_exception() from exc

    # If email verification is required, return without setting cookie
    if result.get("email_verification_required"):
        return JSONResponse(status_code=status.HTTP_200_OK, content=result)

    refresh_token = result.pop("refresh_token")
    response = JSONResponse(status_code=status.HTTP_200_OK, content=result)
    _set_refresh_cookie(response, refresh_token)
    return response


@router.post(r.REFRESH, summary="Refresh access token")
@limiter.limit("20/minute")
async def refresh(request: Request, db: AsyncSession = Depends(get_db)) -> JSONResponse:
    """Read refresh token from httpOnly cookie, verify via Redis, issue new pair (rotation)."""
    refresh_token = request.cookies.get(_REFRESH_COOKIE_NAME)
    if not refresh_token:
        raise AuthError(ErrorCodes.INVALID_TOKEN, ResponseMessages.REFRESH_TOKEN_INVALID).as_http_exception()
    try:
        payload = decode_refresh_token(refresh_token)
        user_id = int(payload["sub"])
    except Exception as exc:
        raise AuthError(ErrorCodes.INVALID_TOKEN, ResponseMessages.REFRESH_TOKEN_INVALID).as_http_exception() from exc
    try:
        result = await service.refresh_tokens(db=db, user_id=user_id, refresh_token=refresh_token)
    except AppError as exc:
        raise exc.as_http_exception() from exc
    new_refresh = result.pop("refresh_token")
    response = JSONResponse(status_code=status.HTTP_200_OK, content=result)
    _set_refresh_cookie(response, new_refresh)
    return response


@router.post(r.LOGOUT, summary="Logout — revoke refresh token")
async def logout(
    current_user: User = Depends(get_current_user),
) -> JSONResponse:
    """Delete the Redis refresh token and clear the httpOnly cookie."""
    result = await service.logout_user(user_id=current_user.id)
    response = JSONResponse(status_code=status.HTTP_200_OK, content=result)
    _clear_refresh_cookie(response)
    return response


@router.post(r.VERIFY_OTP, summary="Verify email OTP")
@limiter.limit("5/minute")
async def verify_otp(request: Request, body: VerifyOtpIn, db: AsyncSession = Depends(get_db)) -> JSONResponse:
    """Verify an OTP. Email verification sets an httpOnly refresh cookie; password reset returns a reset token."""
    try:
        result = await service.verify_otp(db=db, email=body.email, otp=body.otp, purpose=body.purpose.value)
    except AppError as exc:
        raise exc.as_http_exception() from exc
    refresh_token = result.pop("refresh_token", None)
    response = JSONResponse(status_code=status.HTTP_200_OK, content=result)
    if refresh_token:
        _set_refresh_cookie(response, refresh_token)
    return response


@router.post(r.RESEND_OTP, summary="Resend OTP")
@limiter.limit("3/minute")
async def resend_otp(request: Request, body: ResendOtpIn, db: AsyncSession = Depends(get_db)) -> JSONResponse:
    """Invalidate the current OTP and send a fresh one."""
    try:
        result = await service.resend_otp(db=db, email=body.email, purpose=body.purpose.value)
    except AppError as exc:
        raise exc.as_http_exception() from exc
    return JSONResponse(status_code=status.HTTP_200_OK, content=result)


@router.post(r.FORGOT_PASSWORD, summary="Request a password reset OTP")
@limiter.limit("3/minute")
async def forgot_password(request: Request, body: ForgotPasswordIn, db: AsyncSession = Depends(get_db)) -> JSONResponse:
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
        result = await service.change_password(db=db, user_id=current_user.id, new_password=body.new_password)
    except AppError as exc:
        raise exc.as_http_exception() from exc
    return JSONResponse(status_code=status.HTTP_200_OK, content=result)
