"""Domain exception hierarchy.

Services raise these typed exceptions instead of ``HTTPException``.
Route handlers catch them and map them to the appropriate HTTP response.
This keeps HTTP concerns out of the business logic layer.

Usage in a service::

    from app.core.exceptions import AuthError, NotFoundError

    raise AuthError("INVALID_CREDENTIALS", "Invalid email or password.")

Usage in a route handler::

    from app.core.exceptions import AppError

    try:
        result = await service.login_user(...)
    except AppError as exc:
        raise exc.as_http_exception()
"""

from __future__ import annotations

from fastapi import HTTPException, status


class AppError(Exception):
    """Base class for all application domain exceptions.

    Attributes:
        code:        Machine-readable error code (e.g. ``INVALID_CREDENTIALS``).
        message:     Human-readable default message.
        status_code: HTTP status code this error maps to.
    """

    status_code: int = status.HTTP_500_INTERNAL_SERVER_ERROR

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message

    def as_http_exception(self) -> HTTPException:
        """Convert this domain exception into a FastAPI HTTPException."""
        return HTTPException(
            status_code=self.status_code,
            detail={"success": False, "error_code": self.code, "message": self.message},
        )


# ── Auth ─────────────────────────────────────────────────────────────────────


class AuthError(AppError):
    """Authentication failure — invalid credentials, bad OTP, etc."""

    status_code = status.HTTP_401_UNAUTHORIZED


class ForbiddenError(AppError):
    """Authorisation failure — valid credentials but insufficient permissions."""

    status_code = status.HTTP_403_FORBIDDEN


class TokenError(AppError):
    """Invalid, expired, or revoked JWT token."""

    status_code = status.HTTP_401_UNAUTHORIZED


# ── Resource ─────────────────────────────────────────────────────────────────


class NotFoundError(AppError):
    """Requested resource does not exist."""

    status_code = status.HTTP_404_NOT_FOUND


class ConflictError(AppError):
    """Resource already exists or violates a uniqueness constraint."""

    status_code = status.HTTP_409_CONFLICT


class BadRequestError(AppError):
    """Invalid request that violates a domain constraint (e.g. modifying a protected resource)."""

    status_code = status.HTTP_400_BAD_REQUEST


# ── Input / Validation ───────────────────────────────────────────────────────


class ValidationError(AppError):
    """Request payload failed domain-level validation."""

    status_code = status.HTTP_422_UNPROCESSABLE_ENTITY


class RateLimitError(AppError):
    """Client has exceeded the allowed request rate."""

    status_code = status.HTTP_429_TOO_MANY_REQUESTS


# ── Session ──────────────────────────────────────────────────────────────────


class SessionError(AppError):
    """Session-related failure — revoked, expired, or not found."""

    status_code = status.HTTP_401_UNAUTHORIZED
