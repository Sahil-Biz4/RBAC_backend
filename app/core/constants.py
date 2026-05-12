"""Core system-level constants — never hardcode these values directly in the codebase."""

from enum import Enum


# ── JWT ────────────────────────────────────────────────────────────────────
JWT_ALGORITHM = "HS256"
JWT_ACCESS_TOKEN_EXPIRE_MINUTES = 2
JWT_REFRESH_TOKEN_EXPIRE_MINUTES = 10080  # 7 days
PASSWORD_RESET_TOKEN_EXPIRE_MINUTES = 15

JWT_SCOPE_ACCESS = "access"
JWT_SCOPE_REFRESH = "refresh"
JWT_SCOPE_PASSWORD_RESET = "password_reset"

# ── OTP ────────────────────────────────────────────────────────────────────
OTP_EXPIRE_MINUTES = 10
OTP_MAX_VERIFY_ATTEMPTS = 5
OTP_LOCKOUT_MINUTES = 15
OTP_MAX_RESENDS = 5
OTP_RESEND_WINDOW_MINUTES = 60
OTP_LENGTH = 6
OTP_PURPOSE_EMAIL_VERIFY = "email_verification"
OTP_PURPOSE_PASSWORD_RESET = "password_reset"


class OtpPurpose(str, Enum):
    """Valid OTP purposes — used as Pydantic schema field type to prevent arbitrary strings."""

    EMAIL_VERIFICATION = "email_verification"
    PASSWORD_RESET = "password_reset"


# ── CORS ───────────────
CORS_WILDCARD = "*"


# ── API Tags ───────────────────────────────────────────────────────────────
class APITags:
    AUTH = "Auth"
    USERS = "Users"
    ADMIN = "Admin"
    SESSIONS = "Sessions"
    HEALTH = "Health"


# ── Route Paths ────────────────────────────────────────────────────────────
class RoutePaths:
    HEALTH = "/health"
    DOCS = "/docs"
    REDOC = "/redoc"
    OPENAPI_JSON = "/openapi.json"


# ── Response field keys ────────────────────────────────────────────────────
class ResponseFields:
    SUCCESS = "success"
    MESSAGE = "message"
    DATA = "data"
    ACCESS_TOKEN = "access_token"
    REFRESH_TOKEN = "refresh_token"
    TOKEN_TYPE = "token_type"


# ── Health check ───────────────────────────────────────────────────────────
class HealthCheckFields:
    STATUS = "status"
    SERVICE = "service"
    DATABASE = "database"


class HealthCheckStatus:
    HEALTHY = "healthy"
    UNHEALTHY = "unhealthy"
    OK = "ok"
    UNREACHABLE = "unreachable"


# ── Error Messages ─────────────────────────────────────────────────────────
class ErrorMessages:
    INTERNAL_SERVER_ERROR = "An unexpected error occurred. Please try again later."
    UNAUTHORIZED = "Authentication required."
    FORBIDDEN = "You do not have permission to perform this action."
    NOT_FOUND = "The requested resource was not found."
