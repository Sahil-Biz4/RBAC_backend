"""Core system-level constants — never hardcode these values directly in the codebase."""

from enum import Enum


# ── JWT ────────────────────────────────────────────────────────────────────
JWT_ALGORITHM = "HS256"
JWT_ACCESS_TOKEN_EXPIRE_MINUTES = 15
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


# ── Audit Events ───────────────────────────────────────────────────────────
class AuditEvent(str, Enum):
    """Machine-readable codes for all security-relevant audit log events."""

    # Authentication
    LOGIN_SUCCESS = "LOGIN_SUCCESS"
    LOGIN_FAILED = "LOGIN_FAILED"
    LOGOUT = "LOGOUT"
    REGISTER = "REGISTER"
    REGISTER_ADMIN = "REGISTER_ADMIN"

    # Session
    SESSION_REVOKED = "SESSION_REVOKED"
    ALL_SESSIONS_REVOKED = "ALL_SESSIONS_REVOKED"
    TOKEN_REFRESHED = "TOKEN_REFRESHED"
    TOKEN_REPLAY_DETECTED = "TOKEN_REPLAY_DETECTED"

    # Email / OTP
    EMAIL_VERIFIED = "EMAIL_VERIFIED"
    OTP_SENT = "OTP_SENT"
    OTP_RESENT = "OTP_RESENT"
    OTP_VERIFIED = "OTP_VERIFIED"
    OTP_FAILED = "OTP_FAILED"
    OTP_MAX_ATTEMPTS = "OTP_MAX_ATTEMPTS"

    # Password
    PASSWORD_RESET_REQUESTED = "PASSWORD_RESET_REQUESTED"
    PASSWORD_RESET = "PASSWORD_RESET"
    PASSWORD_CHANGED = "PASSWORD_CHANGED"

    # Admin
    ROLE_ASSIGNED = "ROLE_ASSIGNED"
    ROLE_REVOKED = "ROLE_REVOKED"
    PERMISSION_ASSIGNED = "PERMISSION_ASSIGNED"
    PERMISSION_REVOKED = "PERMISSION_REVOKED"
    USER_DELETED = "USER_DELETED"


# ── CORS ───────────────────────────────────────────────────────────────────
CORS_WILDCARD = "*"
CORS_ALLOWED_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"]
CORS_ALLOWED_HEADERS = ["Content-Type", "Authorization"]

# ── Rate Limiting ──────────────────────────────────────────────────────────
class RateLimits:
    DEFAULT_GLOBAL = "200/minute"
    AUTH_STRICT = "10/minute"
    OTP_RESEND = "5/minute"


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
    RATE_LIMIT_EXCEEDED = "Too many requests. Please slow down and try again later."
    UNAUTHORIZED = "Authentication required."
    FORBIDDEN = "You do not have permission to perform this action."
    NOT_FOUND = "The requested resource was not found."
