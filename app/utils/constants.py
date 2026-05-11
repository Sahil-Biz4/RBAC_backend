"""Feature-level user-facing string constants — all response messages and domain values."""

# ── Project metadata ───────────────────────────────────────────────────────
PROJECT_NAME = "Auth Module"
VERSION = "1.0.0"
APP_NAME = "AuthModule"
SUPPORT_EMAIL = "support@yourdomain.com"
BRAND_COLOR = "#1a1a2e"

# ── Default Roles ──────────────────────────────────────────────────────────
class RoleNames:
    SUPER_ADMIN = "super_admin"
    ADMIN = "admin"
    MANAGER = "manager"
    USER = "user"

    ALL = [SUPER_ADMIN, ADMIN, MANAGER, USER]
    DEFAULT = USER
    ADMIN_ROLES = [SUPER_ADMIN, ADMIN]


# ── Default Permissions (resource:action format) ───────────────────────────
class Permissions:
    # Users
    USERS_READ = "users:read"
    USERS_WRITE = "users:write"
    USERS_DELETE = "users:delete"

    # Roles
    ROLES_READ = "roles:read"
    ROLES_WRITE = "roles:write"
    ROLES_DELETE = "roles:delete"

    # Permissions
    PERMISSIONS_READ = "permissions:read"
    PERMISSIONS_WRITE = "permissions:write"
    PERMISSIONS_DELETE = "permissions:delete"

    # Profile
    PROFILE_READ = "profile:read"
    PROFILE_WRITE = "profile:write"

    ALL = [
        USERS_READ, USERS_WRITE, USERS_DELETE,
        ROLES_READ, ROLES_WRITE, ROLES_DELETE,
        PERMISSIONS_READ, PERMISSIONS_WRITE, PERMISSIONS_DELETE,
        PROFILE_READ, PROFILE_WRITE,
    ]


# ── Default Role → Permission mapping (used in seed migration) ─────────────
DEFAULT_ROLE_PERMISSIONS: dict[str, list[str]] = {
    RoleNames.SUPER_ADMIN: Permissions.ALL,
    RoleNames.ADMIN: [
        Permissions.USERS_READ, Permissions.USERS_WRITE, Permissions.USERS_DELETE,
        Permissions.ROLES_READ,
        Permissions.PERMISSIONS_READ,
        Permissions.PROFILE_READ, Permissions.PROFILE_WRITE,
    ],
    RoleNames.MANAGER: [
        Permissions.USERS_READ,
        Permissions.ROLES_READ,
        Permissions.PROFILE_READ, Permissions.PROFILE_WRITE,
    ],
    RoleNames.USER: [
        Permissions.PROFILE_READ, Permissions.PROFILE_WRITE,
    ],
}


# ── Machine-readable codes (for API clients / i18n) ───────────────────────
class ResponseCodes:
    # Auth
    REGISTER_SUCCESS = "register_success"
    LOGIN_SUCCESS = "login_success"
    LOGOUT_SUCCESS = "logout_success"
    TOKEN_REFRESHED = "token_refreshed"
    OTP_VERIFIED = "otp_verified"
    OTP_RESENT = "otp_resent"
    OTP_SENT = "otp_sent"
    PASSWORD_RESET_EMAIL_SENT = "password_reset_email_sent"
    PASSWORD_CHANGED = "password_changed"

    # Users
    USER_DELETED = "user_deleted"
    PROFILE_UPDATED = "profile_updated"


class ErrorCodes:
    # Auth
    INVALID_CREDENTIALS = "invalid_credentials"
    INVALID_TOKEN = "invalid_token"
    INVALID_TOKEN_SCOPE = "invalid_token_scope"
    TOKEN_REPLAYED = "token_replayed"
    TOKEN_NOT_FOUND = "token_not_found"
    EMAIL_EXISTS = "email_exists"
    EMAIL_NOT_VERIFIED = "email_not_verified"
    ACCOUNT_INACTIVE = "account_inactive"
    INVALID_OTP = "invalid_otp"
    OTP_MAX_ATTEMPTS = "otp_max_attempts"
    OTP_RESEND_LIMIT = "otp_resend_limit"
    FORBIDDEN = "forbidden"

    # Resource
    USER_NOT_FOUND = "user_not_found"
    ROLE_NOT_FOUND = "role_not_found"
    PERMISSION_NOT_FOUND = "permission_not_found"

    # Conflict
    ROLE_EXISTS = "role_exists"
    PERMISSION_EXISTS = "permission_exists"
    ROLE_ALREADY_ASSIGNED = "role_already_assigned"
    PERMISSION_ALREADY_ASSIGNED = "permission_already_assigned"

    # Admin
    INVALID_ADMIN_SECRET = "invalid_admin_secret"

    # Permissions sync
    PERMISSIONS_CHANGED = "permissions_changed"


# ── Response Messages ──────────────────────────────────────────────────────
class ResponseMessages:
    # Auth
    REGISTER_SUCCESS = "Account created successfully. Please verify your email."
    LOGIN_SUCCESS = "Login successful."
    LOGOUT_SUCCESS = "Logged out successfully."
    TOKEN_REFRESHED = "Token refreshed successfully."
    OTP_SENT = "OTP sent to your email address."
    OTP_VERIFIED = "Email verified successfully."
    OTP_RESENT = "OTP resent successfully."
    PASSWORD_RESET_EMAIL_SENT = "Password reset instructions sent to your email."
    PASSWORD_CHANGED = "Password changed successfully."

    # Errors — Auth
    INVALID_CREDENTIALS = "Invalid email or password."
    INVALID_TOKEN = "Invalid or expired token."
    INVALID_TOKEN_SCOPE = "Token scope is invalid for this operation."
    TOKEN_BLACKLISTED = "Token has been revoked. Please log in again."
    EMAIL_ALREADY_EXISTS = "An account with this email already exists."
    EMAIL_NOT_VERIFIED = "Please verify your email before logging in."
    ACCOUNT_INACTIVE = "Your account is inactive. Please contact support."
    INVALID_OTP = "Invalid or expired OTP."
    OTP_MAX_ATTEMPTS = "Maximum OTP attempts exceeded. Please request a new OTP."
    OTP_RESEND_LIMIT = "Maximum OTP resend limit reached. Please try again later."
    OTP_ALREADY_USED = "This OTP has already been used."
    INVALID_ADMIN_SECRET = "Invalid admin secret key."
    REFRESH_TOKEN_INVALID = "Invalid or expired refresh token."

    # Errors — Users
    USER_NOT_FOUND = "User not found."
    USER_DELETED = "User deleted successfully."
    CANNOT_DELETE_SELF = "You cannot delete your own account."

    # Errors — Roles & Permissions
    ROLE_NOT_FOUND = "Role not found."
    ROLE_ALREADY_EXISTS = "A role with this name already exists."
    PERMISSION_NOT_FOUND = "Permission not found."
    PERMISSION_ALREADY_EXISTS = "A permission with this name already exists."
    ROLE_ALREADY_ASSIGNED = "This role is already assigned to the user."
    PERMISSION_ALREADY_ASSIGNED = "This permission is already assigned to the role."
    ROLE_NOT_ASSIGNED = "This role is not assigned to the user."
    PERMISSION_NOT_ASSIGNED = "This permission is not assigned to the role."
    CANNOT_DELETE_DEFAULT_ROLE = "Default system roles cannot be deleted."

    # Access control
    ADMIN_ONLY = "Admin access required."
    FORBIDDEN = "You do not have permission to perform this action."
    PERMISSION_DENIED = "You lack the required permission: {permission}."
    ROLE_DENIED = "You lack the required role: {role}."

    # Permissions sync
    PERMISSIONS_CHANGED = "Your permissions have changed. Please re-authenticate."
