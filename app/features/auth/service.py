"""Auth service — public API re-exported from focused sub-modules.

Sub-modules:
    account_service — register_user, register_admin
    session_service — login_user, refresh_tokens, logout_user
    otp_service     — verify_otp, resend_otp, forgot_password, change_password
"""

from app.features.auth.account_service import register_admin, register_user
from app.features.auth.otp_service import change_password, forgot_password, resend_otp, verify_otp
from app.features.auth.session_service import login_user, logout_user, refresh_tokens


__all__ = [
    "register_user",
    "register_admin",
    "login_user",
    "refresh_tokens",
    "logout_user",
    "verify_otp",
    "resend_otp",
    "forgot_password",
    "change_password",
]
