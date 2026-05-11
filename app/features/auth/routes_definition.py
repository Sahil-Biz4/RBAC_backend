"""Auth feature route path constants."""


class AuthRoutes:
    BASE = "/api/v1/auth"
    REGISTER = "/register"
    REGISTER_ADMIN = "/register-admin"
    LOGIN = "/login"
    REFRESH = "/refresh"
    LOGOUT = "/logout"
    VERIFY_OTP = "/verify-otp"
    RESEND_OTP = "/resend-otp"
    FORGOT_PASSWORD = "/forgot-password"
    CHANGE_PASSWORD = "/change-password"


routes = AuthRoutes()
