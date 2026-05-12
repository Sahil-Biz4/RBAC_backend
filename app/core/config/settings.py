"""Application settings — loaded automatically from environment variables and .env files.

Uses pydantic-settings BaseSettings for automatic env loading, type coercion,
and validation. Supports mode-specific .env files (local/development/staging/production).
Zero manual os.environ.get() calls — all values are declarative field definitions.
"""

import os
from pathlib import Path

from pydantic import Field, computed_field, field_validator
from pydantic_settings import BaseSettings

from app.core import constants


def _resolve_env_files() -> list[str]:
    """Return an ordered list of .env file paths to load, most-specific first.

    The MODE env var selects the environment (default: local).
    Supported modes: local | development | staging | production
    Falls back to .env if a mode-specific file does not exist.
    """
    mode = os.getenv("MODE", "local").lower()
    mode_map = {
        "production": ".env.production",
        "development": ".env.development",
        "staging": ".env.staging",
        "local": ".env.local",
    }
    candidates = [mode_map.get(mode, ".env.local"), ".env"]
    return [f for f in candidates if Path(f).exists()]


class Settings(BaseSettings):
    """Centralised application configuration.

    All fields map directly to environment variables (case-insensitive).
    Required fields (no default) will raise a ValidationError at startup if missing.
    Optional fields fall back to the constant defaults defined in core.constants.
    """

    # ── Environment ─────────────────────────────────────────────────────────
    mode: str = Field(default="local", alias="MODE")

    # ── Database ─────────────────────────────────────────────────────────────
    database_url: str = Field(alias="DATABASE_URL")

    # ── JWT ──────────────────────────────────────────────────────────────────
    jwt_secret_key: str = Field(alias="JWT_SECRET_KEY")
    jwt_algorithm: str = Field(default=constants.JWT_ALGORITHM, alias="JWT_ALGORITHM")
    jwt_access_token_expire_minutes: int = Field(
        default=constants.JWT_ACCESS_TOKEN_EXPIRE_MINUTES,
        alias="JWT_ACCESS_TOKEN_EXPIRE_MINUTES",
    )
    jwt_refresh_token_expire_minutes: int = Field(
        default=constants.JWT_REFRESH_TOKEN_EXPIRE_MINUTES,
        alias="JWT_REFRESH_TOKEN_EXPIRE_MINUTES",
    )
    password_reset_token_expire_minutes: int = Field(
        default=constants.PASSWORD_RESET_TOKEN_EXPIRE_MINUTES,
        alias="PASSWORD_RESET_TOKEN_EXPIRE_MINUTES",
    )

    # ── OTP ──────────────────────────────────────────────────────────────────
    otp_secret_key: str = Field(default="", alias="OTP_SECRET_KEY")
    otp_expire_minutes: int = Field(default=constants.OTP_EXPIRE_MINUTES, alias="OTP_EXPIRE_MINUTES")
    otp_max_verify_attempts: int = Field(
        default=constants.OTP_MAX_VERIFY_ATTEMPTS,
        alias="OTP_MAX_VERIFY_ATTEMPTS",
    )
    otp_lockout_minutes: int = Field(default=constants.OTP_LOCKOUT_MINUTES, alias="OTP_LOCKOUT_MINUTES")
    otp_max_resends: int = Field(default=constants.OTP_MAX_RESENDS, alias="OTP_MAX_RESENDS")
    otp_resend_window_minutes: int = Field(
        default=constants.OTP_RESEND_WINDOW_MINUTES,
        alias="OTP_RESEND_WINDOW_MINUTES",
    )

    # ── Email ─────────────────────────────────────────────────────────────────
    sendgrid_api_key: str = Field(default="", alias="SENDGRID_API_KEY")
    sendgrid_from_email: str = Field(default="", alias="SENDGRID_FROM_EMAIL")

    # ── Redis ─────────────────────────────────────────────────────────────────
    redis_url: str = Field(default="redis://localhost:6379/0", alias="REDIS_URL")

    # ── CORS ─────────────────────────────────────────────────────────────────
    cors_origins_raw: str = Field(default="", alias="CORS_ORIGINS")
    cors_allowed_methods_raw: str = Field(
        default="GET,POST,PUT,DELETE,PATCH", alias="CORS_ALLOWED_METHODS"
    )
    cors_allowed_headers_raw: str = Field(
        default="Content-Type,Authorization", alias="CORS_ALLOWED_HEADERS"
    )

    # ── Admin ─────────────────────────────────────────────────────────────────
    admin_secret_key: str = Field(default="", alias="ADMIN_SECRET_KEY")

    # ── Docs Auth ─────────────────────────────────────────────────────────────
    docs_username: str = Field(default="", alias="DOCS_USERNAME")
    docs_password: str = Field(default="", alias="DOCS_PASSWORD")

    @field_validator("jwt_secret_key")
    @classmethod
    def _jwt_secret_must_not_be_empty(cls, v: str) -> str:
        if not v:
            raise ValueError("JWT_SECRET_KEY must be set and non-empty.")
        return v

    @field_validator("admin_secret_key")
    @classmethod
    def _admin_secret_must_not_be_empty(cls, v: str) -> str:
        if not v:
            raise ValueError("ADMIN_SECRET_KEY must be set and non-empty.")
        return v

    @computed_field  # type: ignore[misc]
    @property
    def environment(self) -> str:
        """Alias for 'mode' — used throughout the codebase for environment checks."""
        return self.mode

    @computed_field  # type: ignore[misc]
    @property
    def cors_origins(self) -> list[str]:
        """Parse the comma-separated CORS_ORIGINS string into a list."""
        if not self.cors_origins_raw:
            return []
        return [o.strip() for o in self.cors_origins_raw.split(",") if o.strip()]

    @computed_field  # type: ignore[misc]
    @property
    def cors_allowed_methods(self) -> list[str]:
        """Parse the comma-separated CORS_ALLOWED_METHODS string into a list."""
        return [m.strip() for m in self.cors_allowed_methods_raw.split(",") if m.strip()]

    @computed_field  # type: ignore[misc]
    @property
    def cors_allowed_headers(self) -> list[str]:
        """Parse the comma-separated CORS_ALLOWED_HEADERS string into a list."""
        return [h.strip() for h in self.cors_allowed_headers_raw.split(",") if h.strip()]

    @computed_field  # type: ignore[misc]
    @property
    def effective_otp_secret(self) -> str:
        """The secret key used for HMAC-based OTP hashing.

        Falls back to the JWT secret key if OTP_SECRET_KEY is not set.
        Setting a dedicated OTP_SECRET_KEY is strongly recommended in production.
        """
        return self.otp_secret_key or self.jwt_secret_key

    model_config = {
        "env_file": _resolve_env_files(),
        "env_file_encoding": "utf-8",
        "populate_by_name": True,
        "extra": "ignore",
    }


settings = Settings()
