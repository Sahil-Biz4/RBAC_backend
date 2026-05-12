"""Auth feature Pydantic request/response schemas."""

import re

from pydantic import BaseModel, EmailStr, Field, field_validator, model_validator
from typing_extensions import Self

from app.core.constants import OtpPurpose


_PASSWORD_PATTERN = re.compile(
    r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&#^()\-_=+])[A-Za-z\d@$!%*?&#^()\-_=+]{8,64}$"
)
_PASSWORD_STRENGTH_MSG = (
    "Password must be 8–64 characters and include at least one uppercase letter, "
    "one lowercase letter, one digit, and one special character (@$!%*?&#^()-_=+)."
)


def _validate_password_strength(v: str) -> str:
    """Shared password strength validator — reused across all registration schemas."""
    if not _PASSWORD_PATTERN.match(v):
        raise ValueError(_PASSWORD_STRENGTH_MSG)
    return v


class RegisterIn(BaseModel):
    name: str = Field(..., min_length=2, max_length=100)
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=64)

    @field_validator("password")
    @classmethod
    def validate_password_strength(cls, v: str) -> str:
        return _validate_password_strength(v)


class RegisterAdminIn(BaseModel):
    name: str = Field(..., min_length=2, max_length=100)
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=64)
    admin_secret_key: str

    @field_validator("password")
    @classmethod
    def validate_password_strength(cls, v: str) -> str:
        return _validate_password_strength(v)


class LoginIn(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=1)


class VerifyOtpIn(BaseModel):
    email: EmailStr
    otp: str = Field(..., min_length=6, max_length=6, pattern=r"^\d{6}$")
    purpose: OtpPurpose


class ResendOtpIn(BaseModel):
    email: EmailStr
    purpose: OtpPurpose


class ForgotPasswordIn(BaseModel):
    email: EmailStr


class RefreshIn(BaseModel):
    refresh_token: str


class ChangePasswordIn(BaseModel):
    new_password: str = Field(..., min_length=8, max_length=64)
    confirm_password: str = Field(..., min_length=8, max_length=64)

    @field_validator("new_password")
    @classmethod
    def validate_password_strength(cls, v: str) -> str:
        return _validate_password_strength(v)

    @model_validator(mode="after")
    def passwords_match(self) -> Self:
        if self.new_password != self.confirm_password:
            raise ValueError("Passwords do not match.")
        return self
