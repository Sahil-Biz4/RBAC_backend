"""Auth feature Pydantic request/response schemas."""

from typing import Self

from pydantic import BaseModel, EmailStr, Field, field_validator, model_validator

from app.core.constants import OtpPurpose
from app.utils.validators import validate_password_strength as _validate_password_strength


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
