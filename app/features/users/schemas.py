"""Users feature Pydantic schemas."""

from datetime import datetime
from typing import Self

from pydantic import BaseModel, EmailStr, Field, field_validator, model_validator

from app.utils.validators import validate_password_strength as _validate_password_strength


class UserRoleOut(BaseModel):
    """Serialises a role assigned to a user."""

    id: int
    name: str

    model_config = {"from_attributes": True}


class UserOut(BaseModel):
    """Serialises a complete user profile for API responses."""

    id: int
    name: str
    email: EmailStr
    is_active: bool
    is_email_verified: bool
    roles: list[UserRoleOut]
    created_at: datetime

    model_config = {"from_attributes": True}

    @classmethod
    def from_user(cls, user: "User") -> dict:  # type: ignore[name-defined]  # noqa: F821
        return cls.model_validate(
            {
                "id": user.id,
                "name": user.name,
                "email": user.email,
                "is_active": user.is_active,
                "is_email_verified": user.is_email_verified,
                "roles": [{"id": ur.role.id, "name": ur.role.name} for ur in user.user_roles],
                "created_at": user.created_at,
            }
        ).model_dump(mode="json")


class UserUpdateIn(BaseModel):
    name: str | None = Field(default=None, min_length=2, max_length=100)


class CreateUserIn(BaseModel):
    """Schema for creating a new user (admin only)."""

    name: str = Field(min_length=2, max_length=100)
    email: EmailStr
    password: str = Field(min_length=8, max_length=100)
    is_active: bool = True


class ChangeMyPasswordIn(BaseModel):
    """Schema for an authenticated user changing their own password."""

    current_password: str = Field(..., min_length=1, max_length=64)
    new_password: str = Field(..., min_length=8, max_length=64)
    confirm_password: str = Field(..., min_length=8, max_length=64)

    @field_validator("new_password")
    @classmethod
    def validate_new_password_strength(cls, v: str) -> str:
        return _validate_password_strength(v)

    @model_validator(mode="after")
    def validate_passwords(self) -> Self:
        if self.new_password == self.current_password:
            raise ValueError("New password cannot be the same as your current password.")
        if self.new_password != self.confirm_password:
            raise ValueError("Passwords do not match.")
        return self


class AdminUserUpdateIn(BaseModel):
    """Schema for updating user details (admin only)."""

    name: str | None = Field(default=None, min_length=2, max_length=100)
    email: EmailStr | None = None
    is_active: bool | None = None
