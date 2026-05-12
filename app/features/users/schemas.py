"""Users feature Pydantic schemas."""

from datetime import datetime

from pydantic import BaseModel, EmailStr, Field


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


class UserUpdateIn(BaseModel):
    name: str | None = Field(default=None, min_length=2, max_length=100)


class CreateUserIn(BaseModel):
    """Schema for creating a new user (admin only)."""
    
    name: str = Field(min_length=2, max_length=100)
    email: EmailStr
    password: str = Field(min_length=8, max_length=100)
    is_active: bool = True


class AdminUserUpdateIn(BaseModel):
    """Schema for updating user details (admin only)."""
    
    name: str | None = Field(default=None, min_length=2, max_length=100)
    email: EmailStr | None = None
    is_active: bool | None = None
