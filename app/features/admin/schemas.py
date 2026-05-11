"""Admin feature Pydantic schemas."""

from pydantic import BaseModel, Field


class RoleIn(BaseModel):
    name: str = Field(..., min_length=2, max_length=50)
    description: str | None = Field(default=None, max_length=255)


class RoleOut(BaseModel):
    id: int
    name: str
    description: str | None
    permissions: list[str] = []

    model_config = {"from_attributes": True}


class PermissionIn(BaseModel):
    name: str = Field(..., min_length=3, max_length=100, pattern=r"^[a-z_]+:[a-z_]+$")
    resource: str = Field(..., min_length=2, max_length=50)
    action: str = Field(..., min_length=2, max_length=50)
    description: str | None = Field(default=None, max_length=255)


class PermissionOut(BaseModel):
    id: int
    name: str
    resource: str
    action: str
    description: str | None

    model_config = {"from_attributes": True}


class AssignRoleIn(BaseModel):
    role_id: int = Field(..., gt=0)


class AssignPermissionIn(BaseModel):
    permission_id: int = Field(..., gt=0)
