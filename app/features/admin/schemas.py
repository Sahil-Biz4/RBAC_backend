"""Admin feature Pydantic schemas."""

from pydantic import BaseModel, Field, field_validator, model_validator

from app.core.config.settings import settings


class RoleIn(BaseModel):
    name: str = Field(..., min_length=2, max_length=50)
    description: str | None = Field(default=None, max_length=255)


class RoleOut(BaseModel):
    id: int
    name: str
    description: str | None
    permissions: list["PermissionOut"] = []

    model_config = {"from_attributes": True}


class PermissionIn(BaseModel):
    name: str = Field(..., min_length=3, max_length=100, pattern=r"^[a-z_]+:[a-z_]+$")
    resource: str = Field(..., min_length=2, max_length=50, pattern=r"^[a-z][a-z0-9_]*$")
    action: str = Field(..., min_length=2, max_length=50)
    description: str | None = Field(default=None, max_length=255)

    @field_validator("resource")
    @classmethod
    def validate_resource_implemented(cls, v: str) -> str:
        """Only allow creating permissions for implemented features."""
        allowed = settings.allowed_resources
        if v not in allowed:
            raise ValueError(
                f"Resource '{v}' is not implemented. "
                f"Allowed resources: {', '.join(sorted(allowed))}. "
                f"Please implement the feature first or contact the development team."
            )
        return v

    @field_validator("action")
    @classmethod
    def validate_action_allowed(cls, v: str) -> str:
        """Only allow standard CRUD actions."""
        allowed = settings.allowed_actions
        if v not in allowed:
            raise ValueError(f"Action '{v}' is not allowed. Allowed actions: {', '.join(sorted(allowed))}.")
        return v

    @model_validator(mode="after")
    def validate_name_matches_parts(self) -> "PermissionIn":
        """Ensure name matches resource:action format."""
        if ":" not in self.name:
            raise ValueError("Permission name must be in format 'resource:action'")

        parts = self.name.split(":")
        if len(parts) != 2:
            raise ValueError("Permission name must have exactly one colon separator")

        name_resource, name_action = parts

        if self.resource and name_resource != self.resource:
            raise ValueError(f"Resource in name '{name_resource}' doesn't match resource field '{self.resource}'")

        if self.action and name_action != self.action:
            raise ValueError(f"Action in name '{name_action}' doesn't match action field '{self.action}'")

        return self


class PermissionOut(BaseModel):
    id: int
    name: str
    resource: str
    action: str
    description: str | None

    model_config = {"from_attributes": True}


RoleOut.model_rebuild()


class AssignRoleIn(BaseModel):
    role_id: int = Field(..., gt=0)


class AssignPermissionIn(BaseModel):
    permission_id: int = Field(..., gt=0)
