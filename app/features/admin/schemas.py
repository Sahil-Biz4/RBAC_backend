"""Admin feature Pydantic schemas."""

from pydantic import BaseModel, Field, field_validator


class RoleIn(BaseModel):
    name: str = Field(..., min_length=2, max_length=50)
    description: str | None = Field(default=None, max_length=255)


class RoleOut(BaseModel):
    id: int
    name: str
    description: str | None
    permissions: list["PermissionOut"] = []

    model_config = {"from_attributes": True}


# Whitelist of allowed resources (features that are implemented)
ALLOWED_RESOURCES = {
    'users',
    'roles', 
    'permissions',
    'profile',
}

# Whitelist of allowed actions (standard CRUD operations)
ALLOWED_ACTIONS = {
    'read',
    'create',
    'update',
    'delete',
}


class PermissionIn(BaseModel):
    name: str = Field(..., min_length=3, max_length=100, pattern=r"^[a-z_]+:[a-z_]+$")
    resource: str = Field(..., min_length=2, max_length=50, pattern=r"^[a-z][a-z0-9_]*$")
    action: str = Field(..., min_length=2, max_length=50)
    description: str | None = Field(default=None, max_length=255)

    @field_validator('resource')
    @classmethod
    def validate_resource_implemented(cls, v: str) -> str:
        """Only allow creating permissions for implemented features."""
        if v not in ALLOWED_RESOURCES:
            raise ValueError(
                f"Resource '{v}' is not implemented. "
                f"Allowed resources: {', '.join(sorted(ALLOWED_RESOURCES))}. "
                f"Please implement the feature first or contact the development team."
            )
        return v

    @field_validator('action')
    @classmethod
    def validate_action_allowed(cls, v: str) -> str:
        """Only allow standard CRUD actions."""
        if v not in ALLOWED_ACTIONS:
            raise ValueError(
                f"Action '{v}' is not allowed. "
                f"Allowed actions: {', '.join(sorted(ALLOWED_ACTIONS))}."
            )
        return v

    @field_validator('name')
    @classmethod
    def validate_name_matches_parts(cls, v: str, info) -> str:
        """Ensure name matches resource:action format."""
        if ':' not in v:
            raise ValueError("Permission name must be in format 'resource:action'")
        
        parts = v.split(':')
        if len(parts) != 2:
            raise ValueError("Permission name must have exactly one colon separator")
        
        name_resource, name_action = parts
        
        # Check if resource and action from name match the fields
        resource = info.data.get('resource')
        action = info.data.get('action')
        
        if resource and name_resource != resource:
            raise ValueError(
                f"Resource in name '{name_resource}' doesn't match resource field '{resource}'"
            )
        
        if action and name_action != action:
            raise ValueError(
                f"Action in name '{name_action}' doesn't match action field '{action}'"
            )
        
        return v


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
