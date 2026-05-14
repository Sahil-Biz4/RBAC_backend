"""Shared SQLAlchemy eager-load strategies for reuse across feature repositories."""

from sqlalchemy.orm import selectinload

from app.models.associations import RolePermission, UserRole
from app.models.role import Role
from app.models.user import User


USER_WITH_ROLES_AND_PERMISSIONS = (
    selectinload(User.user_roles)
    .selectinload(UserRole.role)
    .selectinload(Role.role_permissions)
    .selectinload(RolePermission.permission)
)
