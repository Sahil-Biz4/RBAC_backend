"""Model registry — import every ORM model here so ``Base.metadata`` is fully populated.

Alembic's ``env.py`` imports ``Base`` from ``app.core.database`` (which re-exports it
from ``app.models.base``). For autogenerate to detect all tables, every model class
must be imported before ``Base.metadata`` is inspected. This file is the single place
that guarantees all models are registered.
"""

from app.models.associations import RolePermission, UserRole
from app.models.base import Base
from app.models.email_otp import EmailOtp
from app.models.permission import Permission
from app.models.role import Role
from app.models.user import User


__all__ = [
    "Base",
    "User",
    "Role",
    "Permission",
    "UserRole",
    "RolePermission",
    "EmailOtp",
]
