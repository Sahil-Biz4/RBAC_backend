"""Model registry — import every ORM model here so ``Base.metadata`` is fully populated.

Alembic's ``env.py`` imports ``Base`` from ``app.core.database`` (which re-exports it
from ``app.models.base``). For autogenerate to detect all tables, every model class
must be imported before ``Base.metadata`` is inspected. This file is the single place
that guarantees all models are registered.
"""

from app.models.associations import RolePermission, UserRole  # noqa: F401
from app.models.base import Base  # noqa: F401
from app.models.email_otp import EmailOtp  # noqa: F401
from app.models.permission import Permission  # noqa: F401
from app.models.refresh_token import RefreshToken  # noqa: F401
from app.models.role import Role  # noqa: F401
from app.models.user import User  # noqa: F401

__all__ = [
    "Base",
    "User",
    "Role",
    "Permission",
    "UserRole",
    "RolePermission",
    "EmailOtp",
    "RefreshToken",
]
