"""006 seed default roles and permissions

Revision ID: 006
Revises: 005
Create Date: 2025-01-01 00:06:00
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy import table, column, String, Integer, Text

revision = "006"
down_revision = "005"
branch_labels = None
depends_on = None


roles_table = table(
    "roles",
    column("id", Integer),
    column("name", String),
    column("description", String),
)

permissions_table = table(
    "permissions",
    column("id", Integer),
    column("name", String),
    column("resource", String),
    column("action", String),
    column("description", Text),
)

role_permissions_table = table(
    "role_permissions",
    column("role_id", Integer),
    column("permission_id", Integer),
)


ROLES = [
    {"id": 1, "name": "super_admin", "description": "Full access to everything"},
    {"id": 2, "name": "admin", "description": "Admin access"},
    {"id": 3, "name": "manager", "description": "Manager access"},
    {"id": 4, "name": "user", "description": "Standard user"},
]

PERMISSIONS = [
    {"id": 1,  "name": "users:read",        "resource": "users",       "action": "read",   "description": None},
    {"id": 2,  "name": "users:write",       "resource": "users",       "action": "write",  "description": None},
    {"id": 3,  "name": "users:delete",      "resource": "users",       "action": "delete", "description": None},
    {"id": 4,  "name": "roles:read",        "resource": "roles",       "action": "read",   "description": None},
    {"id": 5,  "name": "roles:write",       "resource": "roles",       "action": "write",  "description": None},
    {"id": 6,  "name": "roles:delete",      "resource": "roles",       "action": "delete", "description": None},
    {"id": 7,  "name": "permissions:read",  "resource": "permissions", "action": "read",   "description": None},
    {"id": 8,  "name": "permissions:write", "resource": "permissions", "action": "write",  "description": None},
    {"id": 9,  "name": "permissions:delete","resource": "permissions", "action": "delete", "description": None},
    {"id": 10, "name": "profile:read",      "resource": "profile",     "action": "read",   "description": None},
    {"id": 11, "name": "profile:write",     "resource": "profile",     "action": "write",  "description": None},
]

ROLE_PERMISSIONS = {
    1: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11],   # super_admin — all
    2: [1, 2, 3, 4, 7, 10, 11],                # admin
    3: [1, 4, 10, 11],                         # manager
    4: [10, 11],                               # user
}


def upgrade() -> None:
    op.bulk_insert(roles_table, ROLES)
    op.bulk_insert(permissions_table, PERMISSIONS)
    rp_rows = [
        {"role_id": role_id, "permission_id": perm_id}
        for role_id, perm_ids in ROLE_PERMISSIONS.items()
        for perm_id in perm_ids
    ]
    op.bulk_insert(role_permissions_table, rp_rows)


def downgrade() -> None:
    conn = op.get_bind()
    conn.execute(role_permissions_table.delete())
    conn.execute(permissions_table.delete())
    conn.execute(roles_table.delete())
