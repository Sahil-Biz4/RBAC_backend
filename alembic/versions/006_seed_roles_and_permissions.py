"""006 seed default roles and permissions

Revision ID: 006
Revises: 005
Create Date: 2025-01-01 00:06:00

Updated to remove explicit IDs and properly reset sequences to prevent
primary key conflicts when creating new records.
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
    column("id", Integer),
    column("role_id", Integer),
    column("permission_id", Integer),
)


# Roles WITHOUT explicit IDs — let PostgreSQL auto-generate
ROLES = [
    {"name": "super_admin", "description": "Full access to everything"},
    {"name": "admin", "description": "Admin access"},
    {"name": "manager", "description": "Manager access"},
    {"name": "user", "description": "Standard user"},
]

# Permissions WITHOUT explicit IDs — let PostgreSQL auto-generate
# Using CRUD actions: read, create, update, delete
PERMISSIONS = [
    # Users permissions
    {"name": "users:read",   "resource": "users", "action": "read",   "description": None},
    {"name": "users:create", "resource": "users", "action": "create", "description": None},
    {"name": "users:update", "resource": "users", "action": "update", "description": None},
    {"name": "users:delete", "resource": "users", "action": "delete", "description": None},
    
    # Roles permissions
    {"name": "roles:read",   "resource": "roles", "action": "read",   "description": None},
    {"name": "roles:create", "resource": "roles", "action": "create", "description": None},
    {"name": "roles:update", "resource": "roles", "action": "update", "description": None},
    {"name": "roles:delete", "resource": "roles", "action": "delete", "description": None},
    
    # Permissions permissions
    {"name": "permissions:read",   "resource": "permissions", "action": "read",   "description": None},
    {"name": "permissions:create", "resource": "permissions", "action": "create", "description": None},
    {"name": "permissions:update", "resource": "permissions", "action": "update", "description": None},
    {"name": "permissions:delete", "resource": "permissions", "action": "delete", "description": None},
    
    # Profile permissions
    {"name": "profile:read",   "resource": "profile", "action": "read",   "description": None},
    {"name": "profile:update", "resource": "profile", "action": "update", "description": None},
]


def upgrade() -> None:
    conn = op.get_bind()
    
    # Insert roles (IDs will be auto-generated)
    op.bulk_insert(roles_table, ROLES)
    
    # Insert permissions (IDs will be auto-generated)
    op.bulk_insert(permissions_table, PERMISSIONS)
    
    # Get actual IDs that were generated
    role_result = conn.execute(sa.text("SELECT id, name FROM roles ORDER BY id"))
    role_map = {row[1]: row[0] for row in role_result}
    
    perm_result = conn.execute(sa.text("SELECT id, name FROM permissions ORDER BY id"))
    perm_map = {row[1]: row[0] for row in perm_result}
    
    # Create role-permission associations using actual IDs
    rp_rows = [
        # super_admin — all permissions
        *[{"role_id": role_map["super_admin"], "permission_id": perm_map[p["name"]]} for p in PERMISSIONS],
        
        # admin — users:*, roles:read, permissions:read, profile:*
        {"role_id": role_map["admin"], "permission_id": perm_map["users:read"]},
        {"role_id": role_map["admin"], "permission_id": perm_map["users:create"]},
        {"role_id": role_map["admin"], "permission_id": perm_map["users:update"]},
        {"role_id": role_map["admin"], "permission_id": perm_map["users:delete"]},
        {"role_id": role_map["admin"], "permission_id": perm_map["roles:read"]},
        {"role_id": role_map["admin"], "permission_id": perm_map["permissions:read"]},
        {"role_id": role_map["admin"], "permission_id": perm_map["profile:read"]},
        {"role_id": role_map["admin"], "permission_id": perm_map["profile:update"]},
        
        # manager — users:read, roles:read, profile:*
        {"role_id": role_map["manager"], "permission_id": perm_map["users:read"]},
        {"role_id": role_map["manager"], "permission_id": perm_map["roles:read"]},
        {"role_id": role_map["manager"], "permission_id": perm_map["profile:read"]},
        {"role_id": role_map["manager"], "permission_id": perm_map["profile:update"]},
        
        # user — profile:*
        {"role_id": role_map["user"], "permission_id": perm_map["profile:read"]},
        {"role_id": role_map["user"], "permission_id": perm_map["profile:update"]},
    ]
    
    op.bulk_insert(role_permissions_table, rp_rows)
    
    # CRITICAL: Reset sequences to prevent primary key conflicts
    conn.execute(sa.text("SELECT setval('roles_id_seq', (SELECT MAX(id) FROM roles))"))
    conn.execute(sa.text("SELECT setval('permissions_id_seq', (SELECT MAX(id) FROM permissions))"))
    conn.execute(sa.text("SELECT setval('role_permissions_id_seq', (SELECT MAX(id) FROM role_permissions))"))


def downgrade() -> None:
    conn = op.get_bind()
    conn.execute(sa.text("DELETE FROM role_permissions"))
    conn.execute(sa.text("DELETE FROM permissions"))
    conn.execute(sa.text("DELETE FROM roles"))
