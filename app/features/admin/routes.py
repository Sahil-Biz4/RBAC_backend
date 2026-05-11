"""Admin feature HTTP routes — role and permission management."""

from fastapi import APIRouter, Depends, HTTPException, Path, status
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth.rbac import require_any_role
from app.core.constants import APITags, ResponseFields
from app.core.database import get_db
from app.features.admin import repository as repo
from app.features.admin.routes_definition import routes as r
from app.features.admin.schemas import AssignPermissionIn, AssignRoleIn, PermissionIn, RoleIn
from app.utils.constants import Permissions, ResponseMessages, RoleNames


_admin_gate = [Depends(require_any_role(RoleNames.ADMIN_ROLES))]

router = APIRouter(prefix=r.BASE, tags=[APITags.ADMIN], dependencies=_admin_gate)


# ── Roles ──────────────────────────────────────────────────────────────────

@router.get(r.ROLES, summary="List all roles")
async def list_roles(db: AsyncSession = Depends(get_db)) -> JSONResponse:
    roles = await repo.get_all_roles(db=db)
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={
            ResponseFields.SUCCESS: True,
            "roles": [
                {
                    "id": role.id,
                    "name": role.name,
                    "description": role.description,
                    "permissions": [rp.permission.name for rp in role.role_permissions],
                }
                for role in roles
            ],
        },
    )


@router.post(r.ROLES, status_code=status.HTTP_201_CREATED, summary="Create a role")
async def create_role(body: RoleIn, db: AsyncSession = Depends(get_db)) -> JSONResponse:
    existing = await repo.get_role_by_name(db=db, name=body.name)
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={ResponseFields.SUCCESS: False, ResponseFields.MESSAGE: ResponseMessages.ROLE_ALREADY_EXISTS},
        )
    role = await repo.create_role(db=db, name=body.name, description=body.description)
    return JSONResponse(
        status_code=status.HTTP_201_CREATED,
        content={
            ResponseFields.SUCCESS: True,
            "role": {"id": role.id, "name": role.name, "description": role.description, "permissions": []},
        },
    )


@router.put(r.ROLE_BY_ID, summary="Update a role")
async def update_role(
    body: RoleIn,
    role_id: int = Path(..., gt=0),
    db: AsyncSession = Depends(get_db),
) -> JSONResponse:
    role = await repo.get_role_by_id(db=db, role_id=role_id)
    if not role:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={ResponseFields.SUCCESS: False, ResponseFields.MESSAGE: ResponseMessages.ROLE_NOT_FOUND},
        )
    if role.name in RoleNames.ALL and body.name != role.name:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={ResponseFields.SUCCESS: False, ResponseFields.MESSAGE: ResponseMessages.CANNOT_DELETE_DEFAULT_ROLE},
        )
    role = await repo.update_role(db=db, role=role, name=body.name, description=body.description)
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={
            ResponseFields.SUCCESS: True,
            "role": {
                "id": role.id,
                "name": role.name,
                "description": role.description,
                "permissions": [rp.permission.name for rp in role.role_permissions],
            },
        },
    )


@router.delete(r.ROLE_BY_ID, summary="Delete a role")
async def delete_role(
    role_id: int = Path(..., gt=0),
    db: AsyncSession = Depends(get_db),
) -> JSONResponse:
    role = await repo.get_role_by_id(db=db, role_id=role_id)
    if not role:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={ResponseFields.SUCCESS: False, ResponseFields.MESSAGE: ResponseMessages.ROLE_NOT_FOUND},
        )
    if role.name in RoleNames.ALL:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={ResponseFields.SUCCESS: False, ResponseFields.MESSAGE: ResponseMessages.CANNOT_DELETE_DEFAULT_ROLE},
        )
    await repo.delete_role(db=db, role=role)
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={ResponseFields.SUCCESS: True, ResponseFields.MESSAGE: "Role deleted."},
    )


# ── Role ↔ Permission assignments ─────────────────────────────────────────

@router.post(r.ROLE_PERMISSIONS, summary="Assign permission to role")
async def assign_permission_to_role(
    body: AssignPermissionIn,
    role_id: int = Path(..., gt=0),
    db: AsyncSession = Depends(get_db),
) -> JSONResponse:
    role = await repo.get_role_by_id(db=db, role_id=role_id)
    if not role:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={ResponseFields.SUCCESS: False, ResponseFields.MESSAGE: ResponseMessages.ROLE_NOT_FOUND},
        )
    permission = await repo.get_permission_by_id(db=db, permission_id=body.permission_id)
    if not permission:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={ResponseFields.SUCCESS: False, ResponseFields.MESSAGE: ResponseMessages.PERMISSION_NOT_FOUND},
        )
    assigned = await repo.assign_permission_to_role(db=db, role_id=role_id, permission_id=body.permission_id)
    if not assigned:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={ResponseFields.SUCCESS: False, ResponseFields.MESSAGE: ResponseMessages.PERMISSION_ALREADY_ASSIGNED},
        )
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={ResponseFields.SUCCESS: True, ResponseFields.MESSAGE: "Permission assigned to role."},
    )


@router.delete(r.ROLE_PERMISSION_BY_ID, summary="Revoke permission from role")
async def revoke_permission_from_role(
    role_id: int = Path(..., gt=0),
    permission_id: int = Path(..., gt=0),
    db: AsyncSession = Depends(get_db),
) -> JSONResponse:
    removed = await repo.revoke_permission_from_role(db=db, role_id=role_id, permission_id=permission_id)
    if not removed:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={ResponseFields.SUCCESS: False, ResponseFields.MESSAGE: ResponseMessages.PERMISSION_NOT_ASSIGNED},
        )
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={ResponseFields.SUCCESS: True, ResponseFields.MESSAGE: "Permission revoked from role."},
    )


# ── Permissions ────────────────────────────────────────────────────────────

@router.get(r.PERMISSIONS, summary="List all permissions")
async def list_permissions(db: AsyncSession = Depends(get_db)) -> JSONResponse:
    permissions = await repo.get_all_permissions(db=db)
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={
            ResponseFields.SUCCESS: True,
            "permissions": [
                {"id": p.id, "name": p.name, "resource": p.resource, "action": p.action, "description": p.description}
                for p in permissions
            ],
        },
    )


@router.post(r.PERMISSIONS, status_code=status.HTTP_201_CREATED, summary="Create a permission")
async def create_permission(body: PermissionIn, db: AsyncSession = Depends(get_db)) -> JSONResponse:
    existing = await repo.get_permission_by_name(db=db, name=body.name)
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={ResponseFields.SUCCESS: False, ResponseFields.MESSAGE: ResponseMessages.PERMISSION_ALREADY_EXISTS},
        )
    permission = await repo.create_permission(
        db=db, name=body.name, resource=body.resource, action=body.action, description=body.description
    )
    return JSONResponse(
        status_code=status.HTTP_201_CREATED,
        content={
            ResponseFields.SUCCESS: True,
            "permission": {
                "id": permission.id,
                "name": permission.name,
                "resource": permission.resource,
                "action": permission.action,
                "description": permission.description,
            },
        },
    )


@router.delete(r.PERMISSION_BY_ID, summary="Delete a permission")
async def delete_permission(
    permission_id: int = Path(..., gt=0),
    db: AsyncSession = Depends(get_db),
) -> JSONResponse:
    permission = await repo.get_permission_by_id(db=db, permission_id=permission_id)
    if not permission:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={ResponseFields.SUCCESS: False, ResponseFields.MESSAGE: ResponseMessages.PERMISSION_NOT_FOUND},
        )
    await repo.delete_permission(db=db, permission=permission)
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={ResponseFields.SUCCESS: True, ResponseFields.MESSAGE: "Permission deleted."},
    )


# ── User ↔ Role assignments ────────────────────────────────────────────────

@router.get(r.USER_ROLES, summary="Get roles assigned to a user")
async def get_user_roles(
    user_id: int = Path(..., gt=0),
    db: AsyncSession = Depends(get_db),
) -> JSONResponse:
    user = await repo.get_user_with_roles(db=db, user_id=user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={ResponseFields.SUCCESS: False, ResponseFields.MESSAGE: ResponseMessages.USER_NOT_FOUND},
        )
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={
            ResponseFields.SUCCESS: True,
            "roles": [{"id": ur.role.id, "name": ur.role.name} for ur in user.user_roles],
        },
    )


@router.post(r.USER_ROLES, summary="Assign role to user")
async def assign_role_to_user(
    body: AssignRoleIn,
    user_id: int = Path(..., gt=0),
    db: AsyncSession = Depends(get_db),
) -> JSONResponse:
    user = await repo.get_user_with_roles(db=db, user_id=user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={ResponseFields.SUCCESS: False, ResponseFields.MESSAGE: ResponseMessages.USER_NOT_FOUND},
        )
    role = await repo.get_role_by_id(db=db, role_id=body.role_id)
    if not role:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={ResponseFields.SUCCESS: False, ResponseFields.MESSAGE: ResponseMessages.ROLE_NOT_FOUND},
        )
    assigned = await repo.assign_role_to_user(db=db, user_id=user_id, role_id=body.role_id)
    if not assigned:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={ResponseFields.SUCCESS: False, ResponseFields.MESSAGE: ResponseMessages.ROLE_ALREADY_ASSIGNED},
        )
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={ResponseFields.SUCCESS: True, ResponseFields.MESSAGE: "Role assigned to user."},
    )


@router.delete(r.USER_ROLE_BY_ID, summary="Revoke role from user")
async def revoke_role_from_user(
    user_id: int = Path(..., gt=0),
    role_id: int = Path(..., gt=0),
    db: AsyncSession = Depends(get_db),
) -> JSONResponse:
    removed = await repo.revoke_role_from_user(db=db, user_id=user_id, role_id=role_id)
    if not removed:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={ResponseFields.SUCCESS: False, ResponseFields.MESSAGE: ResponseMessages.ROLE_NOT_ASSIGNED},
        )
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={ResponseFields.SUCCESS: True, ResponseFields.MESSAGE: "Role revoked from user."},
    )
