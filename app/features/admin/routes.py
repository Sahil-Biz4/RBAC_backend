"""Admin feature HTTP routes — role and permission management."""

from fastapi import APIRouter, Depends, Path, Query, Request, status
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth.dependencies import get_current_user
from app.core.auth.rbac import require_permission
from app.core.constants import APITags, ResponseFields
from app.core.database import get_db
from app.core.exceptions import AppError
from app.core.limiter import limiter
from app.core.response import paginated_json
from app.features.admin import service
from app.features.admin.routes_definition import routes as r
from app.features.admin.schemas import AssignPermissionIn, AssignRoleIn, PermissionIn, RoleIn
from app.utils.constants import Permissions, ResponseMessages


router = APIRouter(
    prefix=r.BASE,
    tags=[APITags.ADMIN],
    dependencies=[Depends(get_current_user)],
)


# ── Roles ──────────────────────────────────────────────────────────────────


@router.get(r.ROLES, summary="List all roles", dependencies=[Depends(require_permission(Permissions.ROLES_READ))])
@limiter.limit("60/minute")
async def list_roles(
    request: Request,
    page: int = Query(default=1, ge=1),
    limit: int = Query(default=20, ge=1, le=100),
    search: str | None = Query(default=None, max_length=100),
    db: AsyncSession = Depends(get_db),
) -> JSONResponse:
    """Return a paginated list of roles. Requires ``roles:read`` permission."""
    skip = max(0, (page - 1) * limit)
    roles, total = await service.list_roles(db=db, skip=skip, limit=limit, search=search)
    roles_data = [
        {
            "id": role.id,
            "name": role.name,
            "description": role.description,
            "permissions": [
                {
                    "id": rp.permission.id,
                    "name": rp.permission.name,
                    "resource": rp.permission.resource,
                    "action": rp.permission.action,
                    "description": rp.permission.description,
                }
                for rp in role.role_permissions
            ],
        }
        for role in roles
    ]
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content=paginated_json("roles", roles_data, total, page, limit, skip, **{ResponseFields.SEARCH: search}),
    )


@router.post(
    r.ROLES,
    status_code=status.HTTP_201_CREATED,
    summary="Create a role",
    dependencies=[Depends(require_permission(Permissions.ROLES_CREATE))],
)
@limiter.limit("30/minute")
async def create_role(request: Request, body: RoleIn, db: AsyncSession = Depends(get_db)) -> JSONResponse:
    try:
        role = await service.create_role(db=db, name=body.name, description=body.description)
    except AppError as exc:
        raise exc.as_http_exception() from exc
    return JSONResponse(
        status_code=status.HTTP_201_CREATED,
        content={
            ResponseFields.SUCCESS: True,
            "role": {"id": role.id, "name": role.name, "description": role.description, "permissions": []},
        },
    )


@router.put(r.ROLE_BY_ID, summary="Update a role", dependencies=[Depends(require_permission(Permissions.ROLES_UPDATE))])
@limiter.limit("30/minute")
async def update_role(
    request: Request,
    body: RoleIn,
    role_id: int = Path(..., gt=0),
    db: AsyncSession = Depends(get_db),
) -> JSONResponse:
    try:
        role = await service.update_role(db=db, role_id=role_id, name=body.name, description=body.description)
    except AppError as exc:
        raise exc.as_http_exception() from exc
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


@router.delete(
    r.ROLE_BY_ID, summary="Delete a role", dependencies=[Depends(require_permission(Permissions.ROLES_DELETE))]
)
@limiter.limit("30/minute")
async def delete_role(
    request: Request,
    role_id: int = Path(..., gt=0),
    db: AsyncSession = Depends(get_db),
) -> JSONResponse:
    try:
        await service.delete_role(db=db, role_id=role_id)
    except AppError as exc:
        raise exc.as_http_exception() from exc
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={ResponseFields.SUCCESS: True, ResponseFields.MESSAGE: ResponseMessages.ROLE_DELETED},
    )


# ── Role ↔ Permission assignments ─────────────────────────────────────────


@router.post(
    r.ROLE_PERMISSIONS,
    summary="Assign permission to role",
    dependencies=[Depends(require_permission(Permissions.ROLES_UPDATE))],
)
@limiter.limit("30/minute")
async def assign_permission_to_role(
    request: Request,
    body: AssignPermissionIn,
    role_id: int = Path(..., gt=0),
    db: AsyncSession = Depends(get_db),
) -> JSONResponse:
    try:
        await service.assign_permission_to_role(db=db, role_id=role_id, permission_id=body.permission_id)
    except AppError as exc:
        raise exc.as_http_exception() from exc
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={ResponseFields.SUCCESS: True, ResponseFields.MESSAGE: ResponseMessages.PERMISSION_ASSIGNED_TO_ROLE},
    )


@router.delete(
    r.ROLE_PERMISSION_BY_ID,
    summary="Revoke permission from role",
    dependencies=[Depends(require_permission(Permissions.ROLES_UPDATE))],
)
@limiter.limit("30/minute")
async def revoke_permission_from_role(
    request: Request,
    role_id: int = Path(..., gt=0),
    permission_id: int = Path(..., gt=0),
    db: AsyncSession = Depends(get_db),
) -> JSONResponse:
    try:
        await service.revoke_permission_from_role(db=db, role_id=role_id, permission_id=permission_id)
    except AppError as exc:
        raise exc.as_http_exception() from exc
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={ResponseFields.SUCCESS: True, ResponseFields.MESSAGE: ResponseMessages.PERMISSION_REVOKED_FROM_ROLE},
    )


# ── Permissions ────────────────────────────────────────────────────────────


@router.get(
    r.PERMISSIONS,
    summary="List all permissions",
    dependencies=[Depends(require_permission(Permissions.PERMISSIONS_READ))],
)
@limiter.limit("60/minute")
async def list_permissions(
    request: Request,
    page: int = Query(default=1, ge=1),
    limit: int = Query(default=20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
) -> JSONResponse:
    skip = max(0, (page - 1) * limit)
    permissions, total = await service.list_permissions(db=db, skip=skip, limit=limit)
    perms_data = [
        {"id": p.id, "name": p.name, "resource": p.resource, "action": p.action, "description": p.description}
        for p in permissions
    ]
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content=paginated_json("permissions", perms_data, total, page, limit, skip),
    )


@router.post(
    r.PERMISSIONS,
    status_code=status.HTTP_201_CREATED,
    summary="Create a permission",
    dependencies=[Depends(require_permission(Permissions.PERMISSIONS_CREATE))],
)
@limiter.limit("30/minute")
async def create_permission(request: Request, body: PermissionIn, db: AsyncSession = Depends(get_db)) -> JSONResponse:
    try:
        permission = await service.create_permission(
            db=db, name=body.name, resource=body.resource, action=body.action, description=body.description
        )
    except AppError as exc:
        raise exc.as_http_exception() from exc
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


@router.delete(
    r.PERMISSION_BY_ID,
    summary="Delete a permission",
    dependencies=[Depends(require_permission(Permissions.PERMISSIONS_DELETE))],
)
@limiter.limit("30/minute")
async def delete_permission(
    request: Request,
    permission_id: int = Path(..., gt=0),
    db: AsyncSession = Depends(get_db),
) -> JSONResponse:
    try:
        await service.delete_permission(db=db, permission_id=permission_id)
    except AppError as exc:
        raise exc.as_http_exception() from exc
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={ResponseFields.SUCCESS: True, ResponseFields.MESSAGE: ResponseMessages.PERMISSION_DELETED},
    )


# ── User ↔ Role assignments ────────────────────────────────────────────────


@router.get(
    r.USER_ROLES,
    summary="Get roles assigned to a user",
    dependencies=[Depends(require_permission(Permissions.USERS_READ))],
)
@limiter.limit("60/minute")
async def get_user_roles(
    request: Request,
    user_id: int = Path(..., gt=0),
    db: AsyncSession = Depends(get_db),
) -> JSONResponse:
    try:
        user = await service.get_user_roles(db=db, user_id=user_id)
    except AppError as exc:
        raise exc.as_http_exception() from exc
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={
            ResponseFields.SUCCESS: True,
            "roles": [{"id": ur.role.id, "name": ur.role.name} for ur in user.user_roles],
        },
    )


@router.post(
    r.USER_ROLES, summary="Assign role to user", dependencies=[Depends(require_permission(Permissions.USERS_UPDATE))]
)
@limiter.limit("30/minute")
async def assign_role_to_user(
    request: Request,
    body: AssignRoleIn,
    user_id: int = Path(..., gt=0),
    db: AsyncSession = Depends(get_db),
) -> JSONResponse:
    try:
        await service.assign_role_to_user(db=db, user_id=user_id, role_id=body.role_id)
    except AppError as exc:
        raise exc.as_http_exception() from exc
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={ResponseFields.SUCCESS: True, ResponseFields.MESSAGE: ResponseMessages.ROLE_ASSIGNED_TO_USER},
    )


@router.delete(
    r.USER_ROLE_BY_ID,
    summary="Revoke role from user",
    dependencies=[Depends(require_permission(Permissions.USERS_UPDATE))],
)
@limiter.limit("30/minute")
async def revoke_role_from_user(
    request: Request,
    user_id: int = Path(..., gt=0),
    role_id: int = Path(..., gt=0),
    db: AsyncSession = Depends(get_db),
) -> JSONResponse:
    try:
        await service.revoke_role_from_user(db=db, user_id=user_id, role_id=role_id)
    except AppError as exc:
        raise exc.as_http_exception() from exc
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={ResponseFields.SUCCESS: True, ResponseFields.MESSAGE: ResponseMessages.ROLE_REVOKED_FROM_USER},
    )
