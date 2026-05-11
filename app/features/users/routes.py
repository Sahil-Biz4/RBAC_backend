"""Users feature HTTP routes."""

from fastapi import APIRouter, Depends, Path, status
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth.dependencies import get_current_user
from app.core.auth.rbac import require_permission
from app.core.constants import APITags
from app.core.database import get_db
from app.core.exceptions import AppError
from app.features.users import repository as repo
from app.features.users import service
from app.features.users.routes_definition import routes as r
from app.features.users.schemas import UserOut, UserUpdateIn
from app.models.user import User
from app.utils.constants import Permissions, ResponseCodes


router = APIRouter(prefix=r.BASE, tags=[APITags.USERS])


def _user_out(user: User) -> dict:
    """Serialise a User ORM object to a JSON-safe dict."""
    return UserOut.model_validate(
        {
            "id": user.id,
            "name": user.name,
            "email": user.email,
            "is_active": user.is_active,
            "is_email_verified": user.is_email_verified,
            "roles": [{"id": ur.role.id, "name": ur.role.name} for ur in user.user_roles],
            "created_at": user.created_at,
        }
    ).model_dump(mode="json")


@router.get(r.ME, summary="Get current user profile")
async def get_me(current_user: User = Depends(get_current_user)) -> JSONResponse:
    """Return the authenticated user's profile and roles."""
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={"success": True, "user": _user_out(current_user)},
    )


@router.get("/perms-version", summary="Check permissions version")
async def check_perms_version(current_user: User = Depends(get_current_user)) -> JSONResponse:
    """Lightweight endpoint to check if the user's permissions have changed.
    
    Returns 401 with error_code=permissions_changed if the JWT's perms_version
    is stale, triggering the frontend to refresh. Otherwise returns current version.
    """
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={"success": True, "perms_version": current_user.perms_version},
    )


@router.put(r.ME, summary="Update current user profile")
async def update_me(
    body: UserUpdateIn,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> JSONResponse:
    """Update the authenticated user's display name."""
    if body.name:
        current_user = await repo.update_user_name(db=db, user=current_user, name=body.name)
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={"success": True, "success_code": ResponseCodes.PROFILE_UPDATED, "user": _user_out(current_user)},
    )


@router.get(
    "",
    summary="List all users (admin)",
    dependencies=[Depends(require_permission(Permissions.USERS_READ))],
)
async def list_users(
    skip: int = 0,
    limit: int = 50,
    db: AsyncSession = Depends(get_db),
) -> JSONResponse:
    """Return a paginated list of all users. Requires ``users:read`` permission."""
    try:
        result = await service.list_users(db=db, skip=skip, limit=limit)
    except AppError as exc:
        raise exc.as_http_exception()
    users_out = [_user_out(u) for u in result["users"]]
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={"success": True, "users": users_out, "total": result["total"]},
    )


@router.get(
    r.BY_ID,
    summary="Get user by ID (admin)",
    dependencies=[Depends(require_permission(Permissions.USERS_READ))],
)
async def get_user(
    user_id: int = Path(..., gt=0),
    db: AsyncSession = Depends(get_db),
) -> JSONResponse:
    """Return a single user by ID. Requires ``users:read`` permission."""
    try:
        user = await service.get_user_by_id(db=db, user_id=user_id)
    except AppError as exc:
        raise exc.as_http_exception()
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={"success": True, "user": _user_out(user)},
    )


@router.delete(
    r.BY_ID,
    summary="Delete user (admin)",
    dependencies=[Depends(require_permission(Permissions.USERS_DELETE))],
)
async def delete_user(
    user_id: int = Path(..., gt=0),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> JSONResponse:
    """Soft-delete a user by UUID. Requires ``users:delete`` permission. Cannot delete self."""
    try:
        result = await service.delete_user(
            db=db, user_id=user_id, requesting_user_id=current_user.id
        )
    except AppError as exc:
        raise exc.as_http_exception()
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content=result,
    )
