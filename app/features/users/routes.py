"""Users feature HTTP routes."""

from fastapi import APIRouter, Depends, Path, Query, status
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth.dependencies import get_current_user
from app.core.auth.rbac import require_permission
from app.core.constants import APITags, ResponseFields
from app.core.database import get_db
from app.core.exceptions import AppError
from app.features.users import service
from app.features.users.routes_definition import routes as r
from app.features.users.schemas import AdminUserUpdateIn, ChangeMyPasswordIn, CreateUserIn, UserOut, UserUpdateIn
from app.models.user import User
from app.utils.constants import Permissions, ResponseCodes


router = APIRouter(prefix=r.BASE, tags=[APITags.USERS])


@router.get(r.ME, summary="Get current user profile")
async def get_me(current_user: User = Depends(get_current_user)) -> JSONResponse:
    """Return the authenticated user's profile and roles."""
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={"success": True, "user": UserOut.from_user(current_user)},
    )


@router.get("/perms-version", summary="Check permissions version")
async def check_perms_version(current_user: User = Depends(get_current_user)) -> JSONResponse:
    """Lightweight endpoint to check if the user's permissions have changed."""
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={"success": True, "perms_version": current_user.perms_version},
    )


@router.post(r.CHANGE_PASSWORD, summary="Change current user password")
async def change_my_password(
    body: ChangeMyPasswordIn,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> JSONResponse:
    """Change password for the currently authenticated user."""
    try:
        result = await service.change_my_password(
            db=db,
            user=current_user,
            current_password=body.current_password,
            new_password=body.new_password,
        )
    except AppError as exc:
        raise exc.as_http_exception() from exc
    return JSONResponse(status_code=status.HTTP_200_OK, content=result)


@router.put(r.ME, summary="Update current user profile")
async def update_me(
    body: UserUpdateIn,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> JSONResponse:
    """Update the authenticated user's display name."""
    try:
        updated = await service.update_my_profile(db=db, user=current_user, name=body.name)
    except AppError as exc:
        raise exc.as_http_exception() from exc
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={"success": True, "success_code": ResponseCodes.PROFILE_UPDATED, "user": UserOut.from_user(updated)},
    )


@router.post(
    "",
    summary="Create user (admin)",
    dependencies=[Depends(require_permission(Permissions.USERS_CREATE))],
)
async def create_user(
    body: CreateUserIn,
    db: AsyncSession = Depends(get_db),
) -> JSONResponse:
    """Create a new user. Requires ``users:create`` permission."""
    try:
        user = await service.create_user(
            db=db, name=body.name, email=body.email, password=body.password, is_active=body.is_active
        )
    except AppError as exc:
        raise exc.as_http_exception() from exc
    return JSONResponse(
        status_code=status.HTTP_201_CREATED,
        content={"success": True, "user": UserOut.from_user(user)},
    )


@router.get(
    "",
    summary="List all users (admin)",
    dependencies=[Depends(require_permission(Permissions.USERS_READ))],
)
async def list_users(
    page: int = 1,
    limit: int = 20,
    search: str | None = Query(default=None, max_length=100),
    db: AsyncSession = Depends(get_db),
) -> JSONResponse:
    """Return a paginated list of all users. Accepts optional ``search`` to filter by name or email."""
    skip = max(0, (page - 1) * limit)
    try:
        result = await service.list_users(db=db, skip=skip, limit=limit, search=search)
    except AppError as exc:
        raise exc.as_http_exception() from exc
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={
            ResponseFields.SUCCESS: True,
            "users": [UserOut.from_user(u) for u in result["users"]],
            "total": result["total"],
            "page": page,
            "limit": limit,
            "has_next": result["has_next"],
            ResponseFields.SEARCH: search,
        },
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
        raise exc.as_http_exception() from exc
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={"success": True, "user": UserOut.from_user(user)},
    )


@router.put(
    r.BY_ID,
    summary="Update user (admin)",
    dependencies=[Depends(require_permission(Permissions.USERS_UPDATE))],
)
async def update_user(
    body: AdminUserUpdateIn,
    user_id: int = Path(..., gt=0),
    db: AsyncSession = Depends(get_db),
) -> JSONResponse:
    """Update user details. Requires ``users:update`` permission."""
    try:
        user = await service.update_user(
            db=db, user_id=user_id, name=body.name, email=body.email, is_active=body.is_active
        )
    except AppError as exc:
        raise exc.as_http_exception() from exc
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={"success": True, "user": UserOut.from_user(user)},
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
    """Soft-delete a user by ID. Requires ``users:delete`` permission. Cannot delete self."""
    try:
        result = await service.delete_user(db=db, user_id=user_id, requesting_user_id=current_user.id)
    except AppError as exc:
        raise exc.as_http_exception() from exc
    return JSONResponse(status_code=status.HTTP_200_OK, content=result)
