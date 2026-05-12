"""RBAC dependency factories — reusable role and permission enforcement for any route.

Permissions are checked via exact string match only (e.g. "roles:read").
Higher-privilege actions do NOT automatically grant lower ones — each
permission must be explicitly assigned to a role.
"""

from collections.abc import Callable

from fastapi import Depends, HTTPException, Request, status

from app.utils.constants import ErrorCodes, ResponseMessages


def _get_token_payload(request: Request) -> dict:
    """Extract the pre-validated JWT payload from request state.

    The AuthMiddleware populates request.state.token_payload before any route
    handler is called, so this function never re-decodes the token.

    Raises:
        HTTPException 401: If the payload is absent (unauthenticated request).
    """
    payload = getattr(request.state, "token_payload", None)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"success": False, "message": ResponseMessages.INVALID_TOKEN},
        )
    return payload


def require_role(role: str) -> Callable:
    """Return a FastAPI dependency that enforces a single required role.

    Usage:
        @router.delete("/users/{id}", dependencies=[Depends(require_role("admin"))])

    Args:
        role: The role name the user must possess (e.g. "admin", "super_admin").

    Returns:
        FastAPI dependency function.
    """

    async def _dependency(payload: dict = Depends(_get_token_payload)) -> None:
        user_roles: list[str] = payload.get("roles", [])
        if role not in user_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "success": False,
                    "message": ResponseMessages.ROLE_DENIED.format(role=role),
                    "error_code": ErrorCodes.FORBIDDEN,
                },
            )

    return _dependency


def require_any_role(roles: list[str]) -> Callable:
    """Return a dependency that passes if the user holds AT LEAST ONE of the given roles.

    Usage:
        @router.get("/dashboard", dependencies=[Depends(require_any_role(["admin", "manager"]))])

    Args:
        roles: List of acceptable role names (OR logic).

    Returns:
        FastAPI dependency function.
    """

    async def _dependency(payload: dict = Depends(_get_token_payload)) -> None:
        user_roles: list[str] = payload.get("roles", [])
        if not any(r in user_roles for r in roles):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "success": False,
                    "message": ResponseMessages.FORBIDDEN,
                    "error_code": ErrorCodes.FORBIDDEN,
                },
            )

    return _dependency


def require_permission(permission: str) -> Callable:
    """Return a dependency that enforces a single fine-grained permission.

    Usage:
        @router.post("/reports", dependencies=[Depends(require_permission("reports:write"))])

    Args:
        permission: The permission string in "resource:action" format.

    Returns:
        FastAPI dependency function.
    """

    async def _dependency(payload: dict = Depends(_get_token_payload)) -> None:
        user_permissions: list[str] = payload.get("permissions", [])
        if permission not in user_permissions:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "success": False,
                    "message": ResponseMessages.PERMISSION_DENIED.format(permission=permission),
                    "error_code": ErrorCodes.FORBIDDEN,
                },
            )

    return _dependency


def require_any_permission(permissions: list[str]) -> Callable:
    """Return a dependency that passes if the user holds AT LEAST ONE of the given permissions.

    Args:
        permissions: List of permission strings (OR logic).

    Returns:
        FastAPI dependency function.
    """

    async def _dependency(payload: dict = Depends(_get_token_payload)) -> None:
        user_permissions: list[str] = payload.get("permissions", [])
        if not any(p in user_permissions for p in permissions):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "success": False,
                    "message": ResponseMessages.FORBIDDEN,
                    "error_code": ErrorCodes.FORBIDDEN,
                },
            )

    return _dependency


def require_all_permissions(permissions: list[str]) -> Callable:
    """Return a dependency that passes only if the user holds ALL given permissions.

    Args:
        permissions: List of permission strings (AND logic).

    Returns:
        FastAPI dependency function.
    """

    async def _dependency(payload: dict = Depends(_get_token_payload)) -> None:
        user_permissions: list[str] = payload.get("permissions", [])
        missing = [p for p in permissions if p not in user_permissions]
        if missing:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "success": False,
                    "message": ResponseMessages.PERMISSION_DENIED.format(permission=", ".join(missing)),
                    "error_code": ErrorCodes.FORBIDDEN,
                },
            )

    return _dependency
