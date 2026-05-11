"""JWT authentication middleware — validates Bearer tokens and populates request.state."""

import logging

import jwt
from fastapi import status
from fastapi.responses import JSONResponse
from jwt.exceptions import PyJWTError
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from app.core.config.settings import settings
from app.core.constants import JWT_SCOPE_ACCESS, ResponseFields
from app.utils.constants import ResponseMessages


logger = logging.getLogger(__name__)


class AuthMiddleware(BaseHTTPMiddleware):
    """Validate the Bearer JWT on every request, except excluded path prefixes.

    On success: attaches the decoded payload to ``request.state.token_payload``.
    On failure: returns a 401 JSON response immediately without calling the route.

    The payload includes 'sub', 'email', 'roles', 'permissions', 'jti', and 'scope'.
    Route-level dependencies read roles/permissions from the payload — no DB hit required.
    """

    def __init__(self, app, excluded_prefixes: list[str] | None = None) -> None:
        super().__init__(app)
        self._excluded_prefixes: list[str] = excluded_prefixes or []

    async def dispatch(self, request: Request, call_next) -> Response:
        if self._is_excluded(request.url.path):
            return await call_next(request)

        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return self._unauthorized(ResponseMessages.INVALID_TOKEN)

        token = auth_header.removeprefix("Bearer ").strip()
        try:
            payload = jwt.decode(token, settings.jwt_secret_key, algorithms=[settings.jwt_algorithm])
        except PyJWTError:
            return self._unauthorized(ResponseMessages.INVALID_TOKEN)

        if payload.get("scope") != JWT_SCOPE_ACCESS:
            return self._unauthorized(ResponseMessages.INVALID_TOKEN)

        request.state.token_payload = payload
        return await call_next(request)

    def _is_excluded(self, path: str) -> bool:
        return any(path.startswith(prefix) for prefix in self._excluded_prefixes)

    @staticmethod
    def _unauthorized(message: str) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={ResponseFields.SUCCESS: False, ResponseFields.MESSAGE: message},
        )
