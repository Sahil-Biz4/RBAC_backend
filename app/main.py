"""Application entry point — creates and configures the FastAPI instance."""

import asyncio
import logging
import sys

from fastapi import Depends, FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config.settings import settings
from app.core.logging_config import configure_logging

configure_logging(environment=settings.environment)

from app.core.constants import (
    APITags,
    CORS_WILDCARD,
    ErrorMessages,
    HealthCheckFields,
    HealthCheckStatus,
    ResponseFields,
    RoutePaths,
)
from app.core.database import get_db
from app.core.middleware.auth import AuthMiddleware
from app.core.middleware.request_logging import RequestLoggingMiddleware
from app.core.middleware.security_headers import SecurityHeadersMiddleware
from app.features.admin.routes import router as admin_router
from app.features.auth.routes import router as auth_router
from app.features.auth.routes_definition import routes as auth_routes
from app.features.users.routes import router as users_router
from app.utils.constants import PROJECT_NAME, VERSION


if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

logger = logging.getLogger(__name__)

import app.models  # noqa: E402, F401 — ensure all ORM models are registered in metadata


def create_app() -> FastAPI:
    """Build and return the FastAPI application with all middleware and routers.

    Middleware order (outermost → innermost):
        RequestLoggingMiddleware → SecurityHeadersMiddleware → AuthMiddleware → CORSMiddleware

    Routers:
        /api/v1/auth   — public auth endpoints
        /api/v1/users  — authenticated user endpoints
        /api/v1/admin  — admin-only role/permission management
    """
    docs_url = None if settings.environment == "production" else "/docs"
    redoc_url = None if settings.environment == "production" else "/redoc"
    openapi_url = None if settings.environment == "production" else "/openapi.json"

    app = FastAPI(
        title=PROJECT_NAME,
        version=VERSION,
        docs_url=docs_url,
        redoc_url=redoc_url,
        openapi_url=openapi_url,
    )

    @app.exception_handler(Exception)
    async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        """Catch all unhandled exceptions and return a safe error response."""
        logger.exception("Unhandled exception: %s", exc)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={ResponseFields.SUCCESS: False, ResponseFields.MESSAGE: ErrorMessages.INTERNAL_SERVER_ERROR},
        )

    app.add_middleware(RequestLoggingMiddleware)
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(
        AuthMiddleware,
        excluded_prefixes=[
            auth_routes.BASE,
            RoutePaths.DOCS,
            RoutePaths.REDOC,
            RoutePaths.OPENAPI_JSON,
            RoutePaths.HEALTH,
        ],
    )

    if settings.cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.cors_origins,
            allow_credentials=True,
            allow_methods=[CORS_WILDCARD],
            allow_headers=[CORS_WILDCARD],
        )

    @app.get(RoutePaths.HEALTH, tags=[APITags.HEALTH], summary="Health check")
    async def health_check(db: AsyncSession = Depends(get_db)) -> JSONResponse:
        """Verify service and database are reachable."""
        health = {
            HealthCheckFields.STATUS: HealthCheckStatus.HEALTHY,
            HealthCheckFields.SERVICE: HealthCheckStatus.OK,
            HealthCheckFields.DATABASE: HealthCheckStatus.OK,
        }
        try:
            await db.execute(text("SELECT 1"))
        except Exception as exc:
            logger.error("Database health check failed: %s", exc)
            health[HealthCheckFields.STATUS] = HealthCheckStatus.UNHEALTHY
            health[HealthCheckFields.DATABASE] = HealthCheckStatus.UNREACHABLE
            return JSONResponse(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, content=health)

        return JSONResponse(status_code=status.HTTP_200_OK, content=health)

    app.include_router(auth_router)
    app.include_router(users_router)
    app.include_router(admin_router)

    return app


app = create_app()
