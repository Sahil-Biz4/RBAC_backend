"""Application entry point — creates and configures the FastAPI instance."""

import asyncio
import logging
import sys
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

import app.models  # ensure all ORM models are registered in metadata
from app.core.config.settings import settings
from app.core.constants import (
    APITags,
    ErrorMessages,
    HealthCheckFields,
    HealthCheckStatus,
    ResponseFields,
    RoutePaths,
)
from app.core.database import get_db
from app.core.limiter import limiter
from app.core.logging_config import configure_logging
from app.core.middleware.auth import AuthMiddleware
from app.core.middleware.request_logging import RequestLoggingMiddleware
from app.core.middleware.security_headers import SecurityHeadersMiddleware
from app.core.services.redis_service import redis_service
from app.features.admin.routes import router as admin_router
from app.features.auth.routes import router as auth_router
from app.features.auth.routes_definition import routes as auth_routes
from app.features.users.routes import router as users_router
from app.utils.constants import PROJECT_NAME, VERSION


configure_logging(environment=settings.environment)

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(_: FastAPI):
    await redis_service.connect()
    yield
    await redis_service.disconnect()


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
        lifespan=lifespan,
    )

    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

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
            auth_routes.BASE + auth_routes.REGISTER,
            auth_routes.BASE + auth_routes.REGISTER_ADMIN,
            auth_routes.BASE + auth_routes.LOGIN,
            auth_routes.BASE + auth_routes.REFRESH,
            auth_routes.BASE + auth_routes.VERIFY_OTP,
            auth_routes.BASE + auth_routes.RESEND_OTP,
            auth_routes.BASE + auth_routes.FORGOT_PASSWORD,
            auth_routes.BASE + auth_routes.CHANGE_PASSWORD,
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
            allow_methods=settings.cors_allowed_methods,
            allow_headers=settings.cors_allowed_headers,
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
