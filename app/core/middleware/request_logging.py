"""Request logging middleware — structured logs with correlation ID, method, path, status, duration."""

import logging
import time
import uuid

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response


logger = logging.getLogger(__name__)

_REQUEST_ID_HEADER = "X-Request-ID"


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Attach a unique X-Request-ID to every request and log method/path/status/duration."""

    async def dispatch(self, request: Request, call_next) -> Response:
        request_id = request.headers.get(_REQUEST_ID_HEADER) or str(uuid.uuid4())
        request.state.request_id = request_id

        start = time.perf_counter()
        response = await call_next(request)
        duration_ms = round((time.perf_counter() - start) * 1000, 2)

        response.headers[_REQUEST_ID_HEADER] = request_id

        logger.info(
            "%(method)s %(path)s → %(status)s (%(duration)sms) [%(request_id)s]",
            {
                "method": request.method,
                "path": request.url.path,
                "status": response.status_code,
                "duration": duration_ms,
                "request_id": request_id,
            },
        )

        return response
