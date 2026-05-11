"""Standardised API response envelope.

All route handlers should return responses through this wrapper to guarantee
a consistent response structure across the entire API.

Response shape::

    {
        "success": true | false,
        "message": "Human-readable status message",
        "data": <T> | null,
        "error_code": "MACHINE_CODE" | null   (only on errors)
    }

Usage::

    from app.core.response import ApiResponse, success_response, error_response

    # success with data
    return success_response(data={"user": user_dict}, message="Login successful.")

    # success without data
    return success_response(message="Logged out successfully.")

    # error
    return error_response(message="Invalid credentials.", code="INVALID_CREDENTIALS", status_code=401)
"""

from __future__ import annotations

from typing import Generic, TypeVar

from fastapi.responses import JSONResponse
from pydantic import BaseModel


T = TypeVar("T")


class ApiResponse(BaseModel, Generic[T]):
    """Generic response envelope used as the canonical API response shape.

    This Pydantic model is used for OpenAPI schema generation.
    Actual HTTP responses are built via the helper functions below.
    """

    success: bool
    message: str
    data: T | None = None
    error_code: str | None = None


def success_response(
    *,
    message: str,
    data: dict | list | None = None,
    status_code: int = 200,
    extra: dict | None = None,
) -> JSONResponse:
    """Build a successful JSON response.

    Args:
        message:     Human-readable success message.
        data:        Optional response payload.
        status_code: HTTP status code (default 200).
        extra:       Additional top-level keys to merge into the response body.
    """
    body: dict = {"success": True, "message": message}
    if data is not None:
        body["data"] = data
    if extra:
        body.update(extra)
    return JSONResponse(status_code=status_code, content=body)


def error_response(
    *,
    message: str,
    code: str = "ERROR",
    status_code: int = 400,
    extra: dict | None = None,
) -> JSONResponse:
    """Build an error JSON response.

    Args:
        message:     Human-readable error message.
        code:        Machine-readable error code.
        status_code: HTTP status code (default 400).
        extra:       Additional top-level keys to merge into the response body.
    """
    body: dict = {"success": False, "message": message, "error_code": code}
    if extra:
        body.update(extra)
    return JSONResponse(status_code=status_code, content=body)
