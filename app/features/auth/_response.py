"""Shared auth response builders."""

from app.core.constants import TokenTypes


def build_token_response(access_token: str, refresh_token: str, success_code: str) -> dict:
    return {
        "success": True,
        "success_code": success_code,
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": TokenTypes.BEARER,
    }
