"""Typed definitions for JWT payload structures issued by this application."""

from typing import TypedDict


class AccessTokenPayload(TypedDict):
    sub: str
    email: str
    roles: list[str]
    permissions: list[str]
    perms_version: int
    jti: str
    scope: str
    exp: int


class RefreshTokenPayload(TypedDict):
    sub: str
    email: str
    jti: str
    scope: str
    exp: int


class PasswordResetTokenPayload(TypedDict):
    sub: str
    email: str
    scope: str
    exp: int
