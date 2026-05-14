"""Shared Pydantic field validators — reusable across all feature schemas."""

import re


_PASSWORD_PATTERN = re.compile(
    r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&#^()\-_=+])[A-Za-z\d@$!%*?&#^()\-_=+]{8,64}$"
)
_PASSWORD_STRENGTH_MSG = (
    "Password must be 8-64 characters and include at least one uppercase letter, "
    "one lowercase letter, one digit, and one special character (@$!%*?&#^()-_=+)."
)


def validate_password_strength(v: str) -> str:
    """Validate password strength — reused across all schemas that set a new password."""
    if not _PASSWORD_PATTERN.match(v):
        raise ValueError(_PASSWORD_STRENGTH_MSG)
    return v
