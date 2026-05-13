"""Singleton slowapi rate limiter.

Initialised once at module level and imported by auth routes.
Set RATE_LIMIT_ENABLED=false in the test environment to skip limits.
"""

from slowapi import Limiter
from slowapi.util import get_remote_address


limiter = Limiter(key_func=get_remote_address)
