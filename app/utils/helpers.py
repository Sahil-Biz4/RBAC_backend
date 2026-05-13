"""Shared utility helpers — pure functions with no side effects."""

import hashlib
import hmac
import random
import string

from app.core.config.settings import settings
from app.core.constants import OTP_LENGTH


def generate_numeric_otp(length: int = OTP_LENGTH) -> str:
    """Generate a cryptographically random numeric OTP of the given length."""
    return "".join(random.SystemRandom().choices(string.digits, k=length))


def hash_otp(otp: str) -> str:
    """Return an HMAC-SHA256 hex digest of the OTP.

    Uses ``settings.effective_otp_secret`` as the HMAC key, which defaults to a
    dedicated ``OTP_SECRET_KEY`` env var — completely independent of the JWT secret.
    This decoupling means a JWT secret rotation does not invalidate pending OTPs,
    and vice versa.

    Security properties:
      - Constant-time comparison via ``hmac.compare_digest`` prevents timing attacks.
      - HMAC prevents length-extension attacks vs. plain SHA-256.
      - The key is never stored alongside the hash.
    """
    key = settings.effective_otp_secret.encode()
    return hmac.new(key, otp.encode(), hashlib.sha256).hexdigest()


def verify_otp_hash(otp: str, stored_hash: str) -> bool:
    """Constant-time comparison of an OTP against its stored HMAC hash.

    Always use this instead of ``hash_otp(otp) == stored_hash`` to prevent
    timing side-channel attacks.
    """
    expected = hash_otp(otp)
    return hmac.compare_digest(expected, stored_hash)


def mask_email(email: str) -> str:
    """Return a partially masked email for safe display in responses.

    Example: john.doe@example.com → jo*****e@example.com
    """
    local, _, domain = email.partition("@")
    masked_local = local[0] + "*" if len(local) <= 2 else local[0] + "*" * (len(local) - 2) + local[-1]
    return f"{masked_local}@{domain}"
