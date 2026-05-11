"""Password hashing and verification — Argon2 primary, PBKDF2-SHA256 legacy fallback."""

from passlib.context import CryptContext


_pwd_context = CryptContext(
    schemes=["argon2", "pbkdf2_sha256"],
    deprecated="auto",
)


def hash_password(plain_password: str) -> str:
    """Return an Argon2 hash of the given plain-text password."""
    return _pwd_context.hash(plain_password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Return True if plain_password matches the stored hash.

    Handles both Argon2 (current) and PBKDF2-SHA256 (legacy) hashes transparently.
    """
    return _pwd_context.verify(plain_password, hashed_password)


def needs_rehash(hashed_password: str) -> bool:
    """Return True if the hash was created with a deprecated scheme and should be upgraded."""
    return _pwd_context.needs_update(hashed_password)
