"""Password hashing and verification using argon2-cffi directly."""

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError


_ph = PasswordHasher()


def hash_password(plain_password: str) -> str:
    """Return an Argon2id hash of the given plain-text password."""
    return _ph.hash(plain_password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Return True if plain_password matches the stored Argon2id hash."""
    try:
        return _ph.verify(hashed_password, plain_password)
    except VerifyMismatchError:
        return False
    except (VerificationError, InvalidHashError):
        return False


def needs_rehash(hashed_password: str) -> bool:
    """Return True if the hash parameters are outdated and should be re-hashed on next login."""
    return _ph.check_needs_rehash(hashed_password)
