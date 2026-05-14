"""Unit tests for password hashing and verification."""

from app.core.auth.password import hash_password, needs_rehash, verify_password


class TestHashPassword:
    def test_returns_non_empty_string(self):
        result = hash_password("MyPassword1!")
        assert isinstance(result, str)
        assert len(result) > 0

    def test_hash_is_not_plaintext(self):
        pw = "MyPassword1!"
        assert hash_password(pw) != pw

    def test_two_hashes_of_same_password_differ(self):
        pw = "MyPassword1!"
        assert hash_password(pw) != hash_password(pw)

    def test_argon2_prefix_present(self):
        result = hash_password("MyPassword1!")
        assert result.startswith("$argon2")


class TestVerifyPassword:
    def test_correct_password_returns_true(self):
        pw = "CorrectPassword1!"
        hashed = hash_password(pw)
        assert verify_password(pw, hashed) is True

    def test_wrong_password_returns_false(self):
        hashed = hash_password("CorrectPassword1!")
        assert verify_password("WrongPassword1!", hashed) is False

    def test_empty_password_returns_false(self):
        hashed = hash_password("CorrectPassword1!")
        assert verify_password("", hashed) is False

    def test_case_sensitive(self):
        hashed = hash_password("Password1!")
        assert verify_password("password1!", hashed) is False

    def test_malformed_hash_returns_false(self):
        """A completely invalid (non-Argon2) hash must return False, not raise."""
        assert verify_password("AnyPassword1!", "not-a-valid-hash") is False

    def test_truncated_hash_returns_false(self):
        """A partially-valid Argon2 hash that is truncated must return False."""
        assert verify_password("AnyPassword1!", "$argon2id$v=19$m=65536") is False


class TestNeedsRehash:
    def test_fresh_argon2_hash_does_not_need_rehash(self):
        hashed = hash_password("TestPassword1!")
        assert needs_rehash(hashed) is False
