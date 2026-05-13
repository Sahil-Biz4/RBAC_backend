"""Unit tests for utility helper functions."""

from app.utils.helpers import generate_numeric_otp, hash_otp, mask_email, verify_otp_hash


class TestGenerateNumericOtp:
    def test_returns_string_of_correct_length(self):
        otp = generate_numeric_otp()
        assert isinstance(otp, str)
        assert len(otp) == 6

    def test_all_digits(self):
        otp = generate_numeric_otp()
        assert otp.isdigit()

    def test_custom_length(self):
        otp = generate_numeric_otp(length=8)
        assert len(otp) == 8

    def test_different_each_call(self):
        otps = {generate_numeric_otp() for _ in range(20)}
        assert len(otps) > 1


class TestHashOtp:
    def test_returns_hex_string(self):
        result = hash_otp("123456")
        assert isinstance(result, str)
        assert len(result) == 64  # SHA-256 hex digest

    def test_same_otp_produces_same_hash(self):
        assert hash_otp("123456") == hash_otp("123456")

    def test_different_otps_produce_different_hashes(self):
        assert hash_otp("123456") != hash_otp("654321")


class TestVerifyOtpHash:
    def test_correct_otp_returns_true(self):
        otp = "123456"
        hashed = hash_otp(otp)
        assert verify_otp_hash(otp, hashed) is True

    def test_wrong_otp_returns_false(self):
        hashed = hash_otp("123456")
        assert verify_otp_hash("999999", hashed) is False

    def test_empty_otp_returns_false(self):
        hashed = hash_otp("123456")
        assert verify_otp_hash("", hashed) is False

    def test_tampered_hash_returns_false(self):
        otp = "123456"
        hashed = hash_otp(otp)
        tampered = hashed[:-1] + "X"
        assert verify_otp_hash(otp, tampered) is False


class TestMaskEmail:
    def test_masks_long_local_part(self):
        result = mask_email("john.doe@example.com")
        assert result == "j******e@example.com"

    def test_short_local_part_gets_single_asterisk(self):
        result = mask_email("ab@example.com")
        assert result == "a*@example.com"

    def test_very_short_local_part(self):
        result = mask_email("a@example.com")
        assert result == "a*@example.com"

    def test_domain_is_preserved(self):
        result = mask_email("user@gmail.com")
        assert result.endswith("@gmail.com")

    def test_format_is_correct(self):
        result = mask_email("hello@world.org")
        assert "@" in result
        assert result.endswith("@world.org")
