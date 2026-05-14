"""Unit tests for auth service — calls service functions directly with DB session."""

from unittest.mock import AsyncMock, patch

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth.jwt_handler import create_refresh_token
from app.core.config.settings import settings
from app.core.constants import OtpPurpose
from app.core.exceptions import AuthError, ConflictError, ForbiddenError, NotFoundError, RateLimitError
from app.features.auth import repository as repo
from app.features.auth import service
from app.models.role import Role
from app.models.user import User
from app.utils.helpers import hash_otp


# ── register_user ──────────────────────────────────────────────────────────


class TestRegisterUser:
    async def test_register_new_user_success(self, db: AsyncSession, sample_user_role: Role):
        with patch("app.features.auth.account_service.send_otp_email", new_callable=AsyncMock):
            result = await service.register_user(
                db=db, name="Fresh User", email="fresh@example.com", password="Password1!"
            )
        assert result["success"] is True
        assert result["success_code"] == "register_success"

    async def test_register_stores_user_in_db(self, db: AsyncSession):
        with patch("app.features.auth.account_service.send_otp_email", new_callable=AsyncMock):
            await service.register_user(db=db, name="DB User", email="dbuser@example.com", password="Password1!")
        user = await repo.get_user_by_email(db=db, email="dbuser@example.com")
        assert user is not None
        assert user.name == "DB User"
        assert not user.is_email_verified

    async def test_register_sends_otp_email(self, db: AsyncSession):
        with patch("app.features.auth.account_service.send_otp_email", new_callable=AsyncMock) as mock_email:
            await service.register_user(db=db, name="OTP User", email="otpuser@example.com", password="Password1!")
        mock_email.assert_called_once()

    async def test_register_duplicate_email_raises_conflict(self, db: AsyncSession, sample_user: User):
        with (
            pytest.raises(ConflictError) as exc_info,
            patch("app.features.auth.account_service.send_otp_email", new_callable=AsyncMock),
        ):
            await service.register_user(db=db, name="Dup", email=sample_user.email, password="Password1!")
        assert "email_exists" in str(exc_info.value.code)


# ── register_admin ─────────────────────────────────────────────────────────


class TestRegisterAdmin:
    async def test_correct_secret_returns_success(self, db: AsyncSession):
        result = await service.register_admin(
            db=db,
            name="AdminUser",
            email="admin_svc@example.com",
            password="Password1!",
            secret_key=settings.admin_secret_key,
        )
        assert result["success"] is True

    async def test_admin_user_is_email_verified(self, db: AsyncSession):
        await service.register_admin(
            db=db,
            name="AdminUser",
            email="admin_verified@example.com",
            password="Password1!",
            secret_key=settings.admin_secret_key,
        )
        user = await repo.get_user_by_email(db=db, email="admin_verified@example.com")
        assert user is not None
        assert user.is_email_verified is True

    async def test_wrong_secret_raises_forbidden(self, db: AsyncSession):
        with pytest.raises(ForbiddenError):
            await service.register_admin(
                db=db,
                name="BadAdmin",
                email="badmin@example.com",
                password="Password1!",
                secret_key="totally-wrong-key",
            )

    async def test_duplicate_email_raises_conflict(self, db: AsyncSession, sample_user: User):
        with pytest.raises(ConflictError):
            await service.register_admin(
                db=db,
                name="DupAdmin",
                email=sample_user.email,
                password="Password1!",
                secret_key=settings.admin_secret_key,
            )

    async def test_ip_lockout_raises_rate_limit(self, db: AsyncSession):
        """When Redis reports too many failures for an IP, registration is blocked."""
        with (
            patch(
                "app.features.auth.account_service.redis_service.get_ip_failures",
                new_callable=AsyncMock,
                return_value=settings.admin_register_max_failures,
            ),
            pytest.raises(RateLimitError),
        ):
            await service.register_admin(
                db=db,
                name="LockedAdmin",
                email="locked@example.com",
                password="Password1!",
                secret_key=settings.admin_secret_key,
                ip_address="1.2.3.4",
            )

    async def test_ip_lockout_redis_unavailable_is_fail_open(self, db: AsyncSession):
        """When Redis is unavailable for IP check, registration proceeds (fail-open)."""
        with (
            patch(
                "app.features.auth.account_service.redis_service.get_ip_failures",
                side_effect=RuntimeError("Redis down"),
            ),
            patch(
                "app.features.auth.account_service.redis_service.clear_ip_failures",
                new_callable=AsyncMock,
            ),
        ):
            result = await service.register_admin(
                db=db,
                name="FailOpenAdmin",
                email="failopen@example.com",
                password="Password1!",
                secret_key=settings.admin_secret_key,
                ip_address="1.2.3.4",
            )
        assert result["success"] is True

    async def test_wrong_secret_with_ip_increments_failure_counter(self, db: AsyncSession):
        """A wrong secret when ip_address is given should increment the failure counter."""
        mock_increment = AsyncMock(return_value=1)
        with (
            patch(
                "app.features.auth.account_service.redis_service.get_ip_failures",
                new_callable=AsyncMock,
                return_value=0,
            ),
            patch(
                "app.features.auth.account_service.redis_service.increment_ip_failures",
                new=mock_increment,
            ),
            pytest.raises(ForbiddenError),
        ):
            await service.register_admin(
                db=db,
                name="WrongAdmin",
                email="wrongip@example.com",
                password="Password1!",
                secret_key="wrong-secret",
                ip_address="9.9.9.9",
            )
        mock_increment.assert_called_once()

    async def test_correct_secret_with_ip_clears_failure_counter(self, db: AsyncSession):
        """Successful registration with ip_address should clear the failure counter."""
        mock_clear = AsyncMock()
        with (
            patch(
                "app.features.auth.account_service.redis_service.get_ip_failures",
                new_callable=AsyncMock,
                return_value=0,
            ),
            patch(
                "app.features.auth.account_service.redis_service.clear_ip_failures",
                new=mock_clear,
            ),
        ):
            result = await service.register_admin(
                db=db,
                name="SuccessAdmin",
                email="successip@example.com",
                password="Password1!",
                secret_key=settings.admin_secret_key,
                ip_address="5.5.5.5",
            )
        assert result["success"] is True
        mock_clear.assert_called_once()


# ── login_user ─────────────────────────────────────────────────────────────


class TestLoginUser:
    async def test_valid_credentials_returns_tokens(self, db: AsyncSession, sample_user: User, mock_redis):
        result = await service.login_user(db=db, email=sample_user.email, password="Password1!")
        assert result["success"] is True
        assert "access_token" in result
        assert "refresh_token" in result
        assert result["token_type"] == "bearer"

    async def test_wrong_password_raises_auth_error(self, db: AsyncSession, sample_user: User):
        with pytest.raises(AuthError):
            await service.login_user(db=db, email=sample_user.email, password="WrongPassword1!")

    async def test_nonexistent_email_raises_auth_error(self, db: AsyncSession):
        with pytest.raises(AuthError):
            await service.login_user(db=db, email="nobody@example.com", password="Password1!")

    async def test_unverified_email_returns_verification_required(
        self, db: AsyncSession, unverified_user: User, mock_redis
    ):
        with patch("app.features.auth.session_service.send_otp_email", new_callable=AsyncMock):
            result = await service.login_user(db=db, email=unverified_user.email, password="Password1!")
        assert result["success"] is False
        assert result["email_verification_required"] is True

    async def test_unverified_email_sends_new_otp(self, db: AsyncSession, unverified_user: User, mock_redis):
        with patch("app.features.auth.session_service.send_otp_email", new_callable=AsyncMock) as mock_email:
            await service.login_user(db=db, email=unverified_user.email, password="Password1!")
        mock_email.assert_called_once()

    async def test_inactive_user_raises_forbidden(self, db: AsyncSession, inactive_user: User):
        with pytest.raises(ForbiddenError):
            await service.login_user(db=db, email=inactive_user.email, password="Password1!")

    async def test_login_stores_refresh_token_in_redis(self, db: AsyncSession, sample_user: User, mock_redis):
        await service.login_user(db=db, email=sample_user.email, password="Password1!")
        assert sample_user.id in mock_redis.refresh

    async def test_login_with_needs_rehash_updates_password(self, db: AsyncSession, sample_user: User, mock_redis):
        """When the hash needs rehashing, login should update it."""
        with patch("app.features.auth.session_service.needs_rehash", return_value=True):
            result = await service.login_user(db=db, email=sample_user.email, password="Password1!")
        assert result["success"] is True


# ── refresh_tokens ─────────────────────────────────────────────────────────


class TestRefreshTokens:
    async def test_valid_refresh_token_returns_new_pair(self, db: AsyncSession, sample_user: User, mock_redis):
        refresh_token, _ = create_refresh_token(subject=sample_user.id, email=sample_user.email)
        mock_redis[sample_user.id] = refresh_token
        result = await service.refresh_tokens(db=db, user_id=sample_user.id, refresh_token=refresh_token)
        assert result["success"] is True
        assert "access_token" in result
        assert "refresh_token" in result

    async def test_token_not_in_redis_raises_auth_error(self, db: AsyncSession, sample_user: User, mock_redis):
        refresh_token, _ = create_refresh_token(subject=sample_user.id, email=sample_user.email)
        # Not stored in Redis
        with pytest.raises(AuthError):
            await service.refresh_tokens(db=db, user_id=sample_user.id, refresh_token=refresh_token)

    async def test_invalid_jwt_raises_auth_error(self, db: AsyncSession, sample_user: User, mock_redis):
        mock_redis[sample_user.id] = "bad.token.here"
        with pytest.raises(AuthError):
            await service.refresh_tokens(db=db, user_id=sample_user.id, refresh_token="bad.token.here")

    async def test_inactive_user_raises_auth_error(self, db: AsyncSession, inactive_user: User, mock_redis):
        refresh_token, _ = create_refresh_token(subject=inactive_user.id, email=inactive_user.email)
        mock_redis[inactive_user.id] = refresh_token
        with pytest.raises(AuthError):
            await service.refresh_tokens(db=db, user_id=inactive_user.id, refresh_token=refresh_token)

    async def test_nonexistent_user_raises_auth_error(self, db: AsyncSession, mock_redis):
        refresh_token, _ = create_refresh_token(subject=99999, email="ghost@example.com")
        mock_redis[99999] = refresh_token
        with pytest.raises(AuthError):
            await service.refresh_tokens(db=db, user_id=99999, refresh_token=refresh_token)

    async def test_rotation_replaces_old_token(self, db: AsyncSession, sample_user: User, mock_redis):
        old_token, _ = create_refresh_token(subject=sample_user.id, email=sample_user.email)
        mock_redis[sample_user.id] = old_token
        result = await service.refresh_tokens(db=db, user_id=sample_user.id, refresh_token=old_token)
        # New token should be stored
        assert mock_redis.get(sample_user.id) == result["refresh_token"]


# ── logout_user ────────────────────────────────────────────────────────────


class TestLogoutUser:
    async def test_logout_returns_success(self, mock_redis):
        result = await service.logout_user(user_id=1)
        assert result["success"] is True

    async def test_logout_nonexistent_session_still_succeeds(self, mock_redis):
        result = await service.logout_user(user_id=99999)
        assert result["success"] is True

    async def test_logout_removes_redis_token(self, sample_user: User, mock_redis):
        mock_redis[sample_user.id] = "some-token"
        await service.logout_user(user_id=sample_user.id)
        assert sample_user.id not in mock_redis.refresh

    async def test_logout_handles_redis_error_gracefully(self):
        with patch(
            "app.core.services.redis_service.redis_service.delete_refresh_token",
            side_effect=Exception("Redis connection error"),
        ):
            result = await service.logout_user(user_id=1)
        assert result["success"] is True


# ── verify_otp ─────────────────────────────────────────────────────────────


class TestVerifyOtp:
    async def test_valid_email_verification_otp_returns_tokens(
        self, db: AsyncSession, unverified_user: User, mock_redis
    ):
        otp = "123456"
        await repo.create_email_otp(
            db=db,
            user_id=unverified_user.id,
            otp_hash=hash_otp(otp),
            purpose=OtpPurpose.EMAIL_VERIFICATION,
            expire_minutes=10,
        )
        result = await service.verify_otp(
            db=db,
            email=unverified_user.email,
            otp=otp,
            purpose=OtpPurpose.EMAIL_VERIFICATION,
        )
        assert result["success"] is True
        assert "access_token" in result

    async def test_valid_email_verification_marks_email_verified(
        self, db: AsyncSession, unverified_user: User, mock_redis
    ):
        otp = "123456"
        await repo.create_email_otp(
            db=db,
            user_id=unverified_user.id,
            otp_hash=hash_otp(otp),
            purpose=OtpPurpose.EMAIL_VERIFICATION,
            expire_minutes=10,
        )
        await service.verify_otp(
            db=db,
            email=unverified_user.email,
            otp=otp,
            purpose=OtpPurpose.EMAIL_VERIFICATION,
        )
        await db.refresh(unverified_user)
        assert unverified_user.is_email_verified is True

    async def test_valid_password_reset_otp_returns_reset_token(self, db: AsyncSession, sample_user: User):
        otp = "654321"
        await repo.create_email_otp(
            db=db,
            user_id=sample_user.id,
            otp_hash=hash_otp(otp),
            purpose=OtpPurpose.PASSWORD_RESET,
            expire_minutes=10,
        )
        result = await service.verify_otp(
            db=db,
            email=sample_user.email,
            otp=otp,
            purpose=OtpPurpose.PASSWORD_RESET,
        )
        assert result["success"] is True
        assert "reset_token" in result
        assert "access_token" not in result

    async def test_wrong_otp_raises_auth_error(self, db: AsyncSession, unverified_user: User):
        await repo.create_email_otp(
            db=db,
            user_id=unverified_user.id,
            otp_hash=hash_otp("111111"),
            purpose=OtpPurpose.EMAIL_VERIFICATION,
            expire_minutes=10,
        )
        with pytest.raises(AuthError):
            await service.verify_otp(
                db=db,
                email=unverified_user.email,
                otp="999999",
                purpose=OtpPurpose.EMAIL_VERIFICATION,
            )

    async def test_wrong_otp_increments_attempts(self, db: AsyncSession, unverified_user: User):
        otp_record = await repo.create_email_otp(
            db=db,
            user_id=unverified_user.id,
            otp_hash=hash_otp("111111"),
            purpose=OtpPurpose.EMAIL_VERIFICATION,
            expire_minutes=10,
        )
        with pytest.raises(AuthError):
            await service.verify_otp(
                db=db,
                email=unverified_user.email,
                otp="999999",
                purpose=OtpPurpose.EMAIL_VERIFICATION,
            )
        await db.refresh(otp_record)
        assert otp_record.attempts == 1

    async def test_nonexistent_email_raises_auth_error(self, db: AsyncSession):
        with pytest.raises(AuthError):
            await service.verify_otp(
                db=db,
                email="ghost@example.com",
                otp="123456",
                purpose=OtpPurpose.EMAIL_VERIFICATION,
            )

    async def test_no_active_otp_raises_auth_error(self, db: AsyncSession, sample_user: User):
        with pytest.raises(AuthError):
            await service.verify_otp(
                db=db,
                email=sample_user.email,
                otp="123456",
                purpose=OtpPurpose.EMAIL_VERIFICATION,
            )

    async def test_max_attempts_exceeded_raises_rate_limit(self, db: AsyncSession, unverified_user: User):
        otp = "123456"
        otp_record = await repo.create_email_otp(
            db=db,
            user_id=unverified_user.id,
            otp_hash=hash_otp(otp),
            purpose=OtpPurpose.EMAIL_VERIFICATION,
            expire_minutes=10,
        )
        otp_record.attempts = settings.otp_max_verify_attempts
        await db.commit()
        with pytest.raises(RateLimitError):
            await service.verify_otp(
                db=db,
                email=unverified_user.email,
                otp=otp,
                purpose=OtpPurpose.EMAIL_VERIFICATION,
            )


# ── resend_otp ─────────────────────────────────────────────────────────────


class TestResendOtp:
    async def test_valid_email_sends_otp_and_returns_success(self, db: AsyncSession, unverified_user: User):
        with patch("app.features.auth.otp_service.send_otp_email", new_callable=AsyncMock):
            result = await service.resend_otp(db=db, email=unverified_user.email, purpose=OtpPurpose.EMAIL_VERIFICATION)
        assert result["success"] is True

    async def test_unknown_email_returns_success_anti_enumeration(self, db: AsyncSession):
        result = await service.resend_otp(db=db, email="ghost@example.com", purpose=OtpPurpose.EMAIL_VERIFICATION)
        assert result["success"] is True

    async def test_rate_limit_exceeded_raises_error(self, db: AsyncSession, unverified_user: User):
        for _ in range(settings.otp_max_resends):
            await repo.create_email_otp(
                db=db,
                user_id=unverified_user.id,
                otp_hash=hash_otp("123456"),
                purpose=OtpPurpose.EMAIL_VERIFICATION,
                expire_minutes=10,
            )
        with pytest.raises(RateLimitError):
            await service.resend_otp(
                db=db,
                email=unverified_user.email,
                purpose=OtpPurpose.EMAIL_VERIFICATION,
            )

    async def test_resend_invalidates_previous_otp(self, db: AsyncSession, unverified_user: User):
        old_otp = await repo.create_email_otp(
            db=db,
            user_id=unverified_user.id,
            otp_hash=hash_otp("123456"),
            purpose=OtpPurpose.EMAIL_VERIFICATION,
            expire_minutes=10,
        )
        with patch("app.features.auth.otp_service.send_otp_email", new_callable=AsyncMock):
            await service.resend_otp(
                db=db,
                email=unverified_user.email,
                purpose=OtpPurpose.EMAIL_VERIFICATION,
            )
        await db.refresh(old_otp)
        assert old_otp.is_used is True


# ── forgot_password ────────────────────────────────────────────────────────


class TestForgotPassword:
    async def test_known_active_user_sends_otp(self, db: AsyncSession, sample_user: User):
        with patch("app.features.auth.otp_service.send_otp_email", new_callable=AsyncMock) as mock_email:
            result = await service.forgot_password(db=db, email=sample_user.email)
        assert result["success"] is True
        mock_email.assert_called_once()

    async def test_unknown_email_returns_success_anti_enumeration(self, db: AsyncSession):
        with patch("app.features.auth.otp_service.send_otp_email", new_callable=AsyncMock) as mock_email:
            result = await service.forgot_password(db=db, email="ghost@example.com")
        assert result["success"] is True
        mock_email.assert_not_called()

    async def test_inactive_user_skips_otp_sending(self, db: AsyncSession, inactive_user: User):
        with patch("app.features.auth.otp_service.send_otp_email", new_callable=AsyncMock) as mock_email:
            result = await service.forgot_password(db=db, email=inactive_user.email)
        assert result["success"] is True
        mock_email.assert_not_called()

    async def test_rate_limit_exceeded_skips_otp_sending(self, db: AsyncSession, sample_user: User):
        for _ in range(settings.otp_max_resends):
            await repo.create_email_otp(
                db=db,
                user_id=sample_user.id,
                otp_hash=hash_otp("123456"),
                purpose=OtpPurpose.PASSWORD_RESET,
                expire_minutes=10,
            )
        with patch("app.features.auth.otp_service.send_otp_email", new_callable=AsyncMock) as mock_email:
            result = await service.forgot_password(db=db, email=sample_user.email)
        assert result["success"] is True
        mock_email.assert_not_called()


# ── change_password ────────────────────────────────────────────────────────


class TestChangePassword:
    async def test_valid_user_changes_password_successfully(self, db: AsyncSession, sample_user: User, mock_redis):
        result = await service.change_password(db=db, user_id=sample_user.id, new_password="NewPassword2@")
        assert result["success"] is True

    async def test_change_password_revokes_all_sessions(self, db: AsyncSession, sample_user: User, mock_redis):
        mock_redis[sample_user.id] = "old-refresh-token"
        await service.change_password(db=db, user_id=sample_user.id, new_password="NewPassword2@")
        assert sample_user.id not in mock_redis.refresh

    async def test_nonexistent_user_raises_not_found(self, db: AsyncSession, mock_redis):
        with pytest.raises(NotFoundError):
            await service.change_password(db=db, user_id=99999, new_password="NewPassword2@")
