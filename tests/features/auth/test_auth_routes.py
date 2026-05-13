"""Integration tests for auth feature routes — comprehensive coverage."""

from unittest.mock import AsyncMock, patch

from fastapi import status
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth.jwt_handler import create_password_reset_token
from app.core.config.settings import settings
from app.models.user import User
from app.utils.helpers import hash_otp


# ── Helpers ────────────────────────────────────────────────────────────────


async def _seed_otp(db: AsyncSession, user: User, otp: str, purpose: str) -> None:
    """Insert a valid (unused, unexpired) OTP for a user into the test DB."""
    from app.features.auth import repository as repo

    await repo.create_email_otp(
        db=db,
        user_id=user.id,
        otp_hash=hash_otp(otp),
        purpose=purpose,
        expire_minutes=10,
    )


# ── Register ───────────────────────────────────────────────────────────────


class TestRegister:
    async def test_new_user_returns_201(self, client: AsyncClient):
        with patch("app.features.auth.service.send_otp_email", new_callable=AsyncMock, return_value=True):
            resp = await client.post(
                "/api/v1/auth/register",
                json={"name": "New User", "email": "new@example.com", "password": "Password1!"},
            )
        assert resp.status_code == status.HTTP_201_CREATED
        assert resp.json()["success"] is True

    async def test_duplicate_email_returns_409(self, client: AsyncClient, sample_user: User):
        with patch("app.features.auth.service.send_otp_email", new_callable=AsyncMock, return_value=True):
            resp = await client.post(
                "/api/v1/auth/register",
                json={"name": "Dup", "email": sample_user.email, "password": "Password1!"},
            )
        assert resp.status_code == status.HTTP_409_CONFLICT

    async def test_weak_password_returns_422(self, client: AsyncClient):
        resp = await client.post(
            "/api/v1/auth/register",
            json={"name": "User", "email": "weak@example.com", "password": "weak"},
        )
        assert resp.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    async def test_password_no_special_char_returns_422(self, client: AsyncClient):
        resp = await client.post(
            "/api/v1/auth/register",
            json={"name": "User", "email": "nospecial@example.com", "password": "Password123"},
        )
        assert resp.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    async def test_invalid_email_returns_422(self, client: AsyncClient):
        resp = await client.post(
            "/api/v1/auth/register",
            json={"name": "User", "email": "not-an-email", "password": "Password1!"},
        )
        assert resp.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    async def test_name_too_short_returns_422(self, client: AsyncClient):
        resp = await client.post(
            "/api/v1/auth/register",
            json={"name": "X", "email": "short@example.com", "password": "Password1!"},
        )
        assert resp.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    async def test_missing_required_fields_returns_422(self, client: AsyncClient):
        resp = await client.post("/api/v1/auth/register", json={"email": "only@example.com"})
        assert resp.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


# ── Login ──────────────────────────────────────────────────────────────────


class TestLogin:
    async def test_valid_credentials_returns_tokens(self, client: AsyncClient, sample_user: User, mock_redis):
        resp = await client.post(
            "/api/v1/auth/login",
            json={"email": sample_user.email, "password": "Password1!"},
        )
        assert resp.status_code == status.HTTP_200_OK
        data = resp.json()
        assert data["success"] is True
        assert "access_token" in data
        assert "refresh_token" not in data
        assert data["token_type"] == "bearer"
        assert "refresh_token" in resp.cookies

    async def test_wrong_password_returns_401(self, client: AsyncClient, sample_user: User, mock_redis):
        resp = await client.post(
            "/api/v1/auth/login",
            json={"email": sample_user.email, "password": "WrongPassword1!"},
        )
        assert resp.status_code == status.HTTP_401_UNAUTHORIZED

    async def test_unknown_email_returns_401(self, client: AsyncClient, mock_redis):
        resp = await client.post(
            "/api/v1/auth/login",
            json={"email": "nobody@example.com", "password": "Password1!"},
        )
        assert resp.status_code == status.HTTP_401_UNAUTHORIZED

    async def test_unverified_email_returns_200_with_flag(self, client: AsyncClient, unverified_user: User, mock_redis):
        with patch("app.features.auth.service.send_otp_email", new_callable=AsyncMock, return_value=True):
            resp = await client.post(
                "/api/v1/auth/login",
                json={"email": unverified_user.email, "password": "Password1!"},
            )
        assert resp.status_code == status.HTTP_200_OK
        assert resp.json()["email_verification_required"] is True

    async def test_inactive_account_returns_403(self, client: AsyncClient, inactive_user: User, mock_redis):
        resp = await client.post(
            "/api/v1/auth/login",
            json={"email": inactive_user.email, "password": "Password1!"},
        )
        assert resp.status_code == status.HTTP_403_FORBIDDEN

    async def test_missing_password_field_returns_422(self, client: AsyncClient):
        resp = await client.post("/api/v1/auth/login", json={"email": "user@example.com"})
        assert resp.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


# ── Verify OTP ─────────────────────────────────────────────────────────────


class TestVerifyOtp:
    async def test_valid_email_verification_otp_returns_tokens(
        self, client: AsyncClient, db: AsyncSession, unverified_user: User, mock_redis
    ):
        otp = "123456"
        await _seed_otp(db, unverified_user, otp, "email_verification")
        resp = await client.post(
            "/api/v1/auth/verify-otp",
            json={"email": unverified_user.email, "otp": otp, "purpose": "email_verification"},
        )
        assert resp.status_code == status.HTTP_200_OK
        data = resp.json()
        assert data["success"] is True
        assert "access_token" in data
        assert "refresh_token" not in data
        assert "refresh_token" in resp.cookies

    async def test_valid_password_reset_otp_returns_reset_token(
        self, client: AsyncClient, db: AsyncSession, sample_user: User
    ):
        otp = "654321"
        await _seed_otp(db, sample_user, otp, "password_reset")
        resp = await client.post(
            "/api/v1/auth/verify-otp",
            json={"email": sample_user.email, "otp": otp, "purpose": "password_reset"},
        )
        assert resp.status_code == status.HTTP_200_OK
        data = resp.json()
        assert "reset_token" in data

    async def test_wrong_otp_returns_401(self, client: AsyncClient, db: AsyncSession, unverified_user: User):
        await _seed_otp(db, unverified_user, "111111", "email_verification")
        resp = await client.post(
            "/api/v1/auth/verify-otp",
            json={"email": unverified_user.email, "otp": "999999", "purpose": "email_verification"},
        )
        assert resp.status_code == status.HTTP_401_UNAUTHORIZED

    async def test_no_active_otp_returns_401(self, client: AsyncClient, sample_user: User):
        resp = await client.post(
            "/api/v1/auth/verify-otp",
            json={"email": sample_user.email, "otp": "000000", "purpose": "email_verification"},
        )
        assert resp.status_code == status.HTTP_401_UNAUTHORIZED

    async def test_nonexistent_email_returns_401(self, client: AsyncClient):
        resp = await client.post(
            "/api/v1/auth/verify-otp",
            json={"email": "ghost@example.com", "otp": "123456", "purpose": "email_verification"},
        )
        assert resp.status_code == status.HTTP_401_UNAUTHORIZED

    async def test_invalid_purpose_returns_422(self, client: AsyncClient):
        resp = await client.post(
            "/api/v1/auth/verify-otp",
            json={"email": "u@example.com", "otp": "123456", "purpose": "bad_purpose"},
        )
        assert resp.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    async def test_otp_wrong_length_returns_422(self, client: AsyncClient):
        resp = await client.post(
            "/api/v1/auth/verify-otp",
            json={"email": "u@example.com", "otp": "12345", "purpose": "email_verification"},
        )
        assert resp.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


# ── Resend OTP ─────────────────────────────────────────────────────────────


class TestResendOtp:
    async def test_valid_email_returns_200(self, client: AsyncClient, unverified_user: User):
        with patch("app.features.auth.service.send_otp_email", new_callable=AsyncMock, return_value=True):
            resp = await client.post(
                "/api/v1/auth/resend-otp",
                json={"email": unverified_user.email, "purpose": "email_verification"},
            )
        assert resp.status_code == status.HTTP_200_OK
        assert resp.json()["success"] is True

    async def test_unknown_email_returns_200_anti_enumeration(self, client: AsyncClient):
        """Anti-enumeration: must return 200 even for unknown emails."""
        resp = await client.post(
            "/api/v1/auth/resend-otp",
            json={"email": "ghost@example.com", "purpose": "email_verification"},
        )
        assert resp.status_code == status.HTTP_200_OK
        assert resp.json()["success"] is True

    async def test_rate_limit_exceeded_returns_429(self, client: AsyncClient, db: AsyncSession, unverified_user: User):
        from app.features.auth import repository as repo
        from app.utils.helpers import hash_otp

        for _ in range(settings.otp_max_resends):
            await repo.create_email_otp(
                db=db,
                user_id=unverified_user.id,
                otp_hash=hash_otp("123456"),
                purpose="email_verification",
                expire_minutes=10,
            )
        resp = await client.post(
            "/api/v1/auth/resend-otp",
            json={"email": unverified_user.email, "purpose": "email_verification"},
        )
        assert resp.status_code == status.HTTP_429_TOO_MANY_REQUESTS

    async def test_invalid_purpose_returns_422(self, client: AsyncClient):
        resp = await client.post(
            "/api/v1/auth/resend-otp",
            json={"email": "u@example.com", "purpose": "hack_attempt"},
        )
        assert resp.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


# ── Refresh ────────────────────────────────────────────────────────────────


class TestRefresh:
    async def test_valid_token_returns_new_pair(self, client: AsyncClient, user_refresh_token: str):
        resp = await client.post(
            "/api/v1/auth/refresh",
            cookies={"refresh_token": user_refresh_token},
        )
        assert resp.status_code == status.HTTP_200_OK
        data = resp.json()
        assert "access_token" in data
        assert "refresh_token" not in data
        assert data["token_type"] == "bearer"
        assert "refresh_token" in resp.cookies

    async def test_no_cookie_returns_401(self, client: AsyncClient):
        resp = await client.post("/api/v1/auth/refresh")
        assert resp.status_code == status.HTTP_401_UNAUTHORIZED

    async def test_invalid_token_returns_401(self, client: AsyncClient):
        resp = await client.post(
            "/api/v1/auth/refresh",
            cookies={"refresh_token": "invalid.token.here"},
        )
        assert resp.status_code == status.HTTP_401_UNAUTHORIZED

    async def test_used_token_returns_401(self, client: AsyncClient, user_refresh_token: str):
        """After first use the old token is removed from Redis — replaying it must be rejected."""
        await client.post("/api/v1/auth/refresh", cookies={"refresh_token": user_refresh_token})
        resp = await client.post("/api/v1/auth/refresh", cookies={"refresh_token": user_refresh_token})
        assert resp.status_code == status.HTTP_401_UNAUTHORIZED

    async def test_access_token_used_as_refresh_returns_401(self, client: AsyncClient, user_token: str):
        """An access token must be rejected when sent to the refresh endpoint."""
        resp = await client.post(
            "/api/v1/auth/refresh",
            cookies={"refresh_token": user_token},
        )
        assert resp.status_code == status.HTTP_401_UNAUTHORIZED


# ── Logout ─────────────────────────────────────────────────────────────────


class TestLogout:
    async def test_authenticated_user_can_logout(self, client: AsyncClient, user_token: str, mock_redis):
        resp = await client.post(
            "/api/v1/auth/logout",
            headers={"Authorization": f"Bearer {user_token}"},
        )
        assert resp.status_code == status.HTTP_200_OK
        assert resp.json()["success"] is True

    async def test_logout_without_auth_returns_401(self, client: AsyncClient):
        resp = await client.post("/api/v1/auth/logout")
        assert resp.status_code == status.HTTP_401_UNAUTHORIZED

    async def test_logout_with_invalid_bearer_returns_401(self, client: AsyncClient):
        resp = await client.post(
            "/api/v1/auth/logout",
            headers={"Authorization": "Bearer garbage.token.here"},
        )
        assert resp.status_code == status.HTTP_401_UNAUTHORIZED


# ── Forgot Password ────────────────────────────────────────────────────────


class TestForgotPassword:
    async def test_always_returns_200_for_unknown_email(self, client: AsyncClient):
        """Anti-enumeration: must return 200 even for non-existent email."""
        resp = await client.post("/api/v1/auth/forgot-password", json={"email": "nobody@example.com"})
        assert resp.status_code == status.HTTP_200_OK
        assert resp.json()["success"] is True

    async def test_returns_200_for_known_email(self, client: AsyncClient, sample_user: User):
        with patch("app.features.auth.service.send_otp_email", new_callable=AsyncMock, return_value=True):
            resp = await client.post("/api/v1/auth/forgot-password", json={"email": sample_user.email})
        assert resp.status_code == status.HTTP_200_OK
        assert resp.json()["success"] is True

    async def test_invalid_email_format_returns_422(self, client: AsyncClient):
        resp = await client.post("/api/v1/auth/forgot-password", json={"email": "not-an-email"})
        assert resp.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


# ── Change Password ────────────────────────────────────────────────────────


class TestChangePassword:
    async def test_valid_reset_token_changes_password(self, client: AsyncClient, sample_user: User, mock_redis):
        reset_token = create_password_reset_token(subject=sample_user.id, email=sample_user.email)
        resp = await client.post(
            "/api/v1/auth/change-password",
            headers={"Authorization": f"Bearer {reset_token}"},
            json={"new_password": "NewPassword2@", "confirm_password": "NewPassword2@"},
        )
        assert resp.status_code == status.HTTP_200_OK
        assert resp.json()["success"] is True

    async def test_invalid_token_returns_400(self, client: AsyncClient):
        resp = await client.post(
            "/api/v1/auth/change-password",
            headers={"Authorization": "Bearer garbage.token.here"},
            json={"new_password": "NewPassword2@", "confirm_password": "NewPassword2@"},
        )
        assert resp.status_code in (status.HTTP_400_BAD_REQUEST, status.HTTP_401_UNAUTHORIZED)

    async def test_passwords_mismatch_returns_422(self, client: AsyncClient, sample_user: User):
        reset_token = create_password_reset_token(subject=sample_user.id, email=sample_user.email)
        resp = await client.post(
            "/api/v1/auth/change-password",
            headers={"Authorization": f"Bearer {reset_token}"},
            json={"new_password": "NewPassword2@", "confirm_password": "DifferentPass1!"},
        )
        assert resp.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    async def test_weak_new_password_returns_422(self, client: AsyncClient, sample_user: User):
        reset_token = create_password_reset_token(subject=sample_user.id, email=sample_user.email)
        resp = await client.post(
            "/api/v1/auth/change-password",
            headers={"Authorization": f"Bearer {reset_token}"},
            json={"new_password": "weakpass", "confirm_password": "weakpass"},
        )
        assert resp.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    async def test_access_token_used_as_reset_token_returns_error(self, client: AsyncClient, user_token: str):
        """An access-scoped token must be rejected by the change-password endpoint."""
        resp = await client.post(
            "/api/v1/auth/change-password",
            headers={"Authorization": f"Bearer {user_token}"},
            json={"new_password": "NewPassword2@", "confirm_password": "NewPassword2@"},
        )
        assert resp.status_code in (status.HTTP_400_BAD_REQUEST, status.HTTP_401_UNAUTHORIZED)


# ── Register Admin ─────────────────────────────────────────────────────────


class TestRegisterAdmin:
    async def test_correct_secret_creates_admin_201(self, client: AsyncClient):
        resp = await client.post(
            "/api/v1/auth/register-admin",
            json={
                "name": "NewAdmin",
                "email": "newadmin@example.com",
                "password": "Password1!",
                "admin_secret_key": settings.admin_secret_key,
            },
        )
        assert resp.status_code == status.HTTP_201_CREATED
        assert resp.json()["success"] is True

    async def test_wrong_secret_returns_403(self, client: AsyncClient):
        resp = await client.post(
            "/api/v1/auth/register-admin",
            json={
                "name": "Admin",
                "email": "admin2@example.com",
                "password": "Password1!",
                "admin_secret_key": "wrong-secret-key",
            },
        )
        assert resp.status_code == status.HTTP_403_FORBIDDEN

    async def test_duplicate_email_returns_409(self, client: AsyncClient, sample_user: User):
        resp = await client.post(
            "/api/v1/auth/register-admin",
            json={
                "name": "Admin",
                "email": sample_user.email,
                "password": "Password1!",
                "admin_secret_key": settings.admin_secret_key,
            },
        )
        assert resp.status_code == status.HTTP_409_CONFLICT

    async def test_weak_password_returns_422(self, client: AsyncClient):
        resp = await client.post(
            "/api/v1/auth/register-admin",
            json={
                "name": "Admin",
                "email": "admin3@example.com",
                "password": "weak",
                "admin_secret_key": settings.admin_secret_key,
            },
        )
        assert resp.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
