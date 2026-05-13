"""Unit tests for the auth feature repository layer."""

from datetime import UTC, datetime, timedelta

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.constants import OtpPurpose
from app.features.auth import repository as repo
from app.models.role import Role
from app.models.user import User
from app.utils.helpers import hash_otp


# ── get_user_by_email ──────────────────────────────────────────────────────


class TestGetUserByEmail:
    async def test_returns_existing_user(self, db: AsyncSession, sample_user: User):
        result = await repo.get_user_by_email(db=db, email=sample_user.email)
        assert result is not None
        assert result.id == sample_user.id

    async def test_returns_none_for_unknown_email(self, db: AsyncSession):
        result = await repo.get_user_by_email(db=db, email="ghost@example.com")
        assert result is None

    async def test_excludes_soft_deleted_user(self, db: AsyncSession, sample_user: User):
        from datetime import UTC, datetime

        sample_user.deleted_at = datetime.now(UTC)
        await db.commit()
        result = await repo.get_user_by_email(db=db, email=sample_user.email)
        assert result is None


# ── get_user_by_id ─────────────────────────────────────────────────────────


class TestGetUserById:
    async def test_returns_existing_user(self, db: AsyncSession, sample_user: User):
        result = await repo.get_user_by_id(db=db, user_id=sample_user.id)
        assert result is not None
        assert result.email == sample_user.email

    async def test_returns_none_for_unknown_id(self, db: AsyncSession):
        result = await repo.get_user_by_id(db=db, user_id=99999)
        assert result is None

    async def test_excludes_soft_deleted_user(self, db: AsyncSession, sample_user: User):
        sample_user.deleted_at = datetime.now(UTC)
        await db.commit()
        result = await repo.get_user_by_id(db=db, user_id=sample_user.id)
        assert result is None


# ── create_user ────────────────────────────────────────────────────────────


class TestCreateUser:
    async def test_creates_user_with_correct_fields(self, db: AsyncSession):
        user = await repo.create_user(db=db, name="Created User", email="created@example.com", password_hash="hash123")
        await db.commit()
        assert user.id is not None
        assert user.name == "Created User"
        assert user.email == "created@example.com"
        assert user.password_hash == "hash123"

    async def test_new_user_email_not_verified(self, db: AsyncSession):
        user = await repo.create_user(db=db, name="New User", email="new@example.com", password_hash="hash")
        await db.commit()
        assert user.is_email_verified is False

    async def test_new_user_is_active(self, db: AsyncSession):
        user = await repo.create_user(db=db, name="Active User", email="active@example.com", password_hash="hash")
        await db.commit()
        assert user.is_active is True


# ── assign_role_to_user ────────────────────────────────────────────────────


class TestAssignRoleToUser:
    async def test_assigns_existing_role(self, db: AsyncSession, sample_user: User, sample_user_role: Role):
        user2 = await repo.create_user(db=db, name="Role Test", email="roletest@example.com", password_hash="hash")
        await db.commit()
        await repo.assign_role_to_user(db=db, user_id=user2.id, role_name=sample_user_role.name)
        await db.commit()
        result = await repo.get_user_by_id(db=db, user_id=user2.id)
        assert result is not None

    async def test_noop_if_role_not_found(self, db: AsyncSession, sample_user: User):
        await repo.assign_role_to_user(db=db, user_id=sample_user.id, role_name="nonexistent_role")
        await db.commit()

    async def test_noop_if_already_assigned(self, db: AsyncSession, sample_user: User, sample_user_role: Role):
        await repo.assign_role_to_user(db=db, user_id=sample_user.id, role_name=sample_user_role.name)
        await db.commit()


# ── create_email_otp ───────────────────────────────────────────────────────


class TestCreateEmailOtp:
    async def test_creates_otp_with_correct_purpose(self, db: AsyncSession, sample_user: User):
        otp_record = await repo.create_email_otp(
            db=db,
            user_id=sample_user.id,
            otp_hash=hash_otp("123456"),
            purpose=OtpPurpose.EMAIL_VERIFICATION,
            expire_minutes=10,
        )
        assert otp_record.id is not None
        assert otp_record.purpose == OtpPurpose.EMAIL_VERIFICATION
        assert otp_record.is_used is False
        assert otp_record.attempts == 0

    async def test_creates_otp_with_correct_expiry(self, db: AsyncSession, sample_user: User):
        before = datetime.now(UTC)
        otp_record = await repo.create_email_otp(
            db=db,
            user_id=sample_user.id,
            otp_hash=hash_otp("654321"),
            purpose=OtpPurpose.EMAIL_VERIFICATION,
            expire_minutes=10,
        )
        after = datetime.now(UTC) + timedelta(minutes=10)
        assert before < otp_record.expires_at.replace(tzinfo=UTC) <= after


# ── get_active_otp ─────────────────────────────────────────────────────────


class TestGetActiveOtp:
    async def test_returns_active_otp(self, db: AsyncSession, sample_user: User):
        await repo.create_email_otp(
            db=db,
            user_id=sample_user.id,
            otp_hash=hash_otp("111111"),
            purpose=OtpPurpose.EMAIL_VERIFICATION,
            expire_minutes=10,
        )
        result = await repo.get_active_otp(db=db, user_id=sample_user.id, purpose=OtpPurpose.EMAIL_VERIFICATION)
        assert result is not None

    async def test_returns_none_when_no_active_otp(self, db: AsyncSession, sample_user: User):
        result = await repo.get_active_otp(db=db, user_id=sample_user.id, purpose=OtpPurpose.EMAIL_VERIFICATION)
        assert result is None

    async def test_ignores_used_otp(self, db: AsyncSession, sample_user: User):
        otp_record = await repo.create_email_otp(
            db=db,
            user_id=sample_user.id,
            otp_hash=hash_otp("222222"),
            purpose=OtpPurpose.EMAIL_VERIFICATION,
            expire_minutes=10,
        )
        otp_record.is_used = True
        await db.commit()
        result = await repo.get_active_otp(db=db, user_id=sample_user.id, purpose=OtpPurpose.EMAIL_VERIFICATION)
        assert result is None

    async def test_ignores_expired_otp(self, db: AsyncSession, sample_user: User):
        otp_record = await repo.create_email_otp(
            db=db,
            user_id=sample_user.id,
            otp_hash=hash_otp("333333"),
            purpose=OtpPurpose.EMAIL_VERIFICATION,
            expire_minutes=10,
        )
        otp_record.expires_at = datetime.now(UTC) - timedelta(minutes=1)
        await db.commit()
        result = await repo.get_active_otp(db=db, user_id=sample_user.id, purpose=OtpPurpose.EMAIL_VERIFICATION)
        assert result is None


# ── increment_otp_attempts ─────────────────────────────────────────────────


class TestIncrementOtpAttempts:
    async def test_increments_attempt_counter(self, db: AsyncSession, sample_user: User):
        otp_record = await repo.create_email_otp(
            db=db,
            user_id=sample_user.id,
            otp_hash=hash_otp("444444"),
            purpose=OtpPurpose.EMAIL_VERIFICATION,
            expire_minutes=10,
        )
        assert otp_record.attempts == 0
        await repo.increment_otp_attempts(db=db, otp=otp_record)
        await db.refresh(otp_record)
        assert otp_record.attempts == 1

    async def test_multiple_increments_accumulate(self, db: AsyncSession, sample_user: User):
        otp_record = await repo.create_email_otp(
            db=db,
            user_id=sample_user.id,
            otp_hash=hash_otp("555555"),
            purpose=OtpPurpose.EMAIL_VERIFICATION,
            expire_minutes=10,
        )
        await repo.increment_otp_attempts(db=db, otp=otp_record)
        await repo.increment_otp_attempts(db=db, otp=otp_record)
        await db.refresh(otp_record)
        assert otp_record.attempts == 2


# ── mark_otp_used ──────────────────────────────────────────────────────────


class TestMarkOtpUsed:
    async def test_marks_otp_as_used(self, db: AsyncSession, sample_user: User):
        otp_record = await repo.create_email_otp(
            db=db,
            user_id=sample_user.id,
            otp_hash=hash_otp("666666"),
            purpose=OtpPurpose.EMAIL_VERIFICATION,
            expire_minutes=10,
        )
        assert otp_record.is_used is False
        await repo.mark_otp_used(db=db, otp=otp_record)
        await db.refresh(otp_record)
        assert otp_record.is_used is True


# ── invalidate_user_otps ───────────────────────────────────────────────────


class TestInvalidateUserOtps:
    async def test_marks_all_active_otps_as_used(self, db: AsyncSession, sample_user: User):
        otp1 = await repo.create_email_otp(
            db=db,
            user_id=sample_user.id,
            otp_hash=hash_otp("777777"),
            purpose=OtpPurpose.EMAIL_VERIFICATION,
            expire_minutes=10,
        )
        otp2 = await repo.create_email_otp(
            db=db,
            user_id=sample_user.id,
            otp_hash=hash_otp("888888"),
            purpose=OtpPurpose.EMAIL_VERIFICATION,
            expire_minutes=10,
        )
        await repo.invalidate_user_otps(db=db, user_id=sample_user.id, purpose=OtpPurpose.EMAIL_VERIFICATION)
        await db.refresh(otp1)
        await db.refresh(otp2)
        assert otp1.is_used is True
        assert otp2.is_used is True

    async def test_does_not_invalidate_different_purpose(self, db: AsyncSession, sample_user: User):
        otp_record = await repo.create_email_otp(
            db=db,
            user_id=sample_user.id,
            otp_hash=hash_otp("999999"),
            purpose=OtpPurpose.PASSWORD_RESET,
            expire_minutes=10,
        )
        await repo.invalidate_user_otps(db=db, user_id=sample_user.id, purpose=OtpPurpose.EMAIL_VERIFICATION)
        await db.refresh(otp_record)
        assert otp_record.is_used is False


# ── count_recent_resends ───────────────────────────────────────────────────


class TestCountRecentResends:
    async def test_counts_otps_within_window(self, db: AsyncSession, sample_user: User):
        for _ in range(3):
            await repo.create_email_otp(
                db=db,
                user_id=sample_user.id,
                otp_hash=hash_otp("000000"),
                purpose=OtpPurpose.EMAIL_VERIFICATION,
                expire_minutes=10,
            )
        count = await repo.count_recent_resends(
            db=db, user_id=sample_user.id, purpose=OtpPurpose.EMAIL_VERIFICATION, window_minutes=60
        )
        assert count == 3

    async def test_returns_zero_for_no_resends(self, db: AsyncSession, sample_user: User):
        count = await repo.count_recent_resends(
            db=db, user_id=sample_user.id, purpose=OtpPurpose.EMAIL_VERIFICATION, window_minutes=60
        )
        assert count == 0


# ── update_user_password ───────────────────────────────────────────────────


class TestUpdateUserPassword:
    async def test_updates_password_hash(self, db: AsyncSession, sample_user: User):
        original_hash = sample_user.password_hash
        await repo.update_user_password(db=db, user=sample_user, new_hash="new_hash_value")
        await db.refresh(sample_user)
        assert sample_user.password_hash == "new_hash_value"
        assert sample_user.password_hash != original_hash


# ── verify_user_email ──────────────────────────────────────────────────────


class TestVerifyUserEmail:
    async def test_marks_email_as_verified(self, db: AsyncSession, unverified_user: User):
        assert unverified_user.is_email_verified is False
        await repo.verify_user_email(db=db, user=unverified_user)
        await db.refresh(unverified_user)
        assert unverified_user.is_email_verified is True
