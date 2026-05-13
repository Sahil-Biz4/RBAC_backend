"""Unit tests for users service — calls service functions directly with DB session."""

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth.password import verify_password
from app.core.exceptions import AuthError, ConflictError, ForbiddenError, NotFoundError
from app.features.users import service
from app.models.user import User


# ── change_my_password ─────────────────────────────────────────────────────


class TestChangeMyPassword:
    async def test_correct_current_password_changes_successfully(self, db: AsyncSession, sample_user: User):
        result = await service.change_my_password(
            db=db,
            user=sample_user,
            current_password="Password1!",
            new_password="NewPassword2@",
        )
        assert result["success"] is True

    async def test_wrong_current_password_raises_auth_error(self, db: AsyncSession, sample_user: User):
        with pytest.raises(AuthError):
            await service.change_my_password(
                db=db,
                user=sample_user,
                current_password="WrongPass1!",
                new_password="NewPassword2@",
            )

    async def test_same_password_raises_auth_error(self, db: AsyncSession, sample_user: User):
        with pytest.raises(AuthError):
            await service.change_my_password(
                db=db,
                user=sample_user,
                current_password="Password1!",
                new_password="Password1!",
            )

    async def test_no_password_hash_raises_auth_error(self, db: AsyncSession, sample_user: User):
        sample_user.password_hash = None
        with pytest.raises(AuthError):
            await service.change_my_password(
                db=db,
                user=sample_user,
                current_password="Password1!",
                new_password="NewPassword2@",
            )

    async def test_password_is_updated_in_db(self, db: AsyncSession, sample_user: User):
        await service.change_my_password(
            db=db,
            user=sample_user,
            current_password="Password1!",
            new_password="NewPassword2@",
        )
        await db.refresh(sample_user)
        assert verify_password("NewPassword2@", sample_user.password_hash) is True


# ── update_my_profile ──────────────────────────────────────────────────────


class TestUpdateMyProfile:
    async def test_update_name_returns_updated_user(self, db: AsyncSession, sample_user: User):
        result = await service.update_my_profile(db=db, user=sample_user, name="Updated Name")
        assert result.name == "Updated Name"

    async def test_none_name_returns_user_unchanged(self, db: AsyncSession, sample_user: User):
        original_name = sample_user.name
        result = await service.update_my_profile(db=db, user=sample_user, name=None)
        assert result.name == original_name


# ── list_users ─────────────────────────────────────────────────────────────


class TestListUsers:
    async def test_returns_paginated_result(self, db: AsyncSession, sample_user: User):
        result = await service.list_users(db=db, skip=0, limit=20)
        assert "users" in result
        assert result["total"] >= 1

    async def test_pagination_fields_present(self, db: AsyncSession):
        result = await service.list_users(db=db, skip=0, limit=5)
        assert "skip" in result
        assert "limit" in result
        assert "has_next" in result

    async def test_has_next_false_when_all_returned(self, db: AsyncSession, sample_user: User):
        result = await service.list_users(db=db, skip=0, limit=100)
        assert result["has_next"] is False

    async def test_has_next_true_when_more_exist(self, db: AsyncSession, sample_user: User, sample_admin_user: User):
        result = await service.list_users(db=db, skip=0, limit=1)
        assert result["has_next"] is True


# ── get_user_by_id ─────────────────────────────────────────────────────────


class TestGetUserById:
    async def test_existing_user_returns_user(self, db: AsyncSession, sample_user: User):
        result = await service.get_user_by_id(db=db, user_id=sample_user.id)
        assert result.id == sample_user.id

    async def test_nonexistent_user_raises_not_found(self, db: AsyncSession):
        with pytest.raises(NotFoundError):
            await service.get_user_by_id(db=db, user_id=99999)


# ── delete_user ────────────────────────────────────────────────────────────


class TestDeleteUser:
    async def test_admin_can_delete_other_user(self, db: AsyncSession, sample_user: User, sample_admin_user: User):
        result = await service.delete_user(db=db, user_id=sample_user.id, requesting_user_id=sample_admin_user.id)
        assert result["success"] is True

    async def test_cannot_delete_self_raises_forbidden(self, db: AsyncSession, sample_admin_user: User):
        with pytest.raises(ForbiddenError):
            await service.delete_user(
                db=db,
                user_id=sample_admin_user.id,
                requesting_user_id=sample_admin_user.id,
            )

    async def test_nonexistent_user_raises_not_found(self, db: AsyncSession, sample_admin_user: User):
        with pytest.raises(NotFoundError):
            await service.delete_user(db=db, user_id=99999, requesting_user_id=sample_admin_user.id)


# ── create_user ────────────────────────────────────────────────────────────


class TestCreateUser:
    async def test_creates_new_user_successfully(self, db: AsyncSession):
        result = await service.create_user(
            db=db,
            name="New Admin User",
            email="newadminuser@example.com",
            password="Password1!",
        )
        assert result.name == "New Admin User"
        assert result.email == "newadminuser@example.com"

    async def test_duplicate_email_raises_conflict(self, db: AsyncSession, sample_user: User):
        with pytest.raises(ConflictError):
            await service.create_user(
                db=db,
                name="Dup",
                email=sample_user.email,
                password="Password1!",
            )

    async def test_inactive_user_can_be_created(self, db: AsyncSession):
        result = await service.create_user(
            db=db,
            name="Inactive User",
            email="inactiveadmin@example.com",
            password="Password1!",
            is_active=False,
        )
        assert result.is_active is False


# ── update_user ────────────────────────────────────────────────────────────


class TestUpdateUser:
    async def test_update_name_succeeds(self, db: AsyncSession, sample_user: User):
        result = await service.update_user(db=db, user_id=sample_user.id, name="New Name")
        assert result.name == "New Name"

    async def test_update_is_active_succeeds(self, db: AsyncSession, sample_user: User):
        result = await service.update_user(db=db, user_id=sample_user.id, is_active=False)
        assert result.is_active is False

    async def test_update_email_to_new_unique_email_succeeds(self, db: AsyncSession, sample_user: User):
        result = await service.update_user(db=db, user_id=sample_user.id, email="new_unique@example.com")
        assert result.email == "new_unique@example.com"

    async def test_update_email_to_same_email_succeeds(self, db: AsyncSession, sample_user: User):
        result = await service.update_user(db=db, user_id=sample_user.id, email=sample_user.email)
        assert result.email == sample_user.email

    async def test_update_email_to_existing_email_raises_conflict(
        self, db: AsyncSession, sample_user: User, sample_admin_user: User
    ):
        with pytest.raises(ConflictError):
            await service.update_user(
                db=db,
                user_id=sample_user.id,
                email=sample_admin_user.email,
            )

    async def test_nonexistent_user_raises_not_found(self, db: AsyncSession):
        with pytest.raises(NotFoundError):
            await service.update_user(db=db, user_id=99999, name="Ghost")
