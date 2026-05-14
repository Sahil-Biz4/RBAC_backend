"""Unit tests for users repository — direct DB operations."""

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth.password import hash_password
from app.features.users import repository as repo
from app.models.user import User


async def _make_user(
    db: AsyncSession,
    email: str = "repo_user@example.com",
    name: str = "Repo User",
    is_active: bool = True,
) -> User:
    user = User(
        name=name,
        email=email,
        password_hash=hash_password("Password1!"),
        is_active=is_active,
        is_email_verified=True,
    )
    db.add(user)
    await db.flush()
    await db.refresh(user)
    return user


# ── get_all_users ──────────────────────────────────────────────────────────


class TestGetAllUsers:
    async def test_returns_empty_list_when_no_users(self, db: AsyncSession):
        users, total = await repo.get_all_users(db=db)
        assert users == []
        assert total == 0

    async def test_returns_all_active_users(self, db: AsyncSession):
        await _make_user(db, "u1@example.com")
        await _make_user(db, "u2@example.com")
        users, total = await repo.get_all_users(db=db)
        assert total == 2
        assert len(users) == 2

    async def test_excludes_soft_deleted_users(self, db: AsyncSession):
        user = await _make_user(db, "deleted@example.com")
        await repo.soft_delete_user(db=db, user=user)
        users, total = await repo.get_all_users(db=db)
        assert total == 0

    async def test_respects_limit(self, db: AsyncSession):
        for i in range(5):
            await _make_user(db, f"paged{i}@example.com")
        users, total = await repo.get_all_users(db=db, skip=0, limit=3)
        assert total == 5
        assert len(users) == 3

    async def test_respects_skip(self, db: AsyncSession):
        for i in range(5):
            await _make_user(db, f"skip{i}@example.com")
        users, total = await repo.get_all_users(db=db, skip=3, limit=10)
        assert total == 5
        assert len(users) == 2


# ── get_user_by_id ─────────────────────────────────────────────────────────


class TestGetUserById:
    async def test_returns_user_for_valid_id(self, db: AsyncSession):
        user = await _make_user(db)
        found = await repo.get_user_by_id(db=db, user_id=user.id)
        assert found is not None
        assert found.id == user.id

    async def test_returns_none_for_missing_id(self, db: AsyncSession):
        found = await repo.get_user_by_id(db=db, user_id=99999)
        assert found is None

    async def test_returns_none_for_soft_deleted_user(self, db: AsyncSession):
        user = await _make_user(db, "deleted_id@example.com")
        await repo.soft_delete_user(db=db, user=user)
        found = await repo.get_user_by_id(db=db, user_id=user.id)
        assert found is None


# ── get_user_by_email ──────────────────────────────────────────────────────


class TestGetUserByEmail:
    async def test_returns_user_for_valid_email(self, db: AsyncSession):
        user = await _make_user(db, "valid_email@example.com")
        found = await repo.get_user_by_email(db=db, email="valid_email@example.com")
        assert found is not None
        assert found.id == user.id

    async def test_returns_none_for_missing_email(self, db: AsyncSession):
        found = await repo.get_user_by_email(db=db, email="ghost@example.com")
        assert found is None

    async def test_returns_none_for_soft_deleted_user(self, db: AsyncSession):
        user = await _make_user(db, "del_email@example.com")
        await repo.soft_delete_user(db=db, user=user)
        found = await repo.get_user_by_email(db=db, email="del_email@example.com")
        assert found is None


# ── create_user ────────────────────────────────────────────────────────────


class TestCreateUser:
    async def test_creates_user_with_given_fields(self, db: AsyncSession):
        user = await repo.create_user(
            db=db,
            name="Created",
            email="created@example.com",
            password_hash=hash_password("Password1!"),
        )
        assert user.id is not None
        assert user.name == "Created"
        assert user.email == "created@example.com"
        assert user.is_email_verified is False

    async def test_creates_inactive_user_when_requested(self, db: AsyncSession):
        user = await repo.create_user(
            db=db,
            name="Inactive",
            email="inactive_repo@example.com",
            password_hash=hash_password("Password1!"),
            is_active=False,
        )
        assert user.is_active is False


# ── update_user_password ───────────────────────────────────────────────────


class TestUpdateUserPassword:
    async def test_updates_password_hash(self, db: AsyncSession):
        user = await _make_user(db, "pw_update@example.com")
        new_hash = hash_password("NewPassword2@")
        await repo.update_user_password(db=db, user=user, new_hash=new_hash)
        await db.refresh(user)
        assert user.password_hash == new_hash


# ── update_user_name ───────────────────────────────────────────────────────


class TestUpdateUserName:
    async def test_updates_name_successfully(self, db: AsyncSession):
        user = await _make_user(db, "name_update@example.com")
        updated = await repo.update_user_name(db=db, user=user, name="New Name")
        assert updated.name == "New Name"


# ── soft_delete_user ───────────────────────────────────────────────────────


class TestSoftDeleteUser:
    async def test_sets_deleted_at_and_deactivates(self, db: AsyncSession):
        user = await _make_user(db, "soft_del@example.com")
        await repo.soft_delete_user(db=db, user=user)
        await db.refresh(user)
        assert user.deleted_at is not None
        assert user.is_active is False


# ── update_user ────────────────────────────────────────────────────────────


class TestUpdateUser:
    async def test_update_all_fields(self, db: AsyncSession):
        user = await _make_user(db, "full_update@example.com")
        updated = await repo.update_user(db=db, user=user, name="Updated", email="updated@example.com", is_active=False)
        assert updated.name == "Updated"
        assert updated.email == "updated@example.com"
        assert updated.is_active is False

    async def test_update_only_name(self, db: AsyncSession):
        user = await _make_user(db, "partial_update@example.com")
        original_email = user.email
        updated = await repo.update_user(db=db, user=user, name="Only Name Changed")
        assert updated.name == "Only Name Changed"
        assert updated.email == original_email

    async def test_update_only_is_active(self, db: AsyncSession):
        user = await _make_user(db, "active_update@example.com")
        updated = await repo.update_user(db=db, user=user, is_active=False)
        assert updated.is_active is False
