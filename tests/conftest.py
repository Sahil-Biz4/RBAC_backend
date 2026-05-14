"""Shared pytest fixtures for the entire test suite."""

import os


os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
os.environ.setdefault("JWT_SECRET_KEY", "test-jwt-secret-key-for-tests-only")
os.environ.setdefault("ADMIN_SECRET_KEY", "test-admin-secret-key")
os.environ.setdefault("RATELIMIT_ENABLED", "false")

from unittest.mock import AsyncMock, patch

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from app.core.auth.jwt_handler import create_access_token, create_refresh_token
from app.core.auth.password import hash_password
from app.core.database import Base, get_db
from app.core.services.redis_service import redis_service as _redis_service
from app.main import app
from app.models.associations import RolePermission, UserRole
from app.models.permission import Permission
from app.models.role import Role
from app.models.user import User
from app.utils.constants import Permissions, RoleNames


_TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"


@pytest_asyncio.fixture
async def engine():
    """Create a fresh in-memory SQLite engine for each test function."""
    _engine = create_async_engine(
        _TEST_DATABASE_URL,
        echo=False,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    async with _engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield _engine
    await _engine.dispose()


@pytest_asyncio.fixture
async def db(engine):
    """Yield a fresh database session per test."""
    session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with session_factory() as session:
        yield session


@pytest_asyncio.fixture
async def client(db):
    """Yield an AsyncClient with the DB dependency overridden to use the test session."""

    async def _override_get_db():
        yield db

    app.dependency_overrides[get_db] = _override_get_db
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac
    app.dependency_overrides.clear()


# ── Redis mock fixture ─────────────────────────────────────────────────────


class MockRedisStore:
    """In-memory store replacing Redis for tests.

    Dict-like operations ([], get, pop) map to the refresh token store for
    backward compatibility with fixtures that do ``mock_redis[user_id] = token``.
    JTI access uses ``mock_redis.jti[user_id]``.
    """

    def __init__(self) -> None:
        self.refresh: dict[int, str] = {}
        self.jti: dict[int, str] = {}

    def __setitem__(self, key: int, value: str) -> None:
        self.refresh[key] = value

    def __getitem__(self, key: int) -> str:
        return self.refresh[key]

    def get(self, key: int, default: str | None = None) -> str | None:
        return self.refresh.get(key, default)

    def pop(self, key: int, *args) -> str | None:
        return self.refresh.pop(key, *args)

    def __contains__(self, key: int) -> bool:
        return key in self.refresh


@pytest.fixture
def mock_redis():
    """Replace redis_service with an in-memory MockRedisStore so tests need no real Redis."""
    store = MockRedisStore()

    async def _store_refresh(user_id: int, token: str, ttl: int) -> None:
        store.refresh[user_id] = token

    async def _verify_refresh(user_id: int, token: str) -> bool:
        return store.refresh.get(user_id) == token

    async def _get_refresh(user_id: int) -> str | None:
        return store.refresh.get(user_id)

    async def _delete_refresh(user_id: int) -> None:
        store.refresh.pop(user_id, None)

    async def _store_jti(user_id: int, jti: str, ttl: int) -> None:
        store.jti[user_id] = jti

    async def _verify_jti(user_id: int, jti: str) -> bool:
        return store.jti.get(user_id) == jti

    async def _delete_jti(user_id: int) -> None:
        store.jti.pop(user_id, None)

    async def _delete_all(user_id: int) -> None:
        store.refresh.pop(user_id, None)
        store.jti.pop(user_id, None)

    with (
        patch.object(_redis_service, "store_refresh_token", new=AsyncMock(side_effect=_store_refresh)),
        patch.object(_redis_service, "verify_refresh_token", new=AsyncMock(side_effect=_verify_refresh)),
        patch.object(_redis_service, "get_refresh_token", new=AsyncMock(side_effect=_get_refresh)),
        patch.object(_redis_service, "delete_refresh_token", new=AsyncMock(side_effect=_delete_refresh)),
        patch.object(_redis_service, "store_access_jti", new=AsyncMock(side_effect=_store_jti)),
        patch.object(_redis_service, "verify_access_jti", new=AsyncMock(side_effect=_verify_jti)),
        patch.object(_redis_service, "delete_access_jti", new=AsyncMock(side_effect=_delete_jti)),
        patch.object(_redis_service, "delete_all_user_sessions", new=AsyncMock(side_effect=_delete_all)),
    ):
        yield store


# ── Role & Permission helpers ──────────────────────────────────────────────


async def _create_role(db: AsyncSession, name: str) -> Role:
    role = Role(name=name, description=f"{name} role")
    db.add(role)
    await db.flush()
    await db.refresh(role)
    return role


async def _create_permission(db: AsyncSession, name: str) -> Permission:
    resource, action = name.split(":")
    perm = Permission(name=name, resource=resource, action=action)
    db.add(perm)
    await db.flush()
    await db.refresh(perm)
    return perm


async def _assign_permission(db: AsyncSession, role_id: int, permission_id: int) -> None:
    db.add(RolePermission(role_id=role_id, permission_id=permission_id))
    await db.flush()


async def _assign_role(db: AsyncSession, user_id: int, role_id: int) -> None:
    db.add(UserRole(user_id=user_id, role_id=role_id))
    await db.flush()


# ── User fixtures ──────────────────────────────────────────────────────────


@pytest_asyncio.fixture
async def sample_user_role(db: AsyncSession) -> Role:
    return await _create_role(db, RoleNames.USER)


@pytest_asyncio.fixture
async def sample_admin_role(db: AsyncSession) -> Role:
    role = await _create_role(db, RoleNames.ADMIN)
    for perm_name in [Permissions.USERS_READ, Permissions.USERS_UPDATE, Permissions.USERS_DELETE]:
        perm = await _create_permission(db, perm_name)
        await _assign_permission(db, role.id, perm.id)
    db.expire(role, ["role_permissions"])
    return role


@pytest_asyncio.fixture
async def sample_user(db: AsyncSession, sample_user_role: Role) -> User:
    """A verified, active regular user."""
    user = User(
        name="Test User",
        email="user@example.com",
        password_hash=hash_password("Password1!"),
        is_active=True,
        is_email_verified=True,
    )
    db.add(user)
    await db.flush()
    await db.refresh(user)
    await _assign_role(db, user.id, sample_user_role.id)
    db.expire(user, ["user_roles"])  # expire only this attr so selectinload re-queries
    return user


@pytest_asyncio.fixture
async def sample_admin_user(db: AsyncSession, sample_admin_role: Role) -> User:
    """A verified, active admin user."""
    user = User(
        name="Admin User",
        email="admin@example.com",
        password_hash=hash_password("Password1!"),
        is_active=True,
        is_email_verified=True,
    )
    db.add(user)
    await db.flush()
    await db.refresh(user)
    await _assign_role(db, user.id, sample_admin_role.id)
    db.expire(user, ["user_roles"])  # expire only this attr so selectinload re-queries
    return user


@pytest_asyncio.fixture
async def inactive_user(db: AsyncSession, sample_user_role: Role) -> User:
    """A verified but inactive user."""
    user = User(
        name="Inactive User",
        email="inactive@example.com",
        password_hash=hash_password("Password1!"),
        is_active=False,
        is_email_verified=True,
    )
    db.add(user)
    await db.flush()
    await db.refresh(user)
    await _assign_role(db, user.id, sample_user_role.id)
    db.expire(user, ["user_roles"])
    return user


@pytest_asyncio.fixture
async def unverified_user(db: AsyncSession, sample_user_role: Role) -> User:
    """A user whose email has NOT been verified."""
    user = User(
        name="Unverified User",
        email="unverified@example.com",
        password_hash=hash_password("Password1!"),
        is_active=True,
        is_email_verified=False,
    )
    db.add(user)
    await db.flush()
    await db.refresh(user)
    await _assign_role(db, user.id, sample_user_role.id)
    db.expire(user, ["user_roles"])
    return user


# ── Token fixtures ─────────────────────────────────────────────────────────


@pytest_asyncio.fixture
async def user_token(sample_user: User, mock_redis: MockRedisStore) -> str:
    """Valid access token for sample_user with 'user' role. JTI stored in mock Redis."""
    token, jti = create_access_token(
        subject=sample_user.id,
        email=sample_user.email,
        roles=[RoleNames.USER],
        permissions=[Permissions.PROFILE_READ, Permissions.PROFILE_UPDATE],
        perms_version=sample_user.perms_version,
    )
    mock_redis.jti[sample_user.id] = jti
    return token


@pytest_asyncio.fixture
async def admin_token(sample_admin_user: User, mock_redis: MockRedisStore) -> str:
    """Valid access token for sample_admin_user with 'admin' role. JTI stored in mock Redis."""
    token, jti = create_access_token(
        subject=sample_admin_user.id,
        email=sample_admin_user.email,
        roles=[RoleNames.ADMIN],
        permissions=[Permissions.USERS_READ, Permissions.USERS_UPDATE, Permissions.USERS_DELETE],
        perms_version=sample_admin_user.perms_version,
    )
    mock_redis.jti[sample_admin_user.id] = jti
    return token


@pytest_asyncio.fixture
async def admin_full_token(sample_admin_user: User, mock_redis: MockRedisStore) -> str:
    """Access token for sample_admin_user with ALL admin permissions. JTI stored in mock Redis."""
    token, jti = create_access_token(
        subject=sample_admin_user.id,
        email=sample_admin_user.email,
        roles=[RoleNames.ADMIN],
        permissions=Permissions.ALL,
        perms_version=sample_admin_user.perms_version,
    )
    mock_redis.jti[sample_admin_user.id] = jti
    return token


@pytest_asyncio.fixture
async def user_refresh_token(sample_user: User, mock_redis: MockRedisStore) -> str:
    """Valid refresh token for sample_user, stored in mock Redis."""
    token, _ = create_refresh_token(subject=sample_user.id, email=sample_user.email)
    mock_redis[sample_user.id] = token
    return token
