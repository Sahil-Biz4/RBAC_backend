"""Auth feature database operations."""

from datetime import UTC, datetime, timedelta

from sqlalchemy import and_, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models.associations import RolePermission, UserRole
from app.models.email_otp import EmailOtp
from app.models.role import Role
from app.models.user import User


async def get_user_by_email(db: AsyncSession, email: str) -> User | None:
    """Fetch a user by email address, eagerly loading their roles."""
    result = await db.execute(
        select(User)
        .where(User.email == email)
        .options(selectinload(User.user_roles).selectinload(UserRole.role).selectinload(Role.role_permissions))
    )
    return result.scalars().first()


async def get_user_by_id(db: AsyncSession, user_id: int) -> User | None:
    """Fetch a user by integer primary key, eagerly loading their roles."""
    result = await db.execute(
        select(User)
        .where(User.id == user_id)
        .options(selectinload(User.user_roles).selectinload(UserRole.role).selectinload(Role.role_permissions))
    )
    return result.scalars().first()


async def create_user(
    db: AsyncSession, name: str, email: str, password_hash: str, commit: bool = True
) -> User:
    """Insert a new user record and return it."""
    user = User(name=name, email=email, password_hash=password_hash)
    db.add(user)
    if commit:
        await db.commit()
    else:
        await db.flush()
    await db.refresh(user)
    return user


async def assign_role_to_user(
    db: AsyncSession, user_id: int, role_name: str, commit: bool = True
) -> None:
    """Assign a named role to a user. No-ops if already assigned."""
    role_result = await db.execute(select(Role).where(Role.name == role_name))
    role = role_result.scalars().first()
    if not role:
        return

    existing = await db.execute(
        select(UserRole).where(and_(UserRole.user_id == user_id, UserRole.role_id == role.id))
    )
    if existing.scalars().first():
        return

    db.add(UserRole(user_id=user_id, role_id=role.id))
    if commit:
        await db.commit()


async def get_user_roles_and_permissions(db: AsyncSession, user_id: int) -> tuple[list[str], list[str]]:
    """Return (roles, permissions) lists for embedding into a JWT.

    Permissions are deduplicated across all assigned roles.
    """
    result = await db.execute(
        select(UserRole)
        .where(UserRole.user_id == user_id)
        .options(selectinload(UserRole.role).selectinload(Role.role_permissions).selectinload(RolePermission.permission))
    )
    user_roles = result.scalars().all()

    roles: list[str] = []
    permissions: set[str] = set()

    for ur in user_roles:
        roles.append(ur.role.name)
        for rp in ur.role.role_permissions:
            permissions.add(rp.permission.name)

    return roles, list(permissions)


async def create_email_otp(
    db: AsyncSession,
    user_id: int,
    otp_hash: str,
    purpose: str,
    expire_minutes: int,
    commit: bool = True,
) -> EmailOtp:
    """Insert a new OTP record and return it."""
    expires_at = datetime.now(UTC) + timedelta(minutes=expire_minutes)
    otp = EmailOtp(user_id=user_id, otp_hash=otp_hash, purpose=purpose, expires_at=expires_at)
    db.add(otp)
    if commit:
        await db.commit()
    else:
        await db.flush()
    await db.refresh(otp)
    return otp


async def get_active_otp(db: AsyncSession, user_id: int, purpose: str) -> EmailOtp | None:
    """Fetch the most recent unused, unexpired OTP for a user/purpose."""
    now = datetime.now(UTC)
    result = await db.execute(
        select(EmailOtp)
        .where(
            and_(
                EmailOtp.user_id == user_id,
                EmailOtp.purpose == purpose,
                EmailOtp.is_used == False,  # noqa: E712
                EmailOtp.expires_at > now,
            )
        )
        .order_by(EmailOtp.created_at.desc())
    )
    return result.scalars().first()


async def increment_otp_attempts(db: AsyncSession, otp: EmailOtp) -> None:
    """Increment the attempt counter on an OTP record."""
    otp.attempts += 1
    await db.commit()


async def mark_otp_used(db: AsyncSession, otp: EmailOtp) -> None:
    """Mark an OTP as used so it cannot be replayed."""
    otp.is_used = True
    await db.commit()


async def invalidate_user_otps(db: AsyncSession, user_id: int, purpose: str) -> None:
    """Mark all active OTPs for a user/purpose as used (e.g. before resending).

    Uses a bulk UPDATE statement instead of fetching rows into Python memory.
    """
    await db.execute(
        update(EmailOtp)
        .where(
            and_(
                EmailOtp.user_id == user_id,
                EmailOtp.purpose == purpose,
                EmailOtp.is_used == False,  # noqa: E712
            )
        )
        .values(is_used=True)
    )
    await db.commit()


async def count_recent_resends(db: AsyncSession, user_id: int, purpose: str, window_minutes: int) -> int:
    """Count how many OTPs have been sent in the given time window.

    Uses DB-level COUNT aggregation — no rows fetched into Python memory.
    """
    since = datetime.now(UTC) - timedelta(minutes=window_minutes)
    result = await db.execute(
        select(func.count()).select_from(EmailOtp).where(
            and_(
                EmailOtp.user_id == user_id,
                EmailOtp.purpose == purpose,
                EmailOtp.created_at >= since,
            )
        )
    )
    return result.scalar_one()


async def update_user_password(db: AsyncSession, user: User, new_hash: str) -> None:
    """Update the stored password hash for a user."""
    user.password_hash = new_hash
    await db.commit()


async def verify_user_email(db: AsyncSession, user: User) -> None:
    """Mark the user's email as verified."""
    user.is_email_verified = True
    await db.commit()
