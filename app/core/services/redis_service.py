"""Redis service — server-side refresh token storage keyed by user_id."""

import redis.asyncio as aioredis

from app.core.config.settings import settings


class RedisService:
    def __init__(self) -> None:
        self._client: aioredis.Redis | None = None

    async def connect(self) -> None:
        """Open an async Redis connection pool."""
        self._client = await aioredis.from_url(
            settings.redis_url,
            encoding="utf-8",
            decode_responses=True,
        )

    async def disconnect(self) -> None:
        """Close the Redis connection."""
        if self._client:
            await self._client.aclose()

    @property
    def client(self) -> aioredis.Redis:
        if self._client is None:
            raise RuntimeError("Redis not connected — call connect() first.")
        return self._client

    async def store_refresh_token(self, user_id: int, token: str, ttl_seconds: int) -> None:
        """Store a refresh token keyed by user_id with TTL."""
        await self.client.setex(f"refresh_token:{user_id}", ttl_seconds, token)

    async def get_refresh_token(self, user_id: int) -> str | None:
        """Retrieve the stored refresh token for a user."""
        return await self.client.get(f"refresh_token:{user_id}")

    async def verify_refresh_token(self, user_id: int, token: str) -> bool:
        """Return True if the stored token matches the provided one."""
        stored = await self.get_refresh_token(user_id)
        return stored is not None and stored == token

    async def delete_refresh_token(self, user_id: int) -> None:
        """Remove the refresh token on logout."""
        await self.client.delete(f"refresh_token:{user_id}")

    async def store_access_jti(self, user_id: int, jti: str, ttl_seconds: int) -> None:
        """Store the active access token JTI keyed by user_id with TTL."""
        await self.client.setex(f"access_jti:{user_id}", ttl_seconds, jti)

    async def get_access_jti(self, user_id: int) -> str | None:
        """Retrieve the stored access JTI for a user."""
        return await self.client.get(f"access_jti:{user_id}")

    async def verify_access_jti(self, user_id: int, jti: str) -> bool:
        """Return True if the stored JTI matches the provided one."""
        stored = await self.get_access_jti(user_id)
        return stored is not None and stored == jti

    async def delete_access_jti(self, user_id: int) -> None:
        """Remove the access JTI (e.g. on logout)."""
        await self.client.delete(f"access_jti:{user_id}")

    async def delete_all_user_sessions(self, user_id: int) -> None:
        """Revoke all sessions for a user (e.g. after password change)."""
        await self.delete_refresh_token(user_id)
        await self.delete_access_jti(user_id)

    async def increment_ip_failures(self, key_prefix: str, ip: str, ttl_seconds: int) -> int:
        """Increment the failure counter for an IP and return the new count.

        The TTL is set from the first increment so the lockout window is fixed,
        not sliding — the IP is released exactly one window after the first failure.
        Uses SETNX to set TTL only on key creation; subsequent failures extend nothing.
        """
        key = f"{key_prefix}:{ip}"
        count = await self.client.incr(key)
        if count == 1:
            await self.client.expire(key, ttl_seconds)
        return count

    async def get_ip_failures(self, key_prefix: str, ip: str) -> int:
        """Return the current failure count for an IP (0 if no record exists)."""
        value = await self.client.get(f"{key_prefix}:{ip}")
        return int(value) if value else 0

    async def clear_ip_failures(self, key_prefix: str, ip: str) -> None:
        """Remove the failure counter after a successful operation."""
        await self.client.delete(f"{key_prefix}:{ip}")


redis_service = RedisService()
