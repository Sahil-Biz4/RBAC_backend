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

    async def delete_all_user_sessions(self, user_id: int) -> None:
        """Revoke all sessions for a user (e.g. after password change)."""
        await self.delete_refresh_token(user_id)


redis_service = RedisService()
