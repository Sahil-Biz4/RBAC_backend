"""Unit tests for Redis service using a mock Redis client."""

from unittest.mock import AsyncMock, patch

import pytest

from app.core.services.redis_service import RedisService


@pytest.fixture
def redis_svc():
    """Return a fresh RedisService with a mocked client."""
    svc = RedisService()
    mock_client = AsyncMock()
    svc._client = mock_client
    return svc, mock_client


class TestRedisServiceConnect:
    async def test_connect_sets_client(self):
        svc = RedisService()
        mock_client = AsyncMock()
        with patch("app.core.services.redis_service.aioredis.from_url", new=AsyncMock(return_value=mock_client)):
            await svc.connect()
        assert svc._client is mock_client

    async def test_disconnect_closes_client(self):
        svc = RedisService()
        mock_client = AsyncMock()
        svc._client = mock_client
        await svc.disconnect()
        mock_client.aclose.assert_called_once()

    async def test_disconnect_no_client_does_nothing(self):
        svc = RedisService()
        await svc.disconnect()  # Should not raise


class TestRedisServiceClientProperty:
    def test_client_raises_when_not_connected(self):
        svc = RedisService()
        with pytest.raises(RuntimeError, match="Redis not connected"):
            _ = svc.client


class TestStoreRefreshToken:
    async def test_stores_with_setex(self, redis_svc):
        svc, mock_client = redis_svc
        await svc.store_refresh_token(user_id=1, token="mytoken", ttl_seconds=3600)
        mock_client.setex.assert_called_once_with("refresh_token:1", 3600, "mytoken")


class TestGetRefreshToken:
    async def test_returns_stored_token(self, redis_svc):
        svc, mock_client = redis_svc
        mock_client.get.return_value = "stored-token"
        result = await svc.get_refresh_token(user_id=1)
        assert result == "stored-token"
        mock_client.get.assert_called_once_with("refresh_token:1")

    async def test_returns_none_when_not_found(self, redis_svc):
        svc, mock_client = redis_svc
        mock_client.get.return_value = None
        result = await svc.get_refresh_token(user_id=99)
        assert result is None


class TestVerifyRefreshToken:
    async def test_returns_true_when_token_matches(self, redis_svc):
        svc, mock_client = redis_svc
        mock_client.get.return_value = "my-token"
        result = await svc.verify_refresh_token(user_id=1, token="my-token")
        assert result is True

    async def test_returns_false_when_token_differs(self, redis_svc):
        svc, mock_client = redis_svc
        mock_client.get.return_value = "stored-token"
        result = await svc.verify_refresh_token(user_id=1, token="different-token")
        assert result is False

    async def test_returns_false_when_not_stored(self, redis_svc):
        svc, mock_client = redis_svc
        mock_client.get.return_value = None
        result = await svc.verify_refresh_token(user_id=1, token="any-token")
        assert result is False


class TestDeleteRefreshToken:
    async def test_deletes_token(self, redis_svc):
        svc, mock_client = redis_svc
        await svc.delete_refresh_token(user_id=1)
        mock_client.delete.assert_called_once_with("refresh_token:1")


class TestStoreAccessJti:
    async def test_stores_jti_with_setex(self, redis_svc):
        svc, mock_client = redis_svc
        await svc.store_access_jti(user_id=1, jti="my-jti", ttl_seconds=900)
        mock_client.setex.assert_called_once_with("access_jti:1", 900, "my-jti")


class TestGetAccessJti:
    async def test_returns_stored_jti(self, redis_svc):
        svc, mock_client = redis_svc
        mock_client.get.return_value = "stored-jti"
        result = await svc.get_access_jti(user_id=1)
        assert result == "stored-jti"
        mock_client.get.assert_called_once_with("access_jti:1")


class TestVerifyAccessJti:
    async def test_returns_true_when_jti_matches(self, redis_svc):
        svc, mock_client = redis_svc
        mock_client.get.return_value = "my-jti"
        result = await svc.verify_access_jti(user_id=1, jti="my-jti")
        assert result is True

    async def test_returns_false_when_jti_differs(self, redis_svc):
        svc, mock_client = redis_svc
        mock_client.get.return_value = "stored-jti"
        result = await svc.verify_access_jti(user_id=1, jti="different-jti")
        assert result is False

    async def test_returns_false_when_not_stored(self, redis_svc):
        svc, mock_client = redis_svc
        mock_client.get.return_value = None
        result = await svc.verify_access_jti(user_id=1, jti="any-jti")
        assert result is False


class TestDeleteAccessJti:
    async def test_deletes_access_jti(self, redis_svc):
        svc, mock_client = redis_svc
        await svc.delete_access_jti(user_id=1)
        mock_client.delete.assert_called_once_with("access_jti:1")


class TestDeleteAllUserSessions:
    async def test_deletes_both_refresh_and_access_tokens(self, redis_svc):
        svc, mock_client = redis_svc
        await svc.delete_all_user_sessions(user_id=1)
        assert mock_client.delete.call_count == 2
        calls = [c.args[0] for c in mock_client.delete.call_args_list]
        assert "refresh_token:1" in calls
        assert "access_jti:1" in calls


class TestIncrementIpFailures:
    async def test_increments_counter_and_sets_ttl_on_first_call(self, redis_svc):
        """On the first increment (count == 1), the TTL must be set."""
        svc, mock_client = redis_svc
        mock_client.incr.return_value = 1
        result = await svc.increment_ip_failures("admin_fail", "1.2.3.4", 300)
        mock_client.incr.assert_called_once_with("admin_fail:1.2.3.4")
        mock_client.expire.assert_called_once_with("admin_fail:1.2.3.4", 300)
        assert result == 1

    async def test_subsequent_increments_skip_ttl_reset(self, redis_svc):
        """On count > 1, the TTL must NOT be reset (non-sliding window)."""
        svc, mock_client = redis_svc
        mock_client.incr.return_value = 2
        result = await svc.increment_ip_failures("admin_fail", "1.2.3.4", 300)
        mock_client.expire.assert_not_called()
        assert result == 2


class TestGetIpFailures:
    async def test_returns_count_when_key_exists(self, redis_svc):
        svc, mock_client = redis_svc
        mock_client.get.return_value = "3"
        result = await svc.get_ip_failures("admin_fail", "1.2.3.4")
        assert result == 3

    async def test_returns_zero_when_key_missing(self, redis_svc):
        svc, mock_client = redis_svc
        mock_client.get.return_value = None
        result = await svc.get_ip_failures("admin_fail", "1.2.3.4")
        assert result == 0


class TestClearIpFailures:
    async def test_deletes_failure_key(self, redis_svc):
        svc, mock_client = redis_svc
        await svc.clear_ip_failures("admin_fail", "1.2.3.4")
        mock_client.delete.assert_called_once_with("admin_fail:1.2.3.4")
