"""Unit tests for email service and OTP email templates."""

from unittest.mock import AsyncMock, MagicMock, patch

from app.core.services.email_service import send_otp_email
from app.core.services.email_templates import otp_email_html


class TestOtpEmailHtml:
    def test_returns_html_string_containing_otp(self):
        result = otp_email_html(otp="123456", purpose="email verification")
        assert isinstance(result, str)
        assert "123456" in result
        assert "email verification" in result

    def test_html_contains_doctype(self):
        result = otp_email_html(otp="000000", purpose="password reset")
        assert "<!DOCTYPE html>" in result


class TestSendOtpEmail:
    async def test_returns_false_when_sendgrid_not_configured(self):
        mock_settings = MagicMock()
        mock_settings.sendgrid_api_key = None
        mock_settings.sendgrid_from_email = None
        with patch("app.core.services.email_service.settings", mock_settings):
            result = await send_otp_email("test@example.com", "123456", "email_verification")
        assert result is False

    async def test_returns_true_when_send_succeeds(self):
        mock_settings = MagicMock()
        mock_settings.sendgrid_api_key = "fake-api-key"
        mock_settings.sendgrid_from_email = "from@example.com"
        with (
            patch("app.core.services.email_service.settings", mock_settings),
            patch(
                "app.core.services.email_service.asyncio.to_thread",
                new=AsyncMock(return_value=202),
            ),
        ):
            result = await send_otp_email("to@example.com", "123456", "email_verification")
        assert result is True

    async def test_returns_false_when_send_raises_exception(self):
        mock_settings = MagicMock()
        mock_settings.sendgrid_api_key = "fake-api-key"
        mock_settings.sendgrid_from_email = "from@example.com"
        with (
            patch("app.core.services.email_service.settings", mock_settings),
            patch(
                "app.core.services.email_service.asyncio.to_thread",
                new=AsyncMock(side_effect=Exception("connection refused")),
            ),
        ):
            result = await send_otp_email("to@example.com", "123456", "email_verification")
        assert result is False
