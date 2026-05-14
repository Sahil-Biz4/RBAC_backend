"""Unit tests for email service and OTP email templates."""

from unittest.mock import AsyncMock, MagicMock, patch

from app.core.services.email_service import _send_via_sendgrid, send_otp_email
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


class TestSendViaSendgrid:
    def test_calls_sendgrid_client_and_returns_status_code(self):
        """_send_via_sendgrid must instantiate the client, call send(), and return the status code."""
        mock_response = MagicMock()
        mock_response.status_code = 202

        mock_client_instance = MagicMock()
        mock_client_instance.send.return_value = mock_response

        mock_mail = MagicMock()

        with patch("app.core.services.email_service.SendGridAPIClient", return_value=mock_client_instance) as mock_cls:
            result = _send_via_sendgrid("test-api-key", mock_mail)

        mock_cls.assert_called_once_with("test-api-key")
        mock_client_instance.send.assert_called_once_with(mock_mail)
        assert result == 202
