"""Email delivery service via SendGrid.

The SendGrid Python SDK uses the synchronous ``requests`` library internally.
All outbound calls are wrapped in ``asyncio.to_thread`` to prevent blocking
the async event loop — critical for maintaining throughput under concurrent load.
"""

import asyncio
import logging

from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail

from app.core.config.settings import settings
from app.core.services.email_templates import otp_email_html


logger = logging.getLogger(__name__)


def _send_via_sendgrid(api_key: str, message: Mail) -> int:
    """Synchronous SendGrid send — runs in a thread pool via asyncio.to_thread."""
    client = SendGridAPIClient(api_key)
    response = client.send(message)
    return response.status_code


async def send_otp_email(to_email: str, otp: str, purpose: str) -> bool:
    """Send a branded OTP email to the given address via SendGrid.

    The blocking SendGrid HTTP call is dispatched to a thread executor so it
    does not stall the event loop.

    Args:
        to_email: Recipient email address.
        otp:      The one-time password to include in the email.
        purpose:  Human-readable purpose shown in the email subject and body.

    Returns:
        True if SendGrid accepted the message (2xx status), False otherwise.
    """
    if not settings.sendgrid_api_key or not settings.sendgrid_from_email:
        logger.warning("SendGrid not configured — OTP email not sent to %s", to_email)
        return False

    subject = f"{settings.app_name} — Your OTP for {purpose}"
    html_content = otp_email_html(otp=otp, purpose=purpose)

    message = Mail(
        from_email=settings.sendgrid_from_email,
        to_emails=to_email,
        subject=subject,
        html_content=html_content,
    )

    try:
        status_code = await asyncio.to_thread(_send_via_sendgrid, settings.sendgrid_api_key, message)
        logger.info("OTP email sent to %s — status %s", to_email, status_code)
        return True
    except Exception as exc:
        logger.error("Failed to send OTP email to %s: %s", to_email, exc)
        return False
