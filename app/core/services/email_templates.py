"""Branded HTML email templates — all display strings defined as constants."""

from app.core.config.settings import settings


def otp_email_html(otp: str, purpose: str) -> str:
    """Return a branded HTML OTP email body.

    Args:
        otp: The one-time password to display.
        purpose: Human-readable purpose string (e.g. "email verification").

    Returns:
        HTML string ready to send as the email body.
    """
    app_name = settings.app_name
    brand_color = settings.brand_color
    support_email = settings.support_email

    return f"""
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="UTF-8" />
      <meta name="viewport" content="width=device-width, initial-scale=1.0" />
      <title>{app_name} — OTP</title>
    </head>
    <body style="margin:0;padding:0;background:#f4f4f4;font-family:Arial,sans-serif;">
      <table width="100%" cellpadding="0" cellspacing="0"
             style="background:#f4f4f4;padding:40px 0;">
        <tr>
          <td align="center">
            <table width="560" cellpadding="0" cellspacing="0"
                   style="background:#ffffff;border-radius:8px;overflow:hidden;
                          box-shadow:0 2px 8px rgba(0,0,0,0.08);">

              <!-- Header -->
              <tr>
                <td align="center"
                    style="background:{brand_color};padding:32px 40px;">
                  <h1 style="margin:0;color:#ffffff;font-size:24px;font-weight:700;">
                    {app_name}
                  </h1>
                </td>
              </tr>

              <!-- Body -->
              <tr>
                <td style="padding:40px;">
                  <p style="margin:0 0 16px;font-size:16px;color:#333333;">
                    Your one-time password for <strong>{purpose}</strong> is:
                  </p>
                  <div style="text-align:center;margin:32px 0;">
                    <span style="display:inline-block;background:#f0f4ff;
                                 border-radius:8px;padding:16px 40px;
                                 font-size:36px;font-weight:700;
                                 letter-spacing:12px;color:{brand_color};">
                      {otp}
                    </span>
                  </div>
                  <p style="margin:0 0 8px;font-size:14px;color:#666666;">
                    This OTP expires in a few minutes. Do not share it with anyone.
                  </p>
                  <p style="margin:0;font-size:14px;color:#666666;">
                    If you did not request this, please contact us at
                    <a href="mailto:{support_email}"
                       style="color:{brand_color};">{support_email}</a>.
                  </p>
                </td>
              </tr>

              <!-- Footer -->
              <tr>
                <td align="center"
                    style="padding:24px 40px;border-top:1px solid #eeeeee;">
                  <p style="margin:0;font-size:12px;color:#999999;">
                    &copy; {app_name}. All rights reserved.
                  </p>
                </td>
              </tr>

            </table>
          </td>
        </tr>
      </table>
    </body>
    </html>
    """
