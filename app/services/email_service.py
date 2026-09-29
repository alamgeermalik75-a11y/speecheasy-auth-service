import logging
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Optional
import aiosmtplib
from app.config import settings

logger = logging.getLogger(__name__)


class EmailService:
    @staticmethod
    def _is_smtp_configured() -> bool:
        return bool(settings.SMTP_HOST and settings.SMTP_USERNAME and settings.SMTP_PASSWORD)

    @classmethod
    async def send_verification_email(cls, to_email: str, token: str, parent_name: str = "Parent") -> bool:
        """
        Sends a 6-digit OTP code and direct verification link to the newly registered patient.
        """
        verification_link = f"{settings.BACKEND_URL}/api/v1/auth/verify-email-link?token={token}"
        formatted_otp = token.strip()

        subject = "SpeechEasy — Your Verification Code: " + token.strip()
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <style>
                body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #f4f7f6; margin: 0; padding: 20px; }}
                .container {{ max-width: 580px; margin: 0 auto; background: #ffffff; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 12px rgba(0,0,0,0.06); }}
                .header {{ background: #1B5E20; padding: 32px 24px; text-align: center; color: #ffffff; }}
                .header h1 {{ margin: 0; font-size: 26px; font-weight: 700; letter-spacing: 0.5px; }}
                .content {{ padding: 32px 28px; color: #333333; line-height: 1.6; font-size: 15px; }}
                .otp-box {{ background: #f0fdf4; border: 1.5px solid #22c55e; border-radius: 12px; padding: 24px 16px; margin: 28px 0; text-align: center; }}
                .otp-title {{ font-size: 13px; font-weight: 700; text-transform: uppercase; letter-spacing: 1.5px; color: #166534; margin-bottom: 12px; }}
                .otp-code {{ font-family: 'SF Pro Display', -apple-system, Roboto, monospace; font-size: 36px; font-weight: 800; letter-spacing: 8px; color: #15803d; line-height: 1; }}
                .otp-sub {{ font-size: 13px; color: #4ade80; margin-top: 10px; color: #166534; }}
                .divider {{ text-align: center; margin: 24px 0 16px 0; font-size: 12px; font-weight: 600; color: #94a3b8; letter-spacing: 1.5px; }}
                .btn-container {{ text-align: center; margin: 16px 0 24px 0; }}
                .button {{ background-color: #1B5E20; color: #ffffff !important; padding: 14px 34px; text-decoration: none; border-radius: 8px; font-weight: 600; display: inline-block; font-size: 15px; }}
                .footer {{ background: #f8fafc; padding: 20px; text-align: center; font-size: 12px; color: #94a3b8; border-top: 1px solid #e2e8f0; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>SpeechEasy</h1>
                </div>
                <div class="content">
                    <p>Dear {parent_name},</p>
                    <p>Welcome to <strong>SpeechEasy</strong>! Thank you for registering your child's speech therapy account.</p>
                    <p>Please use the 6-digit verification code below to activate your account in the app:</p>
                    
                    <div class="otp-box">
                        <div class="otp-title">Your 6-Digit Verification Code (OTP)</div>
                        <div class="otp-code">{formatted_otp}</div>
                        <div class="otp-sub">Enter this code in the SpeechEasy app to verify your account</div>
                    </div>

                    <div class="divider">— OR VERIFY WITH ONE CLICK —</div>

                    <div class="btn-container">
                        <a href="{verification_link}" class="button" target="_blank">Verify Email Address</a>
                    </div>

                    <p style="font-size: 13px; color: #64748b; margin-top: 24px;">
                        This verification code and link will expire in {settings.EMAIL_VERIFICATION_TOKEN_EXPIRE_HOURS} hours.<br>
                        If you did not create an account on SpeechEasy, you can safely ignore this email.
                    </p>
                </div>
                <div class="footer">
                    &copy; 2026 SpeechEasy. All rights reserved.
                </div>
            </div>
        </body>
        </html>
        """

        plain_text = (
            f"Dear {parent_name},\n\n"
            f"Welcome to SpeechEasy! Your 6-digit verification code (OTP) is:\n\n"
            f"   {formatted_otp}\n\n"
            f"Enter this code in the app to activate your account.\n\n"
            f"Or verify instantly with one click:\n"
            f"{verification_link}\n\n"
            f"This code will expire in {settings.EMAIL_VERIFICATION_TOKEN_EXPIRE_HOURS} hours.\n"
        )

        return await cls._send_email(to_email, subject, plain_text, html_content)

    @classmethod
    async def send_password_reset_email(cls, to_email: str, token: str) -> bool:
        """
        Sends a 6-digit password reset OTP and direct reset link to the patient account.
        """
        reset_link = f"{settings.BACKEND_URL}/api/v1/auth/reset-password-link?token={token}"
        formatted_otp = token.strip()

        subject = "SpeechEasy — Your Password Reset Code: " + token.strip()
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <style>
                body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #f4f7f6; margin: 0; padding: 20px; }}
                .container {{ max-width: 580px; margin: 0 auto; background: #ffffff; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 12px rgba(0,0,0,0.06); }}
                .header {{ background: #1B5E20; padding: 32px 24px; text-align: center; color: #ffffff; }}
                .header h1 {{ margin: 0; font-size: 26px; font-weight: 700; letter-spacing: 0.5px; }}
                .content {{ padding: 32px 28px; color: #333333; line-height: 1.6; font-size: 15px; }}
                .otp-box {{ background: #f0fdf4; border: 1.5px solid #22c55e; border-radius: 12px; padding: 24px 16px; margin: 28px 0; text-align: center; }}
                .otp-title {{ font-size: 13px; font-weight: 700; text-transform: uppercase; letter-spacing: 1.5px; color: #166534; margin-bottom: 12px; }}
                .otp-code {{ font-family: 'SF Pro Display', -apple-system, Roboto, monospace; font-size: 36px; font-weight: 800; letter-spacing: 8px; color: #15803d; line-height: 1; }}
                .otp-sub {{ font-size: 13px; color: #166534; margin-top: 10px; }}
                .divider {{ text-align: center; margin: 24px 0 16px 0; font-size: 12px; font-weight: 600; color: #94a3b8; letter-spacing: 1.5px; }}
                .btn-container {{ text-align: center; margin: 16px 0 24px 0; }}
                .button {{ background-color: #1B5E20; color: #ffffff !important; padding: 14px 34px; text-decoration: none; border-radius: 8px; font-weight: 600; display: inline-block; font-size: 15px; }}
                .footer {{ background: #f8fafc; padding: 20px; text-align: center; font-size: 12px; color: #94a3b8; border-top: 1px solid #e2e8f0; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>SpeechEasy</h1>
                </div>
                <div class="content">
                    <p>Hello,</p>
                    <p>We received a request to reset the password for your SpeechEasy account.</p>
                    <p>Please use the 6-digit verification code below in the app to set your new password:</p>
                    
                    <div class="otp-box">
                        <div class="otp-title">Your 6-Digit Password Reset Code (OTP)</div>
                        <div class="otp-code">{formatted_otp}</div>
                        <div class="otp-sub">Enter this code in the SpeechEasy app along with your new password</div>
                    </div>

                    <div class="divider">— OR RESET DIRECTLY IN BROWSER —</div>

                    <div class="btn-container">
                        <a href="{reset_link}" class="button" target="_blank">Reset Password Now</a>
                    </div>

                    <p style="font-size: 13px; color: #64748b; margin-top: 24px;">
                        This password reset code will expire in {settings.PASSWORD_RESET_TOKEN_EXPIRE_MINUTES} minutes.<br>
                        If you did not request a password reset, please ignore this email. Your account remains secure.
                    </p>
                </div>
                <div class="footer">
                    &copy; 2026 SpeechEasy. All rights reserved.
                </div>
            </div>
        </body>
        </html>
        """

        plain_text = (
            f"Hello,\n\n"
            f"We received a request to reset your SpeechEasy password. Your 6-digit reset code (OTP) is:\n\n"
            f"   {formatted_otp}\n\n"
            f"Enter this code in the app to set a new password.\n\n"
            f"Or reset directly in your browser:\n"
            f"{reset_link}\n\n"
            f"This code will expire in {settings.PASSWORD_RESET_TOKEN_EXPIRE_MINUTES} minutes.\n"
        )

        return await cls._send_email(to_email, subject, plain_text, html_content)

    @classmethod
    async def _send_email(cls, to_email: str, subject: str, plain_text: str, html_content: str) -> bool:
        """Internal helper to dispatch email over SMTP or log in dev mode."""
        if not cls._is_smtp_configured():
            logger.info("=" * 60)
            logger.info("[MOCK SMTP DISPATCH]")
            logger.info(f"To: {to_email}")
            logger.info(f"Subject: {subject}")
            logger.info(f"Body: {plain_text}")
            logger.info("=" * 60)
            return True

        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = subject
            msg["From"] = f"{settings.SMTP_FROM_NAME} <{settings.SMTP_FROM_EMAIL}>"
            msg["To"] = to_email

            part1 = MIMEText(plain_text, "plain", "utf-8")
            part2 = MIMEText(html_content, "html", "utf-8")
            msg.attach(part1)
            msg.attach(part2)

            use_ssl = (settings.SMTP_PORT == 465)
            await aiosmtplib.send(
                msg,
                hostname=settings.SMTP_HOST,
                port=settings.SMTP_PORT,
                username=settings.SMTP_USERNAME,
                password=settings.SMTP_PASSWORD.replace(" ", ""),
                use_tls=use_ssl,
                start_tls=not use_ssl
            )
            logger.info(f"Email successfully sent to {to_email}")
            return True
        except Exception as e:
            logger.error(f"Failed to send email to {to_email} via SMTP: {e}")
            return False
