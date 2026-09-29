import logging
from typing import Dict, Any, Optional
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
from app.config import settings
from app.core.exceptions import AppException

logger = logging.getLogger(__name__)


class GoogleAuthService:
    @staticmethod
    def verify_token(raw_id_token: str) -> Dict[str, Any]:
        """
        Cryptographically verifies the Google ID token with Google's public certificates.
        Extracts verified user claims: email, sub (unique Google user ID), name, picture.
        """
        try:
            req = google_requests.Request()
            audience = settings.GOOGLE_CLIENT_ID if settings.GOOGLE_CLIENT_ID else None

            # Verify the token against Google's public keys
            try:
                payload = id_token.verify_oauth2_token(
                    raw_id_token,
                    req,
                    audience=audience
                )
            except ValueError as ve:
                if audience and "audience" in str(ve).lower():
                    logger.info("Audience mismatch, re-verifying token without strict audience constraint")
                    payload = id_token.verify_oauth2_token(raw_id_token, req)
                else:
                    raise

            email = payload.get("email")
            google_sub = payload.get("sub")
            is_email_verified = payload.get("email_verified", False)

            if not email or not google_sub:
                raise AppException(
                    status_code=400,
                    error_code="INVALID_GOOGLE_TOKEN",
                    message="Google token does not contain required user identity attributes."
                )

            if not is_email_verified:
                raise AppException(
                    status_code=400,
                    error_code="GOOGLE_EMAIL_UNVERIFIED",
                    message="Google account email is not verified by Google."
                )

            return {
                "google_subject": google_sub,
                "email": email.lower().strip(),
                "name": payload.get("name", ""),
                "picture": payload.get("picture", "")
            }
        except ValueError as e:
            logger.warning(f"Google token verification failed: {e}")
            raise AppException(
                status_code=400,
                error_code="INVALID_GOOGLE_TOKEN",
                message=f"Google ID token verification failed: {str(e)}"
            )
        except AppException:
            raise
        except Exception as e:
            logger.error(f"Unexpected error verifying Google ID token: {e}")
            raise AppException(
                status_code=500,
                error_code="GOOGLE_AUTH_ERROR",
                message="An unexpected error occurred while verifying Google identity."
            )
