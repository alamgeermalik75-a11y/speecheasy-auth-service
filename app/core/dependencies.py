import logging
from typing import Dict, Any
from fastapi import Depends, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import jwt

from app.core.exceptions import (
    UnauthorizedException,
    RoleMismatchException,
    EmailNotVerifiedException
)
from app.core.security import decode_access_token
from app.core.supabase import get_supabase

logger = logging.getLogger(__name__)
security_scheme = HTTPBearer(auto_error=False)


async def get_current_patient_user(
    credentials: HTTPAuthorizationCredentials = Security(security_scheme)
) -> Dict[str, Any]:
    """
    Extracts, validates, and decodes the JWT access token from the Authorization header.
    Strictly verifies role == 'patient' and is_verified == True.
    """
    if not credentials or not credentials.credentials:
        raise UnauthorizedException("Missing or malformed Authorization header.")

    raw_token = credentials.credentials

    try:
        payload = decode_access_token(raw_token)
    except jwt.ExpiredSignatureError:
        raise UnauthorizedException("Access token has expired. Please refresh your session.")
    except jwt.InvalidTokenError:
        raise UnauthorizedException("Invalid access token.")
    except Exception as e:
        logger.warning(f"Token decoding error: {e}")
        raise UnauthorizedException("Could not validate credentials.")

    # Validate role isolation
    role = payload.get("role")
    if role != "patient":
        logger.warning(f"Access forbidden: User with role '{role}' tried accessing patient endpoints.")
        raise RoleMismatchException("Access restricted: This application is for patients only.")

    # Validate email verification status
    if not payload.get("is_verified", False):
        raise EmailNotVerifiedException("Please verify your email address to access this resource.")

    user_id = payload.get("sub")
    if not user_id:
        raise UnauthorizedException("Invalid token payload: missing subject.")

    return {
        "id": str(user_id),
        "email": payload.get("email"),
        "role": role,
        "is_verified": payload.get("is_verified")
    }


async def get_current_patient_uid(
    current_user: Dict[str, Any] = Depends(get_current_patient_user)
) -> str:
    """
    Returns the authenticated patient UID strictly from the validated JWT subject.
    ZERO TRUST in client-supplied headers or body fields!
    """
    return current_user["id"]
