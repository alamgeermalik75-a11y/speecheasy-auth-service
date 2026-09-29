import hashlib
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any
import bcrypt
import jwt
from app.config import settings


def hash_password(password: str) -> str:
    """Hashes a plaintext password using native bcrypt."""
    pwd_bytes = password.encode("utf-8")[:72]
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(pwd_bytes, salt).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifies a plaintext password against a bcrypt hash."""
    if not hashed_password:
        return False
    try:
        pwd_bytes = plain_password.encode("utf-8")[:72]
        hash_bytes = hashed_password.encode("utf-8")
        return bcrypt.checkpw(pwd_bytes, hash_bytes)
    except Exception:
        return False


def generate_secure_token(nbytes: int = 32) -> str:
    """Generates a cryptographically secure URL-safe random string."""
    return secrets.token_urlsafe(nbytes)


def generate_otp_code(digits: int = 6) -> str:
    """Generates a cryptographically secure numeric OTP code (e.g. 6-digits)."""
    min_val = 10 ** (digits - 1)
    max_val = 10 ** digits - 1
    return str(secrets.randbelow(max_val - min_val + 1) + min_val)


def hash_token(raw_token: str) -> str:
    """Hashes a token using SHA-256 for secure database storage."""
    return hashlib.sha256(raw_token.strip().encode("utf-8")).hexdigest()


def create_access_token(
    user_id: str,
    email: str,
    role: str = "patient",
    is_verified: bool = True,
    expires_delta: Optional[timedelta] = None
) -> str:
    """Creates a short-lived HS256 JWT access token."""
    now = datetime.now(timezone.utc)
    if expires_delta:
        expire = now + expires_delta
    else:
        expire = now + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)

    payload: Dict[str, Any] = {
        "sub": str(user_id),
        "email": email,
        "role": role,
        "is_verified": is_verified,
        "token_type": "access",
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp())
    }

    return jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def decode_access_token(token: str) -> Dict[str, Any]:
    """Decodes and validates a JWT access token."""
    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM]
        )
        if payload.get("token_type") != "access":
            raise jwt.InvalidTokenError("Invalid token type")
        return payload
    except jwt.ExpiredSignatureError:
        raise
    except jwt.InvalidTokenError:
        raise


def create_refresh_token_data() -> Dict[str, Any]:
    """
    Generates a new raw refresh token, its SHA-256 hash, family ID, and expiry.
    """
    raw_token = generate_secure_token(48)
    token_hash = hash_token(raw_token)
    family_id = str(uuid.uuid4())
    expires_at = datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)

    return {
        "raw_token": raw_token,
        "token_hash": token_hash,
        "family_id": family_id,
        "expires_at": expires_at.isoformat()
    }
