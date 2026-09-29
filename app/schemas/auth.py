import re
from typing import Optional, Dict, Any
from pydantic import BaseModel, EmailStr, Field, field_validator


class PatientRegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8, description="Minimum 8 characters with at least 1 letter and 1 number")
    parent_name: str = Field(..., min_length=2, description="Parent's full name, minimum 2 characters")
    child_name: Optional[str] = Field(None, min_length=2, description="Child's full name")
    phone: Optional[str] = Field(None, description="Contact phone number")

    @field_validator("password")
    @classmethod
    def validate_password_strength(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters long.")
        if not re.search(r"[A-Za-z]", v):
            raise ValueError("Password must contain at least one letter.")
        if not re.search(r"\d", v):
            raise ValueError("Password must contain at least one number.")
        return v

    @field_validator("parent_name")
    @classmethod
    def validate_parent_name(cls, v: str) -> str:
        v_stripped = v.strip()
        if len(v_stripped) < 2:
            raise ValueError("parent_name must be at least 2 characters long after trimming.")
        return v_stripped

    @field_validator("child_name")
    @classmethod
    def validate_child_name(cls, v: Optional[str]) -> Optional[str]:
        if v is not None:
            v_stripped = v.strip()
            if len(v_stripped) < 2:
                raise ValueError("child_name must be at least 2 characters long.")
            return v_stripped
        return v


class PatientRegisterResponse(BaseModel):
    user_id: str
    email: str
    role: str = "patient"
    is_verified: bool = False
    message: str


class VerifyEmailRequest(BaseModel):
    token: str = Field(..., min_length=1, description="Email verification token received via email")


class ResendVerificationRequest(BaseModel):
    email: EmailStr


class LoginRequest(BaseModel):
    email: EmailStr
    password: str
    client_type: Optional[str] = Field("patient", description="Client identifier to prevent cross-app logins")


class GoogleAuthRequest(BaseModel):
    id_token: str = Field(..., min_length=1, description="Google OAuth ID Token obtained from Google Sign-In SDK")


class UserData(BaseModel):
    id: str
    email: str
    role: str = "patient"
    is_verified: bool
    auth_provider: str
    has_password: bool = False


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int = 1800 # 30 minutes in seconds
    user: UserData


class VerifyEmailResponse(BaseModel):
    message: str = "Email verified successfully."
    access_token: Optional[str] = None
    refresh_token: Optional[str] = None
    token_type: Optional[str] = "bearer"
    expires_in: Optional[int] = 1800
    user: Optional[UserData] = None


class GoogleAuthResponse(BaseModel):
    access_token: Optional[str] = None
    refresh_token: Optional[str] = None
    token_type: Optional[str] = "bearer"
    expires_in: Optional[int] = 1800
    is_verified: bool
    verification_required: bool = False
    message: str
    email: str
    user: Optional[UserData] = None


class RefreshTokenRequest(BaseModel):
    refresh_token: str = Field(..., min_length=1, description="Cryptographic refresh token")


class LogoutRequest(BaseModel):
    refresh_token: Optional[str] = Field(None, description="Optional refresh token to revoke")


class ForgotPasswordRequest(BaseModel):
    email: EmailStr


class ResetPasswordRequest(BaseModel):
    token: str = Field(..., min_length=1, description="Password reset token")
    new_password: str = Field(..., min_length=8, description="Minimum 8 characters with at least 1 letter and 1 number")

    @field_validator("new_password")
    @classmethod
    def validate_new_password(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters long.")
        if not re.search(r"[A-Za-z]", v):
            raise ValueError("Password must contain at least one letter.")
        if not re.search(r"\d", v):
            raise ValueError("Password must contain at least one number.")
        return v


class UserResponse(BaseModel):
    id: str
    email: str
    role: str
    auth_provider: str
    is_verified: bool
    is_active: bool
    has_password: bool = False
    created_at: Optional[str] = None


class SetPasswordRequest(BaseModel):
    new_password: str = Field(..., min_length=8, description="Minimum 8 characters with at least 1 letter and 1 number")

    @field_validator("new_password")
    @classmethod
    def validate_new_password(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters long.")
        if not re.search(r"[A-Za-z]", v):
            raise ValueError("Password must contain at least one letter.")
        if not re.search(r"\d", v):
            raise ValueError("Password must contain at least one number.")
        return v


class ChangePasswordRequest(BaseModel):
    current_password: str = Field(..., min_length=1, description="Current password")
    new_password: str = Field(..., min_length=8, description="Minimum 8 characters with at least 1 letter and 1 number")

    @field_validator("new_password")
    @classmethod
    def validate_new_password(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters long.")
        if not re.search(r"[A-Za-z]", v):
            raise ValueError("Password must contain at least one letter.")
        if not re.search(r"\d", v):
            raise ValueError("Password must contain at least one number.")
        return v
