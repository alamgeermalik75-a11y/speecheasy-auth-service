from typing import Optional, Any, Dict
from fastapi import HTTPException, status


class AppException(HTTPException):
    def __init__(
        self,
        status_code: int,
        error_code: str,
        message: str,
        details: Optional[Any] = None,
        headers: Optional[Dict[str, str]] = None
    ):
        super().__init__(
            status_code=status_code,
            detail={
                "error": {
                    "code": error_code,
                    "message": message,
                    "details": details
                }
            },
            headers=headers
        )
        self.error_code = error_code
        self.message = message
        self.details = details


class EmailAlreadyExistsException(AppException):
    def __init__(self, message: str = "A user with this email address already exists."):
        super().__init__(
            status_code=status.HTTP_409_CONFLICT,
            error_code="EMAIL_ALREADY_EXISTS",
            message=message
        )


class InvalidCredentialsException(AppException):
    def __init__(self, message: str = "Invalid email or password."):
        super().__init__(
            status_code=status.HTTP_401_UNAUTHORIZED,
            error_code="INVALID_CREDENTIALS",
            message=message,
            headers={"WWW-Authenticate": "Bearer"}
        )


class EmailNotVerifiedException(AppException):
    def __init__(self, message: str = "Please verify your email address before logging in."):
        super().__init__(
            status_code=status.HTTP_403_FORBIDDEN,
            error_code="EMAIL_NOT_VERIFIED",
            message=message
        )


class RoleMismatchException(AppException):
    def __init__(self, message: str = "Access restricted: This application is for patients and parents only."):
        super().__init__(
            status_code=status.HTTP_403_FORBIDDEN,
            error_code="ROLE_MISMATCH",
            message=message
        )


class InvalidTokenException(AppException):
    def __init__(self, message: str = "The verification token is invalid or has already been used."):
        super().__init__(
            status_code=status.HTTP_400_BAD_REQUEST,
            error_code="INVALID_TOKEN",
            message=message
        )


class TokenExpiredException(AppException):
    def __init__(self, message: str = "The verification token has expired. Please request a new one."):
        super().__init__(
            status_code=status.HTTP_400_BAD_REQUEST,
            error_code="TOKEN_EXPIRED",
            message=message
        )


class ProfileNotFoundException(AppException):
    def __init__(self, message: str = "Patient profile not found. Please complete profile setup."):
        super().__init__(
            status_code=status.HTTP_404_NOT_FOUND,
            error_code="PROFILE_NOT_FOUND",
            message=message
        )


class ProfileAlreadyExistsException(AppException):
    def __init__(self, message: str = "Profile already exists for this patient account."):
        super().__init__(
            status_code=status.HTTP_409_CONFLICT,
            error_code="PROFILE_ALREADY_EXISTS",
            message=message
        )


class InvalidSoundFieldsException(AppException):
    def __init__(self, message: str = "sound and alphabet_name must both be provided, or both omitted."):
        super().__init__(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            error_code="INVALID_SOUND_FIELDS",
            message=message
        )


class UnauthorizedException(AppException):
    def __init__(self, message: str = "Authentication credentials were not provided or are invalid."):
        super().__init__(
            status_code=status.HTTP_401_UNAUTHORIZED,
            error_code="UNAUTHORIZED",
            message=message,
            headers={"WWW-Authenticate": "Bearer"}
        )
