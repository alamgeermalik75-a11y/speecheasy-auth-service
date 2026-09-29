import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, Optional

from app.config import settings
from app.core.exceptions import (
    AppException,
    EmailAlreadyExistsException,
    InvalidCredentialsException,
    EmailNotVerifiedException,
    RoleMismatchException,
    InvalidTokenException,
    TokenExpiredException,
)
from app.core.security import (
    hash_password,
    verify_password,
    generate_secure_token,
    generate_otp_code,
    hash_token,
    create_access_token,
    create_refresh_token_data,
)
from app.core.supabase import get_supabase
from app.schemas.auth import (
    PatientRegisterRequest,
    PatientRegisterResponse,
    VerifyEmailResponse,
    LoginRequest,
    GoogleAuthRequest,
    GoogleAuthResponse,
    TokenResponse,
    UserData,
)
from app.schemas.common import MessageResponse
from app.services.email_service import EmailService
from app.services.google_auth_service import GoogleAuthService

logger = logging.getLogger(__name__)


class AuthService:
    @classmethod
    async def register_patient(cls, req: PatientRegisterRequest) -> PatientRegisterResponse:
        """
        Registers a new patient account with role='patient' strictly enforced by server.
        Generates a hashed single-use email verification token and dispatches verification email.
        """
        sb = get_supabase()
        clean_email = req.email.strip().lower()

        # 1. Check if user already exists
        existing_res = sb.table("users").select("id").eq("email", clean_email).execute()
        if existing_res.data:
            raise EmailAlreadyExistsException()

        # 2. Hash password & prepare user data
        hashed_pwd = hash_password(req.password)
        new_user_id = str(uuid.uuid4())

        user_data = {
            "id": new_user_id,
            "email": clean_email,
            "password_hash": hashed_pwd,
            "role": "patient",  # ALWAYS hardcoded server-side!
            "auth_provider": "password",
            "is_verified": False,
            "is_active": True,
        }

        user_insert = sb.table("users").insert(user_data).execute()
        if not user_insert.data:
            raise AppException(500, "REGISTRATION_FAILED", "Failed to create user record.")

        created_user = user_insert.data[0]

        # 3. Create single-use 6-digit email verification OTP code
        raw_token = generate_otp_code(6)
        token_hash = hash_token(raw_token)
        expires_at = datetime.now(timezone.utc) + timedelta(
            hours=settings.EMAIL_VERIFICATION_TOKEN_EXPIRE_HOURS
        )

        token_data = {
            "id": str(uuid.uuid4()),
            "user_id": created_user["id"],
            "token_hash": token_hash,
            "token_type": "email_verification",
            "expires_at": expires_at.isoformat(),
            "used_at": None,
        }
        sb.table("auth_tokens").insert(token_data).execute()

        # 4. Create initial profile entry if parent_name provided
        try:
            profile_data = {
                "patient_uid": created_user["id"],
                "parent_name": req.parent_name,
                "child_name": req.child_name or "Child",
            }
            sb.table("profiles").insert(profile_data).execute()
        except Exception as e:
            logger.warning(f"Initial profile creation note: {e}")

        # 5. Dispatch email
        await EmailService.send_verification_email(
            to_email=clean_email,
            token=raw_token,
            parent_name=req.parent_name
        )

        return PatientRegisterResponse(
            user_id=created_user["id"],
            email=created_user["email"],
            role="patient",
            is_verified=False,
            message="Registration successful! Please check your email to verify your account."
        )

    @classmethod
    async def verify_email(cls, token: str) -> MessageResponse:
        """
        Validates email verification token and marks patient account as verified.
        """
        sb = get_supabase()
        raw_clean = token.strip()
        digits_clean = "".join(c for c in raw_clean if c.isdigit())
        now = datetime.now(timezone.utc)

        candidates = []
        if len(digits_clean) == 6:
            candidates.append(hash_token(digits_clean))
        candidates.append(hash_token(raw_clean))

        token_record = None
        for th in candidates:
            token_res = (
                sb.table("auth_tokens")
                .select("*")
                .eq("token_hash", th)
                .eq("token_type", "email_verification")
                .execute()
            )
            if token_res.data:
                token_record = token_res.data[0]
                break

        if not token_record:
            raise InvalidTokenException()

        if token_record.get("used_at") is not None:
            raise InvalidTokenException("This verification token has already been used.")

        # Check expiration
        expires_str = token_record.get("expires_at")
        expires_at = datetime.fromisoformat(expires_str.replace("Z", "+00:00"))
        if expires_at < now:
            raise TokenExpiredException()

        # Update user to is_verified = True
        sb.table("users").update({"is_verified": True}).eq("id", token_record["user_id"]).execute()

        # Mark token as used
        sb.table("auth_tokens").update({"used_at": now.isoformat()}).eq("id", token_record["id"]).execute()

        # Fetch full updated user record
        u_res = sb.table("users").select("*").eq("id", token_record["user_id"]).execute()
        user = u_res.data[0] if u_res.data else {}

        if user.get("auth_provider") in ("google", "password_and_google"):
            logger.info(f"AUDIT: event=google_otp_verified user_id={token_record['user_id']} email={user.get('email')}")

        # Issue access & refresh tokens immediately upon email verification
        token_resp = cls._issue_tokens(user)

        return VerifyEmailResponse(
            message="Email verified successfully.",
            access_token=token_resp.access_token,
            refresh_token=token_resp.refresh_token,
            token_type=token_resp.token_type,
            expires_in=token_resp.expires_in,
            user=token_resp.user
        )

    @classmethod
    async def resend_verification(cls, email: str) -> MessageResponse:
        """
        Resends verification email to an unverified patient account.
        """
        sb = get_supabase()
        clean_email = email.strip().lower()

        user_res = sb.table("users").select("*").eq("email", clean_email).execute()
        if not user_res.data:
            # Prevent user enumeration
            return MessageResponse(
                message="If an account exists with this email, a verification link has been sent."
            )

        user = user_res.data[0]
        if user.get("is_verified"):
            return MessageResponse(message="This account is already verified. Please log in.")

        # Invalidate old unused verification tokens
        now = datetime.now(timezone.utc)
        sb.table("auth_tokens").update({"used_at": now.isoformat()}).eq("user_id", user["id"]).eq("token_type", "email_verification").is_("used_at", "null").execute()

        # Create new 6-digit OTP code
        raw_token = generate_otp_code(6)
        token_hash = hash_token(raw_token)
        expires_at = now + timedelta(hours=settings.EMAIL_VERIFICATION_TOKEN_EXPIRE_HOURS)

        token_data = {
            "id": str(uuid.uuid4()),
            "user_id": user["id"],
            "token_hash": token_hash,
            "token_type": "email_verification",
            "expires_at": expires_at.isoformat(),
            "used_at": None,
        }
        sb.table("auth_tokens").insert(token_data).execute()

        # Fetch parent name from profile if available
        parent_name = "Parent"
        prof_res = sb.table("profiles").select("parent_name").eq("patient_uid", user["id"]).execute()
        if prof_res.data and prof_res.data[0].get("parent_name"):
            parent_name = prof_res.data[0]["parent_name"]

        await EmailService.send_verification_email(
            to_email=clean_email,
            token=raw_token,
            parent_name=parent_name
        )

        return MessageResponse(
            message="If an account exists with this email, a verification link has been sent."
        )

    @classmethod
    async def login(cls, req: LoginRequest) -> TokenResponse:
        """
        Email & password authentication for Patient App.
        Enforces verified email and strictly prevents therapists/admins from logging in here.
        """
        sb = get_supabase()
        clean_email = req.email.strip().lower()

        user_res = sb.table("users").select("*").eq("email", clean_email).execute()
        if not user_res.data:
            raise InvalidCredentialsException()

        user = user_res.data[0]

        # Check password
        pwd_hash = user.get("password_hash")
        if not pwd_hash or not verify_password(req.password, pwd_hash):
            raise InvalidCredentialsException()

        # Guard against role mismatch (Therapist or Admin attempting to use Patient App)
        if user.get("role") != "patient":
            logger.warning(f"Unauthorized login attempt: user with role '{user.get('role')}' attempted patient login.")
            raise RoleMismatchException()

        # Check verification status
        if not user.get("is_verified"):
            raise EmailNotVerifiedException()

        # Check if active
        if not user.get("is_active", True):
            raise AppException(403, "ACCOUNT_INACTIVE", "Your account is deactivated. Please contact support.")

        return cls._issue_tokens(user)

    @classmethod
    async def login_with_google(cls, req: GoogleAuthRequest) -> GoogleAuthResponse:
        """
        Google OAuth ID Token verification and patient authentication.
        Enforces server-side token validation, identity linking to public.users.id,
        and email verification OTP dispatch for unverified accounts.
        """
        # 1. Cryptographically verify Google token server-side
        try:
            claims = GoogleAuthService.verify_token(req.id_token)
        except Exception as e:
            logger.warning(f"AUDIT: event=google_login_failed reason=token_verification_failed error={e}")
            raise

        google_sub = claims["google_subject"]
        email = claims["email"]
        name = claims.get("name") or "Parent"

        sb = get_supabase()
        now = datetime.now(timezone.utc)

        # 2. Check whether user already exists
        # Rule 1: First match by google_subject
        user_res = sb.table("users").select("*").eq("google_subject", google_sub).execute()
        user = None

        if user_res.data:
            user = user_res.data[0]
        else:
            # Rule 2: If not matched, match by verified email
            email_res = sb.table("users").select("*").eq("email", email).execute()
            if email_res.data:
                user = email_res.data[0]
                # If matched by email and google_subject is empty, link google_subject
                if not user.get("google_subject"):
                    auth_prov = "password_and_google" if user.get("password_hash") else "google"
                    sb.table("users").update({
                        "google_subject": google_sub,
                        "auth_provider": auth_prov
                    }).eq("id", user["id"]).execute()
                    user["google_subject"] = google_sub
                    user["auth_provider"] = auth_prov

        # CASE 1: USER DOES NOT EXIST (NEW GOOGLE USER)
        if not user:
            new_user_id = str(uuid.uuid4())
            new_user = {
                "id": new_user_id,
                "email": email,
                "password_hash": None,
                "role": "patient",
                "auth_provider": "google",
                "google_subject": google_sub,
                "is_verified": False,
                "is_active": True,
            }
            insert_res = sb.table("users").insert(new_user).execute()
            if not insert_res.data:
                logger.error("AUDIT: event=google_login_failed reason=user_creation_failed")
                raise AppException(500, "GOOGLE_AUTH_FAILED", "Failed to create user account.")
            user = insert_res.data[0]
            logger.info(f"AUDIT: event=google_registration user_id={user['id']} email={email}")

            # Do not create placeholder profile; user completes profile via Create Profile screen
            # Generate single-use verification token / OTP
            raw_token = generate_otp_code(6)
            token_hash = hash_token(raw_token)
            expires_at = now + timedelta(hours=settings.EMAIL_VERIFICATION_TOKEN_EXPIRE_HOURS)

            token_data = {
                "id": str(uuid.uuid4()),
                "user_id": user["id"],
                "token_hash": token_hash,
                "token_type": "email_verification",
                "expires_at": expires_at.isoformat(),
                "used_at": None,
            }
            sb.table("auth_tokens").insert(token_data).execute()

            # Send OTP to verified Google email
            await EmailService.send_verification_email(
                to_email=email,
                token=raw_token,
                parent_name=name
            )
            logger.info(f"AUDIT: event=google_otp_sent user_id={user['id']} email={email}")

            return GoogleAuthResponse(
                access_token=None,
                refresh_token=None,
                token_type=None,
                expires_in=None,
                is_verified=False,
                verification_required=True,
                message="Account registered. A verification code has been sent to your Google email. Please verify to continue.",
                email=email,
                user=UserData(
                    id=user["id"],
                    email=user["email"],
                    role=user["role"],
                    is_verified=False,
                    auth_provider=user["auth_provider"]
                )
            )

        # CASE 2: USER ALREADY EXISTS
        # Guard against role mismatch (Therapist or Admin attempting patient login)
        if user.get("role") != "patient":
            logger.warning(f"AUDIT: event=google_login_failed reason=role_mismatch user_id={user['id']} role={user.get('role')}")
            raise RoleMismatchException()

        if not user.get("is_active", True):
            logger.warning(f"AUDIT: event=google_login_failed reason=account_inactive user_id={user['id']}")
            raise AppException(403, "ACCOUNT_INACTIVE", "Your account is deactivated. Please contact support.")

        # Check is_verified
        if not user.get("is_verified"):
            # Invalidate old unused verification tokens
            sb.table("auth_tokens").update({"used_at": now.isoformat()}).eq("user_id", user["id"]).eq("token_type", "email_verification").is_("used_at", "null").execute()

            # Generate new single-use verification token / OTP
            raw_token = generate_otp_code(6)
            token_hash = hash_token(raw_token)
            expires_at = now + timedelta(hours=settings.EMAIL_VERIFICATION_TOKEN_EXPIRE_HOURS)

            token_data = {
                "id": str(uuid.uuid4()),
                "user_id": user["id"],
                "token_hash": token_hash,
                "token_type": "email_verification",
                "expires_at": expires_at.isoformat(),
                "used_at": None,
            }
            sb.table("auth_tokens").insert(token_data).execute()

            parent_name = "Parent"
            try:
                prof_res = sb.table("profiles").select("parent_name").eq("patient_uid", user["id"]).execute()
                if prof_res.data and prof_res.data[0].get("parent_name"):
                    parent_name = prof_res.data[0]["parent_name"]
                elif name:
                    parent_name = name
            except Exception:
                pass

            await EmailService.send_verification_email(
                to_email=user["email"],
                token=raw_token,
                parent_name=parent_name
            )
            logger.info(f"AUDIT: event=google_otp_sent user_id={user['id']} email={user['email']}")

            return GoogleAuthResponse(
                access_token=None,
                refresh_token=None,
                token_type=None,
                expires_in=None,
                is_verified=False,
                verification_required=True,
                message="Your account is not verified yet. A new verification code has been sent to your email.",
                email=user["email"],
                user=UserData(
                    id=user["id"],
                    email=user["email"],
                    role=user["role"],
                    is_verified=False,
                    auth_provider=user.get("auth_provider", "google")
                )
            )

        # User is verified: issue access & refresh tokens

        # Issue access & refresh tokens
        token_resp = cls._issue_tokens(user)
        logger.info(f"AUDIT: event=google_login user_id={user['id']} email={user['email']}")

        return GoogleAuthResponse(
            access_token=token_resp.access_token,
            refresh_token=token_resp.refresh_token,
            token_type=token_resp.token_type,
            expires_in=token_resp.expires_in,
            is_verified=True,
            verification_required=False,
            message="Login successful.",
            email=user["email"],
            user=token_resp.user
        )

    @classmethod
    async def refresh_tokens(cls, raw_refresh_token: str) -> TokenResponse:
        """
        Rotates refresh token and issues a fresh 30-minute access token.
        Detects token reuse and revokes entire family if compromise is suspected.
        """
        sb = get_supabase()
        tok_hash = hash_token(raw_refresh_token)
        now = datetime.now(timezone.utc)

        session_res = sb.table("refresh_sessions").select("*").eq("refresh_token_hash", tok_hash).execute()
        if not session_res.data:
            raise InvalidTokenException("Invalid refresh token.")

        session = session_res.data[0]
        family_id = session["family_id"]
        user_id = session["user_id"]

        # Token reuse detection
        if session.get("is_revoked"):
            logger.warning(f"SECURITY ALERT: Revoked refresh token reuse detected for family {family_id}!")
            # Invalidate all sessions in family
            sb.table("refresh_sessions").update({"is_revoked": True}).eq("family_id", family_id).execute()
            raise InvalidTokenException("Refresh token has been revoked. Please sign in again.")

        # Check expiration
        expires_str = session.get("expires_at")
        expires_at = datetime.fromisoformat(expires_str.replace("Z", "+00:00"))
        if expires_at < now:
            raise TokenExpiredException("Refresh token has expired. Please sign in again.")

        # Revoke the used refresh token
        sb.table("refresh_sessions").update({"is_revoked": True}).eq("id", session["id"]).execute()

        # Fetch current user
        user_res = sb.table("users").select("*").eq("id", user_id).execute()
        if not user_res.data:
            raise InvalidCredentialsException("User account not found.")
        user = user_res.data[0]

        if not user.get("is_active", True):
            raise AppException(403, "ACCOUNT_INACTIVE", "User account is deactivated.")

        # Issue new token pair preserving family_id
        new_refresh = create_refresh_token_data()
        new_refresh_session = {
            "id": str(uuid.uuid4()),
            "user_id": user["id"],
            "refresh_token_hash": new_refresh["token_hash"],
            "family_id": family_id,  # Same family
            "is_revoked": False,
            "expires_at": new_refresh["expires_at"],
        }
        sb.table("refresh_sessions").insert(new_refresh_session).execute()

        new_access_token = create_access_token(
            user_id=user["id"],
            email=user["email"],
            role=user["role"],
            is_verified=user["is_verified"]
        )

        return TokenResponse(
            access_token=new_access_token,
            refresh_token=new_refresh["raw_token"],
            token_type="bearer",
            expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            user=UserData(
                id=user["id"],
                email=user["email"],
                role=user["role"],
                is_verified=user["is_verified"],
                auth_provider=user["auth_provider"],
                has_password=bool(user.get("password_hash"))
            )
        )

    @classmethod
    async def logout(cls, raw_refresh_token: Optional[str] = None, user_id: Optional[str] = None) -> MessageResponse:
        """Revokes the refresh token session or all active user sessions."""
        sb = get_supabase()
        if raw_refresh_token and raw_refresh_token.strip():
            tok_hash = hash_token(raw_refresh_token.strip())
            sb.table("refresh_sessions").update({"is_revoked": True}).eq("refresh_token_hash", tok_hash).execute()
        if user_id:
            sb.table("refresh_sessions").update({"is_revoked": True}).eq("user_id", user_id).execute()
        return MessageResponse(message="Successfully logged out.")

    @classmethod
    async def forgot_password(cls, email: str) -> MessageResponse:
        """Generates single-use 15-minute 6-digit password reset OTP and sends email."""
        sb = get_supabase()
        clean_email = email.strip().lower()

        user_res = sb.table("users").select("*").eq("email", clean_email).execute()
        if not user_res.data:
            return MessageResponse(
                message="If an account exists with this email, a password reset link has been sent."
            )

        user = user_res.data[0]
        now = datetime.now(timezone.utc)

        # Invalidate existing reset tokens
        sb.table("auth_tokens").update({"used_at": now.isoformat()}).eq("user_id", user["id"]).eq("token_type", "password_reset").is_("used_at", "null").execute()

        # Generate new 6-digit reset OTP code (15 mins)
        raw_otp = generate_otp_code(6)
        token_hash = hash_token(raw_otp)
        expires_at = now + timedelta(minutes=settings.PASSWORD_RESET_TOKEN_EXPIRE_MINUTES)

        token_data = {
            "id": str(uuid.uuid4()),
            "user_id": user["id"],
            "token_hash": token_hash,
            "token_type": "password_reset",
            "expires_at": expires_at.isoformat(),
            "used_at": None,
        }
        sb.table("auth_tokens").insert(token_data).execute()

        await EmailService.send_password_reset_email(clean_email, raw_otp)

        return MessageResponse(
            message="If an account exists with this email, a password reset link has been sent."
        )

    @classmethod
    async def reset_password(cls, token: str, new_password: str) -> MessageResponse:
        """Validates reset token, updates password, and revokes all active sessions."""
        sb = get_supabase()
        raw_clean = token.strip()
        digits_clean = "".join(c for c in raw_clean if c.isdigit())
        now = datetime.now(timezone.utc)

        candidates = []
        if len(digits_clean) == 6:
            candidates.append(hash_token(digits_clean))
        candidates.append(hash_token(raw_clean))

        token_record = None
        for th in candidates:
            token_res = (
                sb.table("auth_tokens")
                .select("*")
                .eq("token_hash", th)
                .eq("token_type", "password_reset")
                .execute()
            )
            if token_res.data:
                token_record = token_res.data[0]
                break

        if not token_record:
            raise InvalidTokenException("Invalid or already used password reset token.")

        if token_record.get("used_at") is not None:
            raise InvalidTokenException("This password reset token has already been used.")

        expires_str = token_record.get("expires_at")
        expires_at = datetime.fromisoformat(expires_str.replace("Z", "+00:00"))
        if expires_at < now:
            raise TokenExpiredException("Password reset token has expired.")

        user_id = token_record["user_id"]
        new_pwd_hash = hash_password(new_password)

        # Update password & auth_provider if needed
        sb.table("users").update({"password_hash": new_pwd_hash}).eq("id", user_id).execute()

        # Mark token as used
        sb.table("auth_tokens").update({"used_at": now.isoformat()}).eq("id", token_record["id"]).execute()

        # Revoke ALL active refresh sessions for this user for security
        sb.table("refresh_sessions").update({"is_revoked": True}).eq("user_id", user_id).execute()

        return MessageResponse(message="Password reset successfully. You can now log in with your new password.")

    @classmethod
    def _issue_tokens(cls, user: Dict[str, Any]) -> TokenResponse:
        """Helper to create access token and persist a refresh session."""
        sb = get_supabase()

        access_token = create_access_token(
            user_id=user["id"],
            email=user["email"],
            role=user["role"],
            is_verified=user["is_verified"]
        )

        refresh_data = create_refresh_token_data()
        session_record = {
            "id": str(uuid.uuid4()),
            "user_id": user["id"],
            "refresh_token_hash": refresh_data["token_hash"],
            "family_id": refresh_data["family_id"],
            "is_revoked": False,
            "expires_at": refresh_data["expires_at"],
        }
        sb.table("refresh_sessions").insert(session_record).execute()

        return TokenResponse(
            access_token=access_token,
            refresh_token=refresh_data["raw_token"],
            token_type="bearer",
            expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            user=UserData(
                id=user["id"],
                email=user["email"],
                role=user["role"],
                is_verified=user["is_verified"],
                auth_provider=user["auth_provider"],
                has_password=bool(user.get("password_hash"))
            )
        )

    @classmethod
    async def set_password(cls, user_id: str, new_password: str) -> MessageResponse:
        """
        Sets a password for an authenticated user who currently does NOT have a password (e.g. Google user).
        Updates auth_provider to 'password_and_google' if it was 'google'.
        """
        sb = get_supabase()
        u_res = sb.table("users").select("*").eq("id", user_id).execute()
        if not u_res.data:
            raise AppException(404, "USER_NOT_FOUND", "User not found.")
        user = u_res.data[0]

        if user.get("password_hash"):
            raise AppException(400, "PASSWORD_ALREADY_SET", "A password is already set on this account. Please use Change Password.")

        # Hash new password using existing bcrypt mechanism
        pwd_hash = hash_password(new_password)
        auth_prov = "password_and_google" if user.get("google_subject") or user.get("auth_provider") == "google" else "password"

        sb.table("users").update({
            "password_hash": pwd_hash,
            "auth_provider": auth_prov,
            "updated_at": datetime.now(timezone.utc).isoformat()
        }).eq("id", user_id).execute()

        logger.info(f"AUDIT: event=password_set user_id={user_id} email={user.get('email')}")
        return MessageResponse(message="Password set successfully.")

    @classmethod
    async def change_password(cls, user_id: str, current_password: str, new_password: str) -> MessageResponse:
        """
        Updates the password for an authenticated user who already has a password.
        Validates current password using existing bcrypt mechanism.
        """
        sb = get_supabase()
        u_res = sb.table("users").select("*").eq("id", user_id).execute()
        if not u_res.data:
            raise AppException(404, "USER_NOT_FOUND", "User not found.")
        user = u_res.data[0]

        existing_hash = user.get("password_hash")
        if not existing_hash:
            raise AppException(400, "NO_PASSWORD_SET", "No password is set on this account. Please use Set Password.")

        # Verify current password
        if not verify_password(current_password, existing_hash):
            raise AppException(400, "INVALID_CURRENT_PASSWORD", "The current password you entered is incorrect.")

        if current_password == new_password:
            raise AppException(400, "SAME_PASSWORD", "New password cannot be the same as your current password.")

        # Hash new password using existing bcrypt mechanism
        new_hash = hash_password(new_password)

        sb.table("users").update({
            "password_hash": new_hash,
            "updated_at": datetime.now(timezone.utc).isoformat()
        }).eq("id", user_id).execute()

        logger.info(f"AUDIT: event=password_changed user_id={user_id} email={user.get('email')}")
        return MessageResponse(message="Password changed successfully.")
