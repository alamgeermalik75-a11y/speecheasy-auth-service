import logging
from typing import Dict, Any, Optional
from fastapi import APIRouter, Depends, status, Query, Header
from fastapi.responses import HTMLResponse

from app.config import settings
from app.core.dependencies import get_current_patient_user
from app.core.security import decode_access_token
from app.schemas.auth import (
    PatientRegisterRequest,
    PatientRegisterResponse,
    VerifyEmailRequest,
    VerifyEmailResponse,
    ResendVerificationRequest,
    LoginRequest,
    GoogleAuthRequest,
    GoogleAuthResponse,
    TokenResponse,
    RefreshTokenRequest,
    LogoutRequest,
    ForgotPasswordRequest,
    ResetPasswordRequest,
    UserResponse,
    SetPasswordRequest,
    ChangePasswordRequest,
)
from app.schemas.common import MessageResponse, ErrorResponse
from app.services.auth_service import AuthService
from app.core.supabase import get_supabase
from app.core.exceptions import AppException

router = APIRouter(prefix="/auth", tags=["Patient Authentication"])
logger = logging.getLogger(__name__)


@router.post(
    "/register/patient",
    response_model=PatientRegisterResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register new patient/parent account",
    description="Registers a patient account. The role is strictly enforced as 'patient' by the server.",
    responses={
        400: {"model": ErrorResponse, "description": "Validation error"},
        409: {"model": ErrorResponse, "description": "Email already exists"},
    }
)
async def register_patient(req: PatientRegisterRequest):
    return await AuthService.register_patient(req)


@router.post(
    "/verify-email",
    response_model=VerifyEmailResponse,
    summary="Verify patient email address",
    description="Verifies patient account using single-use cryptographic token and issues access & refresh tokens.",
    responses={
        400: {"model": ErrorResponse, "description": "Invalid or expired token"},
    }
)
async def verify_email(req: VerifyEmailRequest):
    return await AuthService.verify_email(req.token)


@router.get(
    "/verify-email-link",
    response_class=HTMLResponse,
    summary="One-click email verification link",
    description="Validates single-use token or OTP from email link click and renders friendly confirmation web page.",
)
async def verify_email_link(token: str = Query(..., description="Verification token or 6-digit OTP")):
    try:
        await AuthService.verify_email(token)
        return HTMLResponse(content=f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <title>Email Verified — SpeechEasy</title>
            <style>
                body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background: #f0fdf4; margin: 0; padding: 40px 16px; display: flex; justify-content: center; align-items: center; min-height: 80vh; }}
                .card {{ background: #ffffff; border-radius: 16px; box-shadow: 0 10px 25px rgba(0,0,0,0.06); max-width: 480px; width: 100%; padding: 40px 32px; text-align: center; border: 1px solid #dcfce7; }}
                .icon {{ width: 72px; height: 72px; background: #dcfce7; color: #16a34a; border-radius: 50%; display: inline-flex; align-items: center; justify-content: center; font-size: 38px; margin-bottom: 20px; }}
                h1 {{ font-size: 24px; color: #1e293b; margin: 0 0 12px 0; font-weight: 700; }}
                p {{ font-size: 15px; color: #64748b; line-height: 1.6; margin: 0 0 28px 0; }}
                .btn {{ background-color: #1B5E20; color: #ffffff !important; padding: 14px 28px; text-decoration: none; border-radius: 8px; font-weight: 600; display: inline-block; font-size: 15px; }}
            </style>
        </head>
        <body>
            <div class="card">
                <div class="icon">✓</div>
                <h1>Email Verified Successfully!</h1>
                <p>Your SpeechEasy patient account is now verified and active. You can safely return to the SpeechEasy mobile or web application to sign in.</p>
                <a href="{settings.FRONTEND_URL}" class="btn">Open SpeechEasy App</a>
            </div>
        </body>
        </html>
        """)
    except AppException as e:
        return HTMLResponse(content=f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <title>Verification Failed — SpeechEasy</title>
            <style>
                body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background: #fef2f2; margin: 0; padding: 40px 16px; display: flex; justify-content: center; align-items: center; min-height: 80vh; }}
                .card {{ background: #ffffff; border-radius: 16px; box-shadow: 0 10px 25px rgba(0,0,0,0.06); max-width: 480px; width: 100%; padding: 40px 32px; text-align: center; border: 1px solid #fee2e2; }}
                .icon {{ width: 72px; height: 72px; background: #fee2e2; color: #dc2626; border-radius: 50%; display: inline-flex; align-items: center; justify-content: center; font-size: 38px; margin-bottom: 20px; }}
                h1 {{ font-size: 24px; color: #1e293b; margin: 0 0 12px 0; font-weight: 700; }}
                p {{ font-size: 15px; color: #64748b; line-height: 1.6; margin: 0 0 28px 0; }}
                .btn {{ background-color: #1e293b; color: #ffffff !important; padding: 14px 28px; text-decoration: none; border-radius: 8px; font-weight: 600; display: inline-block; font-size: 15px; }}
            </style>
        </head>
        <body>
            <div class="card">
                <div class="icon">✕</div>
                <h1>Verification Link Expired or Invalid</h1>
                <p>{e.message}</p>
                <a href="{settings.FRONTEND_URL}" class="btn">Return to App</a>
            </div>
        </body>
        </html>
        """, status_code=400)


@router.post(
    "/resend-verification",
    response_model=MessageResponse,
    summary="Resend email verification token",
    description="Generates and emails a new verification token to the patient.",
)
async def resend_verification(req: ResendVerificationRequest):
    return await AuthService.resend_verification(req.email)


@router.post(
    "/login",
    response_model=TokenResponse,
    summary="Patient email and password login",
    description="Authenticates patient, checks verification, and returns 30-min access JWT and rotatable refresh token.",
    responses={
        401: {"model": ErrorResponse, "description": "Invalid credentials"},
        403: {"model": ErrorResponse, "description": "Email not verified or role mismatch"},
    }
)
async def login(req: LoginRequest):
    return await AuthService.login(req)


@router.post(
    "/google",
    response_model=GoogleAuthResponse,
    summary="Google Sign-In authentication",
    description="Validates Google OAuth ID token, finds or creates patient user, and issues tokens or OTP.",
    responses={
        400: {"model": ErrorResponse, "description": "Invalid Google token"},
        403: {"model": ErrorResponse, "description": "Role mismatch or inactive account"},
    }
)
async def google_auth(req: GoogleAuthRequest):
    return await AuthService.login_with_google(req)


@router.post(
    "/refresh",
    response_model=TokenResponse,
    summary="Refresh access token",
    description="Rotates refresh token and issues a new short-lived access JWT. Re-use triggers session family revocation.",
    responses={
        400: {"model": ErrorResponse, "description": "Invalid or revoked refresh token"},
    }
)
async def refresh_tokens(req: RefreshTokenRequest):
    return await AuthService.refresh_tokens(req.refresh_token)


@router.post(
    "/logout",
    response_model=MessageResponse,
    summary="Logout patient session",
    description="Revokes the provided refresh token session or active user sessions.",
)
async def logout(
    req: Optional[LogoutRequest] = None,
    authorization: Optional[str] = Header(None)
):
    user_id = None
    if authorization and authorization.startswith("Bearer "):
        token = authorization[7:].strip()
        try:
            payload = decode_access_token(token)
            user_id = payload.get("sub")
        except Exception:
            pass
    token_str = req.refresh_token if req else None
    return await AuthService.logout(raw_refresh_token=token_str, user_id=user_id)


@router.post(
    "/forgot-password",
    response_model=MessageResponse,
    summary="Request password reset email",
    description="Generates 15-minute single-use password reset OTP code and emails it to the patient.",
)
async def forgot_password(req: ForgotPasswordRequest):
    return await AuthService.forgot_password(req.email)


@router.get(
    "/reset-password-link",
    response_class=HTMLResponse,
    summary="One-click password reset web page",
    description="Renders a friendly web form for setting a new password when clicking the email link.",
)
async def reset_password_link(token: str = Query(..., description="6-digit reset OTP or token")):
    return HTMLResponse(content=f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>Reset Password — SpeechEasy</title>
        <style>
            body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f0fdf4; margin: 0; padding: 40px 16px; display: flex; justify-content: center; align-items: center; min-height: 80vh; }}
            .card {{ background: #ffffff; border-radius: 16px; box-shadow: 0 10px 25px rgba(0,0,0,0.06); max-width: 440px; width: 100%; padding: 36px 28px; text-align: left; border: 1px solid #dcfce7; }}
            .header {{ text-align: center; margin-bottom: 24px; }}
            .logo {{ background: #1B5E20; color: #ffffff; width: 56px; height: 56px; border-radius: 50%; display: inline-flex; align-items: center; justify-content: center; font-size: 28px; margin-bottom: 12px; }}
            h1 {{ font-size: 22px; color: #1e293b; margin: 0 0 6px 0; text-align: center; }}
            p.sub {{ font-size: 14px; color: #64748b; margin: 0 0 24px 0; text-align: center; line-height: 1.5; }}
            .form-group {{ margin-bottom: 18px; }}
            label {{ display: block; font-size: 13px; font-weight: 600; color: #334155; margin-bottom: 6px; }}
            input {{ width: 100%; box-sizing: border-box; padding: 12px 14px; border: 1.5px solid #cbd5e1; border-radius: 8px; font-size: 15px; outline: none; transition: border-color 0.2s; }}
            input:focus {{ border-color: #1B5E20; }}
            .btn {{ width: 100%; background-color: #1B5E20; color: #ffffff; padding: 14px; border: none; border-radius: 8px; font-size: 15px; font-weight: 600; cursor: pointer; margin-top: 10px; }}
            .btn:disabled {{ background-color: #94a3b8; cursor: not-allowed; }}
            .alert {{ padding: 12px; border-radius: 8px; font-size: 13px; margin-bottom: 16px; display: none; line-height: 1.4; }}
            .alert-error {{ background: #fee2e2; color: #991b1b; border: 1px solid #fca5a5; }}
            .alert-success {{ background: #dcfce7; color: #166534; border: 1px solid #86efac; text-align: center; }}
        </style>
    </head>
    <body>
        <div class="card">
            <div class="header">
                <div class="logo">🔒</div>
                <h1>Reset Password</h1>
                <p class="sub">Set a new, secure password for your SpeechEasy account.</p>
            </div>
            
            <div id="error-box" class="alert alert-error"></div>
            <div id="success-box" class="alert alert-success"></div>

            <form id="reset-form">
                <div class="form-group">
                    <label>New Password (min 8 chars, 1 letter, 1 number)</label>
                    <input type="password" id="new_password" required minlength="8" placeholder="••••••••" />
                </div>
                <div class="form-group">
                    <label>Confirm New Password</label>
                    <input type="password" id="confirm_password" required minlength="8" placeholder="••••••••" />
                </div>
                <button type="submit" id="submit-btn" class="btn">Update Password</button>
            </form>
        </div>

        <script>
            const token = "{token}";
            const form = document.getElementById('reset-form');
            const btn = document.getElementById('submit-btn');
            const errBox = document.getElementById('error-box');
            const succBox = document.getElementById('success-box');

            form.addEventListener('submit', async (e) => {{
                e.preventDefault();
                errBox.style.display = 'none';
                succBox.style.display = 'none';

                const pwd = document.getElementById('new_password').value;
                const cpwd = document.getElementById('confirm_password').value;

                if (pwd !== cpwd) {{
                    errBox.innerText = 'Passwords do not match.';
                    errBox.style.display = 'block';
                    return;
                }}
                if (pwd.length < 8 || !/[A-Za-z]/.test(pwd) || !/\d/.test(pwd)) {{
                    errBox.innerText = 'Password must be at least 8 characters and contain both letters and numbers.';
                    errBox.style.display = 'block';
                    return;
                }}

                btn.disabled = true;
                btn.innerText = 'Updating...';

                try {{
                    const res = await fetch('/api/v1/auth/reset-password', {{
                        method: 'POST',
                        headers: {{ 'Content-Type': 'application/json' }},
                        body: JSON.stringify({{ token: token, new_password: pwd }})
                    }});
                    const data = await res.json();
                    if (res.ok) {{
                        form.style.display = 'none';
                        succBox.innerHTML = '<strong>✓ Password Updated Successfully!</strong><br><br>You can now return to the SpeechEasy mobile or web application to sign in with your new password.<br><br><a href="{settings.FRONTEND_URL}" style="display:inline-block; margin-top:12px; padding:10px 20px; background:#1B5E20; color:#fff; text-decoration:none; border-radius:6px; font-weight:600;">Open SpeechEasy App</a>';
                        succBox.style.display = 'block';
                    }} else {{
                        errBox.innerText = (data && data.error && data.error.message) ? data.error.message : (data.detail || 'Password reset failed.');
                        errBox.style.display = 'block';
                        btn.disabled = false;
                        btn.innerText = 'Update Password';
                    }}
                }} catch (err) {{
                    errBox.innerText = 'Network error. Please try again.';
                    errBox.style.display = 'block';
                    btn.disabled = false;
                    btn.innerText = 'Update Password';
                }}
            }});
        </script>
    </body>
    </html>
    """)


@router.post(
    "/reset-password",
    response_model=MessageResponse,
    summary="Reset password using token or OTP",
    description="Validates reset token, updates password, and revokes all active sessions for security.",
    responses={
        400: {"model": ErrorResponse, "description": "Invalid, used, or expired token"},
    }
)
async def reset_password(req: ResetPasswordRequest):
    return await AuthService.reset_password(req.token, req.new_password)


@router.get(
    "/me",
    response_model=UserResponse,
    summary="Get current patient user info",
    description="Returns current authenticated patient profile and account metadata.",
    responses={
        401: {"model": ErrorResponse, "description": "Unauthorized"},
        403: {"model": ErrorResponse, "description": "Email not verified or wrong role"},
    }
)
async def get_me(current_user: Dict[str, Any] = Depends(get_current_patient_user)):
    sb = get_supabase()
    user_res = sb.table("users").select("*").eq("id", current_user["id"]).execute()
    if not user_res.data:
        raise AppException(404, "USER_NOT_FOUND", "User record not found.")

    u = user_res.data[0]
    return UserResponse(
        id=u["id"],
        email=u["email"],
        role=u["role"],
        auth_provider=u["auth_provider"],
        is_verified=u["is_verified"],
        is_active=u["is_active"],
        has_password=bool(u.get("password_hash")),
        created_at=u.get("created_at")
    )


@router.post(
    "/set-password",
    response_model=MessageResponse,
    summary="Set password for user without password (e.g. Google user)",
    responses={
        400: {"model": ErrorResponse, "description": "Validation error or password already set"},
        401: {"model": ErrorResponse, "description": "Unauthorized"},
    }
)
async def set_password(
    req: SetPasswordRequest,
    current_user: Dict[str, Any] = Depends(get_current_patient_user)
):
    return await AuthService.set_password(current_user["id"], req.new_password)


@router.post(
    "/change-password",
    response_model=MessageResponse,
    summary="Change password for user with existing password",
    responses={
        400: {"model": ErrorResponse, "description": "Validation error or invalid current password"},
        401: {"model": ErrorResponse, "description": "Unauthorized"},
    }
)
async def change_password(
    req: ChangePasswordRequest,
    current_user: Dict[str, Any] = Depends(get_current_patient_user)
):
    return await AuthService.change_password(current_user["id"], req.current_password, req.new_password)


@router.get(
    "/smtp-test",
    summary="Diagnostic endpoint to verify SMTP dispatch from server",
)
async def smtp_test(to_email: str = "fahadali721412@gmail.com"):
    import aiosmtplib
    from email.mime.text import MIMEText

    results = {}
    cleaned_pw = settings.SMTP_PASSWORD.replace(" ", "")
    for port, use_ssl in [(587, False), (465, True)]:
        try:
            msg = MIMEText(f"Test email from SpeechEasy server via port {port}")
            msg["Subject"] = f"SpeechEasy Diagnostic Test (Port {port})"
            msg["From"] = f"{settings.SMTP_FROM_NAME} <{settings.SMTP_FROM_EMAIL}>"
            msg["To"] = to_email

            await aiosmtplib.send(
                msg,
                hostname=settings.SMTP_HOST,
                port=port,
                username=settings.SMTP_USERNAME,
                password=cleaned_pw,
                use_tls=use_ssl,
                start_tls=not use_ssl,
                timeout=12
            )
            results[f"port_{port}"] = "SUCCESS"
        except Exception as e:
            results[f"port_{port}"] = f"FAILED: {type(e).__name__} - {str(e)}"

    return {
        "smtp_host": settings.SMTP_HOST,
        "smtp_username": settings.SMTP_USERNAME,
        "to_email": to_email,
        "results": results
    }

