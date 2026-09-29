import asyncio
import sys
import uuid
from pathlib import Path
from unittest.mock import patch, AsyncMock
from pydantic import ValidationError

CURRENT_DIR = Path(__file__).resolve().parent
ROOT_DIR = CURRENT_DIR.parent
sys.path.insert(0, str(CURRENT_DIR))
sys.path.insert(1, str(ROOT_DIR))

from app.services.auth_service import AuthService
from app.services.google_auth_service import GoogleAuthService
from app.schemas.auth import GoogleAuthRequest
from app.core.supabase import get_supabase


async def run_tests():
    print("==================================================")
    print("RUNNING GOOGLE AUTH & COMPULSORY PHONE TEST SUITE")
    print("==================================================")

    # ------------------------------------------------------------------
    # Test 1: Compulsory Phone Validation
    # ------------------------------------------------------------------
    import importlib.util
    spec = importlib.util.spec_from_file_location("speech_profile_schema", str(ROOT_DIR / "speech_backend" / "app" / "schemas" / "profile.py"))
    speech_profile = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(speech_profile)
    ProfileCreateOrUpdate = speech_profile.ProfileCreateOrUpdate

    # Case A: Missing / None phone
    try:
        ProfileCreateOrUpdate(
            parent_name="Test Parent",
            child_name="Test Child",
            phone=None,
        )
        assert False, "Should have failed on phone=None"
    except (ValidationError, ValueError):
        print("  âœ“ Correctly rejected phone=None")

    # Case B: Empty / blank phone
    try:
        ProfileCreateOrUpdate(
            parent_name="Test Parent",
            child_name="Test Child",
            phone="   ",
        )
        assert False, "Should have failed on blank phone"
    except (ValidationError, ValueError):
        print("  âœ“ Correctly rejected blank whitespace phone")

    # Case C: Invalid phone format
    try:
        ProfileCreateOrUpdate(
            parent_name="Test Parent",
            child_name="Test Child",
            phone="123",
        )
        assert False, "Should have failed on short invalid phone"
    except (ValidationError, ValueError):
        print("  âœ“ Correctly rejected invalid format phone ('123')")

    # Case D: Valid phone
    valid_prof = ProfileCreateOrUpdate(
        parent_name="Test Parent",
        child_name="Test Child",
        phone="+92 300 1234567",
        age=5
    )
    assert valid_prof.phone == "+92 300 1234567"
    print(f"  âœ“ Correctly accepted valid phone: {valid_prof.phone}")

    # ------------------------------------------------------------------
    # Setup for Google Auth Tests
    # ------------------------------------------------------------------
    sb = get_supabase()
    test_sub = "test_google_sub_888999"
    test_email = "test_google_patient_888@example.com"
    captured_tokens = []

    # Clean up any leftover test data
    sb.table("users").delete().eq("email", test_email).execute()
    sb.table("users").delete().eq("google_subject", test_sub).execute()

    fake_claims = {
        "google_subject": test_sub,
        "email": test_email,
        "name": "Verified Google Parent",
        "picture": "https://example.com/pic.jpg"
    }

    async def mock_send_email(to_email, token, parent_name):
        captured_tokens.append(token)
        print(f"  [MOCK EMAIL] OTP {token} dispatched to {to_email} for {parent_name}")
        return True

    with patch.object(GoogleAuthService, "verify_token", return_value=fake_claims), \
         patch("app.services.email_service.EmailService.send_verification_email", side_effect=mock_send_email):

        # ------------------------------------------------------------------
        # Test 2: Case 1 - New Google User Registration
        # ------------------------------------------------------------------
        print("\n[TEST 2] Testing New Google User Registration (Case 1)...")
        resp1 = await AuthService.login_with_google(GoogleAuthRequest(id_token="mock_token_1"))

        assert resp1.is_verified is False, "New Google user must not be marked verified immediately"
        assert resp1.verification_required is True, "verification_required must be True"
        assert resp1.access_token is None, "Access token must not be issued for unverified user"
        assert resp1.refresh_token is None, "Refresh token must not be issued for unverified user"
        assert resp1.email == test_email, f"Expected {test_email}, got {resp1.email}"
        assert len(captured_tokens) == 1, "OTP should have been sent to email"
        print("  âœ“ Correct GoogleAuthResponse returned for new unverified Google registration")

        # Verify DB records
        user_query = sb.table("users").select("*").eq("google_subject", test_sub).execute()
        assert len(user_query.data) == 1, "Exactly one user row must exist"
        db_user = user_query.data[0]
        assert db_user["email"] == test_email
        assert db_user["role"] == "patient"
        assert db_user["auth_provider"] == "google"
        assert db_user["is_verified"] is False
        assert db_user["is_active"] is True
        print(f"  âœ“ public.users row verified: id={db_user['id']}, is_verified=False")

        # Verify profile record is NOT created yet (so GET /profiles/me will return 404 -> open Create Profile)
        prof_query = sb.table("profiles").select("*").eq("patient_uid", db_user["id"]).execute()
        assert len(prof_query.data) == 0, "Profile must NOT exist yet for new Google user"
        print("  [OK] public.profiles row correctly does not exist yet (triggers Create Profile)")

        # Verify auth_tokens has single-use OTP
        token_query = sb.table("auth_tokens").select("*").eq("user_id", db_user["id"]).is_("used_at", "null").execute()
        assert len(token_query.data) == 1, "One active unused email_verification token must exist"
        print(f"  [OK] public.auth_tokens OTP record verified: token_type={token_query.data[0]['token_type']}")

        # ------------------------------------------------------------------
        # Test 3: Unverified Google User Repeated Login (Zero Duplicate)
        # ------------------------------------------------------------------
        print("\n[TEST 3] Testing Repeated Google Login for Unverified User...")
        resp2 = await AuthService.login_with_google(GoogleAuthRequest(id_token="mock_token_2"))

        assert resp2.is_verified is False
        assert resp2.verification_required is True
        assert resp2.access_token is None
        assert len(captured_tokens) == 2, "New OTP should have been dispatched"

        # Check DB non-duplication
        user_query2 = sb.table("users").select("*").eq("google_subject", test_sub).execute()
        assert len(user_query2.data) == 1, "Must NEVER create duplicate users"
        prof_query2 = sb.table("profiles").select("*").eq("patient_uid", db_user["id"]).execute()
        assert len(prof_query2.data) == 0, "Profile still does not exist"
        print("  [OK] Zero duplicates created on repeat login; new OTP issued successfully")

        # ------------------------------------------------------------------
        # Test 4: OTP Verification -> Issues access_token & refresh_token!
        # ------------------------------------------------------------------
        print("\n[TEST 4] Testing OTP Email Verification (Issues Tokens)...")
        latest_otp = captured_tokens[-1]
        verify_resp = await AuthService.verify_email(latest_otp)
        assert verify_resp.access_token is not None, "Access token MUST be issued upon verification"
        assert verify_resp.refresh_token is not None, "Refresh token MUST be issued upon verification"
        assert verify_resp.user.id == db_user["id"]
        print(f"  [OK] verify_email returned tokens: access_token={verify_resp.access_token[:15]}...")

        # Check user in DB is now verified
        user_verified_query = sb.table("users").select("is_verified").eq("id", db_user["id"]).execute()
        assert user_verified_query.data[0]["is_verified"] is True, "User must now be is_verified = True"
        print("  [OK] public.users record updated to is_verified = True")

        # ------------------------------------------------------------------
        # Test 5: Verified Google User Login (Case 2 - Verified)
        # ------------------------------------------------------------------
        print("\n[TEST 5] Testing Verified Google User Login (Case 2)...")
        resp3 = await AuthService.login_with_google(GoogleAuthRequest(id_token="mock_token_3"))

        assert resp3.is_verified is True, "Verified user should be marked verified"
        assert resp3.verification_required is False
        assert resp3.access_token is not None, "Access token must be granted"
        assert resp3.refresh_token is not None, "Refresh token must be granted"
        assert resp3.user.id == db_user["id"], "Identity MUST strictly match public.users.id"
        print(f"  [OK] Full login session issued: access_token granted for user {resp3.user.id}")

        # Verify refresh session created in public.refresh_sessions
        session_query = sb.table("refresh_sessions").select("*").eq("user_id", db_user["id"]).execute()
        assert len(session_query.data) >= 1, "Refresh session must be recorded in public.refresh_sessions"
        print(f"  [OK] public.refresh_sessions verified: family_id={session_query.data[0]['family_id']}")

        # ------------------------------------------------------------------
        # Test 6: Linking Existing Email User to Google
        # ------------------------------------------------------------------
        print("\n[TEST 6] Testing Linking Existing Email User to Google Identity...")
        pw_email = "test_pw_user_link_777@example.com"
        sb.table("users").delete().eq("email", pw_email).execute()

        new_pw_user_id = str(uuid.uuid4())
        sb.table("users").insert({
            "id": new_pw_user_id,
            "email": pw_email,
            "password_hash": "mock_hash",
            "role": "patient",
            "auth_provider": "password",
            "google_subject": None,
            "is_verified": True,
            "is_active": True,
        }).execute()
        sb.table("profiles").insert({
            "patient_uid": new_pw_user_id,
            "parent_name": "PW Parent",
            "child_name": "PW Child",
        }).execute()

        pw_google_sub = "test_pw_google_sub_999000"
        with patch.object(GoogleAuthService, "verify_token", return_value={
            "google_subject": pw_google_sub,
            "email": pw_email,
            "name": "PW Parent Google",
            "picture": ""
        }):
            resp_link = await AuthService.login_with_google(GoogleAuthRequest(id_token="mock_token_link"))
            assert resp_link.is_verified is True
            assert resp_link.user.id == new_pw_user_id, "Linked user must maintain existing users.id"

            linked_user = sb.table("users").select("*").eq("id", new_pw_user_id).execute().data[0]
            assert linked_user["google_subject"] == pw_google_sub, "google_subject must be linked"
            assert linked_user["auth_provider"] == "password_and_google", "auth_provider must be updated to password_and_google"
            print("  âœ“ Existing password account successfully linked to Google without duplicating ID")

    # Cleanup
    print("\n[CLEANUP] Cleaning up test records from database...")
    sb.table("users").delete().eq("email", test_email).execute()
    sb.table("users").delete().eq("google_subject", test_sub).execute()
    sb.table("users").delete().eq("email", pw_email).execute()
    print("  âœ“ Cleanup complete.")

    print("\n==================================================")
    print("ALL TESTS PASSED SUCCESSFULLY! (100% VERIFIED)")
    print("==================================================")


if __name__ == "__main__":
    asyncio.run(run_tests())
