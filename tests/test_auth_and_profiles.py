import pytest
from unittest.mock import MagicMock, patch
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.main import app
from app.schemas.auth import PatientRegisterRequest
from app.schemas.profile import ProfileCreateRequest, ProfileUpdateRequest
from app.core.security import (
    hash_password,
    verify_password,
    hash_token,
    create_access_token,
    decode_access_token,
    create_refresh_token_data
)

client = TestClient(app)


def test_health_and_root():
    res = client.get("/")
    assert res.status_code == 200
    assert res.json()["service"] == "SpeechEasy Patient Auth & Profile API"

    res_health = client.get("/health")
    assert res_health.status_code == 200
    assert res_health.json()["status"] == "ok"


def test_password_validation():
    # Valid password
    req = PatientRegisterRequest(
        email="parent@example.com",
        password="ValidPassword123",
        parent_name="John Doe"
    )
    assert req.password == "ValidPassword123"

    # Too short (< 8 chars)
    with pytest.raises(ValidationError):
        PatientRegisterRequest(
            email="parent@example.com",
            password="Short1",
            parent_name="John Doe"
        )

    # Missing number
    with pytest.raises(ValidationError):
        PatientRegisterRequest(
            email="parent@example.com",
            password="NoNumberPassword",
            parent_name="John Doe"
        )

    # Missing letter
    with pytest.raises(ValidationError):
        PatientRegisterRequest(
            email="parent@example.com",
            password="1234567890",
            parent_name="John Doe"
        )


def test_cross_field_sound_validation():
    # Both provided -> valid
    p1 = ProfileCreateRequest(
        parent_name="Ahmad Ali",
        child_name="Zayd",
        sound="k",
        alphabet_name="kaaf"
    )
    assert p1.sound == "k"
    assert p1.alphabet_name == "kaaf"

    # Both omitted -> valid
    p2 = ProfileCreateRequest(
        parent_name="Ahmad Ali",
        child_name="Zayd"
    )
    assert p2.sound is None
    assert p2.alphabet_name is None

    # Only sound provided -> INVALID
    with pytest.raises(ValidationError):
        ProfileCreateRequest(
            parent_name="Ahmad Ali",
            child_name="Zayd",
            sound="k",
            alphabet_name=None
        )

    # Only alphabet_name provided -> INVALID
    with pytest.raises(ValidationError):
        ProfileCreateRequest(
            parent_name="Ahmad Ali",
            child_name="Zayd",
            sound=None,
            alphabet_name="kaaf"
        )


def test_password_hashing():
    pwd = "MySecretPassword2026!"
    hashed = hash_password(pwd)
    assert hashed != pwd
    assert verify_password(pwd, hashed) is True
    assert verify_password("WrongPassword", hashed) is False


def test_token_hashing():
    raw_token = "secure_random_token_string_abc123"
    t_hash1 = hash_token(raw_token)
    t_hash2 = hash_token(raw_token)
    assert t_hash1 == t_hash2
    assert len(t_hash1) == 64  # SHA-256 hex string


def test_jwt_access_token_creation_and_validation():
    user_id = "test-patient-uuid-12345"
    email = "test@example.com"
    token = create_access_token(user_id=user_id, email=email, role="patient", is_verified=True)

    payload = decode_access_token(token)
    assert payload["sub"] == user_id
    assert payload["email"] == email
    assert payload["role"] == "patient"
    assert payload["is_verified"] is True
    assert payload["token_type"] == "access"


def test_profile_endpoints_require_auth():
    # Calling profile without authorization header should return 401 Unauthorized
    res = client.get("/api/v1/profiles/me")
    assert res.status_code == 401
    assert res.json()["error"]["code"] == "UNAUTHORIZED"


def test_profile_endpoints_reject_non_patient_role():
    # Calling profile with therapist token should be rejected with 403 ROLE_MISMATCH
    therapist_token = create_access_token(
        user_id="therapist-uuid-999",
        email="doctor@clinic.com",
        role="therapist",
        is_verified=True
    )
    res = client.get(
        "/api/v1/profiles/me",
        headers={"Authorization": f"Bearer {therapist_token}"}
    )
    assert res.status_code == 403
    assert res.json()["error"]["code"] == "ROLE_MISMATCH"


def test_profile_endpoints_reject_unverified_email():
    # Calling profile with unverified email token should be rejected with 403 EMAIL_NOT_VERIFIED
    unverified_token = create_access_token(
        user_id="patient-uuid-888",
        email="patient@example.com",
        role="patient",
        is_verified=False
    )
    res = client.get(
        "/api/v1/profiles/me",
        headers={"Authorization": f"Bearer {unverified_token}"}
    )
    assert res.status_code == 403
    assert res.json()["error"]["code"] == "EMAIL_NOT_VERIFIED"


def test_login_validation_and_rejection():
    # Invalid password length on login
    res = client.post(
        "/api/v1/auth/register/patient",
        json={
            "email": "invalid-email",
            "password": "123",
            "parent_name": "A"
        }
    )
    assert res.status_code == 422
    assert res.json()["error"]["code"] == "VALIDATION_ERROR"
