# SpeechEasy Patient Authentication & Profile Service

A production-grade, hardened authentication and profile management microservice built for the **SpeechEasy Patient / Parent App**.

Designed to strictly isolate patient data and authentication from therapists and admins, preventing privilege escalation and cross-app credential misuse.

---

## Key Security Features

1. **Server-Enforced Role Isolation**:
   - The registration endpoint is dedicated (`POST /api/v1/auth/register/patient`) and hardcodes `role = 'patient'`. Clients can never supply or modify their role.
   - Login strictly checks `role == 'patient'`. If a therapist or administrator attempts to log into the Patient App, they are rejected with `403 Forbidden` (`ROLE_MISMATCH`).

2. **Single-Use, Time-Limited Verification Tokens**:
   - Verification tokens (24-hour lifespan) and password reset tokens (15-minute lifespan) are generated using `secrets.token_urlsafe(32)`.
   - Only the cryptographic **SHA-256 hash** is persisted in the database; raw tokens exist only in transit in the user's email.

3. **Short-Lived Access Tokens & Rotatable Refresh Sessions**:
   - HS256 JWT access tokens expire after **30 minutes**.
   - Cryptographic 30-day refresh tokens are stored hashed in `refresh_sessions` with family tracking.
   - Upon refresh, the previous refresh token is revoked and rotated. If a revoked token is used again, **Token Reuse Detection** revokes the entire token family immediately.

4. **Google Sign-In with Server-Side Cryptographic Verification**:
   - Client sends Google ID token.
   - Server cryptographically validates signature with Google's public certs (`google-auth`).
   - Links existing accounts or creates new patient accounts safely.

5. **Zero-Trust Profile Ownership**:
   - Profile CRUD endpoints (`/api/v1/profiles/me`, `POST /api/v1/profiles`, `PUT /api/v1/profiles`, `DELETE /api/v1/profiles/me`) **NEVER** accept `patient_uid` or `X-Patient-UID` from the client request.
   - The user identity is extracted strictly from the cryptographically verified JWT `sub` claim.

6. **Phoneme Cross-Field Validation**:
   - Enforces that `sound` (e.g. Urdu target phoneme) and `alphabet_name` (e.g. transliteration) must either **both** be supplied or **both** omitted.

---

## Directory Structure

```text
patient_auth_service/
├── .env.example
├── .env
├── requirements.txt
├── README.md
├── schema.sql
├── app/
│   ├── main.py
│   ├── config.py
│   ├── core/
│   │   ├── exceptions.py
│   │   ├── security.py
│   │   ├── supabase.py
│   │   └── dependencies.py
│   ├── schemas/
│   │   ├── common.py
│   │   ├── auth.py
│   │   └── profile.py
│   ├── services/
│   │   ├── auth_service.py
│   │   ├── google_auth_service.py
│   │   ├── email_service.py
│   │   └── profile_service.py
│   └── api/
│       └── v1/
│           ├── router.py
│           └── endpoints/
│               ├── auth.py
│               └── profiles.py
└── tests/
    └── test_auth_and_profiles.py
```

---

## Database Setup (Supabase PostgreSQL)

1. Open your Supabase Dashboard at [supabase.com](https://supabase.com).
2. Navigate to **SQL Editor**.
3. Copy the contents of `schema.sql` and run the script.
4. Tables created / managed:
   - `public.users`
   - `public.auth_tokens`
   - `public.refresh_sessions`
   - `public.profiles`
   - `public.focus_sound`

---

## Environment Variables (`.env`)

| Variable | Description | Default |
|---|---|---|
| `PORT` | Listening port | `8001` |
| `SUPABASE_URL` | Supabase Project URL | Configured |
| `SUPABASE_SERVICE_ROLE_KEY` | Supabase Service Role Key | Configured |
| `JWT_SECRET_KEY` | HMAC-SHA256 Signing Secret | Set in `.env` |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | Access JWT expiration | `30` |
| `REFRESH_TOKEN_EXPIRE_DAYS` | Refresh token expiration | `30` |
| `EMAIL_VERIFICATION_TOKEN_EXPIRE_HOURS` | Verification token lifespan | `24` |
| `PASSWORD_RESET_TOKEN_EXPIRE_MINUTES` | Password reset lifespan | `15` |
| `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD` | SMTP Email Settings | Gmail / SES / SendGrid |
| `FRONTEND_URL` | Frontend URL for email links | `http://localhost:5000` |

---

## Running the Service

```bash
# Navigate to the service directory
cd patient_auth_service

# Install dependencies (if not already installed)
pip install -r requirements.txt

# Run with Uvicorn
python -m uvicorn app.main:app --host 0.0.0.0 --port 8001 --reload
```

Interactive API documentation will be available at:
- **Swagger UI**: `http://localhost:8001/docs`
- **ReDoc**: `http://localhost:8001/redoc`

---

## API Endpoints Reference

### Authentication (`/api/v1/auth`)

| Method | Endpoint | Description | Auth Required |
|---|---|---|---|
| `POST` | `/api/v1/auth/register/patient` | Register new patient account | No |
| `POST` | `/api/v1/auth/verify-email` | Verify email with token | No |
| `POST` | `/api/v1/auth/resend-verification` | Resend verification email | No |
| `POST` | `/api/v1/auth/login` | Login with email & password | No |
| `POST` | `/api/v1/auth/google` | Sign in with Google ID token | No |
| `POST` | `/api/v1/auth/refresh` | Rotate and refresh access token | No |
| `POST` | `/api/v1/auth/logout` | Revoke refresh token | No |
| `POST` | `/api/v1/auth/forgot-password` | Request password reset token | No |
| `POST` | `/api/v1/auth/reset-password` | Reset password using token | No |
| `GET` | `/api/v1/auth/me` | Get current patient user data | Bearer JWT |

### Patient Profile (`/api/v1/profiles`)

| Method | Endpoint | Description | Auth Required |
|---|---|---|---|
| `GET` | `/api/v1/profiles/me` | Fetch authenticated patient profile & focus sound | Bearer JWT |
| `POST` | `/api/v1/profiles` | Create patient profile (enforces sound cross-validation) | Bearer JWT |
| `PUT` | `/api/v1/profiles` | Update patient profile | Bearer JWT |
| `DELETE` | `/api/v1/profiles/me` | Delete patient profile | Bearer JWT |
