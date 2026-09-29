-- =============================================================================
-- SPEECHEASY: PATIENT AUTH & PROFILE DATABASE SCHEMA FOR SUPABASE POSTGRESQL
-- =============================================================================

-- Enable pgcrypto or uuid-ossp for UUID generation if not already enabled
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- 1. USERS TABLE
CREATE TABLE IF NOT EXISTS public.users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NULL, -- NULL if user registered solely via Google OAuth
    role TEXT NOT NULL DEFAULT 'patient' CHECK (role IN ('patient', 'therapist', 'admin')),
    auth_provider TEXT NOT NULL DEFAULT 'password' CHECK (auth_provider IN ('password', 'google', 'password_and_google')),
    google_subject TEXT UNIQUE NULL,
    is_verified BOOLEAN NOT NULL DEFAULT FALSE,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Index on email and google_subject for ultra-fast auth lookups
CREATE INDEX IF NOT EXISTS idx_users_email ON public.users(email);
CREATE INDEX IF NOT EXISTS idx_users_google_subject ON public.users(google_subject);

-- 2. AUTH TOKENS TABLE (Single-use hashed tokens for email verification & password reset)
CREATE TABLE IF NOT EXISTS public.auth_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL, -- SHA-256 hash of the cryptographically random token
    token_type TEXT NOT NULL CHECK (token_type IN ('email_verification', 'password_reset')),
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_auth_tokens_hash_type ON public.auth_tokens(token_hash, token_type);
CREATE INDEX IF NOT EXISTS idx_auth_tokens_user_id ON public.auth_tokens(user_id);

-- 3. REFRESH SESSIONS TABLE (Rotatable & revocable refresh token sessions)
CREATE TABLE IF NOT EXISTS public.refresh_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
    refresh_token_hash TEXT NOT NULL, -- SHA-256 hash of the issued refresh token
    family_id UUID NOT NULL, -- Token family for detecting reuse / compromise
    is_revoked BOOLEAN NOT NULL DEFAULT FALSE,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_refresh_sessions_hash ON public.refresh_sessions(refresh_token_hash);
CREATE INDEX IF NOT EXISTS idx_refresh_sessions_user ON public.refresh_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_refresh_sessions_family ON public.refresh_sessions(family_id);

-- 4. PROFILES TABLE (Patient / Parent profile)
-- Note: patient_uid is TEXT / UUID matching users.id
CREATE TABLE IF NOT EXISTS public.profiles (
    patient_uid TEXT PRIMARY KEY,
    parent_name TEXT NOT NULL,
    child_name TEXT NOT NULL,
    phone TEXT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 5. FOCUS SOUND TABLE (Urdu phoneme progress tracking)
CREATE TABLE IF NOT EXISTS public.focus_sound (
    patient_uid TEXT PRIMARY KEY REFERENCES public.profiles(patient_uid) ON DELETE CASCADE,
    sound TEXT NULL,
    alphabet_name TEXT NULL,
    progress NUMERIC DEFAULT 0.0,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Triggers for automatic updated_at timestamp
CREATE OR REPLACE FUNCTION update_timestamp_column()
RETURNS TRIGGER AS $$
BEGIN
   NEW.updated_at = NOW();
   RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_users_updated_at ON public.users;
CREATE TRIGGER trg_users_updated_at
BEFORE UPDATE ON public.users
FOR EACH ROW EXECUTE FUNCTION update_timestamp_column();

DROP TRIGGER IF EXISTS trg_profiles_updated_at ON public.profiles;
CREATE TRIGGER trg_profiles_updated_at
BEFORE UPDATE ON public.profiles
FOR EACH ROW EXECUTE FUNCTION update_timestamp_column();

DROP TRIGGER IF EXISTS trg_focus_sound_updated_at ON public.focus_sound;
CREATE TRIGGER trg_focus_sound_updated_at
BEFORE UPDATE ON public.focus_sound
FOR EACH ROW EXECUTE FUNCTION update_timestamp_column();
