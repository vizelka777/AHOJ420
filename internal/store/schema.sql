CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email TEXT UNIQUE NOT NULL,        -- legacy name: internal login ID (not guaranteed contact email)
    created_at TIMESTAMPTZ DEFAULT NOW()
);

ALTER TABLE users ADD COLUMN IF NOT EXISTS display_name TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS profile_email TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS phone TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS share_profile BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verified BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE users ADD COLUMN IF NOT EXISTS phone_verified BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE users ADD COLUMN IF NOT EXISTS profile_completed_at TIMESTAMPTZ;
ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar_key TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar_updated_at TIMESTAMPTZ;
ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar_mime TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar_bytes BIGINT;

CREATE TABLE IF NOT EXISTS credentials (
    id BYTEA PRIMARY KEY,             -- CredentialID
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    public_key BYTEA NOT NULL,        -- Public key
    aaguid BYTEA,                     -- AAGUID
    sign_count BIGINT DEFAULT 0,      -- Sign count (uint32 but safer as big in DB)
    device_name TEXT,                 -- Friendly name
    created_at TIMESTAMPTZ DEFAULT NOW(),
    last_used_at TIMESTAMPTZ
);

UPDATE users
SET display_name = COALESCE(NULLIF(display_name, ''), 'Ahoj User')
WHERE display_name IS NULL OR display_name = '';

-- Enforce unique non-empty profile contacts (normalized).
CREATE UNIQUE INDEX IF NOT EXISTS users_profile_email_unique_idx
    ON users (lower(trim(profile_email)))
    WHERE trim(COALESCE(profile_email, '')) <> '';

CREATE UNIQUE INDEX IF NOT EXISTS users_phone_unique_idx
    ON users (trim(phone))
    WHERE trim(COALESCE(phone, '')) <> '';
