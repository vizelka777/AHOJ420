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

CREATE TABLE IF NOT EXISTS oidc_clients (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL DEFAULT '',
    enabled BOOLEAN NOT NULL DEFAULT true,
    confidential BOOLEAN NOT NULL,
    require_pkce BOOLEAN NOT NULL DEFAULT true,
    auth_method TEXT NOT NULL,
    grant_types TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    response_types TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    scopes TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT oidc_clients_auth_method_check
        CHECK (auth_method IN ('none', 'basic', 'post')),
    CONSTRAINT oidc_clients_grant_types_nonempty
        CHECK (COALESCE(array_length(grant_types, 1), 0) > 0),
    CONSTRAINT oidc_clients_response_types_nonempty
        CHECK (COALESCE(array_length(response_types, 1), 0) > 0),
    CONSTRAINT oidc_clients_scopes_nonempty
        CHECK (COALESCE(array_length(scopes, 1), 0) > 0)
);

CREATE TABLE IF NOT EXISTS oidc_client_redirect_uris (
    client_id TEXT NOT NULL REFERENCES oidc_clients(id) ON DELETE CASCADE,
    redirect_uri TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (client_id, redirect_uri)
);

CREATE TABLE IF NOT EXISTS oidc_client_secrets (
    id BIGSERIAL PRIMARY KEY,
    client_id TEXT NOT NULL REFERENCES oidc_clients(id) ON DELETE CASCADE,
    secret_hash TEXT NOT NULL,
    label TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS oidc_client_secrets_client_idx
    ON oidc_client_secrets (client_id);

CREATE INDEX IF NOT EXISTS oidc_client_secrets_active_idx
    ON oidc_client_secrets (client_id)
    WHERE revoked_at IS NULL;

CREATE TABLE IF NOT EXISTS user_oidc_clients (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id TEXT NOT NULL,
    client_host TEXT,
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, client_id)
);
