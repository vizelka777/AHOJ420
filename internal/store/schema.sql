CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email TEXT UNIQUE NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

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
