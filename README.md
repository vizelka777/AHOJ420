# Project Ahoj420

Passkey-only identity provider (WebAuthn + OIDC). No passwords. Modern UX for fast registration and login.

## Highlights
- Passkey-first registration (biometrics / hardware keys)
- Discoverable login (resident keys) with one-tap UX
- Cross-device login (planned) via QR + caBLE
- Recovery via email (planned)
- OIDC / SSO provider (planned)

## Tech Stack
- Go 1.24+
- HTMX + Tailwind CSS (no-SPA)
- PostgreSQL 16+
- Redis (sessions / challenges)
- Caddy (TLS + reverse proxy)
- Libraries:
  - `github.com/go-webauthn/webauthn`
  - `github.com/zitadel/oidc/v3`

## Quick Start (Docker)
```bash
# build and start everything
sudo docker-compose up -d --build

# logs
sudo docker-compose logs -f --tail=200
```

## Environment
Core variables:
- `POSTGRES_URL=postgres://ahoj:password@postgres:5432/ahoj420?sslmode=disable`
- `REDIS_ADDR=redis:6379` (required, OIDC auth state/codes are in Redis)
- `RP_ID=ahoj420.eu`
- `RP_ORIGIN=https://ahoj420.eu`
- `SESSION_TTL_MINUTES=60`

OIDC mode:
- `AHOJ_ENV=dev|prod` (default: `dev`)

Required in `prod`:
- `OIDC_PRIVKEY_PATH=/run/secrets/oidc_private_key.pem` (no ephemeral fallback in prod)
- `OIDC_CRYPTO_KEY=<at least 32 bytes>` (no insecure default in prod)
- one of:
  - `OIDC_CLIENTS_JSON='[...]'`
  - `OIDC_CLIENTS_FILE=/run/secrets/oidc_clients.json`

Optional for key rotation:
- `OIDC_KEY_ID=key-current`
- `OIDC_PREV_PRIVKEY_PATH=/run/secrets/oidc_private_key_prev.pem`
- `OIDC_PREV_KEY_ID=key-prev`
- `OIDC_CLIENT_MUSHROOM_BFF_SECRET=<secret>` (used when `mushroom-bff` client has no explicit `secrets` in JSON)

Avatar storage:
- `AVATAR_PUBLIC_BASE=https://avatar.ahoj420.eu/` (required in `prod` to emit `picture` claim)
- `BUNNY_STORAGE_ENDPOINT=storage.bunnycdn.com` (default if empty)
- `BUNNY_STORAGE_ZONE=avatar420`
- `BUNNY_STORAGE_ACCESS_KEY=<bunny-storage-access-key>`

If `AHOJ_ENV=dev` and key/crypto key are missing, ephemeral values are generated and tokens/cookies become invalid after restart.

## Caddy
Example (current):
```caddyfile
ahoj420.eu, www.ahoj420.eu {
    @www host www.ahoj420.eu
    redir @www https://ahoj420.eu{uri} 301

    reverse_proxy backend:8080

    header {
        Permissions-Policy "publickey-credentials-get=*"
    }
}
```

## Database Schema (PostgreSQL)
```sql
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email TEXT UNIQUE NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE credentials (
    id BYTEA PRIMARY KEY,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    public_key BYTEA NOT NULL,
    aaguid BYTEA,
    sign_count UINT32 DEFAULT 0,
    device_name TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    last_used_at TIMESTAMPTZ
);
```

## Project Structure
```
.
├── cmd/server/main.go       # entry point
├── internal/
│   ├── auth/                # WebAuthn flows
│   ├── oidc/                # OIDC provider
│   ├── store/               # Postgres access
│   └── cache/               # Redis access
├── web/
│   ├── static/js/glue.js    # navigator.credentials glue
│   └── templates/           # HTMX templates
├── Caddyfile
├── docker-compose.yml
└── README.md
```

## Roadmap
1) Core WebAuthn registration + login
2) Cross-device login (QR + caBLE)
3) Recovery (email magic link)
4) OIDC / SSO provider
5) Device management UI (AAGUID -> device names/icons)

## Notes
- WebAuthn requires HTTPS and correct RP ID/Origin.
- Avoid exposing Postgres/Redis to the internet.
- For production, disable backend port 8080 and keep only Caddy (80/443).
- Public OIDC clients must use PKCE (`S256`) and no client secret.

## OIDC Clients Config
Clients are loaded from `OIDC_CLIENTS_JSON` or `OIDC_CLIENTS_FILE` (JSON array).

Example public client (`client2`) with PKCE:
```json
[
  {
    "id": "client2",
    "redirect_uris": ["https://houbamzdar.cz/callback2.html"],
    "confidential": false,
    "require_pkce": true,
    "auth_method": "none",
    "grant_types": ["authorization_code"],
    "response_types": ["code"]
  }
]
```

Example confidential client:
```json
[
  {
    "id": "mushroom-bff",
    "redirect_uris": ["https://api.houbamzdar.cz/auth/callback"],
    "confidential": true,
    "secrets": ["use OIDC_CLIENT_MUSHROOM_BFF_SECRET in prod"],
    "require_pkce": true,
    "auth_method": "basic",
    "grant_types": ["authorization_code", "refresh_token"],
    "response_types": ["code"],
    "scopes": ["openid", "profile", "email", "phone"]
  }
]
```

## Claims Mapping (ID Token and /userinfo)
By requested scopes:
- `profile` -> `name`, `preferred_username` from `users.display_name`, `picture` from avatar storage URL
- `email` -> `email`, `email_verified` from `users.email`, `users.email_verified`
- `phone` -> `phone_number`, `phone_number_verified` from `users.phone`, `users.phone_verified` (phone claims omitted when phone is empty)

`picture` is returned as:
- `https://avatar.ahoj420.eu/avatars/<user_id>.webp?v=<avatar_updated_at_unix>`

The `?v=` value is added to force cache refresh after avatar updates.
