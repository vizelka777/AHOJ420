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

## Safe Server Deploy
For this repository, use the deploy helper to avoid legacy compose issues and accidental `.env` overwrite:

```bash
./scripts/deploy_server.sh
```

What it does:
- syncs project to `sss@46.36.37.243:/home/sss/AHOJ420`
- excludes `.env` / `.env.*` from sync
- runs `./scripts/remote_deploy.sh` on server
- prefers `docker compose` (v2), falls back to `docker-compose` only if needed
- updates `backend` by default, without restarting `postgres/redis`
- waits until `https://ahoj420.eu/robots.txt` is healthy before finishing

Optional flags:
- `DEPLOY_CADDY=1 ./scripts/deploy_server.sh` to refresh caddy too
- `BUILD_BACKEND=0 ./scripts/deploy_server.sh` to skip backend image rebuild

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
- OIDC clients registry in PostgreSQL must be initialized (table `oidc_clients` is source of truth)
- for one-time bootstrap into empty DB:
  - `OIDC_CLIENTS_BOOTSTRAP=1`
  - one of:
    - `OIDC_CLIENTS_JSON='[...]'`
    - `OIDC_CLIENTS_FILE=/run/secrets/oidc_clients.json`

Optional for key rotation:
- `OIDC_KEY_ID=key-current`
- `OIDC_PREV_PRIVKEY_PATH=/run/secrets/oidc_private_key_prev.pem`
- `OIDC_PREV_KEY_ID=key-prev`
- `OIDC_CLIENT_MUSHROOM_BFF_SECRET=<secret>` (bootstrap compatibility fallback for `mushroom-bff` when JSON has no `secrets`)

Admin API:
- `ADMIN_API_TOKEN=<long-random-shared-secret>`
- `ADMIN_API_HOST=admin.ahoj420.eu`
- if either is unset, `/admin/api/*` returns `503` ("admin api disabled")

Avatar storage:
- `AVATAR_PUBLIC_BASE=https://avatar.ahoj420.eu/` (required in `prod` to emit `picture` claim)
- `BUNNY_STORAGE_ENDPOINT=storage.bunnycdn.com` (default if empty)
- `BUNNY_STORAGE_ZONE=avatar420`
- `BUNNY_STORAGE_ACCESS_KEY=<bunny-storage-access-key>`

If `AHOJ_ENV=dev` and key/crypto key are missing, ephemeral values are generated and tokens/cookies become invalid after restart.

OIDC client source behavior:
- runtime source of truth is PostgreSQL (`oidc_clients`, `oidc_client_redirect_uris`, `oidc_client_secrets`)
- JSON/file is bootstrap/import only (not runtime source)
- if DB is empty:
  - `prod`: requires `OIDC_CLIENTS_BOOTSTRAP=1` + JSON/file source
  - `dev`: auto-seeds DB from JSON/file when provided, otherwise from built-in dev defaults
- if DB is non-empty, bootstrap env vars are ignored (no silent overwrite)

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
    email TEXT UNIQUE NOT NULL, -- legacy name, acts as technical login ID
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

## Terminology Note
We made an early naming mistake: `users.email` is historically named as an email field, but in practice it acts as an internal login identifier (`anon-*` for passkey-first users).

Actual user contact email lives in `users.profile_email` and is the field used for profile email verification and recovery flows.

For backward compatibility we keep the physical DB column name `email` for now. A dedicated schema rename/migration is planned for a future release.

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

## OIDC Clients Bootstrap
OIDC clients are stored in PostgreSQL and loaded from DB at runtime.

`OIDC_CLIENTS_JSON` / `OIDC_CLIENTS_FILE` are used only for one-time bootstrap into an empty DB.

Recommended first bootstrap:
1. Set `OIDC_CLIENTS_BOOTSTRAP=1`.
2. Provide `OIDC_CLIENTS_JSON` or `OIDC_CLIENTS_FILE`.
3. Start backend once, verify clients were imported.
4. Remove bootstrap env (`OIDC_CLIENTS_BOOTSTRAP`, `OIDC_CLIENTS_JSON`, `OIDC_CLIENTS_FILE`) from runtime profile.

JSON shape for bootstrap:

Example public client (`client2`) with PKCE:
```json
[
  {
    "id": "client2",
    "name": "Client 2",
    "enabled": true,
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
    "name": "Mushroom BFF",
    "enabled": true,
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
- `email` -> `email` from `users.profile_email`, `email_verified` from `users.email_verified`
- `phone` -> `phone_number`, `phone_number_verified` from `users.phone`, `users.phone_verified` (phone claims omitted when phone is empty)

`picture` is returned as:
- `https://avatar.ahoj420.eu/avatars/<user_id>.webp?v=<avatar_updated_at_unix>`

The `?v=` value is added to force cache refresh after avatar updates.

## Admin OIDC Clients API (MVP)
Internal-only API for owner/admin usage. Not a public self-service API.

Base path:
- `/admin/api/oidc/clients`

Auth:
- host guard: requests must come to `ADMIN_API_HOST` (wrong host returns `404`)
- `Authorization: Bearer <ADMIN_API_TOKEN>`

Routes:
- `GET /admin/api/oidc/clients`
- `GET /admin/api/oidc/clients/:id`
- `POST /admin/api/oidc/clients`
- `PUT /admin/api/oidc/clients/:id`
- `PUT /admin/api/oidc/clients/:id/redirect-uris`
- `POST /admin/api/oidc/clients/:id/secrets`
- `POST /admin/api/oidc/clients/:id/secrets/:secretID/revoke`

Security behavior:
- admin API is enabled only when both `ADMIN_API_TOKEN` and `ADMIN_API_HOST` are set
- wrong host is rejected in-app (does not rely only on reverse proxy routing)
- secret hashes and plaintext secrets are never returned from list/detail endpoints
- `plain_secret` is returned only one-time in `POST .../secrets` when `generate=true`
- create endpoint expects explicit `initial_secret` for confidential clients and does not echo it back
- successful mutating admin operations trigger OIDC runtime client reload immediately (no process restart required)
- if DB mutation succeeds but runtime reload fails, endpoint returns `500` and operator action is required
- `/admin/api/*` has dedicated IP-based rate limiting (`429` on exceed)
- admin requests include `X-Request-ID` response header

Mutating admin actions are persisted in PostgreSQL `admin_audit_log` and also written to app logs.
