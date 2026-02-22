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
Used in `docker-compose.yml`:
- `POSTGRES_URL=postgres://ahoj:password@postgres:5432/ahoj420?sslmode=disable`
- `REDIS_ADDR=redis:6379`
- `RP_ID=ahoj420.eu`
- `RP_ORIGIN=https://ahoj420.eu`

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

