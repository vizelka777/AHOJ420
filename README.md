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

Admin API + Admin Auth:
- `ADMIN_API_HOST=admin.ahoj420.eu` (required; if unset, `/admin/*` returns `503`)
- `ADMIN_BOOTSTRAP_LOGIN=<login>` (one-time only for first admin passkey bootstrap; remove/empty after bootstrap is finished)
- `ADMIN_RP_ORIGINS=https://admin.ahoj420.eu,https://ahoj420.eu` (optional; explicit WebAuthn origins for admin auth)
- `ADMIN_SESSION_IDLE_MINUTES=30` (optional, default `30`)
- `ADMIN_SESSION_ABSOLUTE_HOURS=12` (optional, default `12`)
- retention cleanup:
  - `ADMIN_AUDIT_RETENTION_DAYS=180` (optional; empty uses default `180`, `<=0` disables cleanup for `admin_audit_log`)
  - `USER_SECURITY_EVENTS_RETENTION_DAYS=180` (optional; empty uses default `180`, `<=0` disables cleanup for `user_security_events`)
  - `RETENTION_DELETE_BATCH_SIZE=1000` (optional batch delete size for cleanup command)
- token fallback (optional emergency mode, disabled by default):
  - `ADMIN_API_TOKEN_ENABLED=true|false` (default `false`)
  - `ADMIN_API_TOKEN=<long-random-shared-secret>` (required only when token fallback is enabled)

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
│   ├── adminauth/           # Admin passkey auth + session middleware
│   ├── adminui/             # Server-rendered admin HTML UI
│   ├── oidc/                # OIDC provider
│   ├── store/               # Postgres access
│   └── cache/               # Redis access
├── web/
│   ├── static/js/glue.js    # navigator.credentials glue
│   └── templates/           # main templates + admin templates
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

## Admin Auth + Admin OIDC API (MVP)
Internal-only admin surface. Not a public self-service API.

Admin auth endpoints (`/admin/auth`):
- `POST /admin/auth/register/begin`
- `POST /admin/auth/register/finish`
- `POST /admin/auth/login/begin`
- `POST /admin/auth/login/finish`
- `POST /admin/auth/invite/register/begin` (public invite accept begin)
- `POST /admin/auth/invite/register/finish` (public invite accept finish)
- `POST /admin/auth/reauth/begin`
- `POST /admin/auth/reauth/finish`
- `POST /admin/auth/passkeys/register/begin` (logged-in admin adds extra passkey)
- `POST /admin/auth/passkeys/register/finish` (logged-in admin adds extra passkey)
- `POST /admin/auth/logout`

Admin OIDC client endpoints (`/admin/api/oidc/clients`):
- `GET /admin/api/oidc/clients`
- `GET /admin/api/oidc/clients/:id`
- `POST /admin/api/oidc/clients`
- `PUT /admin/api/oidc/clients/:id`
- `PUT /admin/api/oidc/clients/:id/redirect-uris`
- `POST /admin/api/oidc/clients/:id/secrets`
- `POST /admin/api/oidc/clients/:id/secrets/:secretID/revoke`

Admin HTML UI routes (`/admin/*`):
- `GET /admin/login`
- `GET /admin/invite`
- `GET /admin/invite/:token`
- `POST /admin/logout`
- `GET /admin/`
- `GET /admin/audit`
- `GET /admin/security`
- `GET /admin/users`
- `GET /admin/users/:id`
- `POST /admin/users/:id/block`
- `POST /admin/users/:id/unblock`
- `POST /admin/users/:id/sessions/logout-all`
- `POST /admin/users/:id/sessions/:sessionID/logout`
- `POST /admin/users/:id/passkeys/:credentialID/revoke`
- `GET /admin/admins`
- `GET /admin/admins/new`
- `POST /admin/admins/new`
- `GET /admin/admins/:id`
- `POST /admin/admins/:id/invites`
- `POST /admin/admins/:id/invites/:inviteID/revoke`
- `POST /admin/admins/:id/enable`
- `POST /admin/admins/:id/disable`
- `POST /admin/admins/:id/role`
- `GET /admin/clients`
- `GET /admin/clients/new`
- `POST /admin/clients/new`
- `GET /admin/clients/:id`
- `GET /admin/clients/:id/edit`
- `POST /admin/clients/:id/edit`
- `GET /admin/clients/:id/redirect-uris`
- `POST /admin/clients/:id/redirect-uris`
- `GET /admin/clients/:id/secrets/new`
- `POST /admin/clients/:id/secrets`
- `POST /admin/clients/:id/secrets/:secretID/revoke`
- `POST /admin/security/passkeys/:id/delete`
- `POST /admin/security/sessions/:id/logout`
- `POST /admin/security/sessions/logout-others`

Authentication and protection:
- primary auth for `/admin/api/*` is `admin_session` cookie (HttpOnly, Secure, SameSite=Strict)
- session auth is passkey-only (`/admin/auth/login/*`), separate from regular user sessions
- admin HTML UI (`/admin/*`) is session-only and always redirects unauthenticated users to `/admin/login`
- admin HTML UI mutating routes (`POST /admin/logout`, `POST /admin/clients/*`, `POST /admin/users/*`, `POST /admin/security/*`, `POST /admin/admins/*`) require CSRF token validation
  - server issues `admin_csrf` cookie (Secure, HttpOnly, SameSite=Strict)
  - server-rendered forms send hidden `csrf_token` and invalid/missing token returns `403 invalid csrf token`
  - CSRF middleware is scoped to authenticated `/admin/*` UI routes and does not apply to `/admin/auth/*` WebAuthn endpoints
- host guard: admin routes are served only on `ADMIN_API_HOST` (wrong host returns `404`)
- dedicated rate limit on admin routes (`429` on exceed)
- legacy bearer token fallback is optional and controlled by `ADMIN_API_TOKEN_ENABLED`
- token fallback is not used for HTML UI routes

Overview dashboard (`GET /admin/`):
- read-only operational landing page after login
- shows compact summaries and recent activity:
  - OIDC client totals/state
  - recent audit activity preview
  - recent failures preview (separate block)
  - recent OIDC client change events
- owner-only blocks:
  - admin users summary (owners/admins/invites)
  - pending active invites list

Bootstrap first admin:
1. Set `ADMIN_BOOTSTRAP_LOGIN`.
2. When there are no admin users/credentials, call `POST /admin/auth/register/begin`.
3. Complete passkey attestation via `POST /admin/auth/register/finish`.
4. Bootstrap closes automatically after first admin credential exists.

Security behavior:
- secret hashes and plaintext secrets are never returned from list/detail endpoints
- `plain_secret` is returned one-time only in `POST .../secrets` when `generate=true`
- generated secret in HTML UI is shown one-time on the immediate success page and never persisted for later reads
- admin audit viewer (`GET /admin/audit`) is read-only and redacts sensitive keys from rendered `details_json`
- admin security page (`GET /admin/security`) is read-only for inventory and CSRF-protected for all mutations
  - admin can add a second passkey while already logged in (`/admin/auth/passkeys/register/*`)
  - last remaining admin passkey cannot be deleted
  - admin can sign out one session or all other sessions
- users support section (`GET /admin/users`, `GET /admin/users/:id`) is available to both `owner` and `admin`
  - mostly read-only support view (search/list/detail)
  - no profile editing, no user deletion, no impersonation
  - user detail now includes a read-only `Recent security events` timeline
    - compact user-scoped timeline with event time, label, status, actor, and safe details
    - category filter: `all|auth|recovery|passkey|session|admin` (`?events=...`; `passkeys/sessions` aliases also accepted)
    - primary source: structured `user_security_events`
    - fallback source (when structured stream is empty): linked client activity (`first_seen_at`, `last_seen_at`)
    - sensitive fields are stripped in storage and render path (`token/secret/password/authorization/challenge/assertion`)
  - safe support mutations:
    - block user (`POST /admin/users/:id/block`)
    - unblock user (`POST /admin/users/:id/unblock`)
    - logout one user session (`POST /admin/users/:id/sessions/:sessionID/logout`)
    - logout all user sessions (`POST /admin/users/:id/sessions/logout-all`)
    - revoke one user passkey (`POST /admin/users/:id/passkeys/:credentialID/revoke`)
    - block/unblock requires recent re-auth and CSRF
    - blocking user invalidates all active user sessions
    - blocked user cannot start new login/recovery and cannot continue session-backed auth flows
    - blocked status is visible in users list/detail (`active`/`blocked`, blocked_at/reason/blocked_by)
  - support mutations are audited:
    - `admin.user.block.success|failure`
    - `admin.user.unblock.success|failure`
    - `admin.user.session.logout.success|failure`
    - `admin.user.session.logout_all.success|failure`
    - `admin.user.passkey.revoke.success|failure`
  - support mutations are also mirrored into `user_security_events` for user-scoped timeline continuity
- multi-admin model:
  - admins are separate users in `admin_users`
  - roles: `owner`, `admin` (stored in `admin_users.role`)
  - owner-only admin-management actions: create admin, admin detail, invite create/revoke, enable/disable, role change
  - logged-in owner can create another admin user and generate one-time invite
  - invite token plaintext is shown only once on immediate success page (never stored in plaintext)
  - invite accept flow (`/admin/invite/*` + `/admin/auth/invite/register/*`) registers first passkey for invited admin
  - invite is one-time (`used_at`), revoked/expired/used invites are blocked
  - invite flow is blocked when target admin already has credentials
  - new admins are created as `admin` by default; promotion/demotion is done on admin detail page
  - system always keeps at least one enabled owner:
    - last enabled owner cannot be demoted to `admin`
    - last enabled owner cannot be disabled
  - disabling admin blocks future login and invalidates active admin sessions for that user
  - overview dashboard is role-aware:
    - `owner` sees pending invites and full admin summary
    - `admin` sees OIDC/audit/failures/client-change blocks only
- sensitive admin actions require recent passkey re-authentication (`/admin/auth/reauth/*`)
  - recent re-auth timestamp is kept in admin session (`recent_auth_at_utc`)
  - TTL is controlled by `ADMIN_REAUTH_TTL_MINUTES` (default `5`)
  - sensitive actions include:
    - create confidential OIDC client
    - disable OIDC client
    - add/revoke OIDC secret
    - delete admin passkey
    - logout other admin sessions
    - block user
    - unblock user
    - logout all user sessions
    - revoke user passkey
  - missing/expired recent re-auth returns `403` with message `recent admin re-auth required` (JSON code `admin_reauth_required`)
- successful mutating admin operations trigger OIDC runtime client reload immediately (no restart required)
- if DB mutation succeeds but runtime reload fails, endpoint returns `500` and requires operator action
- admin requests include `X-Request-ID`

Structured user security event store:
- table: `user_security_events`
- key fields: `user_id`, `created_at`, `event_type`, `category`, `success`, `actor_type`, `actor_id`, `session_id`, `credential_id`, `client_id`, `remote_ip`, `details_json`
- currently written event types:
  - auth: `login_success`, `login_failure`
  - recovery: `recovery_requested`, `recovery_success`, `recovery_failure`
  - session: `session_created`, `session_revoked`, `session_logout_all`
  - passkey: `passkey_added`, `passkey_revoked`
  - account/admin: `account_blocked`, `account_unblocked`

Retention cleanup for event tables:
- target tables:
  - `admin_audit_log`
  - `user_security_events`
- cleanup condition: rows with `created_at < cutoff_utc` are eligible for deletion
- cleanup is batched (`DELETE ... LIMIT N`) to avoid giant table locks/transactions
- per-table retention can be disabled independently by setting retention days to `<=0`
- dry-run mode computes eligible rows and logs summary without deleting
- selective cleanup:
  - `--admin-audit-only` processes only `admin_audit_log`
  - `--user-security-only` processes only `user_security_events`
  - if both flags are provided, both tables are processed
- command examples:
  - dry-run: `./server cleanup-retention --dry-run`
  - env-driven dry-run mode: `MODE=cleanup-retention DRY_RUN=1 ./server`
  - only audit: `./server cleanup-retention --admin-audit-only`
  - only user security events: `./server cleanup-retention --user-security-only --dry-run`
  - optional batch override: `./server cleanup-retention --batch-size 500`
- Docker/Compose one-shot example:
  - `docker compose --env-file .env exec -T backend /usr/local/bin/ahoj420 cleanup-retention --dry-run`
- cron example:
  - `15 3 * * * cd /home/sss/AHOJ420 && docker compose --env-file .env exec -T backend /usr/local/bin/ahoj420 cleanup-retention >> /var/log/ahoj420-retention.log 2>&1`
- systemd timer note:
  - run `cleanup-retention` as a periodic one-shot service (daily/weekly) with logs routed to journald
- operational note:
  - batched `DELETE` reduces lock pressure, but PostgreSQL still needs normal `VACUUM/autovacuum` work after large cleanup runs
  - application does not execute `VACUUM` automatically; keep this in regular DB operations

Audit:
- mutating admin actions are persisted in PostgreSQL `admin_audit_log` and app logs
- actor identity is explicit:
  - `actor_type=admin_user`, `actor_id=<admin_user_id>` for session-based admin actions
  - `actor_type=token`, `actor_id=admin_api_token` for optional token fallback
