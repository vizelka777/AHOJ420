# OIDC Technical Guide (Ahoj420 + zitadel/oidc)

## Endpoints
- Discovery: `/.well-known/openid-configuration`
- Authorize: `/authorize`
- Authorize callback: `/authorize/callback`
- Token (native): `/oauth/token`
- Token (compat alias): `/token`
- JWKS (native): `/keys`
- JWKS (compat alias): `/jwks`
- UserInfo: `/userinfo`
- SSO logout: `/logout` (and `/end_session`)
- Admin auth (internal): `/admin/auth/*`
- Admin API (internal): `/admin/api/oidc/clients`
- Admin UI (internal): `/admin/*`

## Runtime Modes
Environment variable: `AHOJ_ENV=dev|prod` (default `dev`).

### prod requirements (startup fails if missing)
- `OIDC_PRIVKEY_PATH` must exist and contain an RSA private key.
- `OIDC_CRYPTO_KEY` must be set and length >= 32 bytes.
- OIDC clients DB registry must be initialized (`oidc_clients` is runtime source of truth).
- For one-time bootstrap when DB is empty:
  - `OIDC_CLIENTS_BOOTSTRAP=1`
  - `OIDC_CLIENTS_JSON` or `OIDC_CLIENTS_FILE`
- `AVATAR_PUBLIC_BASE` must be set (used for OIDC `picture` claim URL).

### dev behavior
- If signing key is missing/invalid, an ephemeral RSA key is generated.
- If `OIDC_CRYPTO_KEY` is missing/short, an ephemeral key is generated.
- Both are explicitly logged as DEV-only and invalidate tokens/cookies after restart.
- If OIDC clients DB is empty:
  - with `OIDC_CLIENTS_JSON` / `OIDC_CLIENTS_FILE`: bootstrap import to DB
  - without bootstrap source: built-in dev clients are imported to DB

## OIDC State Persistence (Redis)
In-memory OIDC state was removed for auth requests/codes.

Redis keys:
- `oidc:ar:<id>` -> serialized auth request (`TTL 10m`)
- `oidc:code:<code>` -> auth request id (`TTL 10m`)
- `oidc:ar_code:<id>` -> last issued auth code for request (`TTL 10m`)

Used by storage methods:
- `CreateAuthRequest` -> write `oidc:ar:<id>`
- `AuthRequestByID` -> read `oidc:ar:<id>`
- `SaveAuthCode` -> write `oidc:code:<code>`
- `AuthRequestByCode` -> resolve code to auth request id and load request
- `DeleteAuthRequest` -> delete `oidc:ar:<id>`
- `SetAuthRequestDone` -> update persisted auth request (`subject`, `done`, `auth_time`)

## Client Registry (PostgreSQL)
Runtime clients are loaded from DB tables:

- `oidc_clients` (metadata + auth mode + grant/response/scopes + enabled flag)
- `oidc_client_redirect_uris` (1:N redirect URIs)
- `oidc_client_secrets` (hashed secrets with revocation metadata)

Runtime behavior:
- OIDC provider keeps an in-process runtime snapshot for fast client lookup.
- Admin mutating endpoints trigger explicit runtime reload from DB.
- Reload is atomic (new snapshot replaces old one only after full successful build).

`OIDC_CLIENTS_JSON` / `OIDC_CLIENTS_FILE` are bootstrap-only import sources for empty DB.

Bootstrap JSON shape:

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

Fields:
- `id` (required)
- `name` (optional)
- `enabled` (optional, default `true`)
- `redirect_uris` (required)
- `confidential` (required)
- `secrets` (required only for confidential clients)
- `require_pkce` (recommended true for all code clients)
- `auth_method`: `none|basic|post`
- `grant_types`: e.g. `authorization_code`
- `response_types`: e.g. `code`
- `scopes`: e.g. `openid profile email phone` (defaults to these scopes if omitted)

Bootstrap behavior:
- If DB is non-empty: bootstrap env is ignored (no overwrite).
- If DB is empty:
  - `prod`: requires both `OIDC_CLIENTS_BOOTSTRAP=1` and JSON/file source
  - `dev`: bootstrap source is optional (dev defaults are imported when source is missing)

Secret storage:
- plaintext secrets are accepted only at bootstrap / secret creation time
- DB stores only `secret_hash` (bcrypt)
- confidential clients can have multiple active secrets for rotation
- revoked secrets (`revoked_at IS NOT NULL`) are rejected by runtime verification

## Claims in ID Token and /userinfo
Mapping from `users` table:
- `sub` -> `users.id`
- `name` -> `users.display_name`
- `preferred_username` -> `users.display_name`
- `email` -> `users.profile_email`
- `email_verified` -> `users.email_verified`
- `phone_number` -> `users.phone` (only when non-empty)
- `phone_number_verified` -> `users.phone_verified` (only when phone is present)
- `picture` -> `AVATAR_PUBLIC_BASE + users.avatar_key + "?v=<avatar_updated_at_unix>"` (only when avatar exists)

Terminology note:
- `users.email` is a legacy column name kept for backward compatibility and acts as an internal login identifier.
- user-facing contact email is `users.profile_email`.

Scope-based emission:
- `profile` -> `name`, `preferred_username`, `picture`
- `email` -> `email`, `email_verified`
- `phone` -> `phone_number`, `phone_number_verified`

Avatar upload endpoint:
- `POST /auth/avatar` (authenticated via `user_session`)
- input: multipart `file` (jpg/png/webp, max 2 MB)
- server normalizes to `256x256` webp and uploads to Bunny Storage
- DB updates:
  - `users.avatar_key`
  - `users.avatar_updated_at`
  - `users.avatar_mime`
  - `users.avatar_bytes`

Required upload env:
- `BUNNY_STORAGE_ENDPOINT` (default `storage.bunnycdn.com`)
- `BUNNY_STORAGE_ZONE`
- `BUNNY_STORAGE_ACCESS_KEY`

## PKCE Enforcement
For clients with `require_pkce=true`:
- `/authorize` request is rejected when `code_challenge` is missing.
- `/authorize` request is rejected when `code_challenge_method` is not `S256`.

`/token` verification of `code_verifier` vs `code_challenge` is enforced by the OIDC library.

## Authorize + Session Flow
1. Client calls `/authorize?...`.
2. If `user_session` exists, `user_id` is injected into request context and provider can complete auth request immediately.
3. If no session, provider redirects to login UI. Server stores `oidc_auth_request` cookie (`HttpOnly`, `Secure`, `SameSite=Lax`, `MaxAge=300`).
4. After WebAuthn login, server calls `SetAuthRequestDone(auth_request_id, user_id)` and returns redirect `/authorize/callback?id=<id>`.
5. Client receives `code`, exchanges at `/oauth/token` (or `/token`).

## WebAuthn Registration Session
Registration no longer uses `user_id` cookie.

Now:
- Cookie: `reg_session_id` (`HttpOnly`, `Secure`, `SameSite=Lax`, `MaxAge=300`)
- Redis: `reg:<reg_session_id>` -> `{user_id, webauthn_session}` (`TTL 5m`)
- Finish registration:
  - loads Redis entry
  - deletes `reg:<id>`
  - clears `reg_session_id` cookie

`login_session_id` cookie now also has `SameSite=Lax` and `MaxAge=300`.

## Production Checklist
- Redis reachable and persistent enough for OIDC request/code TTLs.
- `AHOJ_ENV=prod`.
- `OIDC_PRIVKEY_PATH` mounted read-only.
- `OIDC_CRYPTO_KEY` set (32+ bytes).
- OIDC clients present in DB (`oidc_clients` not empty).
- First bootstrap executed explicitly with `OIDC_CLIENTS_BOOTSTRAP=1` + JSON/file.
- Bootstrap env removed from steady-state runtime profile after initial import.
- Public clients use `auth_method=none` + `require_pkce=true`.

## Bunny BFF client example
```json
[
  {
    "id": "mushroom-bff",
    "redirect_uris": ["https://api.houbamzdar.cz/auth/callback"],
    "confidential": true,
    "require_pkce": true,
    "auth_method": "basic",
    "grant_types": ["authorization_code", "refresh_token"],
    "response_types": ["code"],
    "scopes": ["openid", "profile", "email", "phone"]
  }
]
```

Secret for `mushroom-bff` is read from `OIDC_CLIENT_MUSHROOM_BFF_SECRET` during bootstrap when `secrets` is not present in client config.

## Admin Auth + Admin API (MVP, Internal)
This surface is intended only for owner/internal admin usage.

Admin auth data model:
- `admin_users` table: separate admin identities (`login`, `enabled`, metadata)
- `admin_credentials` table: separate admin WebAuthn credentials
- `admin_session` is stored in Redis namespace `admin:sess:*` (separate from user session keys)

Configuration:
- `ADMIN_API_HOST` is mandatory for serving `/admin/*` (if empty, admin routes return `503`)
- bootstrap first admin login via `ADMIN_BOOTSTRAP_LOGIN` (one-time only; should be removed/empty after initial bootstrap)
- optional explicit admin WebAuthn origins via `ADMIN_RP_ORIGINS` (comma-separated)
- admin session TTL:
  - `ADMIN_SESSION_IDLE_MINUTES` (default `30`)
  - `ADMIN_SESSION_ABSOLUTE_HOURS` (default `12`)
- optional legacy token fallback:
  - `ADMIN_API_TOKEN_ENABLED=true|false` (default `false`)
  - `ADMIN_API_TOKEN` (required only when token fallback is enabled)

Authentication and perimeter:
- primary auth for `/admin/api/*` is `admin_session` cookie (HttpOnly, Secure, SameSite=Strict)
- admin login is passkey-only via `/admin/auth/login/*`
- host guard enforces `ADMIN_API_HOST` (`404` on wrong host)
- dedicated rate limit for `/admin/auth/*`, `/admin/api/*`, and `/admin/*` HTML UI routes
- token fallback is optional; when enabled it is accepted only if no valid admin session actor is present

Bootstrap and login routes:
- `POST /admin/auth/register/begin` (bootstrap only)
- `POST /admin/auth/register/finish` (bootstrap only)
- `POST /admin/auth/login/begin`
- `POST /admin/auth/login/finish`
- `POST /admin/auth/logout`

OIDC client admin routes:
- `GET /admin/api/oidc/clients`
- `GET /admin/api/oidc/clients/:id`
- `POST /admin/api/oidc/clients`
- `PUT /admin/api/oidc/clients/:id`
- `PUT /admin/api/oidc/clients/:id/redirect-uris`
- `POST /admin/api/oidc/clients/:id/secrets`
- `POST /admin/api/oidc/clients/:id/secrets/:secretID/revoke`

Admin UI routes:
- `GET /admin/login`
- `POST /admin/logout`
- `GET /admin/`
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

Behavior notes:
- API returns only safe secret metadata (`id`, `label`, `created_at`, `revoked_at`, `status`)
- plaintext/hash of existing secrets are never returned
- add-secret endpoint supports generated secret mode (`generate=true`) and returns one-time `plain_secret` only in that creation response
- HTML UI add-secret flow supports generated secret mode and shows one-time reveal page only in immediate response
- for MVP, changing `confidential` flag via update endpoint is blocked (`409`) to avoid unsafe transitions
- successful mutating operations reload OIDC runtime clients immediately from DB (no restart required)
- reload is all-or-nothing: if reload fails, previous runtime snapshot remains active
- when DB mutation succeeds but reload fails, endpoint returns `500` with explicit runtime reload failure message
- admin requests get `X-Request-ID`; this id is included in audit records
- HTML UI uses admin session auth only; token fallback is never used for browser UI routes

Audit logging:
- mutating OIDC routes persist audit records in PostgreSQL table `admin_audit_log`
- mutating HTML UI routes persist the same audit actions in `admin_audit_log`
- auth events are also audited:
  - `admin.auth.register.success|failure`
  - `admin.auth.login.success|failure`
  - `admin.auth.logout`
- actor identity:
  - session-based admin actions -> `actor_type=admin_user`, `actor_id=<admin_user_id>`
  - token fallback actions -> `actor_type=token`, `actor_id=admin_api_token`
- OIDC mutation actions:
  - `admin.oidc_client.create`
  - `admin.oidc_client.update`
  - `admin.oidc_client.redirect_uris.replace`
  - `admin.oidc_client.secret.add`
  - `admin.oidc_client.secret.revoke`
- `details_json` is safe metadata only (no plaintext secret, no `secret_hash`, no auth header).
