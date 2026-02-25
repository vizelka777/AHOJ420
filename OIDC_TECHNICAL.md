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

## Runtime Modes
Environment variable: `AHOJ_ENV=dev|prod` (default `dev`).

### prod requirements (startup fails if missing)
- `OIDC_PRIVKEY_PATH` must exist and contain an RSA private key.
- `OIDC_CRYPTO_KEY` must be set and length >= 32 bytes.
- One client config source must be provided:
  - `OIDC_CLIENTS_JSON`, or
  - `OIDC_CLIENTS_FILE`
- `AVATAR_PUBLIC_BASE` must be set (used for OIDC `picture` claim URL).

### dev behavior
- If signing key is missing/invalid, an ephemeral RSA key is generated.
- If `OIDC_CRYPTO_KEY` is missing/short, an ephemeral key is generated.
- Both are explicitly logged as DEV-only and invalidate tokens/cookies after restart.

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

## Client Configuration
Clients are loaded from JSON (env string or file). Shape:

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

Fields:
- `id` (required)
- `redirect_uris` (required)
- `confidential` (required)
- `secrets` (required only for confidential clients)
- `require_pkce` (recommended true for all code clients)
- `auth_method`: `none|basic|post`
- `grant_types`: e.g. `authorization_code`
- `response_types`: e.g. `code`
- `scopes`: e.g. `openid profile email phone` (defaults to these scopes if omitted)

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
- Clients configured via JSON/file; public clients use `auth_method=none` + `require_pkce=true`.

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

Secret for `mushroom-bff` is read from `OIDC_CLIENT_MUSHROOM_BFF_SECRET` when `secrets` is not present in client config.
