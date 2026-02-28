# Admin UI (MVP)

Internal server-rendered admin panel for OIDC client management.

## Scope
- host-guarded (`ADMIN_API_HOST`)
- session-only auth (`admin_session` cookie)
- CSRF-protected mutating HTML routes (`admin_csrf` cookie + hidden `csrf_token` form field)
- overview dashboard (`GET /admin/`) with role-aware operational summary
- users support section (`/admin/users`) for end-user lookup and security actions
- passkey login via `/admin/auth/login/*`
- admin self-security page (`/admin/security`) for passkeys + sessions
- step-up re-auth for sensitive actions (recent passkey assertion required)
- multi-admin management (`/admin/admins`) with one-time invite onboarding
- no token fallback for browser UI routes
- no dynamic registration / no self-service onboarding

## Routes
Public:
- `GET /admin/login`
- `GET /admin/invite/:token`

Protected (admin session required):
- `GET /admin/`
- `GET /admin/audit`
- `GET /admin/security`
- `GET /admin/users`
- `GET /admin/users/:id`
- `GET /admin/users/:id/delete`
- `POST /admin/users/:id/delete`
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
- `POST /admin/logout`
- `POST /admin/security/passkeys/:id/delete`
- `POST /admin/security/sessions/:id/logout`
- `POST /admin/security/sessions/logout-others`
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

## CSRF protection (HTML UI)
- applied only to authenticated admin UI routes under `/admin/*` (protected group)
- not applied to `/admin/auth/*` WebAuthn login/register flows
- mutating UI routes require valid synchronizer token and fail with `403 invalid csrf token` on mismatch/missing token
- token generation:
  - cryptographically random token is generated server-side (`admin_csrf`, Secure, HttpOnly, SameSite=Strict, Path=/admin)
  - token is injected into templates via shared `layoutData.CSRFToken`
  - all mutating forms include `<input type="hidden" name="csrf_token" ...>`

## Overview Dashboard (`GET /admin/`)
- read-only operational landing page with compact blocks:
  - summary cards (OIDC client state totals)
  - recent audit activity preview
  - recent failures preview (separate from full audit stream)
  - recent client-related audit changes (`admin.oidc_client*`)
- owner-only on dashboard:
  - admin users summary cards (total/enabled/owner/admin/invites)
  - pending active invites list (with links to admin detail)
- non-owner admin still sees:
  - OIDC summary
  - recent audit
  - recent failures
  - recent client changes

## Step-up re-authentication
- endpoints:
  - `POST /admin/auth/reauth/begin`
  - `POST /admin/auth/reauth/finish`
- re-auth state is stored in admin session record as `recent_auth_at_utc`
- default TTL for recent re-auth is `5m` (`ADMIN_REAUTH_TTL_MINUTES`, default `5`)
- sensitive actions require fresh re-auth and return `403` when missing/expired (`recent admin re-auth required`, code `admin_reauth_required` for JSON requests)
- sensitive actions covered:
  - create confidential OIDC client
  - disable OIDC client
  - add OIDC client secret
  - revoke OIDC client secret
  - delete admin passkey
  - logout other admin sessions
  - block end-user account (`POST /admin/users/:id/block`)
  - unblock end-user account (`POST /admin/users/:id/unblock`)
  - revoke end-user passkey (`POST /admin/users/:id/passkeys/:credentialID/revoke`)
  - logout all end-user sessions (`POST /admin/users/:id/sessions/logout-all`)
  - hard-delete end-user (`POST /admin/users/:id/delete`)
- audit actions:
  - `admin.auth.reauth.success`
  - `admin.auth.reauth.failure`

## Multi-admin + Invite flow
- multiple separate `admin_users` are supported (not just multiple passkeys for one user)
- minimal RBAC roles:
  - `owner`
  - `admin`
- owner-only actions:
  - `GET /admin/admins`
  - `GET /admin/admins/new`
  - `POST /admin/admins/new`
  - `GET /admin/admins/:id`
  - `POST /admin/admins/:id/invites`
  - `POST /admin/admins/:id/invites/:inviteID/revoke`
  - `POST /admin/admins/:id/enable`
  - `POST /admin/admins/:id/disable`
  - `POST /admin/admins/:id/role`
- `admin` role can still use allowed features:
  - OIDC clients UI
  - audit viewer
  - own security page/logout/passkeys/sessions
- create admin flow:
  - `POST /admin/admins/new` creates a new admin user and an invite
  - new admin users are created with role `admin` by default
  - plaintext invite token/link is shown only on immediate success page
  - plaintext token is not stored in DB, only `token_hash` in `admin_invites`
- invite accept flow:
  - `POST /admin/auth/invite/register/begin?token=...`
  - `POST /admin/auth/invite/register/finish?token=...`
  - invite is one-time (`used_at` set on success), revoked/expired/used invites are rejected
  - invite flow is for admin users without credentials; if credentials already exist, flow is blocked
- admin detail actions:
  - create/revoke invite
  - enable/disable admin user
  - change role (`admin` <-> `owner`)
  - disable invalidates all active sessions of that admin user
  - protections:
    - last enabled owner cannot be disabled
    - last enabled owner cannot be demoted
- audit actions:
  - `admin.user.create.success|failure`
  - `admin.user.enable.success|failure`
  - `admin.user.disable.success|failure`
  - `admin.user.role_change.success|failure`
  - `admin.invite.create.success|failure`
  - `admin.invite.revoke.success|failure`
  - `admin.invite.accept.success|failure`

## Admin security page (`/admin/security`)
- passkeys:
  - lists current admin credentials (safe display ID + metadata)
  - add passkey flow for logged-in admin via:
    - `POST /admin/auth/passkeys/register/begin`
    - `POST /admin/auth/passkeys/register/finish`
  - delete passkey via CSRF-protected form
  - last remaining passkey cannot be deleted
- sessions:
  - lists active admin sessions from session state store (created/last_seen/expires/ip/user-agent/current)
  - sign out one session (including current session)
  - sign out all other sessions (current remains)
- audit actions emitted:
  - `admin.auth.passkey.add.success|failure`
  - `admin.auth.passkey.delete.success|failure`
  - `admin.auth.session.logout.success|failure`
  - `admin.auth.session.logout_others.success|failure`

## Users support section (`/admin/users`)
- access:
  - available to `owner` and `admin`
  - requires admin session + host guard
- list page (`GET /admin/users`):
  - search by user id / profile email / phone / login id
  - paginated table with:
    - id
    - profile email / phone
    - created_at
    - verified flags
    - passkey count
    - active session count
    - linked client count
    - status badge (`active` / `blocked`)
- detail page (`GET /admin/users/:id`):
  - summary (id, created_at, profile contacts + verification, avatar presence, blocked status/metadata)
  - recent security events timeline (read-only, user-scoped):
    - latest security/auth/support events with time, label, status, actor, safe details
    - category filter via query param: `?events=all|auth|recovery|passkey|session|admin` (`passkeys/sessions` aliases are accepted)
    - primary source of truth: `user_security_events` (structured events)
    - fallback source (only when no structured events exist): linked OIDC client activity (`first_seen_at`, `last_seen_at`)
  - passkeys list (credential id, label, created_at, last_used_at)
  - active sessions list (session id, created_at, last_seen_at, expires_at, ip, user-agent)
  - linked OIDC clients list (client id, first_seen_at, last_seen_at)
- allowed support actions (mutating, audited):
  - `GET /admin/users/:id/delete` (owner-only confirmation page)
  - `POST /admin/users/:id/delete`
    - owner-only
    - requires recent re-auth
    - requires explicit confirmation phrase: `DELETE <user-id>`
    - performs hard delete (no soft delete/restore)
    - runs full session cleanup (`sess:*`, `recovery:*`, `sessmeta:*`, `sesslist:*`, `sessall:*`, `sessdev:*`)
    - audit: `admin.user.delete.success|failure`
    - partial failures (DB delete succeeded but session cleanup failed) are surfaced as operator-visible errors
  - `POST /admin/users/:id/block`
    - requires recent re-auth
    - requires reason
    - invalidates all active user sessions
    - audit: `admin.user.block.success|failure`
  - `POST /admin/users/:id/unblock`
    - requires recent re-auth
    - audit: `admin.user.unblock.success|failure`
  - `POST /admin/users/:id/sessions/:sessionID/logout`
    - audit: `admin.user.session.logout.success|failure`
  - `POST /admin/users/:id/sessions/logout-all`
    - requires recent re-auth
    - audit: `admin.user.session.logout_all.success|failure`
  - `POST /admin/users/:id/passkeys/:credentialID/revoke`
    - requires recent re-auth
    - audit: `admin.user.passkey.revoke.success|failure`
- security posture:
  - all mutating routes are CSRF-protected by existing admin UI CSRF middleware
  - section is mostly read-only (no profile editing, no impersonation)
  - hard-delete is available only to `owner` and requires step-up re-auth + explicit confirmation phrase
  - timeline details are sanitized in storage + render path (secret/token/password/authorization/challenge/assertion fields are removed)

## Structured user security events
- PostgreSQL table: `user_security_events`
- key columns:
  - `user_id`, `created_at`, `event_type`, `category`, `success`
  - `actor_type`, `actor_id`
  - `session_id`, `credential_id`, `client_id`, `remote_ip`
  - `details_json` (safe metadata only)
- events currently written from real flows:
  - auth: `login_success`, `login_failure`
  - recovery: `recovery_requested`, `recovery_success`, `recovery_failure`
  - session: `session_created`, `session_revoked`, `session_logout_all`
  - passkey: `passkey_added`, `passkey_revoked`
  - account/admin actions: `account_blocked`, `account_unblocked`
- admin support actions are mirrored into user timeline events (in addition to `admin_audit_log`):
  - block user
  - unblock user
  - logout one session
  - logout all sessions
  - revoke user passkey

## One-time secret reveal
When creating a secret with `Generate secret automatically`:
- plaintext secret is shown only in immediate success response page
- plaintext is not stored in PostgreSQL
- plaintext is not written to audit log
- plaintext is not available via list/detail API/UI later

## Audit + Reload
All mutating UI actions:
- persist an entry in `admin_audit_log`
- call OIDC runtime client reload (`ReloadClients`) after DB commit
- if reload fails after DB update, action returns error and requires operator attention

Audit viewer (`GET /admin/audit`):
- read-only table with time/action/result/actor/resource/request/ip
- filter by `action`, `success`, `actor`, `resource_id`
- paginated
- `details_json` can be expanded per row and sensitive keys are redacted before render

## Templates
- `web/templates/admin/layout.html`
- `web/templates/admin/login.html`
- `web/templates/admin/index.html`
- `web/templates/admin/audit.html`
- `web/templates/admin/security.html`
- `web/templates/admin/users_list.html`
- `web/templates/admin/user_detail.html`
- `web/templates/admin/user_delete.html`
- `web/templates/admin/admins_list.html`
- `web/templates/admin/admin_new.html`
- `web/templates/admin/admin_detail.html`
- `web/templates/admin/admin_invite_created.html`
- `web/templates/admin/invite_accept.html`
- `web/templates/admin/invite_invalid.html`
- `web/templates/admin/clients_list.html`
- `web/templates/admin/client_detail.html`
- `web/templates/admin/client_new.html`
- `web/templates/admin/client_edit.html`
- `web/templates/admin/client_redirect_uris.html`
- `web/templates/admin/secret_new.html`
- `web/templates/admin/secret_created.html`
