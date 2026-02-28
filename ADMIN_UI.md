# Admin UI (MVP)

Internal server-rendered admin panel for OIDC client management.

## Scope
- host-guarded (`ADMIN_API_HOST`)
- session-only auth (`admin_session` cookie)
- passkey login via `/admin/auth/login/*`
- no token fallback for browser UI routes
- no dynamic registration / no self-service onboarding

## Routes
Public:
- `GET /admin/login`

Protected (admin session required):
- `GET /admin/`
- `POST /admin/logout`
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

## Templates
- `web/templates/admin/layout.html`
- `web/templates/admin/login.html`
- `web/templates/admin/index.html`
- `web/templates/admin/clients_list.html`
- `web/templates/admin/client_detail.html`
- `web/templates/admin/client_new.html`
- `web/templates/admin/client_edit.html`
- `web/templates/admin/client_redirect_uris.html`
- `web/templates/admin/secret_new.html`
- `web/templates/admin/secret_created.html`
