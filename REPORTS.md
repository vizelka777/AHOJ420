# REPORTS

Журнал выполненных работ. Обновляется после каждого значимого изменения (разработка, коммит/пуш, деплой, хотфикс).

## 2026-02-28

### Retention Cleanup Hardening Follow-up
- Ветка: `админ`
- Статус: `implemented`, `tests_passed`

Сделано:
- Убран schema init side-effect из cleanup path:
  - `cleanup-retention` больше не читает и не исполняет `internal/store/schema.sql`
  - команда теперь только подключается к БД и запускает retention cleanup
- Добавлены selective flags:
  - `--admin-audit-only`
  - `--user-security-only`
  - оба флага одновременно => чистятся обе таблицы
- Добавлен env-driven dry-run для mode path:
  - `MODE=cleanup-retention DRY_RUN=1 ./server`
- Улучшен summary output:
  - per-table: `table`, `retention_days`, `cutoff`, `eligible_count`, `deleted_count`, `batches`, `dry_run`, `skipped`
  - final total: `tables_processed`, `tables_skipped`, `eligible_total`, `deleted_total`, `dry_run`
- Обновлён maintenance runner (`internal/maintenance/retention.go`):
  - селективная обработка таблиц
  - агрегированные totals в результате выполнения
  - явный `skipped` для отключённых retention table
- Обновлена документация (`README.md`):
  - примеры запуска dry-run/selective
  - docker compose one-shot пример
  - cron/systemd note
  - operational note про VACUUM/autovacuum после крупных cleanup-run

Тесты:
- `go test ./internal/maintenance ./cmd/server ./internal/store` — `ok`
- Добавлены/обновлены проверки:
  - selective cleanup (admin-only / user-only)
  - dry-run + selective (без delete и только выбранная таблица)
  - summary totals (processed/skipped/eligible/deleted)
  - regression check: cleanup command source не содержит schema init references
  - CLI options parse tests (flags + `DRY_RUN`)

### Retention / Cleanup Policy for Event Tables
- Ветка: `админ`
- Статус: `implemented`, `tests_passed`

Сделано:
- Добавлен retention cleanup для растущих event-таблиц:
  - `admin_audit_log`
  - `user_security_events`
- Добавлен store cleanup/read API:
  - `CountAdminAuditEntriesOlderThan(...)`
  - `DeleteAdminAuditEntriesOlderThan(...)`
  - `CountUserSecurityEventsOlderThan(...)`
  - `DeleteUserSecurityEventsOlderThan(...)`
- Добавлен maintenance сервис `internal/maintenance/retention.go`:
  - dry-run режим (только подсчёт eligible rows)
  - batched deletion (`DELETE` батчами, configurable batch size)
  - UTC cutoff (`created_at < cutoff`)
  - консистентные lifecycle logs:
    - `retention.cleanup.start`
    - `retention.cleanup.batch`
    - `retention.cleanup.done`
    - `retention.cleanup.error`
- Добавлен CLI entrypoint в `cmd/server/main.go`:
  - `./server cleanup-retention --dry-run`
  - `./server cleanup-retention`
  - optional: `--batch-size N`
  - также поддержан env-mode: `MODE=cleanup-retention`
- Добавлены env-настройки retention:
  - `ADMIN_AUDIT_RETENTION_DAYS`
  - `USER_SECURITY_EVENTS_RETENTION_DAYS`
  - `RETENTION_DELETE_BATCH_SIZE`
  - empty значение по retention days => default `180`
  - `<=0` => retention для конкретной таблицы отключён
- Добавлен индекс для глобального cleanup по времени в `user_security_events`:
  - `user_security_events_created_at_idx (created_at DESC)`
- Обновлена документация в `README.md` (env + запуск cleanup команд).

Тесты:
- `go test ./internal/maintenance ./internal/store ./cmd/server` — `ok`
- Добавлены unit tests:
  - count older-than cutoff
  - dry-run ничего не удаляет
  - batched delete удаляет порциями
  - disabled retention table skip
  - empty tables
  - cutoff boundary (`created_at == cutoff` не удаляется)

### Multi-admin MVP
- Ветка: `админ`
- Коммит: `d95c62f`
- Статус: `pushed`, `deployed`

Сделано:
- Добавлена MVP поддержка нескольких admin users.
- Реализован one-time invite flow для регистрации первого passkey нового админа.
- Добавлены UI страницы: список админов, создание админа, detail, invite pages.
- Добавлены store/schema изменения для `admin_invites`.
- Обновлены тесты (`internal/adminauth`, `internal/adminui`) и документация.

Деплой:
- Серверный `.env` обновлён из `/home/houbamydar/Desktop/AHOJ420.server.env`.
- Выполнен `docker compose up -d --build` на проде.
- Проверка после выката:
  - `https://admin.ahoj420.eu/admin/login` -> `200`
  - `https://ahoj420.eu/admin/login` -> `404`

### RBAC MVP (owner/admin)
- Ветка: `админ`
- Статус: `implemented`, `tests_passed`, `deployed`

Сделано:
- Добавлена минимальная RBAC-модель для `admin_users` с ролями `owner` и `admin`.
- Добавлено поле `role` в схему БД (`admin_users`) с ограничением допустимых значений.
- Обеспечено наличие минимум одного enabled owner (блокировки демоушена/disable последнего owner).
- Добавлены owner-only backend guards для раздела `/admin/admins*` и invite/admin-management действий.
- Добавлена смена роли на странице admin detail (`POST /admin/admins/:id/role`).
- В UI скрыт пункт `Admins` для обычного `admin`.
- Обновлены тесты `internal/adminui` и `internal/adminauth` под RBAC-поведение.
- Обновлена документация (`README.md`, `ADMIN_UI.md`).

Проверки:
- `go test ./internal/adminui ./internal/adminauth` (через dockerized Go) — `ok`.
- `go test ./...` (через dockerized Go) — `ok`.
- Прод после выката:
  - `https://admin.ahoj420.eu/admin/login` -> `200`
  - `https://ahoj420.eu/admin/login` -> `404`

### Overview Dashboard MVP
- Ветка: `админ`
- Статус: `implemented`, `tests_passed`

Сделано:
- Доработана landing page `GET /admin/` до операционного overview dashboard.
- Добавлены summary-блоки:
  - OIDC clients: total/enabled/disabled/confidential/public
  - Admin summary (owner-only): total/enabled/owners/admins/active invites/expired unused invites
- Добавлены preview-блоки:
  - recent audit activity
  - recent failures (отдельно)
  - recent OIDC client changes
  - pending invites (owner-only)
- Добавлены новые read-side методы store для invites summary/list:
  - `CountActiveAdminInvites`
  - `CountExpiredUnusedAdminInvites`
  - `ListActiveAdminInvites`
- Dashboard сделан role-aware:
  - owner видит owner-only блоки
  - non-owner эти блоки не видит
- Обновлены тесты dashboard в `internal/adminui/handler_test.go`.
- Обновлена документация (`README.md`, `ADMIN_UI.md`).

Проверки:
- `go test ./internal/adminui` (dockerized Go) — `ok`.
- `go test ./...` (dockerized Go) — `ok`.

### Users Support Section MVP
- Ветка: `админ`
- Статус: `implemented`, `tests_passed`

Сделано:
- Добавлен новый раздел `Users` в admin UI:
  - `GET /admin/users` (поиск + пагинация)
  - `GET /admin/users/:id` (карточка пользователя)
- Добавлены safe support actions:
  - `POST /admin/users/:id/sessions/:sessionID/logout`
  - `POST /admin/users/:id/sessions/logout-all`
  - `POST /admin/users/:id/passkeys/:credentialID/revoke`
- Для user detail реализованы блоки:
  - summary (id, profile email/phone, verified flags, avatar presence)
  - passkeys
  - active sessions
  - linked OIDC clients
- Добавлены store read-model методы:
  - `ListUsersForAdmin`
  - `GetUserProfileForAdmin`
- Добавлены adminauth методы для user session inventory/logout:
  - `CountActiveUserSessionsByUserIDs`
  - `ListUserSessionsForAdmin`
  - `LogoutUserSessionForAdmin`
  - `LogoutAllUserSessionsForAdmin`
- Подключены security guards:
  - CSRF на всех mutating `/admin/users/*` routes
  - recent re-auth на `logout-all` и `passkey revoke`
- Добавлены audit actions:
  - `admin.user.session.logout.success|failure`
  - `admin.user.session.logout_all.success|failure`
  - `admin.user.passkey.revoke.success|failure`
- Обновлена навигация: `Overview`, `Users`, `Clients`, `Audit log`, `Security`, `Admins` (owner-only), `Logout`.
- Обновлена документация: `ADMIN_UI.md`, `README.md`.

Проверки:
- `go test ./internal/adminui` (dockerized Go) — `ok`.
- `go test ./internal/adminauth` (dockerized Go) — `ok`.
- `go test ./...` (dockerized Go) — `ok`.

### User Security Timeline MVP
- Ветка: `админ`
- Статус: `implemented`, `tests_passed`

Сделано:
- На странице `GET /admin/users/:id` добавлен read-only блок `Recent security events`.
- Реализован timeline aggregator в admin UI service layer:
  - нормализует события к единому виду (time/type/category/status/actor/details)
  - сортирует по времени `DESC`
  - ограничивает выдачу (default `20`)
  - поддерживает category filter: `all|auth|recovery|passkeys|sessions|admin` (`?events=...`)
- Источники timeline в MVP:
  - `admin_audit_log` (`admin.user.*` support actions)
  - user passkey metadata (`created_at`, `last_used_at`)
  - user session metadata (`created_at`, `last_seen_at`)
  - linked OIDC client activity (`first_seen_at`, `last_seen_at`)
- Добавлены event labels для support UX:
  - `Admin logged out user session`
  - `Admin logged out all user sessions`
  - `Admin revoked user passkey`
  - `Passkey registered`
  - `Passkey used for authentication`
  - `Session started` / `Session activity observed`
  - `OIDC client linked to user` / `OIDC client activity observed`
- Добавлена санитизация timeline details:
  - sensitive keys (`secret`, `token`, `password`, `authorization`) отбрасываются.
- Обновлён шаблон `web/templates/admin/user_detail.html`:
  - table timeline + status badges + filter chips + empty fallback.
- Обновлены docs: `ADMIN_UI.md`, `README.md`.

Проверки:
- `go test ./internal/adminui` (dockerized Go) — `ok`.
- `go test ./...` (dockerized Go) — `ok`.

### Structured User Auth/Recovery Events + Timeline Integration
- Ветка: `админ`
- Статус: `implemented`, `tests_passed`

Сделано:
- Добавлен structured store `user_security_events`:
  - схема в `internal/store/schema.sql`
  - индексы: `(user_id, created_at desc)`, `(user_id, category, created_at desc)`, `(event_type, created_at desc)`
- Добавлен store layer: `internal/store/user_security_events.go`:
  - `CreateUserSecurityEvent(...)`
  - `ListUserSecurityEvents(...)`
  - фильтры/лимиты + sanitization `details_json` (без `secret/token/password/authorization/challenge/assertion/public_key`)
- В user auth/recovery flow начата запись structured events:
  - login: `login_success`, `login_failure`
  - recovery: `recovery_requested`, `recovery_success`, `recovery_failure`
  - sessions: `session_created`, `session_revoked`
  - passkeys: `passkey_added`, `passkey_revoked`
- Admin support actions из `/admin/users/:id` теперь зеркалятся в `user_security_events` (кроме `admin_audit_log`):
  - logout one session
  - logout all sessions
  - revoke user passkey
- User detail timeline (`GET /admin/users/:id`) переведён на structured events как primary source:
  - фильтр: `all|auth|recovery|passkey|session|admin` (+ aliases `passkeys/sessions`)
  - fallback на linked-client activity остаётся только если structured stream пуст
  - добавлен человекочитаемый label mapping (`Login succeeded`, `Recovery requested`, `Admin revoked user passkey`, и т.д.)

Тесты:
- обновлены и расширены `internal/adminui/handler_test.go`:
  - timeline рендерит structured events
  - category filters работают для structured categories
  - timeline предпочитает structured stream (без лишнего inferred fallback)
  - sensitive fields не отображаются
  - support actions создают audit + mirrored user security events
- auth/store пакетные проверки:
  - `go test ./internal/adminui ./internal/auth` (dockerized Go) — `ok`
  - `go test ./internal/store` (dockerized Go) — `ok`
