# REPORTS

Журнал выполненных работ. Обновляется после каждого значимого изменения (разработка, коммит/пуш, деплой, хотфикс).

## 2026-02-28

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
