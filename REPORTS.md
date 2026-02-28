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
