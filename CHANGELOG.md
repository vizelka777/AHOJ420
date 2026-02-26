# Changelog

## 2026-02-26

### Security
- Fixed phone enumeration oracle in recovery code verification by normalizing error behavior.
- Made recovery/profile phone verification attempts decrement atomic in Redis to block race-based brute force.
- Added protections in avatar upload flow against memory exhaustion and decompression bomb scenarios.
- Enforced unique non-empty `profile_email` and `phone` at DB level.
- Recovery flow now requires both contacts (email and phone) to be confirmed.

### Auth / OIDC
- Added QR login flow with endpoints:
  - `GET /auth/qr/generate`
  - `POST /auth/qr/approve`
  - `GET /auth/qr/status`
- Added QR-based "add device" flow for passkey enrollment on a new device.
- Improved OIDC return behavior and callback redirect handling.
- Added tracking of OIDC clients used by each user.

### Devices and Sessions
- Added "Devices and Sessions" panel in profile UI.
- Added device/session listing with online/current status and timestamps.
- Added per-session logout endpoint and UI action.
- Added per-device removal endpoint and UI action.
- Added server-side protection: last device cannot be removed; user gets guidance to delete account instead.

### Account Deletion
- Added delete-impact endpoint (`GET /auth/delete-impact`) returning linked OIDC clients.
- Added explicit account deletion confirmation modal with impact message and linked clients list.

### UI / UX
- Profile UI restyled and reorganized.
- OIDC "Return to client" action moved to top section for better visibility.
- Hidden profile-share consent block instead of removing it.
- Added compact device controls (logout/remove) in sessions list.
- Phone input changed to two fields:
  - country code selector (`+420`, `+421`)
  - local 9-digit number input
  with automatic composition to E.164 for backend processing.
