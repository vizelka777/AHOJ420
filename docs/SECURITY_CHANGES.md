# Security Changes (2026-02-26)

## 1. Recovery enumeration oracle fixed
- Area: recovery verify-code behavior.
- Problem: different error messages allowed validating whether a phone exists/confirmed.
- Fix: normalized handling and responses to avoid existence leakage.

## 2. Atomic attempts decrement for code verification
- Areas:
  - `internal/auth/profile_phone_verify.go`
  - `internal/auth/recovery.go`
- Problem: parallel wrong-code requests could bypass `AttemptsLeft` via lost updates.
- Fix: switched to atomic update logic in Redis (transaction/watch approach) so each failed check reliably decreases attempts.
- Result: race-based brute-force amplification is blocked.

## 3. Avatar upload hardening (DoS / decompression bomb)
- Area: avatar processing/upload pipeline.
- Problem: crafted images could force excessive memory use.
- Fix: strict size/processing limits and guarded decoding path.
- Result: reduced risk of memory exhaustion and service degradation.

## 4. Profile contact uniqueness constraints
- Area: DB schema (`users` table).
- Added unique indexes for non-empty normalized values:
  - `users_profile_email_unique_idx` on `lower(trim(profile_email))`
  - `users_phone_unique_idx` on `trim(phone)`
- Result: prevents duplicate ownership of profile email/phone.

## 5. Recovery policy tightened
- Recovery path now depends on confirmed contact data as intended.
- Result: lowers account takeover risk through weak/unverified contact states.

## 6. Operational note
- Server restarts during this cycle were executed via runtime environment profile:
  - `/home/sss/AHOJ420/.env.runtime.2026-02-26_02-49-33`
