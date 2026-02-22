# OIDC Technical Guide (Ahoj420 + zitadel/oidc)

This document explains how OIDC should work in this project from the ground up, including registration/login flows, cookies vs JWT, and key management/rotation.

## 1) Roles and Components
- **Ahoj420 (this service)** = Identity Provider (IdP) / Authorization Server
- **Clients** = your other services/apps (forum, CRM, etc.)
- **Users** = humans using passkeys

Main endpoints (IdP):
- `/.well-known/openid-configuration` (discovery)
- `/authorize` (authorization endpoint)
- `/token` (token endpoint)
- `/jwks` (public keys for JWT verification)
- `/userinfo` (optional)

## 2) Two Layers of Auth
There are always two distinct layers:

### A) User Session (browser session)
How Ahoj420 remembers that a user is logged-in in the browser.
Options:
1) **Session cookie (recommended)**
   - HttpOnly, Secure, SameSite=Lax/Strict
   - Stores session ID; server looks up session in Redis/DB
   - Easy to revoke and rotate
2) **JWT in cookie**
   - Stateless, but harder to revoke
   - Still should be HttpOnly + Secure
3) **JWT in localStorage** (not recommended)
   - XSS risk

### B) OIDC Tokens (client tokens)
What Ahoj420 issues to client apps via `/token`:
- **ID Token (JWT)**: user identity for the client
- **Access Token**: for calling APIs (optional here)
- **Refresh Token**: if long sessions required

These tokens are signed by Ahoj420 and verified by clients using JWKS.

## 3) Passkey Registration Flow
Registration is *not* OIDC; it creates a credential.

1) Browser calls `GET /auth/register/begin?email=...`
2) Server creates WebAuthn challenge, stores `session` in Redis
3) Browser prompts the authenticator, gets attestation
4) Browser calls `POST /auth/register/finish`
5) Server verifies, stores credential in DB

Result: user now has at least one credential in DB.

## 4) Passkey Login Flow
Login is also *not* OIDC; it proves identity.

1) Browser calls `GET /auth/login/begin[?email=...]`
2) Server creates assertion challenge, stores session in Redis
3) Browser prompts authenticator, gets assertion
4) Browser calls `POST /auth/login/finish`
5) Server verifies assertion

After step 5 you must decide how to maintain user login state:

### Option A (recommended): session cookie
- Set `user_id` session cookie (or opaque session ID)
- Store session in Redis (e.g. `sess:<id> -> user_id`)
- Then `/authorize` can check session cookie

### Option B: JWT session cookie
- Sign a JWT (`sub = user_id`, `email`, `iat`, `exp`, `kid`)
- Put it into an HttpOnly cookie
- `/authorize` verifies JWT on each request

## 5) OIDC Authorization Code Flow (how clients log in)

### Standard flow
1) Client redirects user to:
   `GET /authorize?client_id=...&redirect_uri=...&response_type=code&scope=openid&state=...&nonce=...`

2) Ahoj420 checks user session cookie:
   - If not logged in: redirect to login page
   - After login, continue authorize flow

3) Ahoj420 issues an **authorization code** to client

4) Client exchanges code at `/token` to get tokens

5) Client verifies ID Token using `/jwks`

### Important
- `/authorize` must be protected by real user session (cookie/JWT).
- Without a user session, OIDC is not secure.

## 6) JWT Signing Keys (critical)

### Current (not safe)
- `CryptoKey` is hardcoded (`sha256.Sum256(...)`) in code.
- No rotation, no KID.

### Recommended
- Keep private key outside code (file/secret)
- Expose public keys via JWKS (`/jwks`)
- Include `kid` in each JWT header
- Support multiple active keys (rotation)

### Rotation process (simple)
1) Add a new key to JWKS, keep old key active
2) Start signing with new `kid`
3) Clients accept both keys
4) After old tokens expire, remove old key

## 7) Where to Store Keys
Best → worst:
1) **KMS/HSM** (cloud) — safest, managed rotation
2) **File secret on VPS**, mounted read-only in container (recommended for this project)
3) **Docker secrets** (if swarm)
4) **ENV variables** (least safe, visible in `docker inspect`)

## 8) What We Should Implement Next
Minimal secure OIDC for this project:

1) **User session cookie** after `/auth/login/finish`
   - Store session in Redis (ttl)
   - Clear on logout

2) **Protect `/authorize`** by session cookie
   - If no session → redirect to login page with `return_to`

3) **Key management**
   - Load signing key from file
   - Publish JWKS with `kid`
   - Support key rotation

4) **OIDC callback UI**
   - After login, redirect back to `/authorize`

## 9) Concrete Examples

### 9.1 Example Env Vars
```
OIDC_ISSUER=https://ahoj420.eu
OIDC_KEY_ID=key-2026-01
OIDC_PRIVKEY_PATH=/run/secrets/oidc_private_key.pem
SESSION_TTL_MINUTES=60
```

### 9.2 Example Redis Session Model (cookie session)
```
cookie:  user_session=abc123 (HttpOnly, Secure, SameSite=Lax)
redis:   sess:abc123 -> {"user_id":"<uuid>","created_at":..., "expires_at":...}
ttl:     60 minutes
```

### 9.3 Example JWT Header/Payload (ID Token)
Header:
```
{"alg":"RS256","typ":"JWT","kid":"key-2026-01"}
```
Payload:
```
{
  "iss":"https://ahoj420.eu",
  "sub":"<user-uuid>",
  "aud":"client-id-123",
  "email":"user@example.com",
  "iat":1700000000,
  "exp":1700003600
}
```

### 9.4 Example JWKS (public keys)
```
{
  "keys": [
    {
      "kty": "RSA",
      "kid": "key-2026-01",
      "use": "sig",
      "alg": "RS256",
      "n": "<base64url-modulus>",
      "e": "AQAB"
    },
    {
      "kty": "RSA",
      "kid": "key-2025-12",
      "use": "sig",
      "alg": "RS256",
      "n": "<base64url-modulus-old>",
      "e": "AQAB"
    }
  ]
}
```

### 9.5 Example Key Generation (file-based)
```
# generate private key
openssl genrsa -out oidc_private_key.pem 2048

# generate public key
openssl rsa -in oidc_private_key.pem -pubout -out oidc_public_key.pem

# lock down permissions
chmod 600 oidc_private_key.pem
```

### 9.6 Example Cookie Settings
```
Name: user_session
HttpOnly: true
Secure: true
SameSite: Lax
Path: /
Max-Age: 3600
```

### 9.7 Example OIDC Flow (with session)
1) Client redirects user to `/authorize?client_id=...&response_type=code&scope=openid&state=...&nonce=...`
2) Server checks `user_session` cookie
3) If missing → redirect to `/?mode=login&return_to=/authorize?...`
4) After login, server resumes authorize flow and issues code
5) Client exchanges code at `/token` and validates ID token using `/jwks`

## 10) Integration With Current Code (What to change where)

### 10.1 Where to set the user session (after login)
File: `internal/auth/webauthn.go` in `FinishLogin`\n
After successful WebAuthn verification:\n
- create a session ID (random)\n
- store in Redis `sess:<id> -> user_id` with TTL\n
- set cookie `user_session=<id>`\n
\nExample (pseudo):\n
```\n// after successful login\nsid := randomString()\nredis.Set(ctx, \"sess:\"+sid, user.ID, 1*time.Hour)\nsetCookie(\"user_session\", sid, 3600)\n```\n\n### 10.2 Where to read session for /authorize\nFile: `cmd/server/main.go` in the `/authorize` middleware\n\nCurrent code checks `user_id` cookie. Replace with:\n- read `user_session` cookie\n- fetch `sess:<id>` from Redis\n- if missing → redirect to login\n- if found → put `user_id` in context\n\nPseudo:\n```\n sid := readCookie(\"user_session\")\n userID := redis.Get(\"sess:\"+sid)\n ctx := context.WithValue(c.Request().Context(), \"user_id\", userID)\n```\n\n### 10.3 Where to add logout\n- new endpoint `POST /auth/logout`\n- delete `sess:<id>` from Redis\n- clear cookie `user_session`\n\n### 10.4 Key storage for OIDC\nFile: `internal/oidc/provider.go`\n\nReplace static `CryptoKey` with:\n- read private key from file path `OIDC_PRIVKEY_PATH`\n- add key id from `OIDC_KEY_ID`\n- expose JWKS with the public key\n\nIf using RSA:\n```\nprivKey, _ := loadRSAPrivateKey(path)\nprovider.WithSigningKey(privKey, kid)\n```\n\n### 10.5 What to update in config\nAdd to `.env`:\n```\nOIDC_ISSUER=https://ahoj420.eu\nOIDC_KEY_ID=key-2026-01\nOIDC_PRIVKEY_PATH=/run/secrets/oidc_private_key.pem\nSESSION_TTL_MINUTES=60\n```\n\n### 10.6 What to update in compose\nMount the key as read-only:\n```\nservices:\n  backend:\n    volumes:\n      - /opt/ahoj420/secrets/oidc_private_key.pem:/run/secrets/oidc_private_key.pem:ro\n```\n+
## 11) Decision Matrix
- Want simplest now? → session cookie + file-based key
- Want zero state? → JWT session cookie (still needs rotation)
- Want strongest security? → KMS + short-lived tokens + refresh tokens

---

If you want, I can implement this step-by-step:
1) Add session cookie + Redis session
2) Add logout
3) Add file-based JWT signing keys with `kid`
4) Update JWKS / rotation docs
