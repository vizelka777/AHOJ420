# SSO Classic Branch Changes

This branch (`stable/sso-classic`) contains the core OIDC/SSO improvements for Ahoj420 provider.

## Changes:

### 1. Secure JWKS Endpoint
- **File:** `internal/oidc/provider.go`
- **Action:** Refactored `KeySet` method.
- **Impact:** Only public RSA components (`n`, `e`) are exposed via `/keys`. Private keys are strictly hidden. This fixes signature verification errors in OIDC clients.

### 2. User Profile Email Priority
- **File:** `internal/oidc/provider.go`
- **Action:** Updated `SetUserinfoFromScopes` and `GetPrivateClaimsFromScopes`.
- **Impact:** The provider now prefers `user.ProfileEmail` over the internal technical `user.Email`. This ensures that when a user updates their email in the Ahoj420 dashboard, the change is reflected on all connected sites (like houbamzdar.cz) upon next login.

### 3. ID Token Claims Assertion
- **File:** `internal/oidc/provider.go`
- **Action:** Enabled `IDTokenUserinfoClaimsAssertion` for static clients.
- **Impact:** User claims (email, name, picture) are included directly in the `id_token`, simplifying the integration for clients and making it more resilient to network issues during userinfo requests.

### 4. Anonymous Email Handling
- **Impact:** Specifically handles `anon-UUID` emails by automatically replacing them with the user's verified profile email in OIDC responses.
