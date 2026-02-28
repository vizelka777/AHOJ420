package adminauth

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/houbamydar/AHOJ420/internal/admin"
	"github.com/houbamydar/AHOJ420/internal/store"
	"github.com/labstack/echo/v4"
	"golang.org/x/time/rate"
)

func TestBootstrapFirstAdminAndCloseBootstrapAfterCredential(t *testing.T) {
	st := newFakeAdminStore()
	wa := &fakeWebAuthn{
		beginRegistrationSession: &webauthn.SessionData{Challenge: "reg-challenge"},
		finishRegistrationCredential: &webauthn.Credential{
			ID:        []byte("cred-bootstrap"),
			PublicKey: []byte("pk-bootstrap"),
		},
	}
	svc := newTestAdminAuthService(st, wa)
	e := echo.New()
	e.POST("/admin/auth/register/begin", svc.BeginRegistration)
	e.POST("/admin/auth/register/finish", svc.FinishRegistration)

	beginRec := doAdminAuthRequest(t, e, http.MethodPost, "/admin/auth/register/begin", nil, nil, "")
	if beginRec.Code != http.StatusOK {
		t.Fatalf("expected 200 on register begin, got %d body=%s", beginRec.Code, beginRec.Body.String())
	}
	regCookie := responseCookie(beginRec, adminRegSessionCookieName)
	if regCookie == nil || strings.TrimSpace(regCookie.Value) == "" {
		t.Fatalf("expected %s cookie", adminRegSessionCookieName)
	}
	if users, _ := st.CountAdminUsers(); users != 1 {
		t.Fatalf("expected exactly one admin user after bootstrap begin, got %d", users)
	}

	finishRec := doAdminAuthRequest(t, e, http.MethodPost, "/admin/auth/register/finish", nil, []*http.Cookie{regCookie}, "")
	if finishRec.Code != http.StatusOK {
		t.Fatalf("expected 200 on register finish, got %d body=%s", finishRec.Code, finishRec.Body.String())
	}
	adminSession := responseCookie(finishRec, adminSessionCookieName)
	if adminSession == nil || strings.TrimSpace(adminSession.Value) == "" {
		t.Fatalf("expected %s cookie after register finish", adminSessionCookieName)
	}
	if creds, _ := st.CountAdminCredentials(); creds != 1 {
		t.Fatalf("expected one admin credential after registration, got %d", creds)
	}

	repeatRec := doAdminAuthRequest(t, e, http.MethodPost, "/admin/auth/register/begin", nil, nil, "")
	if repeatRec.Code != http.StatusConflict {
		t.Fatalf("expected 409 when bootstrap is closed, got %d body=%s", repeatRec.Code, repeatRec.Body.String())
	}
}

func TestAdminLoginBeginFinishIssuesAdminSessionCookie(t *testing.T) {
	st := newFakeAdminStore()
	adminUser, err := st.CreateAdminUser("owner", "Owner")
	if err != nil {
		t.Fatalf("create admin user: %v", err)
	}
	if err := st.AddAdminCredential(adminUser.ID, &webauthn.Credential{
		ID:        []byte("cred-login"),
		PublicKey: []byte("pk-login"),
	}); err != nil {
		t.Fatalf("seed admin credential: %v", err)
	}

	wa := &fakeWebAuthn{
		beginLoginSession: &webauthn.SessionData{Challenge: "login-challenge"},
		finishLoginRawID:  []byte("cred-login"),
		finishLoginCredential: &webauthn.Credential{
			ID: []byte("cred-login"),
			Authenticator: webauthn.Authenticator{
				SignCount: 2,
			},
		},
	}
	svc := newTestAdminAuthService(st, wa)
	e := echo.New()
	e.POST("/admin/auth/login/begin", svc.BeginLogin)
	e.POST("/admin/auth/login/finish", svc.FinishLogin)

	beginRec := doAdminAuthRequest(t, e, http.MethodPost, "/admin/auth/login/begin", nil, nil, "")
	if beginRec.Code != http.StatusOK {
		t.Fatalf("expected 200 on login begin, got %d body=%s", beginRec.Code, beginRec.Body.String())
	}
	loginCookie := responseCookie(beginRec, adminLoginSessionCookieName)
	if loginCookie == nil || strings.TrimSpace(loginCookie.Value) == "" {
		t.Fatalf("expected %s cookie", adminLoginSessionCookieName)
	}

	finishRec := doAdminAuthRequest(t, e, http.MethodPost, "/admin/auth/login/finish", nil, []*http.Cookie{loginCookie}, "")
	if finishRec.Code != http.StatusOK {
		t.Fatalf("expected 200 on login finish, got %d body=%s", finishRec.Code, finishRec.Body.String())
	}
	adminSession := responseCookie(finishRec, adminSessionCookieName)
	if adminSession == nil || strings.TrimSpace(adminSession.Value) == "" {
		t.Fatalf("expected %s cookie after login", adminSessionCookieName)
	}
}

func TestProtectedAdminAPIRequiresSessionAndHostGuard(t *testing.T) {
	st := newFakeAdminStore()
	adminUser, err := st.CreateAdminUser("owner", "Owner")
	if err != nil {
		t.Fatalf("create admin user: %v", err)
	}
	svc := newTestAdminAuthService(st, &fakeWebAuthn{})
	adminSession := issueAdminSessionCookie(t, svc, adminUser.ID)

	e := setupProtectedAdminAPI(svc, "", false)

	unauthorized := doAdminAuthRequest(t, e, http.MethodGet, "/admin/api/ping", nil, nil, "admin.example.test")
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without admin session, got %d body=%s", unauthorized.Code, unauthorized.Body.String())
	}

	okRec := doAdminAuthRequest(t, e, http.MethodGet, "/admin/api/ping", nil, []*http.Cookie{adminSession}, "admin.example.test")
	if okRec.Code != http.StatusOK {
		t.Fatalf("expected 200 with valid admin session, got %d body=%s", okRec.Code, okRec.Body.String())
	}
	var body map[string]string
	if err := json.Unmarshal(okRec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal protected response: %v", err)
	}
	if body["actor_type"] != "admin_user" || body["actor_id"] != adminUser.ID {
		t.Fatalf("unexpected actor context: %+v", body)
	}

	wrongHost := doAdminAuthRequest(t, e, http.MethodGet, "/admin/api/ping", nil, []*http.Cookie{adminSession}, "ahoj420.eu")
	if wrongHost.Code != http.StatusNotFound {
		t.Fatalf("expected 404 on wrong host, got %d body=%s", wrongHost.Code, wrongHost.Body.String())
	}
}

func TestLogoutRevokesSessionAndFurtherAccessFails(t *testing.T) {
	st := newFakeAdminStore()
	adminUser, err := st.CreateAdminUser("owner", "Owner")
	if err != nil {
		t.Fatalf("create admin user: %v", err)
	}
	svc := newTestAdminAuthService(st, &fakeWebAuthn{})
	adminSession := issueAdminSessionCookie(t, svc, adminUser.ID)

	e := setupProtectedAdminAPI(svc, "", false)
	e.POST("/admin/auth/logout", svc.Logout)

	beforeLogout := doAdminAuthRequest(t, e, http.MethodGet, "/admin/api/ping", nil, []*http.Cookie{adminSession}, "admin.example.test")
	if beforeLogout.Code != http.StatusOK {
		t.Fatalf("expected 200 before logout, got %d body=%s", beforeLogout.Code, beforeLogout.Body.String())
	}

	logoutRec := doAdminAuthRequest(t, e, http.MethodPost, "/admin/auth/logout", nil, []*http.Cookie{adminSession}, "admin.example.test")
	if logoutRec.Code != http.StatusOK {
		t.Fatalf("expected 200 on logout, got %d body=%s", logoutRec.Code, logoutRec.Body.String())
	}
	cleared := responseCookie(logoutRec, adminSessionCookieName)
	if cleared == nil || cleared.MaxAge != -1 {
		t.Fatalf("expected cleared %s cookie on logout", adminSessionCookieName)
	}

	afterLogout := doAdminAuthRequest(t, e, http.MethodGet, "/admin/api/ping", nil, []*http.Cookie{adminSession}, "admin.example.test")
	if afterLogout.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 after logout, got %d body=%s", afterLogout.Code, afterLogout.Body.String())
	}
}

func TestAddPasskeyFlowWhileLoggedIn(t *testing.T) {
	st := newFakeAdminStore()
	adminUser, err := st.CreateAdminUser("owner", "Owner")
	if err != nil {
		t.Fatalf("create admin user: %v", err)
	}
	if err := st.AddAdminCredential(adminUser.ID, &webauthn.Credential{
		ID:        []byte("cred-primary"),
		PublicKey: []byte("pk-primary"),
	}); err != nil {
		t.Fatalf("seed primary credential: %v", err)
	}

	wa := &fakeWebAuthn{
		beginRegistrationSession: &webauthn.SessionData{Challenge: "add-passkey-challenge"},
		finishRegistrationCredential: &webauthn.Credential{
			ID:        []byte("cred-secondary"),
			PublicKey: []byte("pk-secondary"),
			Transport: []protocol.AuthenticatorTransport{protocol.USB},
		},
	}
	svc := newTestAdminAuthService(st, wa)
	e := echo.New()
	e.POST("/admin/auth/passkeys/register/begin", svc.BeginAddPasskey)
	e.POST("/admin/auth/passkeys/register/finish", svc.FinishAddPasskey)

	adminSession := issueAdminSessionCookie(t, svc, adminUser.ID)

	beginRec := doAdminAuthRequest(t, e, http.MethodPost, "/admin/auth/passkeys/register/begin", nil, []*http.Cookie{adminSession}, "")
	if beginRec.Code != http.StatusOK {
		t.Fatalf("expected 200 on add-passkey begin, got %d body=%s", beginRec.Code, beginRec.Body.String())
	}
	addCookie := responseCookie(beginRec, adminAddPasskeyCookieName)
	if addCookie == nil || strings.TrimSpace(addCookie.Value) == "" {
		t.Fatalf("expected %s cookie", adminAddPasskeyCookieName)
	}

	finishRec := doAdminAuthRequest(t, e, http.MethodPost, "/admin/auth/passkeys/register/finish", nil, []*http.Cookie{adminSession, addCookie}, "")
	if finishRec.Code != http.StatusOK {
		t.Fatalf("expected 200 on add-passkey finish, got %d body=%s", finishRec.Code, finishRec.Body.String())
	}

	credentials, err := st.ListAdminCredentials(adminUser.ID)
	if err != nil {
		t.Fatalf("list admin credentials failed: %v", err)
	}
	if len(credentials) != 2 {
		t.Fatalf("expected second credential to be stored, got %d", len(credentials))
	}

	if !auditActionExists(st.auditEntries, "admin.auth.passkey.add.success", true) {
		t.Fatalf("expected admin.auth.passkey.add.success audit entry")
	}
}

func TestDeletePasskeyBlocksLastCredential(t *testing.T) {
	st := newFakeAdminStore()
	adminUser, err := st.CreateAdminUser("owner", "Owner")
	if err != nil {
		t.Fatalf("create admin user: %v", err)
	}
	if err := st.AddAdminCredential(adminUser.ID, &webauthn.Credential{
		ID:        []byte("cred-a"),
		PublicKey: []byte("pk-a"),
	}); err != nil {
		t.Fatalf("seed credential A: %v", err)
	}
	if err := st.AddAdminCredential(adminUser.ID, &webauthn.Credential{
		ID:        []byte("cred-b"),
		PublicKey: []byte("pk-b"),
	}); err != nil {
		t.Fatalf("seed credential B: %v", err)
	}

	svc := newTestAdminAuthService(st, &fakeWebAuthn{})
	adminSession := issueAdminSessionCookie(t, svc, adminUser.ID)
	credentials, err := st.ListAdminCredentials(adminUser.ID)
	if err != nil {
		t.Fatalf("list credentials failed: %v", err)
	}
	if len(credentials) != 2 {
		t.Fatalf("expected 2 credentials before delete, got %d", len(credentials))
	}

	ctx := newAdminAuthContext(t, http.MethodPost, "/admin/security/passkeys/delete", []*http.Cookie{adminSession})
	if err := svc.DeletePasskey(ctx, credentials[0].ID); err != nil {
		t.Fatalf("delete non-last passkey failed: %v", err)
	}
	if !auditActionExists(st.auditEntries, "admin.auth.passkey.delete.success", true) {
		t.Fatalf("expected admin.auth.passkey.delete.success audit entry")
	}

	credentials, err = st.ListAdminCredentials(adminUser.ID)
	if err != nil {
		t.Fatalf("list credentials after delete failed: %v", err)
	}
	if len(credentials) != 1 {
		t.Fatalf("expected exactly one credential after delete, got %d", len(credentials))
	}

	ctxLast := newAdminAuthContext(t, http.MethodPost, "/admin/security/passkeys/delete", []*http.Cookie{adminSession})
	err = svc.DeletePasskey(ctxLast, credentials[0].ID)
	if !errors.Is(err, store.ErrAdminCredentialLast) {
		t.Fatalf("expected ErrAdminCredentialLast when deleting final passkey, got %v", err)
	}
	if !auditActionExists(st.auditEntries, "admin.auth.passkey.delete.failure", false) {
		t.Fatalf("expected admin.auth.passkey.delete.failure audit entry")
	}
}

func TestAdminSessionInventoryAndLogoutOthers(t *testing.T) {
	st := newFakeAdminStore()
	adminUser, err := st.CreateAdminUser("owner", "Owner")
	if err != nil {
		t.Fatalf("create admin user: %v", err)
	}
	svc := newTestAdminAuthService(st, &fakeWebAuthn{})

	currentCookie := issueAdminSessionCookie(t, svc, adminUser.ID)
	otherCookie := issueAdminSessionCookie(t, svc, adminUser.ID)
	thirdCookie := issueAdminSessionCookie(t, svc, adminUser.ID)
	if strings.TrimSpace(otherCookie.Value) == strings.TrimSpace(currentCookie.Value) || strings.TrimSpace(thirdCookie.Value) == strings.TrimSpace(currentCookie.Value) {
		t.Fatalf("expected distinct session IDs")
	}

	ctxList := newAdminAuthContext(t, http.MethodGet, "/admin/security", []*http.Cookie{currentCookie})
	sessions, err := svc.ListSessions(ctxList)
	if err != nil {
		t.Fatalf("list sessions failed: %v", err)
	}
	if len(sessions) != 3 {
		t.Fatalf("expected three active sessions, got %d", len(sessions))
	}
	currentCount := 0
	for _, item := range sessions {
		if item.Current {
			currentCount++
		}
	}
	if currentCount != 1 {
		t.Fatalf("expected exactly one current session, got %d", currentCount)
	}

	ctxOthers := newAdminAuthContext(t, http.MethodPost, "/admin/security/sessions/logout-others", []*http.Cookie{currentCookie})
	removed, err := svc.LogoutOtherSessions(ctxOthers)
	if err != nil {
		t.Fatalf("logout other sessions failed: %v", err)
	}
	if removed != 2 {
		t.Fatalf("expected two sessions removed, got %d", removed)
	}
	if !auditActionExists(st.auditEntries, "admin.auth.session.logout_others.success", true) {
		t.Fatalf("expected admin.auth.session.logout_others.success audit entry")
	}

	ctxAfter := newAdminAuthContext(t, http.MethodGet, "/admin/security", []*http.Cookie{currentCookie})
	after, err := svc.ListSessions(ctxAfter)
	if err != nil {
		t.Fatalf("list sessions after logout others failed: %v", err)
	}
	if len(after) != 1 || !after[0].Current {
		t.Fatalf("expected only current session to remain, got %+v", after)
	}
}

func TestLogoutSpecificAdminSession(t *testing.T) {
	st := newFakeAdminStore()
	adminUser, err := st.CreateAdminUser("owner", "Owner")
	if err != nil {
		t.Fatalf("create admin user: %v", err)
	}
	svc := newTestAdminAuthService(st, &fakeWebAuthn{})

	currentCookie := issueAdminSessionCookie(t, svc, adminUser.ID)
	otherCookie := issueAdminSessionCookie(t, svc, adminUser.ID)

	ctxOther := newAdminAuthContext(t, http.MethodPost, "/admin/security/sessions/logout", []*http.Cookie{currentCookie})
	if err := svc.LogoutSessionByID(ctxOther, otherCookie.Value); err != nil {
		t.Fatalf("logout other session failed: %v", err)
	}
	if !auditActionExists(st.auditEntries, "admin.auth.session.logout.success", true) {
		t.Fatalf("expected admin.auth.session.logout.success audit entry")
	}

	ctxAfterOther := newAdminAuthContext(t, http.MethodGet, "/admin/security", []*http.Cookie{currentCookie})
	sessions, err := svc.ListSessions(ctxAfterOther)
	if err != nil {
		t.Fatalf("list sessions after logout other failed: %v", err)
	}
	if len(sessions) != 1 || !sessions[0].Current || strings.TrimSpace(sessions[0].SessionID) != strings.TrimSpace(currentCookie.Value) {
		t.Fatalf("expected only current session to remain after single logout, got %+v", sessions)
	}

	ctxCurrent := newAdminAuthContext(t, http.MethodPost, "/admin/security/sessions/logout", []*http.Cookie{currentCookie})
	if err := svc.LogoutSessionByID(ctxCurrent, currentCookie.Value); err != nil {
		t.Fatalf("logout current session failed: %v", err)
	}
	if _, ok := svc.SessionUser(ctxCurrent); ok {
		t.Fatalf("expected current session to become invalid after logout")
	}
}

func TestExpiredAdminSessionRejected(t *testing.T) {
	st := newFakeAdminStore()
	adminUser, err := st.CreateAdminUser("owner", "Owner")
	if err != nil {
		t.Fatalf("create admin user: %v", err)
	}
	svc := newTestAdminAuthService(st, &fakeWebAuthn{})
	svc.sessionAbsoluteTTL = time.Hour

	record := sessionRecord{AdminUserID: adminUser.ID, CreatedAtUTC: time.Now().Add(-2 * time.Hour).Unix()}
	payload, err := json.Marshal(record)
	if err != nil {
		t.Fatalf("marshal session record: %v", err)
	}
	if err := svc.stateStore.Set(context.Background(), adminSessionRedisKey("expired"), payload, time.Hour); err != nil {
		t.Fatalf("seed expired session: %v", err)
	}

	e := setupProtectedAdminAPI(svc, "", false)
	expiredCookie := &http.Cookie{Name: adminSessionCookieName, Value: "expired", Path: "/admin"}
	rec := doAdminAuthRequest(t, e, http.MethodGet, "/admin/api/ping", nil, []*http.Cookie{expiredCookie}, "admin.example.test")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for expired session, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestCollectAdminRPOrigins(t *testing.T) {
	origins := collectAdminRPOrigins(
		"https://ahoj420.eu",
		"https://admin.ahoj420.eu, https://ahoj420.eu",
		"admin.ahoj420.eu:443",
	)
	if len(origins) < 2 {
		t.Fatalf("expected at least two origins, got %+v", origins)
	}
	if !containsString(origins, "https://ahoj420.eu") {
		t.Fatalf("expected base RP origin in result, got %+v", origins)
	}
	if !containsString(origins, "https://admin.ahoj420.eu") && !containsString(origins, "https://admin.ahoj420.eu:443") {
		t.Fatalf("expected admin origin in result, got %+v", origins)
	}
}

func setupProtectedAdminAPI(svc *Service, token string, tokenEnabled bool) *echo.Echo {
	e := echo.New()
	group := e.Group("/admin/api")
	group.Use(admin.AdminHostGuardMiddleware("admin.example.test"))
	group.Use(admin.AdminRateLimitMiddleware(admin.AdminRateLimitConfig{Rate: rate.Limit(1000), Burst: 1000, ExpiresIn: time.Minute}))
	group.Use(svc.AttachSessionActorMiddleware())
	group.Use(admin.AdminRequireActorMiddleware(token, tokenEnabled))
	group.GET("/ping", func(c echo.Context) error {
		actorType, actorID := admin.AdminActorFromContext(c)
		return c.JSON(http.StatusOK, map[string]string{
			"actor_type": actorType,
			"actor_id":   actorID,
		})
	})
	return e
}

func issueAdminSessionCookie(t *testing.T, svc *Service, adminUserID string) *http.Cookie {
	t.Helper()
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/internal/session", nil)
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)
	if _, err := svc.setSession(ctx, adminUserID); err != nil {
		t.Fatalf("setSession failed: %v", err)
	}
	cookie := responseCookie(rec, adminSessionCookieName)
	if cookie == nil || strings.TrimSpace(cookie.Value) == "" {
		t.Fatalf("expected %s cookie from setSession", adminSessionCookieName)
	}
	return cookie
}

func newAdminAuthContext(t *testing.T, method string, path string, cookies []*http.Cookie) echo.Context {
	t.Helper()
	e := echo.New()
	req := httptest.NewRequest(method, path, nil)
	for _, cookie := range cookies {
		if cookie != nil {
			req.AddCookie(cookie)
		}
	}
	rec := httptest.NewRecorder()
	return e.NewContext(req, rec)
}

func doAdminAuthRequest(t *testing.T, e *echo.Echo, method string, path string, payload any, cookies []*http.Cookie, host string) *httptest.ResponseRecorder {
	t.Helper()

	var body *bytes.Reader
	if payload == nil {
		body = bytes.NewReader(nil)
	} else {
		raw, err := json.Marshal(payload)
		if err != nil {
			t.Fatalf("marshal payload: %v", err)
		}
		body = bytes.NewReader(raw)
	}

	req := httptest.NewRequest(method, path, body)
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	if strings.TrimSpace(host) != "" {
		req.Host = host
	}
	for _, cookie := range cookies {
		if cookie != nil {
			req.AddCookie(cookie)
		}
	}

	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	return rec
}

func responseCookie(rec *httptest.ResponseRecorder, name string) *http.Cookie {
	var found *http.Cookie
	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == name {
			item := *cookie
			found = &item
		}
	}
	return found
}

func newTestAdminAuthService(st *fakeAdminStore, wa *fakeWebAuthn) *Service {
	return &Service{
		wa:                 wa,
		store:              st,
		stateStore:         newFakeAdminSessionStateStore(),
		bootstrapLogin:     "owner",
		sessionIdleTTL:     30 * time.Minute,
		sessionAbsoluteTTL: 12 * time.Hour,
	}
}

type fakeAdminSessionStateStore struct {
	mu   sync.Mutex
	data map[string]fakeAdminSessionStateRecord
}

type fakeAdminSessionStateRecord struct {
	value     []byte
	expiresAt time.Time
}

func newFakeAdminSessionStateStore() *fakeAdminSessionStateStore {
	return &fakeAdminSessionStateStore{data: make(map[string]fakeAdminSessionStateRecord)}
}

func (s *fakeAdminSessionStateStore) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	rec := fakeAdminSessionStateRecord{value: append([]byte(nil), value...)}
	if ttl > 0 {
		rec.expiresAt = time.Now().Add(ttl)
	}
	s.data[strings.TrimSpace(key)] = rec
	return nil
}

func (s *fakeAdminSessionStateStore) Get(ctx context.Context, key string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	normalized := strings.TrimSpace(key)
	rec, ok := s.data[normalized]
	if !ok {
		return nil, errors.New("state not found")
	}
	if !rec.expiresAt.IsZero() && time.Now().After(rec.expiresAt) {
		delete(s.data, normalized)
		return nil, errors.New("state expired")
	}
	return append([]byte(nil), rec.value...), nil
}

func (s *fakeAdminSessionStateStore) Del(ctx context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data, strings.TrimSpace(key))
	return nil
}

func (s *fakeAdminSessionStateStore) Keys(ctx context.Context, pattern string) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	prefix := strings.TrimSpace(pattern)
	if strings.HasSuffix(prefix, "*") {
		prefix = strings.TrimSuffix(prefix, "*")
	}

	out := make([]string, 0, len(s.data))
	now := time.Now()
	for key, rec := range s.data {
		if !rec.expiresAt.IsZero() && now.After(rec.expiresAt) {
			continue
		}
		if strings.HasPrefix(key, prefix) {
			out = append(out, key)
		}
	}
	sort.Strings(out)
	return out, nil
}

func (s *fakeAdminSessionStateStore) TTL(ctx context.Context, key string) (time.Duration, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rec, ok := s.data[strings.TrimSpace(key)]
	if !ok {
		return -2 * time.Second, nil
	}
	if rec.expiresAt.IsZero() {
		return -1 * time.Second, nil
	}
	ttl := time.Until(rec.expiresAt)
	if ttl < 0 {
		return -2 * time.Second, nil
	}
	return ttl, nil
}

type fakeWebAuthn struct {
	beginRegistrationOptions     *protocol.CredentialCreation
	beginRegistrationSession     *webauthn.SessionData
	beginRegistrationErr         error
	finishRegistrationCredential *webauthn.Credential
	finishRegistrationErr        error
	beginLoginOptions            *protocol.CredentialAssertion
	beginLoginSession            *webauthn.SessionData
	beginLoginErr                error
	finishLoginCredential        *webauthn.Credential
	finishLoginRawID             []byte
	finishLoginUserHandle        []byte
	finishLoginErr               error
}

func (f *fakeWebAuthn) BeginRegistration(user webauthn.User, opts ...webauthn.RegistrationOption) (*protocol.CredentialCreation, *webauthn.SessionData, error) {
	if f.beginRegistrationErr != nil {
		return nil, nil, f.beginRegistrationErr
	}
	options := f.beginRegistrationOptions
	if options == nil {
		options = &protocol.CredentialCreation{}
	}
	session := f.beginRegistrationSession
	if session == nil {
		session = &webauthn.SessionData{Challenge: "reg"}
	}
	return options, session, nil
}

func (f *fakeWebAuthn) FinishRegistration(user webauthn.User, session webauthn.SessionData, response *http.Request) (*webauthn.Credential, error) {
	if f.finishRegistrationErr != nil {
		return nil, f.finishRegistrationErr
	}
	if f.finishRegistrationCredential == nil {
		return &webauthn.Credential{ID: []byte("cred-reg"), PublicKey: []byte("pk-reg")}, nil
	}
	out := *f.finishRegistrationCredential
	return &out, nil
}

func (f *fakeWebAuthn) BeginDiscoverableLogin(opts ...webauthn.LoginOption) (*protocol.CredentialAssertion, *webauthn.SessionData, error) {
	if f.beginLoginErr != nil {
		return nil, nil, f.beginLoginErr
	}
	options := f.beginLoginOptions
	if options == nil {
		options = &protocol.CredentialAssertion{}
	}
	session := f.beginLoginSession
	if session == nil {
		session = &webauthn.SessionData{Challenge: "login"}
	}
	return options, session, nil
}

func (f *fakeWebAuthn) FinishDiscoverableLogin(handler webauthn.DiscoverableUserHandler, session webauthn.SessionData, response *http.Request) (*webauthn.Credential, error) {
	if f.finishLoginErr != nil {
		return nil, f.finishLoginErr
	}
	rawID := append([]byte(nil), f.finishLoginRawID...)
	if len(rawID) == 0 {
		rawID = []byte("cred-login")
	}
	userHandle := append([]byte(nil), f.finishLoginUserHandle...)
	if _, err := handler(rawID, userHandle); err != nil {
		return nil, err
	}
	if f.finishLoginCredential == nil {
		return &webauthn.Credential{ID: rawID}, nil
	}
	out := *f.finishLoginCredential
	return &out, nil
}

type fakeAdminStore struct {
	mu               sync.Mutex
	nextUserID       int
	nextCredentialID int64
	users            map[string]*store.AdminUser
	usersByLogin     map[string]string
	credentialOwners map[string]string
	credentialMeta   map[string]credentialMeta
	auditEntries     []store.AdminAuditEntry
}

type credentialMeta struct {
	ID         int64
	CreatedAt  time.Time
	LastUsedAt *time.Time
	Transports []string
}

func newFakeAdminStore() *fakeAdminStore {
	return &fakeAdminStore{
		users:            make(map[string]*store.AdminUser),
		usersByLogin:     make(map[string]string),
		credentialOwners: make(map[string]string),
		credentialMeta:   make(map[string]credentialMeta),
		auditEntries:     make([]store.AdminAuditEntry, 0),
	}
}

func (f *fakeAdminStore) CountAdminUsers() (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.users), nil
}

func (f *fakeAdminStore) CountAdminCredentials() (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.credentialOwners), nil
}

func (f *fakeAdminStore) CreateAdminUser(login string, displayName string) (*store.AdminUser, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	normalized := strings.ToLower(strings.TrimSpace(login))
	if normalized == "" {
		return nil, fmt.Errorf("admin login is required")
	}
	if _, exists := f.usersByLogin[normalized]; exists {
		return nil, fmt.Errorf("admin login already exists")
	}

	f.nextUserID++
	id := fmt.Sprintf("admin-%d", f.nextUserID)
	now := time.Now().UTC()
	user := &store.AdminUser{
		ID:          id,
		Login:       normalized,
		DisplayName: strings.TrimSpace(displayName),
		Enabled:     true,
		CreatedAt:   now,
		UpdatedAt:   now,
		Credentials: []webauthn.Credential{},
	}
	if user.DisplayName == "" {
		user.DisplayName = normalized
	}
	f.users[id] = user
	f.usersByLogin[normalized] = id
	return cloneAdminUser(user), nil
}

func (f *fakeAdminStore) GetAdminUser(id string) (*store.AdminUser, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	user, ok := f.users[strings.TrimSpace(id)]
	if !ok {
		return nil, store.ErrAdminUserNotFound
	}
	return cloneAdminUser(user), nil
}

func (f *fakeAdminStore) GetAdminUserByLogin(login string) (*store.AdminUser, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	normalized := strings.ToLower(strings.TrimSpace(login))
	id, ok := f.usersByLogin[normalized]
	if !ok {
		return nil, store.ErrAdminUserNotFound
	}
	return cloneAdminUser(f.users[id]), nil
}

func (f *fakeAdminStore) GetAdminUserByCredentialID(credentialID []byte) (*store.AdminUser, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	ownerID, ok := f.credentialOwners[string(credentialID)]
	if !ok {
		return nil, store.ErrAdminUserNotFound
	}
	return cloneAdminUser(f.users[ownerID]), nil
}

func (f *fakeAdminStore) AddAdminCredential(adminUserID string, credential *webauthn.Credential) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	user, ok := f.users[strings.TrimSpace(adminUserID)]
	if !ok {
		return store.ErrAdminUserNotFound
	}
	if !user.Enabled {
		return store.ErrAdminUserDisabled
	}
	if credential == nil || len(credential.ID) == 0 {
		return fmt.Errorf("credential is required")
	}
	key := string(credential.ID)
	if _, exists := f.credentialOwners[key]; exists {
		return fmt.Errorf("credential already exists")
	}

	copied := cloneCredential(*credential)
	user.Credentials = append(user.Credentials, copied)
	user.UpdatedAt = time.Now().UTC()
	f.credentialOwners[key] = user.ID
	f.nextCredentialID++
	transports := make([]string, 0, len(copied.Transport))
	for _, transport := range copied.Transport {
		trimmed := strings.TrimSpace(string(transport))
		if trimmed == "" {
			continue
		}
		transports = append(transports, trimmed)
	}
	f.credentialMeta[key] = credentialMeta{
		ID:         f.nextCredentialID,
		CreatedAt:  time.Now().UTC(),
		LastUsedAt: nil,
		Transports: transports,
	}
	return nil
}

func (f *fakeAdminStore) UpdateAdminCredential(credential *webauthn.Credential) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if credential == nil || len(credential.ID) == 0 {
		return fmt.Errorf("credential id is required")
	}
	ownerID, ok := f.credentialOwners[string(credential.ID)]
	if !ok {
		return store.ErrAdminCredentialNotFound
	}
	user := f.users[ownerID]
	for idx := range user.Credentials {
		if bytes.Equal(user.Credentials[idx].ID, credential.ID) {
			user.Credentials[idx].Authenticator.SignCount = credential.Authenticator.SignCount
			user.UpdatedAt = time.Now().UTC()
			if meta, ok := f.credentialMeta[string(credential.ID)]; ok {
				now := time.Now().UTC()
				meta.LastUsedAt = &now
				f.credentialMeta[string(credential.ID)] = meta
			}
			return nil
		}
	}
	return store.ErrAdminCredentialNotFound
}

func (f *fakeAdminStore) ListAdminCredentials(adminUserID string) ([]store.AdminCredentialInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	user, ok := f.users[strings.TrimSpace(adminUserID)]
	if !ok {
		return nil, store.ErrAdminUserNotFound
	}
	out := make([]store.AdminCredentialInfo, 0, len(user.Credentials))
	for _, credential := range user.Credentials {
		key := string(credential.ID)
		meta := f.credentialMeta[key]
		item := store.AdminCredentialInfo{
			ID:           meta.ID,
			CredentialID: base64.RawURLEncoding.EncodeToString(credential.ID),
			CreatedAt:    meta.CreatedAt,
			Transports:   append([]string(nil), meta.Transports...),
		}
		if meta.LastUsedAt != nil {
			value := meta.LastUsedAt.UTC()
			item.LastUsedAt = &value
		}
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (f *fakeAdminStore) DeleteAdminCredential(adminUserID string, credentialID int64) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	user, ok := f.users[strings.TrimSpace(adminUserID)]
	if !ok {
		return store.ErrAdminUserNotFound
	}
	if credentialID <= 0 {
		return store.ErrAdminCredentialNotFound
	}
	if len(user.Credentials) <= 1 {
		return store.ErrAdminCredentialLast
	}
	idx := -1
	var key string
	for i, credential := range user.Credentials {
		meta := f.credentialMeta[string(credential.ID)]
		if meta.ID == credentialID {
			idx = i
			key = string(credential.ID)
			break
		}
	}
	if idx < 0 {
		return store.ErrAdminCredentialNotFound
	}
	delete(f.credentialOwners, key)
	delete(f.credentialMeta, key)
	user.Credentials = append(user.Credentials[:idx], user.Credentials[idx+1:]...)
	user.UpdatedAt = time.Now().UTC()
	return nil
}

func (f *fakeAdminStore) CountAdminCredentialsForUser(adminUserID string) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	user, ok := f.users[strings.TrimSpace(adminUserID)]
	if !ok {
		return 0, store.ErrAdminUserNotFound
	}
	return len(user.Credentials), nil
}

func (f *fakeAdminStore) CreateAdminAuditEntry(ctx context.Context, entry store.AdminAuditEntry) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	item := entry
	item.DetailsJSON = append([]byte(nil), entry.DetailsJSON...)
	f.auditEntries = append(f.auditEntries, item)
	return nil
}

func cloneAdminUser(in *store.AdminUser) *store.AdminUser {
	if in == nil {
		return nil
	}
	out := *in
	out.Credentials = make([]webauthn.Credential, 0, len(in.Credentials))
	for _, credential := range in.Credentials {
		out.Credentials = append(out.Credentials, cloneCredential(credential))
	}
	return &out
}

func cloneCredential(in webauthn.Credential) webauthn.Credential {
	out := in
	out.ID = append([]byte(nil), in.ID...)
	out.PublicKey = append([]byte(nil), in.PublicKey...)
	out.Transport = append([]protocol.AuthenticatorTransport(nil), in.Transport...)
	out.Authenticator = in.Authenticator
	out.Authenticator.AAGUID = append([]byte(nil), in.Authenticator.AAGUID...)
	return out
}

func containsString(items []string, needle string) bool {
	for _, item := range items {
		if item == needle {
			return true
		}
	}
	return false
}

func auditActionExists(entries []store.AdminAuditEntry, action string, success bool) bool {
	for _, entry := range entries {
		if strings.TrimSpace(entry.Action) == strings.TrimSpace(action) && entry.Success == success {
			return true
		}
	}
	return false
}
