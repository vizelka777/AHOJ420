package adminauth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
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
	users            map[string]*store.AdminUser
	usersByLogin     map[string]string
	credentialOwners map[string]string
	auditEntries     []store.AdminAuditEntry
}

func newFakeAdminStore() *fakeAdminStore {
	return &fakeAdminStore{
		users:            make(map[string]*store.AdminUser),
		usersByLogin:     make(map[string]string),
		credentialOwners: make(map[string]string),
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
			return nil
		}
	}
	return store.ErrAdminCredentialNotFound
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
