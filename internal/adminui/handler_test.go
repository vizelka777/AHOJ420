package adminui

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/houbamydar/AHOJ420/internal/admin"
	"github.com/houbamydar/AHOJ420/internal/store"
	"github.com/labstack/echo/v4"
)

func TestLoginPage(t *testing.T) {
	e := setupTestAdminUI(t, newFakeUIStore(), &fakeUIAuth{}, &fakeReloader{}, &fakeAuditStore{})

	rec := doUIRequest(t, e, http.MethodGet, "/admin/login", nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "Sign in with passkey") {
		t.Fatalf("expected login page content, got %s", rec.Body.String())
	}
}

func TestClientsRequireSession(t *testing.T) {
	fakeStore := newFakeUIStore()
	_ = fakeStore.CreateOIDCClient(store.OIDCClient{
		ID:            "client-a",
		Name:          "Client A",
		Enabled:       true,
		Confidential:  false,
		RequirePKCE:   true,
		AuthMethod:    "none",
		GrantTypes:    []string{"authorization_code"},
		ResponseTypes: []string{"code"},
		Scopes:        []string{"openid"},
		RedirectURIs:  []string{"https://example.com/callback"},
	}, nil)

	auth := &fakeUIAuth{}
	e := setupTestAdminUI(t, fakeStore, auth, &fakeReloader{}, &fakeAuditStore{})

	recNoSession := doUIRequest(t, e, http.MethodGet, "/admin/clients", nil, nil)
	if recNoSession.Code != http.StatusFound {
		t.Fatalf("expected 302 redirect, got %d", recNoSession.Code)
	}
	if location := recNoSession.Header().Get(echo.HeaderLocation); location != "/admin/login" {
		t.Fatalf("expected redirect to /admin/login, got %s", location)
	}

	recSession := doUIRequest(t, e, http.MethodGet, "/admin/clients", nil, auth.sessionCookies())
	if recSession.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", recSession.Code, recSession.Body.String())
	}
	if !strings.Contains(recSession.Body.String(), "client-a") {
		t.Fatalf("expected client id in body, got %s", recSession.Body.String())
	}
}

func TestCreateClientValidationAndSuccess(t *testing.T) {
	fakeStore := newFakeUIStore()
	reloader := &fakeReloader{}
	auditStore := &fakeAuditStore{}
	auth := &fakeUIAuth{}
	e := setupTestAdminUI(t, fakeStore, auth, reloader, auditStore)

	invalidForm := url.Values{}
	invalidForm.Set("name", "Missing ID")
	recInvalid := doUIRequest(t, e, http.MethodPost, "/admin/clients/new", invalidForm, auth.sessionCookies())
	if recInvalid.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid create, got %d body=%s", recInvalid.Code, recInvalid.Body.String())
	}
	if !strings.Contains(recInvalid.Body.String(), "Client ID is required") {
		t.Fatalf("expected validation error in body, got %s", recInvalid.Body.String())
	}

	validForm := url.Values{}
	validForm.Set("id", "ui-created")
	validForm.Set("name", "UI Created")
	validForm.Set("enabled", "true")
	validForm.Set("confidential", "false")
	validForm.Set("require_pkce", "true")
	validForm.Set("auth_method", "none")
	validForm.Set("grant_types", "authorization_code")
	validForm.Set("response_types", "code")
	validForm.Set("scopes", "openid profile")
	validForm.Set("redirect_uris", "https://example.com/callback")

	recOK := doUIRequest(t, e, http.MethodPost, "/admin/clients/new", validForm, auth.sessionCookies())
	if recOK.Code != http.StatusSeeOther {
		t.Fatalf("expected 303 for successful create, got %d body=%s", recOK.Code, recOK.Body.String())
	}
	if location := recOK.Header().Get(echo.HeaderLocation); location != "/admin/clients/ui-created" {
		t.Fatalf("unexpected create redirect location %s", location)
	}
	if reloader.calls != 1 {
		t.Fatalf("expected reload call after create, got %d", reloader.calls)
	}
	if _, err := fakeStore.GetOIDCClient("ui-created"); err != nil {
		t.Fatalf("expected created client in store: %v", err)
	}
	if len(auditStore.entries) == 0 {
		t.Fatalf("expected audit entry after create")
	}
}

func TestEditClient(t *testing.T) {
	fakeStore := newFakeUIStore()
	if err := fakeStore.CreateOIDCClient(store.OIDCClient{
		ID:            "edit-me",
		Name:          "Before",
		Enabled:       true,
		Confidential:  false,
		RequirePKCE:   true,
		AuthMethod:    "none",
		GrantTypes:    []string{"authorization_code"},
		ResponseTypes: []string{"code"},
		Scopes:        []string{"openid"},
		RedirectURIs:  []string{"https://example.com/callback"},
	}, nil); err != nil {
		t.Fatalf("seed client failed: %v", err)
	}

	auth := &fakeUIAuth{}
	reloader := &fakeReloader{}
	e := setupTestAdminUI(t, fakeStore, auth, reloader, &fakeAuditStore{})

	form := url.Values{}
	form.Set("name", "After")
	form.Set("enabled", "true")
	form.Set("require_pkce", "true")
	form.Set("auth_method", "none")
	form.Set("grant_types", "authorization_code")
	form.Set("response_types", "code")
	form.Set("scopes", "openid profile")

	rec := doUIRequest(t, e, http.MethodPost, "/admin/clients/edit-me/edit", form, auth.sessionCookies())
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expected 303 for update, got %d body=%s", rec.Code, rec.Body.String())
	}
	if reloader.calls != 1 {
		t.Fatalf("expected reload call after update, got %d", reloader.calls)
	}
	client, _ := fakeStore.GetOIDCClient("edit-me")
	if client.Name != "After" {
		t.Fatalf("expected updated name, got %s", client.Name)
	}
}

func TestReplaceRedirectURIs(t *testing.T) {
	fakeStore := newFakeUIStore()
	if err := fakeStore.CreateOIDCClient(store.OIDCClient{
		ID:            "redir",
		Name:          "Redirect",
		Enabled:       true,
		Confidential:  false,
		RequirePKCE:   true,
		AuthMethod:    "none",
		GrantTypes:    []string{"authorization_code"},
		ResponseTypes: []string{"code"},
		Scopes:        []string{"openid"},
		RedirectURIs:  []string{"https://example.com/old"},
	}, nil); err != nil {
		t.Fatalf("seed client failed: %v", err)
	}

	auth := &fakeUIAuth{}
	e := setupTestAdminUI(t, fakeStore, auth, &fakeReloader{}, &fakeAuditStore{})

	recBad := doUIRequest(t, e, http.MethodPost, "/admin/clients/redir/redirect-uris", url.Values{"redirect_uris": []string{" \n \n"}}, auth.sessionCookies())
	if recBad.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for empty redirect uris, got %d", recBad.Code)
	}

	okForm := url.Values{}
	okForm.Set("redirect_uris", "https://example.com/new1\nhttps://example.com/new2\nhttps://example.com/new2")
	recOK := doUIRequest(t, e, http.MethodPost, "/admin/clients/redir/redirect-uris", okForm, auth.sessionCookies())
	if recOK.Code != http.StatusSeeOther {
		t.Fatalf("expected 303 for redirect uri replace, got %d body=%s", recOK.Code, recOK.Body.String())
	}
	client, _ := fakeStore.GetOIDCClient("redir")
	if len(client.RedirectURIs) != 2 {
		t.Fatalf("expected 2 redirect uris, got %+v", client.RedirectURIs)
	}
}

func TestAddSecretAndPublicClientError(t *testing.T) {
	fakeStore := newFakeUIStore()
	if err := fakeStore.CreateOIDCClient(store.OIDCClient{
		ID:            "conf",
		Name:          "Conf",
		Enabled:       true,
		Confidential:  true,
		RequirePKCE:   true,
		AuthMethod:    "basic",
		GrantTypes:    []string{"authorization_code"},
		ResponseTypes: []string{"code"},
		Scopes:        []string{"openid"},
		RedirectURIs:  []string{"https://example.com/conf"},
	}, []store.OIDCClientSecretInput{{PlainSecret: "initial", Label: "initial"}}); err != nil {
		t.Fatalf("seed confidential client failed: %v", err)
	}
	if err := fakeStore.CreateOIDCClient(store.OIDCClient{
		ID:            "pub",
		Name:          "Public",
		Enabled:       true,
		Confidential:  false,
		RequirePKCE:   true,
		AuthMethod:    "none",
		GrantTypes:    []string{"authorization_code"},
		ResponseTypes: []string{"code"},
		Scopes:        []string{"openid"},
		RedirectURIs:  []string{"https://example.com/pub"},
	}, nil); err != nil {
		t.Fatalf("seed public client failed: %v", err)
	}

	auth := &fakeUIAuth{}
	auditStore := &fakeAuditStore{}
	e := setupTestAdminUI(t, fakeStore, auth, &fakeReloader{}, auditStore)

	genForm := url.Values{}
	genForm.Set("label", "generated")
	genForm.Set("generate", "true")
	recGen := doUIRequest(t, e, http.MethodPost, "/admin/clients/conf/secrets", genForm, auth.sessionCookies())
	if recGen.Code != http.StatusOK {
		t.Fatalf("expected 200 for generated secret page, got %d body=%s", recGen.Code, recGen.Body.String())
	}
	if !strings.Contains(recGen.Body.String(), "Secret Created") {
		t.Fatalf("expected generated secret page, got %s", recGen.Body.String())
	}
	plainSecret := extractSecretFromPage(recGen.Body.String())
	if plainSecret == "" {
		t.Fatalf("expected one-time secret to be present in response")
	}
	if len(auditStore.entries) == 0 {
		t.Fatalf("expected audit entries after add secret")
	}
	lastAudit := auditStore.entries[len(auditStore.entries)-1]
	if strings.Contains(string(lastAudit.DetailsJSON), plainSecret) {
		t.Fatalf("audit details leaked plaintext secret")
	}

	pubForm := url.Values{}
	pubForm.Set("label", "nope")
	pubForm.Set("secret", "value")
	recPub := doUIRequest(t, e, http.MethodPost, "/admin/clients/pub/secrets", pubForm, auth.sessionCookies())
	if recPub.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for public client secret add, got %d body=%s", recPub.Code, recPub.Body.String())
	}
}

func TestRevokeSecretAndLastActiveConflict(t *testing.T) {
	fakeStore := newFakeUIStore()
	if err := fakeStore.CreateOIDCClient(store.OIDCClient{
		ID:            "revoke",
		Name:          "Revoke",
		Enabled:       true,
		Confidential:  true,
		RequirePKCE:   true,
		AuthMethod:    "basic",
		GrantTypes:    []string{"authorization_code"},
		ResponseTypes: []string{"code"},
		Scopes:        []string{"openid"},
		RedirectURIs:  []string{"https://example.com/conf"},
	}, []store.OIDCClientSecretInput{{PlainSecret: "one", Label: "one"}, {PlainSecret: "two", Label: "two"}}); err != nil {
		t.Fatalf("seed confidential client failed: %v", err)
	}

	secrets, _ := fakeStore.ListOIDCClientSecrets("revoke")
	if len(secrets) != 2 {
		t.Fatalf("expected 2 secrets, got %d", len(secrets))
	}

	auth := &fakeUIAuth{}
	e := setupTestAdminUI(t, fakeStore, auth, &fakeReloader{}, &fakeAuditStore{})

	recOK := doUIRequest(t, e, http.MethodPost, fmt.Sprintf("/admin/clients/revoke/secrets/%d/revoke", secrets[0].ID), nil, auth.sessionCookies())
	if recOK.Code != http.StatusSeeOther {
		t.Fatalf("expected 303 for first revoke, got %d body=%s", recOK.Code, recOK.Body.String())
	}

	recConflict := doUIRequest(t, e, http.MethodPost, fmt.Sprintf("/admin/clients/revoke/secrets/%d/revoke", secrets[1].ID), nil, auth.sessionCookies())
	if recConflict.Code != http.StatusConflict {
		t.Fatalf("expected 409 for last active revoke, got %d body=%s", recConflict.Code, recConflict.Body.String())
	}
	if !strings.Contains(strings.ToLower(recConflict.Body.String()), "at least one active secret") {
		t.Fatalf("expected last active secret error, got %s", recConflict.Body.String())
	}
}

func setupTestAdminUI(t *testing.T, fakeStore *fakeUIStore, auth *fakeUIAuth, reloader *fakeReloader, auditStore *fakeAuditStore) *echo.Echo {
	t.Helper()
	h, err := NewHandler(fakeStore, reloader, auditStore, auth)
	if err != nil {
		t.Fatalf("NewHandler failed: %v", err)
	}

	e := echo.New()
	group := e.Group("/admin")
	RegisterPublicRoutes(group, h)

	protected := group.Group("")
	protected.Use(auth.AttachSessionActorMiddleware())
	protected.Use(auth.RequireSessionMiddleware("/admin/login"))
	RegisterProtectedRoutes(protected, h)
	return e
}

func doUIRequest(t *testing.T, e *echo.Echo, method string, path string, form url.Values, cookies []*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()

	var body *bytes.Reader
	if form != nil {
		body = bytes.NewReader([]byte(form.Encode()))
	} else {
		body = bytes.NewReader(nil)
	}

	req := httptest.NewRequest(method, path, body)
	if form != nil {
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
	}
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}

	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	return rec
}

type fakeUIAuth struct {
	logoutCalled bool
	user         store.AdminUser
}

func (a *fakeUIAuth) SessionUser(c echo.Context) (*store.AdminUser, bool) {
	cookie, err := c.Cookie("admin_session")
	if err != nil || strings.TrimSpace(cookie.Value) != "ok" {
		return nil, false
	}
	user := a.user
	if strings.TrimSpace(user.ID) == "" {
		user = store.AdminUser{ID: "admin-1", Login: "admin", DisplayName: "Admin"}
	}
	admin.SetAdminActor(c, "admin_user", user.ID)
	c.Set("admin_user", &user)
	return &user, true
}

func (a *fakeUIAuth) LogoutSession(c echo.Context) error {
	a.logoutCalled = true
	c.SetCookie(&http.Cookie{Name: "admin_session", Value: "", Path: "/admin", MaxAge: -1})
	return nil
}

func (a *fakeUIAuth) RequireSessionMiddleware(loginPath string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			if _, ok := a.SessionUser(c); ok {
				return next(c)
			}
			return c.Redirect(http.StatusFound, loginPath)
		}
	}
}

func (a *fakeUIAuth) AttachSessionActorMiddleware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			_, _ = a.SessionUser(c)
			return next(c)
		}
	}
}

func (a *fakeUIAuth) sessionCookies() []*http.Cookie {
	return []*http.Cookie{{Name: "admin_session", Value: "ok", Path: "/admin"}}
}

type fakeReloader struct {
	calls int
	fail  bool
}

func (r *fakeReloader) ReloadClients(ctx context.Context) error {
	r.calls++
	if r.fail {
		return errors.New("reload failed")
	}
	return nil
}

type fakeAuditStore struct {
	entries []store.AdminAuditEntry
}

func (a *fakeAuditStore) CreateAdminAuditEntry(ctx context.Context, entry store.AdminAuditEntry) error {
	entry.DetailsJSON = append([]byte(nil), entry.DetailsJSON...)
	a.entries = append(a.entries, entry)
	return nil
}

type fakeUIStore struct {
	clients      map[string]store.OIDCClient
	secrets      map[string][]store.OIDCClientSecret
	nextSecretID int64
}

func newFakeUIStore() *fakeUIStore {
	return &fakeUIStore{
		clients:      map[string]store.OIDCClient{},
		secrets:      map[string][]store.OIDCClientSecret{},
		nextSecretID: 1,
	}
}

func (s *fakeUIStore) ListOIDCClients() ([]store.OIDCClient, error) {
	out := make([]store.OIDCClient, 0, len(s.clients))
	for _, client := range s.clients {
		copyClient := client
		copyClient.GrantTypes = append([]string(nil), client.GrantTypes...)
		copyClient.ResponseTypes = append([]string(nil), client.ResponseTypes...)
		copyClient.Scopes = append([]string(nil), client.Scopes...)
		copyClient.RedirectURIs = append([]string(nil), client.RedirectURIs...)
		out = append(out, copyClient)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (s *fakeUIStore) GetOIDCClient(id string) (*store.OIDCClient, error) {
	id = strings.TrimSpace(id)
	client, ok := s.clients[id]
	if !ok {
		return nil, store.ErrOIDCClientNotFound
	}
	copyClient := client
	copyClient.GrantTypes = append([]string(nil), client.GrantTypes...)
	copyClient.ResponseTypes = append([]string(nil), client.ResponseTypes...)
	copyClient.Scopes = append([]string(nil), client.Scopes...)
	copyClient.RedirectURIs = append([]string(nil), client.RedirectURIs...)
	return &copyClient, nil
}

func (s *fakeUIStore) ListOIDCClientSecrets(clientID string) ([]store.OIDCClientSecret, error) {
	items := s.secrets[strings.TrimSpace(clientID)]
	out := make([]store.OIDCClientSecret, 0, len(items))
	for _, item := range items {
		copyItem := item
		out = append(out, copyItem)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].ID > out[j].ID
		}
		return out[i].CreatedAt.After(out[j].CreatedAt)
	})
	return out, nil
}

func (s *fakeUIStore) CreateOIDCClient(client store.OIDCClient, secrets []store.OIDCClientSecretInput) error {
	client.ID = strings.TrimSpace(client.ID)
	if client.ID == "" {
		return errors.New("client id is required")
	}
	if _, exists := s.clients[client.ID]; exists {
		return errors.New("duplicate client id")
	}
	if len(client.RedirectURIs) == 0 {
		return errors.New("at least one redirect_uri is required")
	}
	if client.Confidential && len(secrets) == 0 {
		return errors.New("confidential client requires at least one active secret")
	}
	if !client.Confidential && len(secrets) > 0 {
		return errors.New("public client must not have secrets")
	}
	if strings.TrimSpace(client.AuthMethod) == "" {
		client.AuthMethod = "none"
	}
	client.GrantTypes = normalizeStringList(client.GrantTypes)
	client.ResponseTypes = normalizeStringList(client.ResponseTypes)
	client.Scopes = normalizeStringList(client.Scopes)
	client.RedirectURIs = normalizeStringList(client.RedirectURIs)
	if len(client.GrantTypes) == 0 || len(client.ResponseTypes) == 0 || len(client.Scopes) == 0 {
		return errors.New("invalid client fields")
	}
	if client.Confidential && strings.EqualFold(client.AuthMethod, "none") {
		return errors.New("unsupported auth_method")
	}

	now := time.Now().UTC()
	client.CreatedAt = now
	client.UpdatedAt = now
	s.clients[client.ID] = client

	for _, secret := range secrets {
		trimmed := strings.TrimSpace(secret.PlainSecret)
		if trimmed == "" {
			continue
		}
		s.secrets[client.ID] = append(s.secrets[client.ID], store.OIDCClientSecret{
			ID:         s.nextSecretID,
			ClientID:   client.ID,
			SecretHash: "hash:" + trimmed,
			Label:      strings.TrimSpace(secret.Label),
			CreatedAt:  now,
		})
		s.nextSecretID++
	}
	return nil
}

func (s *fakeUIStore) UpdateOIDCClient(client store.OIDCClient) error {
	current, ok := s.clients[client.ID]
	if !ok {
		return store.ErrOIDCClientNotFound
	}
	if client.Confidential != current.Confidential {
		return errors.New("confidential flag change is not supported in mvp")
	}
	if client.Confidential {
		active := 0
		for _, secret := range s.secrets[client.ID] {
			if secret.RevokedAt == nil {
				active++
			}
		}
		if active == 0 {
			return errors.New("confidential client requires at least one active secret")
		}
	}
	client.CreatedAt = current.CreatedAt
	client.UpdatedAt = time.Now().UTC()
	client.RedirectURIs = append([]string(nil), current.RedirectURIs...)
	s.clients[client.ID] = client
	return nil
}

func (s *fakeUIStore) ReplaceOIDCClientRedirectURIs(clientID string, uris []string) error {
	client, ok := s.clients[clientID]
	if !ok {
		return store.ErrOIDCClientNotFound
	}
	uris = normalizeStringList(uris)
	if len(uris) == 0 {
		return errors.New("at least one redirect_uri is required")
	}
	client.RedirectURIs = uris
	client.UpdatedAt = time.Now().UTC()
	s.clients[clientID] = client
	return nil
}

func (s *fakeUIStore) AddOIDCClientSecret(clientID string, plainSecret string, label string) error {
	client, ok := s.clients[clientID]
	if !ok {
		return store.ErrOIDCClientNotFound
	}
	if !client.Confidential {
		return errors.New("public client has no secrets")
	}
	if strings.TrimSpace(plainSecret) == "" {
		return errors.New("secret is required")
	}
	now := time.Now().UTC()
	s.secrets[clientID] = append(s.secrets[clientID], store.OIDCClientSecret{
		ID:         s.nextSecretID,
		ClientID:   clientID,
		SecretHash: "hash:" + strings.TrimSpace(plainSecret),
		Label:      strings.TrimSpace(label),
		CreatedAt:  now,
	})
	s.nextSecretID++
	client.UpdatedAt = now
	s.clients[clientID] = client
	return nil
}

func (s *fakeUIStore) RevokeOIDCClientSecret(clientID string, secretID int64) error {
	client, ok := s.clients[clientID]
	if !ok {
		return store.ErrOIDCClientNotFound
	}
	items := s.secrets[clientID]
	idx := -1
	active := 0
	for i, item := range items {
		if item.RevokedAt == nil {
			active++
		}
		if item.ID == secretID {
			idx = i
		}
	}
	if idx < 0 {
		return store.ErrOIDCClientSecretNotFound
	}
	if items[idx].RevokedAt == nil && client.Confidential && active <= 1 {
		return errors.New("must keep at least one active secret for confidential client")
	}
	if items[idx].RevokedAt != nil {
		return nil
	}
	now := time.Now().UTC()
	items[idx].RevokedAt = &now
	s.secrets[clientID] = items
	client.UpdatedAt = now
	s.clients[clientID] = client
	return nil
}

func extractSecretFromPage(body string) string {
	startMarker := "<textarea readonly style=\"min-height:80px; font-size:16px;\">"
	endMarker := "</textarea>"
	start := strings.Index(body, startMarker)
	if start < 0 {
		return ""
	}
	start += len(startMarker)
	end := strings.Index(body[start:], endMarker)
	if end < 0 {
		return ""
	}
	return strings.TrimSpace(body[start : start+end])
}

func TestAuditDetailsJSONNeverContainsSecretMaterial(t *testing.T) {
	details := map[string]any{
		"label":       "x",
		"plain_secret": "hidden",
		"secret_hash": "hashed",
		"secret":      "raw",
	}
	payload := buildAuditDetailsJSON(details, 5, nil)
	if strings.Contains(string(payload), "hidden") || strings.Contains(string(payload), "hashed") || strings.Contains(string(payload), "raw") {
		t.Fatalf("payload leaked secret material: %s", string(payload))
	}
	var parsed map[string]any
	if err := json.Unmarshal(payload, &parsed); err != nil {
		t.Fatalf("invalid payload: %v", err)
	}
	if _, ok := parsed["secret_id"]; !ok {
		t.Fatalf("expected secret_id in payload")
	}
}
