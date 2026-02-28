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

func TestOverviewRequiresSession(t *testing.T) {
	e := setupTestAdminUI(t, newFakeUIStore(), &fakeUIAuth{}, &fakeReloader{}, &fakeAuditStore{})

	rec := doUIRequest(t, e, http.MethodGet, "/admin/", nil, nil)
	if rec.Code != http.StatusFound {
		t.Fatalf("expected 302 redirect, got %d", rec.Code)
	}
	if location := rec.Header().Get(echo.HeaderLocation); location != "/admin/login" {
		t.Fatalf("expected redirect to /admin/login, got %s", location)
	}
}

func TestOverviewRendersSummaryAndRecentBlocks(t *testing.T) {
	fakeStore := newFakeUIStore()
	auth := &fakeUIAuth{}
	auditStore := &fakeAuditStore{
		entries: []store.AdminAuditEntry{
			{
				ID:           1,
				CreatedAt:    time.Now().UTC().Add(-2 * time.Minute),
				Action:       "admin.oidc_client.create",
				Success:      true,
				ActorType:    "admin_user",
				ActorID:      "admin-1",
				ResourceType: "oidc_client",
				ResourceID:   "client-a",
				RequestID:    "req-ok",
				RemoteIP:     "127.0.0.1",
				DetailsJSON:  json.RawMessage(`{"x":1}`),
			},
			{
				ID:           2,
				CreatedAt:    time.Now().UTC().Add(-1 * time.Minute),
				Action:       "admin.oidc_client.secret.revoke",
				Success:      false,
				ActorType:    "admin_user",
				ActorID:      "admin-1",
				ResourceType: "oidc_client_secret",
				ResourceID:   "12",
				RequestID:    "req-fail",
				RemoteIP:     "127.0.0.1",
				DetailsJSON:  json.RawMessage(`{"error":"x"}`),
			},
		},
	}

	_ = fakeStore.CreateOIDCClient(store.OIDCClient{
		ID:            "client-a",
		Name:          "A",
		Enabled:       true,
		Confidential:  true,
		RequirePKCE:   true,
		AuthMethod:    "basic",
		GrantTypes:    []string{"authorization_code"},
		ResponseTypes: []string{"code"},
		Scopes:        []string{"openid"},
		RedirectURIs:  []string{"https://a.example/cb"},
	}, []store.OIDCClientSecretInput{{PlainSecret: "secret-a"}})
	_ = fakeStore.CreateOIDCClient(store.OIDCClient{
		ID:            "client-b",
		Name:          "B",
		Enabled:       false,
		Confidential:  false,
		RequirePKCE:   true,
		AuthMethod:    "none",
		GrantTypes:    []string{"authorization_code"},
		ResponseTypes: []string{"code"},
		Scopes:        []string{"openid"},
		RedirectURIs:  []string{"https://b.example/cb"},
	}, nil)

	target, err := fakeStore.CreateAdminUser("pending", "Pending Admin")
	if err != nil {
		t.Fatalf("create pending admin failed: %v", err)
	}
	_, err = fakeStore.CreateAdminInvite(context.Background(), target.ID, "admin-1", "hash-active", time.Now().UTC().Add(12*time.Hour), "oncall")
	if err != nil {
		t.Fatalf("create active invite failed: %v", err)
	}
	_, err = fakeStore.CreateAdminInvite(context.Background(), target.ID, "admin-1", "hash-expired", time.Now().UTC().Add(-2*time.Hour), "expired")
	if err != nil {
		t.Fatalf("create expired invite failed: %v", err)
	}

	e := setupTestAdminUI(t, fakeStore, auth, &fakeReloader{}, auditStore)
	rec := doUIRequest(t, e, http.MethodGet, "/admin/", nil, auth.sessionCookies())
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, expected := range []string{
		"Overview Dashboard",
		"Recent Audit Activity",
		"Recent Failures",
		"Recent Client Changes",
		"Pending Invites",
		"Admin Users",
	} {
		if !strings.Contains(body, expected) {
			t.Fatalf("expected %q on overview page", expected)
		}
	}
}

func TestOverviewOwnerSeesPendingInvites(t *testing.T) {
	fakeStore := newFakeUIStore()
	auth := &fakeUIAuth{}
	target, _ := fakeStore.CreateAdminUser("invitee", "Invitee")
	_, _ = fakeStore.CreateAdminInvite(context.Background(), target.ID, "admin-1", "h-owner", time.Now().UTC().Add(8*time.Hour), "")

	e := setupTestAdminUI(t, fakeStore, auth, &fakeReloader{}, &fakeAuditStore{})
	rec := doUIRequest(t, e, http.MethodGet, "/admin/", nil, auth.sessionCookies())
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Pending Invites") || !strings.Contains(body, "invitee") {
		t.Fatalf("owner should see pending invites block, body=%s", body)
	}
}

func TestOverviewNonOwnerHidesOwnerOnlyBlocks(t *testing.T) {
	fakeStore := newFakeUIStore()
	auth := &fakeUIAuth{
		user: store.AdminUser{ID: "admin-1", Login: "admin", DisplayName: "Admin", Role: store.AdminRoleAdmin},
	}
	target, _ := fakeStore.CreateAdminUser("invitee", "Invitee")
	_, _ = fakeStore.CreateAdminInvite(context.Background(), target.ID, "admin-1", "h-nonowner", time.Now().UTC().Add(8*time.Hour), "")

	e := setupTestAdminUI(t, fakeStore, auth, &fakeReloader{}, &fakeAuditStore{})
	rec := doUIRequest(t, e, http.MethodGet, "/admin/", nil, auth.sessionCookies())
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if strings.Contains(body, "Pending Invites") || strings.Contains(body, "Admin Users") {
		t.Fatalf("non-owner should not see owner-only dashboard blocks, body=%s", body)
	}
}

func TestOverviewRecentFailuresBlockShowsFailures(t *testing.T) {
	auth := &fakeUIAuth{}
	auditStore := &fakeAuditStore{
		entries: []store.AdminAuditEntry{
			{
				ID:           1,
				CreatedAt:    time.Now().UTC(),
				Action:       "admin.oidc_client.secret.revoke",
				Success:      false,
				ActorType:    "admin_user",
				ActorID:      "admin-1",
				ResourceType: "oidc_client_secret",
				ResourceID:   "99",
				RequestID:    "req-f",
				RemoteIP:     "127.0.0.1",
				DetailsJSON:  json.RawMessage(`{"error":"failed"}`),
			},
		},
	}
	e := setupTestAdminUI(t, newFakeUIStore(), auth, &fakeReloader{}, auditStore)
	rec := doUIRequest(t, e, http.MethodGet, "/admin/", nil, auth.sessionCookies())
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Recent Failures") || !strings.Contains(body, "admin.oidc_client.secret.revoke") {
		t.Fatalf("expected failure action in recent failures block, body=%s", body)
	}
}

func TestOverviewClientSummaryCounts(t *testing.T) {
	fakeStore := newFakeUIStore()
	auth := &fakeUIAuth{
		user: store.AdminUser{ID: "admin-1", Login: "admin", DisplayName: "Admin", Role: store.AdminRoleAdmin},
	}
	_ = fakeStore.CreateOIDCClient(store.OIDCClient{
		ID:            "client-1",
		Name:          "C1",
		Enabled:       true,
		Confidential:  true,
		RequirePKCE:   true,
		AuthMethod:    "basic",
		GrantTypes:    []string{"authorization_code"},
		ResponseTypes: []string{"code"},
		Scopes:        []string{"openid"},
		RedirectURIs:  []string{"https://c1.example/cb"},
	}, []store.OIDCClientSecretInput{{PlainSecret: "secret-1"}})
	_ = fakeStore.CreateOIDCClient(store.OIDCClient{
		ID:            "client-2",
		Name:          "C2",
		Enabled:       false,
		Confidential:  false,
		RequirePKCE:   true,
		AuthMethod:    "none",
		GrantTypes:    []string{"authorization_code"},
		ResponseTypes: []string{"code"},
		Scopes:        []string{"openid"},
		RedirectURIs:  []string{"https://c2.example/cb"},
	}, nil)

	e := setupTestAdminUI(t, fakeStore, auth, &fakeReloader{}, &fakeAuditStore{})
	rec := doUIRequest(t, e, http.MethodGet, "/admin/", nil, auth.sessionCookies())
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, expected := range []string{
		"<dt>Total</dt><dd>2</dd>",
		"<dt>Enabled</dt><dd>1</dd>",
		"<dt>Disabled</dt><dd>1</dd>",
		"<dt>Confidential</dt><dd>1</dd>",
		"<dt>Public</dt><dd>1</dd>",
	} {
		if !strings.Contains(body, expected) {
			t.Fatalf("expected summary snippet %q, body=%s", expected, body)
		}
	}
}

func TestAuditLogPageRequiresSession(t *testing.T) {
	e := setupTestAdminUI(t, newFakeUIStore(), &fakeUIAuth{}, &fakeReloader{}, &fakeAuditStore{})

	rec := doUIRequest(t, e, http.MethodGet, "/admin/audit", nil, nil)
	if rec.Code != http.StatusFound {
		t.Fatalf("expected 302 redirect, got %d", rec.Code)
	}
	if location := rec.Header().Get(echo.HeaderLocation); location != "/admin/login" {
		t.Fatalf("expected redirect to /admin/login, got %s", location)
	}
}

func TestAuditLogPageFiltersAndHidesSensitiveDetails(t *testing.T) {
	auth := &fakeUIAuth{}
	auditStore := &fakeAuditStore{
		entries: []store.AdminAuditEntry{
			{
				ID:           10,
				CreatedAt:    time.Now().UTC().Add(-2 * time.Minute),
				Action:       "admin.oidc_client.create",
				Success:      true,
				ActorType:    "admin_user",
				ActorID:      "alice",
				ResourceType: "oidc_client",
				ResourceID:   "client-a",
				RequestID:    "req-1",
				RemoteIP:     "10.0.0.1",
				DetailsJSON:  json.RawMessage(`{"redirect_uri_count":1}`),
			},
			{
				ID:           11,
				CreatedAt:    time.Now().UTC().Add(-1 * time.Minute),
				Action:       "admin.oidc_client.create",
				Success:      false,
				ActorType:    "admin_user",
				ActorID:      "alice",
				ResourceType: "oidc_client",
				ResourceID:   "client-b",
				RequestID:    "req-2",
				RemoteIP:     "10.0.0.2",
				DetailsJSON:  json.RawMessage(`{"error":"validation_failed","secret":"TOP_SECRET_VALUE","token":"jwt"}`),
			},
			{
				ID:           12,
				CreatedAt:    time.Now().UTC(),
				Action:       "admin.auth.login.success",
				Success:      true,
				ActorType:    "admin_user",
				ActorID:      "bob",
				ResourceType: "admin_user",
				ResourceID:   "bob",
				RequestID:    "req-3",
				RemoteIP:     "10.0.0.3",
				DetailsJSON:  json.RawMessage(`{"login":"bob"}`),
			},
		},
	}

	e := setupTestAdminUI(t, newFakeUIStore(), auth, &fakeReloader{}, auditStore)
	rec := doUIRequest(t, e, http.MethodGet, "/admin/audit?action=admin.oidc_client.create&success=failure&actor=alice&resource_id=client-b", nil, auth.sessionCookies())
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}

	body := rec.Body.String()
	if !strings.Contains(body, "Admin Audit Log") {
		t.Fatalf("expected audit page header")
	}
	if !strings.Contains(body, "client-b") || !strings.Contains(body, "req-2") {
		t.Fatalf("expected filtered entry in response")
	}
	if strings.Contains(body, "client-a") || strings.Contains(body, "req-1") || strings.Contains(body, "bob") {
		t.Fatalf("response contains entries that should have been filtered out: %s", body)
	}
	if strings.Contains(body, "TOP_SECRET_VALUE") || strings.Contains(strings.ToLower(body), "\"secret\"") || strings.Contains(strings.ToLower(body), "\"token\"") {
		t.Fatalf("audit details leaked sensitive values: %s", body)
	}
	if !strings.Contains(body, "validation_failed") {
		t.Fatalf("expected safe details_json fields in response")
	}
}

func TestAuditLogPagination(t *testing.T) {
	auth := &fakeUIAuth{}
	auditEntries := make([]store.AdminAuditEntry, 0, 30)
	now := time.Now().UTC()
	for i := 1; i <= 30; i++ {
		auditEntries = append(auditEntries, store.AdminAuditEntry{
			ID:           int64(i),
			CreatedAt:    now.Add(-time.Duration(i) * time.Second),
			Action:       fmt.Sprintf("action-%02d", i),
			Success:      i%2 == 0,
			ActorType:    "admin_user",
			ActorID:      "pager",
			ResourceType: "oidc_client",
			ResourceID:   fmt.Sprintf("client-%02d", i),
			RequestID:    fmt.Sprintf("req-%02d", i),
			RemoteIP:     "127.0.0.1",
			DetailsJSON:  json.RawMessage(`{"index":1}`),
		})
	}

	e := setupTestAdminUI(t, newFakeUIStore(), auth, &fakeReloader{}, &fakeAuditStore{entries: auditEntries})

	page1 := doUIRequest(t, e, http.MethodGet, "/admin/audit", nil, auth.sessionCookies())
	if page1.Code != http.StatusOK {
		t.Fatalf("expected page 1 200, got %d body=%s", page1.Code, page1.Body.String())
	}
	body1 := page1.Body.String()
	if !strings.Contains(body1, "action-30") || !strings.Contains(body1, "action-06") {
		t.Fatalf("expected newest entries on page 1")
	}
	if strings.Contains(body1, "action-05") {
		t.Fatalf("page 1 should not include second-page entries")
	}
	if !strings.Contains(body1, ">Next<") {
		t.Fatalf("expected next link on page 1")
	}
	if strings.Contains(body1, ">Previous<") {
		t.Fatalf("did not expect previous link on page 1")
	}

	page2 := doUIRequest(t, e, http.MethodGet, "/admin/audit?page=2", nil, auth.sessionCookies())
	if page2.Code != http.StatusOK {
		t.Fatalf("expected page 2 200, got %d body=%s", page2.Code, page2.Body.String())
	}
	body2 := page2.Body.String()
	if !strings.Contains(body2, "Page 2") {
		t.Fatalf("expected page marker for page 2")
	}
	if !strings.Contains(body2, "action-05") || !strings.Contains(body2, "action-01") {
		t.Fatalf("expected second page entries")
	}
	if strings.Contains(body2, "action-30") {
		t.Fatalf("page 2 should not include first-page entries")
	}
	if !strings.Contains(body2, ">Previous<") {
		t.Fatalf("expected previous link on page 2")
	}
	if strings.Contains(body2, ">Next<") {
		t.Fatalf("did not expect next link on last page")
	}
}

func TestSecurityPageRequiresSession(t *testing.T) {
	e := setupTestAdminUI(t, newFakeUIStore(), &fakeUIAuth{}, &fakeReloader{}, &fakeAuditStore{})

	rec := doUIRequest(t, e, http.MethodGet, "/admin/security", nil, nil)
	if rec.Code != http.StatusFound {
		t.Fatalf("expected 302 redirect, got %d", rec.Code)
	}
	if location := rec.Header().Get(echo.HeaderLocation); location != "/admin/login" {
		t.Fatalf("expected redirect to /admin/login, got %s", location)
	}
}

func TestAdminsPageRequiresSession(t *testing.T) {
	e := setupTestAdminUI(t, newFakeUIStore(), &fakeUIAuth{}, &fakeReloader{}, &fakeAuditStore{})

	rec := doUIRequest(t, e, http.MethodGet, "/admin/admins", nil, nil)
	if rec.Code != http.StatusFound {
		t.Fatalf("expected 302 redirect, got %d", rec.Code)
	}
	if location := rec.Header().Get(echo.HeaderLocation); location != "/admin/login" {
		t.Fatalf("expected redirect to /admin/login, got %s", location)
	}
}

func TestOwnerCanAccessAdminsSection(t *testing.T) {
	auth := &fakeUIAuth{}
	e := setupTestAdminUI(t, newFakeUIStore(), auth, &fakeReloader{}, &fakeAuditStore{})

	rec := doUIRequest(t, e, http.MethodGet, "/admin/admins", nil, auth.sessionCookies())
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for owner, got %d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "Admin Users") {
		t.Fatalf("expected admins page content, got %s", rec.Body.String())
	}
}

func TestAdminCannotAccessAdminsSection(t *testing.T) {
	auth := &fakeUIAuth{
		user: store.AdminUser{ID: "admin-1", Login: "admin", DisplayName: "Admin", Role: store.AdminRoleAdmin},
	}
	e := setupTestAdminUI(t, newFakeUIStore(), auth, &fakeReloader{}, &fakeAuditStore{})

	rec := doUIRequest(t, e, http.MethodGet, "/admin/admins", nil, auth.sessionCookies())
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for non-owner, got %d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(strings.ToLower(rec.Body.String()), "owner role required") {
		t.Fatalf("expected owner role error message, got %s", rec.Body.String())
	}
}

func TestCreateSecondAdminUserAndInvite(t *testing.T) {
	fakeStore := newFakeUIStore()
	auth := &fakeUIAuth{}
	auditStore := &fakeAuditStore{}
	e := setupTestAdminUI(t, fakeStore, auth, &fakeReloader{}, auditStore)
	cookies, csrfToken := getCSRFCookiesAndToken(t, e, "/admin/admins/new", auth.sessionCookies())

	form := url.Values{}
	form.Set("login", "second-admin")
	form.Set("display_name", "Second Admin")
	form.Set("invite_note", "oncall")
	form.Set("invite_ttl_hours", "48")

	rec := doUIRequest(t, e, http.MethodPost, "/admin/admins/new", withCSRF(form, csrfToken), cookies)
	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201 on admin create, got %d body=%s", rec.Code, rec.Body.String())
	}

	created, err := fakeStore.GetAdminUserByLogin("second-admin")
	if err != nil {
		t.Fatalf("expected created admin user, err=%v", err)
	}
	if created.Role != store.AdminRoleAdmin {
		t.Fatalf("expected created admin role=%s, got %s", store.AdminRoleAdmin, created.Role)
	}
	invites, err := fakeStore.ListAdminInvites(context.Background(), created.ID)
	if err != nil {
		t.Fatalf("list invites failed: %v", err)
	}
	if len(invites) != 1 {
		t.Fatalf("expected one invite for created admin, got %d", len(invites))
	}

	body := rec.Body.String()
	token := extractInputValueByID(body, "invite_token_copy")
	link := extractInputValueByID(body, "invite_link_copy")
	if token == "" || link == "" {
		t.Fatalf("expected one-time token and link in invite created page")
	}
	if strings.Contains(link, invites[0].TokenHash) {
		t.Fatalf("invite link should not contain token hash")
	}
	if !strings.Contains(link, "/admin/invite/") {
		t.Fatalf("expected invite URL in body, got %s", link)
	}

	for _, entry := range auditStore.entries {
		if strings.Contains(string(entry.DetailsJSON), token) {
			t.Fatalf("plaintext invite token leaked into audit details")
		}
	}

	recDetail := doUIRequest(t, e, http.MethodGet, "/admin/admins/"+created.ID, nil, auth.sessionCookies())
	if recDetail.Code != http.StatusOK {
		t.Fatalf("expected admin detail 200, got %d body=%s", recDetail.Code, recDetail.Body.String())
	}
	if strings.Contains(recDetail.Body.String(), token) {
		t.Fatalf("plaintext invite token should not be visible on admin detail page")
	}
}

func TestAdminCannotCreateAdminUser(t *testing.T) {
	auth := &fakeUIAuth{
		user: store.AdminUser{ID: "admin-1", Login: "admin", DisplayName: "Admin", Role: store.AdminRoleAdmin},
	}
	e := setupTestAdminUI(t, newFakeUIStore(), auth, &fakeReloader{}, &fakeAuditStore{})
	cookies, csrfToken := getCSRFCookiesAndToken(t, e, "/admin/clients", auth.sessionCookies())

	form := url.Values{}
	form.Set("login", "blocked-admin")
	form.Set("display_name", "Blocked Admin")

	rec := doUIRequest(t, e, http.MethodPost, "/admin/admins/new", withCSRF(form, csrfToken), cookies)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for non-owner admin create, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestOwnerCanChangeRole(t *testing.T) {
	fakeStore := newFakeUIStore()
	auth := &fakeUIAuth{}
	e := setupTestAdminUI(t, fakeStore, auth, &fakeReloader{}, &fakeAuditStore{})

	target, err := fakeStore.CreateAdminUser("second", "Second")
	if err != nil {
		t.Fatalf("create second admin failed: %v", err)
	}

	cookies, csrfToken := getCSRFCookiesAndToken(t, e, "/admin/admins/"+target.ID, auth.sessionCookies())
	formPromote := url.Values{}
	formPromote.Set("role", store.AdminRoleOwner)
	recPromote := doUIRequest(t, e, http.MethodPost, "/admin/admins/"+target.ID+"/role", withCSRF(formPromote, csrfToken), cookies)
	if recPromote.Code != http.StatusSeeOther {
		t.Fatalf("expected 303 on promote, got %d body=%s", recPromote.Code, recPromote.Body.String())
	}
	afterPromote, err := fakeStore.GetAdminUser(target.ID)
	if err != nil {
		t.Fatalf("get promoted user failed: %v", err)
	}
	if afterPromote.Role != store.AdminRoleOwner {
		t.Fatalf("expected promoted role owner, got %s", afterPromote.Role)
	}

	formDemote := url.Values{}
	formDemote.Set("role", store.AdminRoleAdmin)
	recDemote := doUIRequest(t, e, http.MethodPost, "/admin/admins/admin-1/role", withCSRF(formDemote, csrfToken), cookies)
	if recDemote.Code != http.StatusSeeOther {
		t.Fatalf("expected 303 on demote, got %d body=%s", recDemote.Code, recDemote.Body.String())
	}
	rootAfter, err := fakeStore.GetAdminUser("admin-1")
	if err != nil {
		t.Fatalf("get root admin failed: %v", err)
	}
	if rootAfter.Role != store.AdminRoleAdmin {
		t.Fatalf("expected root role admin after demote, got %s", rootAfter.Role)
	}
}

func TestCannotDemoteLastEnabledOwner(t *testing.T) {
	fakeStore := newFakeUIStore()
	auth := &fakeUIAuth{}
	e := setupTestAdminUI(t, fakeStore, auth, &fakeReloader{}, &fakeAuditStore{})

	cookies, csrfToken := getCSRFCookiesAndToken(t, e, "/admin/admins/admin-1", auth.sessionCookies())
	form := url.Values{}
	form.Set("role", store.AdminRoleAdmin)
	rec := doUIRequest(t, e, http.MethodPost, "/admin/admins/admin-1/role", withCSRF(form, csrfToken), cookies)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expected 303 on blocked demote, got %d body=%s", rec.Code, rec.Body.String())
	}

	root, err := fakeStore.GetAdminUser("admin-1")
	if err != nil {
		t.Fatalf("get root admin failed: %v", err)
	}
	if root.Role != store.AdminRoleOwner {
		t.Fatalf("expected last owner role to stay owner, got %s", root.Role)
	}
}

func TestCannotDisableLastEnabledOwner(t *testing.T) {
	fakeStore := newFakeUIStore()
	extra, err := fakeStore.CreateAdminUser("owner2", "Owner Two")
	if err != nil {
		t.Fatalf("create extra admin failed: %v", err)
	}
	if err := fakeStore.SetAdminUserRole(extra.ID, store.AdminRoleOwner); err != nil {
		t.Fatalf("set extra role failed: %v", err)
	}
	if err := fakeStore.SetAdminUserEnabled(extra.ID, false); err != nil {
		t.Fatalf("disable extra owner failed: %v", err)
	}

	auth := &fakeUIAuth{
		user: store.AdminUser{ID: extra.ID, Login: "owner2", DisplayName: "Owner Two", Role: store.AdminRoleOwner},
	}
	e := setupTestAdminUI(t, fakeStore, auth, &fakeReloader{}, &fakeAuditStore{})

	cookies, csrfToken := getCSRFCookiesAndToken(t, e, "/admin/admins/admin-1", auth.sessionCookies())
	rec := doUIRequest(t, e, http.MethodPost, "/admin/admins/admin-1/disable", withCSRF(nil, csrfToken), cookies)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expected 303 on blocked disable, got %d body=%s", rec.Code, rec.Body.String())
	}

	root, err := fakeStore.GetAdminUser("admin-1")
	if err != nil {
		t.Fatalf("get root admin failed: %v", err)
	}
	if !root.Enabled {
		t.Fatalf("expected last enabled owner to remain enabled")
	}
}

func TestAdminRoleStillAllowsClientsAuditAndSecurity(t *testing.T) {
	fakeStore := newFakeUIStore()
	_ = fakeStore.CreateOIDCClient(store.OIDCClient{
		ID:            "client-allowed",
		Name:          "Allowed",
		Enabled:       true,
		Confidential:  false,
		RequirePKCE:   true,
		AuthMethod:    "none",
		GrantTypes:    []string{"authorization_code"},
		ResponseTypes: []string{"code"},
		Scopes:        []string{"openid"},
		RedirectURIs:  []string{"https://example.org/cb"},
	}, nil)

	auth := &fakeUIAuth{
		user: store.AdminUser{ID: "admin-1", Login: "admin", DisplayName: "Admin", Role: store.AdminRoleAdmin},
	}
	e := setupTestAdminUI(t, fakeStore, auth, &fakeReloader{}, &fakeAuditStore{})

	recClients := doUIRequest(t, e, http.MethodGet, "/admin/clients", nil, auth.sessionCookies())
	if recClients.Code != http.StatusOK {
		t.Fatalf("expected 200 on /admin/clients for admin role, got %d body=%s", recClients.Code, recClients.Body.String())
	}
	recAudit := doUIRequest(t, e, http.MethodGet, "/admin/audit", nil, auth.sessionCookies())
	if recAudit.Code != http.StatusOK {
		t.Fatalf("expected 200 on /admin/audit for admin role, got %d body=%s", recAudit.Code, recAudit.Body.String())
	}
	recSecurity := doUIRequest(t, e, http.MethodGet, "/admin/security", nil, auth.sessionCookies())
	if recSecurity.Code != http.StatusOK {
		t.Fatalf("expected 200 on /admin/security for admin role, got %d body=%s", recSecurity.Code, recSecurity.Body.String())
	}
}

func TestCreateAdminDuplicateLoginBlocked(t *testing.T) {
	auth := &fakeUIAuth{}
	e := setupTestAdminUI(t, newFakeUIStore(), auth, &fakeReloader{}, &fakeAuditStore{})
	cookies, csrfToken := getCSRFCookiesAndToken(t, e, "/admin/admins/new", auth.sessionCookies())
	form := url.Values{}
	form.Set("login", "admin")
	form.Set("display_name", "Duplicate")

	rec := doUIRequest(t, e, http.MethodPost, "/admin/admins/new", withCSRF(form, csrfToken), cookies)
	if rec.Code != http.StatusConflict {
		t.Fatalf("expected 409 on duplicate admin login, got %d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(strings.ToLower(rec.Body.String()), "already exists") {
		t.Fatalf("expected duplicate login error in response body")
	}
}

func TestAdminsMutatingRoutesRequireCSRF(t *testing.T) {
	auth := &fakeUIAuth{}
	e := setupTestAdminUI(t, newFakeUIStore(), auth, &fakeReloader{}, &fakeAuditStore{})

	form := url.Values{}
	form.Set("login", "no-csrf")
	form.Set("display_name", "No CSRF")
	rec := doUIRequest(t, e, http.MethodPost, "/admin/admins/new", form, auth.sessionCookies())
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 without csrf token, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestRevokeInviteBlocksPublicAcceptFlow(t *testing.T) {
	fakeStore := newFakeUIStore()
	auth := &fakeUIAuth{}
	e := setupTestAdminUI(t, fakeStore, auth, &fakeReloader{}, &fakeAuditStore{})

	created, err := fakeStore.CreateAdminUser("revokable", "Revokable Admin")
	if err != nil {
		t.Fatalf("create admin failed: %v", err)
	}
	token := "plain-token-revoke"
	tokenHash := hashInviteToken(token)
	invite, err := fakeStore.CreateAdminInvite(context.Background(), created.ID, "admin-1", tokenHash, time.Now().UTC().Add(12*time.Hour), "test")
	if err != nil {
		t.Fatalf("create invite failed: %v", err)
	}

	cookies, csrfToken := getCSRFCookiesAndToken(t, e, "/admin/admins/"+created.ID, auth.sessionCookies())
	recRevoke := doUIRequest(t, e, http.MethodPost, fmt.Sprintf("/admin/admins/%s/invites/%d/revoke", created.ID, invite.ID), withCSRF(nil, csrfToken), cookies)
	if recRevoke.Code != http.StatusSeeOther {
		t.Fatalf("expected 303 on revoke, got %d body=%s", recRevoke.Code, recRevoke.Body.String())
	}

	recPublic := doUIRequest(t, e, http.MethodGet, "/admin/invite/"+token, nil, nil)
	if recPublic.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for revoked invite accept page, got %d body=%s", recPublic.Code, recPublic.Body.String())
	}
	if !strings.Contains(strings.ToLower(recPublic.Body.String()), "invalid") {
		t.Fatalf("expected invalid invite message, got body=%s", recPublic.Body.String())
	}
}

func TestSecurityPageRendersPasskeysAndSessions(t *testing.T) {
	auth := &fakeUIAuth{
		passkeys: []store.AdminCredentialInfo{
			{ID: 11, CredentialID: "cred-one", CreatedAt: time.Now().UTC().Add(-2 * time.Hour)},
			{ID: 12, CredentialID: "cred-two", CreatedAt: time.Now().UTC().Add(-1 * time.Hour)},
		},
		sessions: []store.AdminSessionInfo{
			{
				SessionID:  "ok",
				CreatedAt:  time.Now().UTC().Add(-1 * time.Hour),
				LastSeenAt: time.Now().UTC().Add(-5 * time.Minute),
				ExpiresAt:  time.Now().UTC().Add(25 * time.Minute),
				RemoteIP:   "10.10.0.1",
				UserAgent:  "Mozilla/5.0",
				Current:    true,
			},
			{
				SessionID:  "other-session-1",
				CreatedAt:  time.Now().UTC().Add(-30 * time.Minute),
				LastSeenAt: time.Now().UTC().Add(-3 * time.Minute),
				ExpiresAt:  time.Now().UTC().Add(27 * time.Minute),
				RemoteIP:   "10.10.0.2",
				UserAgent:  "curl/8.0",
				Current:    false,
			},
		},
	}

	e := setupTestAdminUI(t, newFakeUIStore(), auth, &fakeReloader{}, &fakeAuditStore{})
	rec := doUIRequest(t, e, http.MethodGet, "/admin/security", nil, auth.sessionCookies())
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Admin Security") || !strings.Contains(body, "Passkeys") || !strings.Contains(body, "Active Sessions") {
		t.Fatalf("expected security sections in html")
	}
	if !strings.Contains(body, "current") {
		t.Fatalf("expected current session badge in html")
	}
	if !strings.Contains(body, `action="/admin/security/passkeys/`) || !strings.Contains(body, `action="/admin/security/sessions/`) {
		t.Fatalf("expected security mutate forms in html")
	}
	if strings.Count(body, `name="csrf_token" value="`) < 3 {
		t.Fatalf("expected csrf hidden fields in security forms")
	}
}

func TestSecurityPasskeyDeleteCSRFAndLastCredentialGuard(t *testing.T) {
	auth := &fakeUIAuth{
		passkeys: []store.AdminCredentialInfo{
			{ID: 21, CredentialID: "cred-a", CreatedAt: time.Now().UTC().Add(-2 * time.Hour)},
			{ID: 22, CredentialID: "cred-b", CreatedAt: time.Now().UTC().Add(-1 * time.Hour)},
		},
		sessions: []store.AdminSessionInfo{
			{SessionID: "ok", CreatedAt: time.Now().UTC().Add(-1 * time.Hour), LastSeenAt: time.Now().UTC().Add(-1 * time.Minute), ExpiresAt: time.Now().UTC().Add(20 * time.Minute), Current: true},
		},
	}
	e := setupTestAdminUI(t, newFakeUIStore(), auth, &fakeReloader{}, &fakeAuditStore{})
	cookies, csrfToken := getCSRFCookiesAndToken(t, e, "/admin/security", auth.sessionCookies())

	noToken := doUIRequest(t, e, http.MethodPost, "/admin/security/passkeys/21/delete", nil, auth.sessionCookies())
	if noToken.Code != http.StatusForbidden {
		t.Fatalf("expected 403 without csrf token, got %d body=%s", noToken.Code, noToken.Body.String())
	}

	recDelete := doUIRequest(t, e, http.MethodPost, "/admin/security/passkeys/21/delete", withCSRF(nil, csrfToken), cookies)
	if recDelete.Code != http.StatusSeeOther {
		t.Fatalf("expected 303 on delete with csrf token, got %d body=%s", recDelete.Code, recDelete.Body.String())
	}
	if len(auth.passkeys) != 1 || auth.passkeys[0].ID != 22 {
		t.Fatalf("expected passkey 21 to be deleted, remaining=%+v", auth.passkeys)
	}

	recLast := doUIRequest(t, e, http.MethodPost, "/admin/security/passkeys/22/delete", withCSRF(nil, csrfToken), cookies)
	if recLast.Code != http.StatusSeeOther {
		t.Fatalf("expected 303 on guarded delete attempt, got %d body=%s", recLast.Code, recLast.Body.String())
	}
	if len(auth.passkeys) != 1 || auth.passkeys[0].ID != 22 {
		t.Fatalf("expected last passkey to stay untouched, remaining=%+v", auth.passkeys)
	}
}

func TestSecuritySessionLogoutAndLogoutOthersWithCSRF(t *testing.T) {
	auth := &fakeUIAuth{
		passkeys: []store.AdminCredentialInfo{
			{ID: 31, CredentialID: "cred-a", CreatedAt: time.Now().UTC().Add(-1 * time.Hour)},
			{ID: 32, CredentialID: "cred-b", CreatedAt: time.Now().UTC().Add(-30 * time.Minute)},
		},
		sessions: []store.AdminSessionInfo{
			{
				SessionID:  "ok",
				CreatedAt:  time.Now().UTC().Add(-1 * time.Hour),
				LastSeenAt: time.Now().UTC().Add(-2 * time.Minute),
				ExpiresAt:  time.Now().UTC().Add(20 * time.Minute),
				Current:    true,
			},
			{
				SessionID:  "sess-2",
				CreatedAt:  time.Now().UTC().Add(-40 * time.Minute),
				LastSeenAt: time.Now().UTC().Add(-3 * time.Minute),
				ExpiresAt:  time.Now().UTC().Add(18 * time.Minute),
				Current:    false,
			},
			{
				SessionID:  "sess-3",
				CreatedAt:  time.Now().UTC().Add(-20 * time.Minute),
				LastSeenAt: time.Now().UTC().Add(-1 * time.Minute),
				ExpiresAt:  time.Now().UTC().Add(25 * time.Minute),
				Current:    false,
			},
		},
	}
	e := setupTestAdminUI(t, newFakeUIStore(), auth, &fakeReloader{}, &fakeAuditStore{})
	cookies, csrfToken := getCSRFCookiesAndToken(t, e, "/admin/security", auth.sessionCookies())

	noToken := doUIRequest(t, e, http.MethodPost, "/admin/security/sessions/sess-2/logout", nil, auth.sessionCookies())
	if noToken.Code != http.StatusForbidden {
		t.Fatalf("expected 403 without csrf token, got %d body=%s", noToken.Code, noToken.Body.String())
	}

	recOne := doUIRequest(t, e, http.MethodPost, "/admin/security/sessions/sess-2/logout", withCSRF(nil, csrfToken), cookies)
	if recOne.Code != http.StatusSeeOther {
		t.Fatalf("expected 303 for single session logout, got %d body=%s", recOne.Code, recOne.Body.String())
	}
	if len(auth.sessions) != 2 {
		t.Fatalf("expected one session removed, sessions=%+v", auth.sessions)
	}

	recOthers := doUIRequest(t, e, http.MethodPost, "/admin/security/sessions/logout-others", withCSRF(nil, csrfToken), cookies)
	if recOthers.Code != http.StatusSeeOther {
		t.Fatalf("expected 303 for logout others, got %d body=%s", recOthers.Code, recOthers.Body.String())
	}
	if len(auth.sessions) != 1 || !auth.sessions[0].Current || auth.sessions[0].SessionID != "ok" {
		t.Fatalf("expected only current session to remain, sessions=%+v", auth.sessions)
	}
}

func TestSensitiveActionRequiresRecentReauth(t *testing.T) {
	auth := &fakeUIAuth{
		disableAutoRecentReauth: true,
		sessions: []store.AdminSessionInfo{
			{
				SessionID:  "ok",
				CreatedAt:  time.Now().UTC().Add(-1 * time.Hour),
				LastSeenAt: time.Now().UTC().Add(-1 * time.Minute),
				ExpiresAt:  time.Now().UTC().Add(20 * time.Minute),
				Current:    true,
			},
			{
				SessionID:  "other",
				CreatedAt:  time.Now().UTC().Add(-40 * time.Minute),
				LastSeenAt: time.Now().UTC().Add(-3 * time.Minute),
				ExpiresAt:  time.Now().UTC().Add(18 * time.Minute),
				Current:    false,
			},
		},
	}
	e := setupTestAdminUI(t, newFakeUIStore(), auth, &fakeReloader{}, &fakeAuditStore{})
	cookies, csrfToken := getCSRFCookiesAndToken(t, e, "/admin/security", auth.sessionCookies())

	rec := doUIRequest(t, e, http.MethodPost, "/admin/security/sessions/logout-others", withCSRF(nil, csrfToken), cookies)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 without recent reauth, got %d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(strings.ToLower(rec.Body.String()), "recent admin re-auth required") {
		t.Fatalf("expected recent reauth required message, got %s", rec.Body.String())
	}
}

func TestSensitiveActionReauthRequiredJSONResponse(t *testing.T) {
	auth := &fakeUIAuth{
		disableAutoRecentReauth: true,
		sessions: []store.AdminSessionInfo{
			{SessionID: "ok", CreatedAt: time.Now().UTC().Add(-1 * time.Hour), LastSeenAt: time.Now().UTC().Add(-1 * time.Minute), ExpiresAt: time.Now().UTC().Add(20 * time.Minute), Current: true},
			{SessionID: "other", CreatedAt: time.Now().UTC().Add(-40 * time.Minute), LastSeenAt: time.Now().UTC().Add(-3 * time.Minute), ExpiresAt: time.Now().UTC().Add(18 * time.Minute), Current: false},
		},
	}
	e := setupTestAdminUI(t, newFakeUIStore(), auth, &fakeReloader{}, &fakeAuditStore{})
	cookies, csrfToken := getCSRFCookiesAndToken(t, e, "/admin/security", auth.sessionCookies())

	form := withCSRF(nil, csrfToken)
	req := httptest.NewRequest(http.MethodPost, "/admin/security/sessions/logout-others", bytes.NewReader([]byte(form.Encode())))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
	req.Header.Set(echo.HeaderAccept, echo.MIMEApplicationJSON)
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 json response without reauth, got %d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"code":"admin_reauth_required"`) {
		t.Fatalf("expected admin_reauth_required code, got %s", rec.Body.String())
	}
}

func TestSensitiveActionAfterRecentReauthSucceeds(t *testing.T) {
	now := time.Now().UTC()
	auth := &fakeUIAuth{
		disableAutoRecentReauth: true,
		recentReauthAt:          &now,
		sessions: []store.AdminSessionInfo{
			{
				SessionID:  "ok",
				CreatedAt:  time.Now().UTC().Add(-1 * time.Hour),
				LastSeenAt: time.Now().UTC().Add(-1 * time.Minute),
				ExpiresAt:  time.Now().UTC().Add(20 * time.Minute),
				Current:    true,
			},
			{
				SessionID:  "other",
				CreatedAt:  time.Now().UTC().Add(-40 * time.Minute),
				LastSeenAt: time.Now().UTC().Add(-3 * time.Minute),
				ExpiresAt:  time.Now().UTC().Add(18 * time.Minute),
				Current:    false,
			},
		},
	}
	e := setupTestAdminUI(t, newFakeUIStore(), auth, &fakeReloader{}, &fakeAuditStore{})
	cookies, csrfToken := getCSRFCookiesAndToken(t, e, "/admin/security", auth.sessionCookies())

	rec := doUIRequest(t, e, http.MethodPost, "/admin/security/sessions/logout-others", withCSRF(nil, csrfToken), cookies)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expected 303 with recent reauth, got %d body=%s", rec.Code, rec.Body.String())
	}
	if len(auth.sessions) != 1 || !auth.sessions[0].Current {
		t.Fatalf("expected other sessions removed after authorized action, sessions=%+v", auth.sessions)
	}
}

func TestExpiredRecentReauthBlocksSensitiveActionAgain(t *testing.T) {
	expired := time.Now().UTC().Add(-11 * time.Minute)
	auth := &fakeUIAuth{
		disableAutoRecentReauth: true,
		recentReauthAt:          &expired,
		reauthMaxAge:            5 * time.Minute,
		sessions: []store.AdminSessionInfo{
			{SessionID: "ok", CreatedAt: time.Now().UTC().Add(-1 * time.Hour), LastSeenAt: time.Now().UTC().Add(-1 * time.Minute), ExpiresAt: time.Now().UTC().Add(20 * time.Minute), Current: true},
			{SessionID: "other", CreatedAt: time.Now().UTC().Add(-40 * time.Minute), LastSeenAt: time.Now().UTC().Add(-3 * time.Minute), ExpiresAt: time.Now().UTC().Add(18 * time.Minute), Current: false},
		},
	}
	e := setupTestAdminUI(t, newFakeUIStore(), auth, &fakeReloader{}, &fakeAuditStore{})
	cookies, csrfToken := getCSRFCookiesAndToken(t, e, "/admin/security", auth.sessionCookies())

	rec := doUIRequest(t, e, http.MethodPost, "/admin/security/sessions/logout-others", withCSRF(nil, csrfToken), cookies)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 with expired reauth, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestCreateConfidentialClientRequiresRecentReauth(t *testing.T) {
	auth := &fakeUIAuth{disableAutoRecentReauth: true}
	fakeStore := newFakeUIStore()
	e := setupTestAdminUI(t, fakeStore, auth, &fakeReloader{}, &fakeAuditStore{})
	cookies, csrfToken := getCSRFCookiesAndToken(t, e, "/admin/clients/new", auth.sessionCookies())

	form := url.Values{}
	form.Set("id", "secure-client")
	form.Set("name", "Secure Client")
	form.Set("confidential", "true")
	form.Set("auth_method", "basic")
	form.Set("enabled", "true")
	form.Set("require_pkce", "true")
	form.Set("grant_types", "authorization_code")
	form.Set("response_types", "code")
	form.Set("scopes", "openid profile")
	form.Set("redirect_uris", "https://example.com/callback")
	form.Set("initial_secret", "topsecret")
	form.Set("initial_secret_label", "initial")

	recNoReauth := doUIRequest(t, e, http.MethodPost, "/admin/clients/new", withCSRF(form, csrfToken), cookies)
	if recNoReauth.Code != http.StatusForbidden {
		t.Fatalf("expected 403 without recent reauth for confidential create, got %d body=%s", recNoReauth.Code, recNoReauth.Body.String())
	}
	if _, err := fakeStore.GetOIDCClient("secure-client"); !errors.Is(err, store.ErrOIDCClientNotFound) {
		t.Fatalf("confidential client should not be created before recent reauth, err=%v", err)
	}

	now := time.Now().UTC()
	auth.recentReauthAt = &now
	recOK := doUIRequest(t, e, http.MethodPost, "/admin/clients/new", withCSRF(form, csrfToken), cookies)
	if recOK.Code != http.StatusSeeOther {
		t.Fatalf("expected 303 with recent reauth for confidential create, got %d body=%s", recOK.Code, recOK.Body.String())
	}
}

func TestDisableClientRequiresRecentReauth(t *testing.T) {
	fakeStore := newFakeUIStore()
	err := fakeStore.CreateOIDCClient(store.OIDCClient{
		ID:            "disable-me",
		Name:          "Disable Me",
		Enabled:       true,
		Confidential:  false,
		RequirePKCE:   true,
		AuthMethod:    "none",
		GrantTypes:    []string{"authorization_code"},
		ResponseTypes: []string{"code"},
		Scopes:        []string{"openid"},
		RedirectURIs:  []string{"https://example.com/callback"},
	}, nil)
	if err != nil {
		t.Fatalf("seed client failed: %v", err)
	}

	auth := &fakeUIAuth{disableAutoRecentReauth: true}
	e := setupTestAdminUI(t, fakeStore, auth, &fakeReloader{}, &fakeAuditStore{})
	cookies, csrfToken := getCSRFCookiesAndToken(t, e, "/admin/clients/disable-me/edit", auth.sessionCookies())

	form := url.Values{}
	form.Set("name", "Disable Me")
	form.Set("auth_method", "none")
	form.Set("require_pkce", "true")
	form.Set("grant_types", "authorization_code")
	form.Set("response_types", "code")
	form.Set("scopes", "openid")

	recNoReauth := doUIRequest(t, e, http.MethodPost, "/admin/clients/disable-me/edit", withCSRF(form, csrfToken), cookies)
	if recNoReauth.Code != http.StatusForbidden {
		t.Fatalf("expected 403 without recent reauth for disable action, got %d body=%s", recNoReauth.Code, recNoReauth.Body.String())
	}

	now := time.Now().UTC()
	auth.recentReauthAt = &now
	recOK := doUIRequest(t, e, http.MethodPost, "/admin/clients/disable-me/edit", withCSRF(form, csrfToken), cookies)
	if recOK.Code != http.StatusSeeOther {
		t.Fatalf("expected 303 with recent reauth for disable action, got %d body=%s", recOK.Code, recOK.Body.String())
	}
}

func TestNonSensitivePageDoesNotRequireRecentReauth(t *testing.T) {
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

	auth := &fakeUIAuth{disableAutoRecentReauth: true}
	e := setupTestAdminUI(t, fakeStore, auth, &fakeReloader{}, &fakeAuditStore{})

	rec := doUIRequest(t, e, http.MethodGet, "/admin/clients", nil, auth.sessionCookies())
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for non-sensitive page without reauth, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestCreateClientCSRFMissingTokenRejected(t *testing.T) {
	fakeStore := newFakeUIStore()
	auth := &fakeUIAuth{}
	e := setupTestAdminUI(t, fakeStore, auth, &fakeReloader{}, &fakeAuditStore{})

	form := url.Values{}
	form.Set("id", "csrf-missing")
	form.Set("name", "Missing token")
	form.Set("enabled", "true")
	form.Set("confidential", "false")
	form.Set("require_pkce", "true")
	form.Set("auth_method", "none")
	form.Set("grant_types", "authorization_code")
	form.Set("response_types", "code")
	form.Set("scopes", "openid profile")
	form.Set("redirect_uris", "https://example.com/callback")

	rec := doUIRequest(t, e, http.MethodPost, "/admin/clients/new", form, auth.sessionCookies())
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 without csrf token, got %d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(strings.ToLower(rec.Body.String()), "invalid csrf token") {
		t.Fatalf("expected invalid csrf token message, got %s", rec.Body.String())
	}
}

func TestCreateClientCSRFInvalidTokenRejected(t *testing.T) {
	fakeStore := newFakeUIStore()
	auth := &fakeUIAuth{}
	e := setupTestAdminUI(t, fakeStore, auth, &fakeReloader{}, &fakeAuditStore{})
	cookies, csrfToken := getCSRFCookiesAndToken(t, e, "/admin/clients/new", auth.sessionCookies())

	wrongToken, err := newCSRFToken()
	if err != nil {
		t.Fatalf("newCSRFToken failed: %v", err)
	}
	if wrongToken == csrfToken {
		t.Fatalf("expected different csrf token values")
	}

	form := url.Values{}
	form.Set("id", "csrf-invalid")
	form.Set("name", "Invalid token")
	form.Set("enabled", "true")
	form.Set("confidential", "false")
	form.Set("require_pkce", "true")
	form.Set("auth_method", "none")
	form.Set("grant_types", "authorization_code")
	form.Set("response_types", "code")
	form.Set("scopes", "openid profile")
	form.Set("redirect_uris", "https://example.com/callback")

	rec := doUIRequest(t, e, http.MethodPost, "/admin/clients/new", withCSRF(form, wrongToken), cookies)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 with invalid csrf token, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestCreateClientCSRFCorrectTokenSucceeds(t *testing.T) {
	fakeStore := newFakeUIStore()
	auth := &fakeUIAuth{}
	reloader := &fakeReloader{}
	e := setupTestAdminUI(t, fakeStore, auth, reloader, &fakeAuditStore{})
	cookies, csrfToken := getCSRFCookiesAndToken(t, e, "/admin/clients/new", auth.sessionCookies())

	form := url.Values{}
	form.Set("id", "csrf-valid")
	form.Set("name", "Valid token")
	form.Set("enabled", "true")
	form.Set("confidential", "false")
	form.Set("require_pkce", "true")
	form.Set("auth_method", "none")
	form.Set("grant_types", "authorization_code")
	form.Set("response_types", "code")
	form.Set("scopes", "openid profile")
	form.Set("redirect_uris", "https://example.com/callback")

	rec := doUIRequest(t, e, http.MethodPost, "/admin/clients/new", withCSRF(form, csrfToken), cookies)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expected 303 with valid csrf token, got %d body=%s", rec.Code, rec.Body.String())
	}
	if location := rec.Header().Get(echo.HeaderLocation); location != "/admin/clients/csrf-valid" {
		t.Fatalf("unexpected create redirect location %s", location)
	}
	if reloader.calls != 1 {
		t.Fatalf("expected reload call after create, got %d", reloader.calls)
	}
}

func TestLogoutCSRFProtection(t *testing.T) {
	fakeStore := newFakeUIStore()
	auth := &fakeUIAuth{}
	e := setupTestAdminUI(t, fakeStore, auth, &fakeReloader{}, &fakeAuditStore{})
	cookies, csrfToken := getCSRFCookiesAndToken(t, e, "/admin/", auth.sessionCookies())

	recNoToken := doUIRequest(t, e, http.MethodPost, "/admin/logout", nil, cookies)
	if recNoToken.Code != http.StatusForbidden {
		t.Fatalf("expected 403 on logout without csrf token, got %d body=%s", recNoToken.Code, recNoToken.Body.String())
	}
	if auth.logoutCalled {
		t.Fatalf("logout session should not be called when csrf validation fails")
	}

	recOK := doUIRequest(t, e, http.MethodPost, "/admin/logout", withCSRF(nil, csrfToken), cookies)
	if recOK.Code != http.StatusFound {
		t.Fatalf("expected 302 on logout with csrf token, got %d body=%s", recOK.Code, recOK.Body.String())
	}
	if location := recOK.Header().Get(echo.HeaderLocation); location != "/admin/login" {
		t.Fatalf("expected redirect to /admin/login, got %s", location)
	}
	if !auth.logoutCalled {
		t.Fatalf("expected logout session call")
	}
	cleared := responseCookie(recOK, adminCSRFCookieName)
	if cleared == nil || cleared.MaxAge >= 0 {
		t.Fatalf("expected cleared %s cookie on logout", adminCSRFCookieName)
	}
}

func TestCSRFTokenRenderedInClientNewForm(t *testing.T) {
	auth := &fakeUIAuth{}
	e := setupTestAdminUI(t, newFakeUIStore(), auth, &fakeReloader{}, &fakeAuditStore{})

	rec := doUIRequest(t, e, http.MethodGet, "/admin/clients/new", nil, auth.sessionCookies())
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}

	body := rec.Body.String()
	token := extractCSRFTokenFromPage(body)
	if token == "" {
		t.Fatalf("expected csrf token in form html")
	}
	if !strings.Contains(body, `name="csrf_token" value="`) {
		t.Fatalf("expected hidden csrf_token input in html")
	}
	csrfCookie := responseCookie(rec, adminCSRFCookieName)
	if csrfCookie == nil {
		t.Fatalf("expected csrf cookie on page render")
	}
	if csrfCookie.Value != token {
		t.Fatalf("expected form csrf token to match cookie token")
	}
}

func TestCSRFTokenRenderedInClientDetailRevokeForms(t *testing.T) {
	fakeStore := newFakeUIStore()
	if err := fakeStore.CreateOIDCClient(store.OIDCClient{
		ID:            "detail-csrf",
		Name:          "Detail CSRF",
		Enabled:       true,
		Confidential:  true,
		RequirePKCE:   true,
		AuthMethod:    "basic",
		GrantTypes:    []string{"authorization_code"},
		ResponseTypes: []string{"code"},
		Scopes:        []string{"openid"},
		RedirectURIs:  []string{"https://example.com/detail"},
	}, []store.OIDCClientSecretInput{{PlainSecret: "one", Label: "one"}, {PlainSecret: "two", Label: "two"}}); err != nil {
		t.Fatalf("seed confidential client failed: %v", err)
	}

	auth := &fakeUIAuth{}
	e := setupTestAdminUI(t, fakeStore, auth, &fakeReloader{}, &fakeAuditStore{})
	rec := doUIRequest(t, e, http.MethodGet, "/admin/clients/detail-csrf", nil, auth.sessionCookies())
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}

	body := rec.Body.String()
	token := extractCSRFTokenFromPage(body)
	if token == "" {
		t.Fatalf("expected csrf token in detail page html")
	}

	revokeForms := strings.Count(body, `action="/admin/clients/detail-csrf/secrets/`)
	if revokeForms < 2 {
		t.Fatalf("expected at least two revoke forms, got %d", revokeForms)
	}

	tokenInputs := strings.Count(body, `name="csrf_token" value="`+token+`"`)
	if tokenInputs < revokeForms+1 {
		t.Fatalf("expected csrf token in logout + revoke forms, got %d inputs for %d revoke forms", tokenInputs, revokeForms)
	}
}

func TestCreateClientValidationAndSuccess(t *testing.T) {
	fakeStore := newFakeUIStore()
	reloader := &fakeReloader{}
	auditStore := &fakeAuditStore{}
	auth := &fakeUIAuth{}
	e := setupTestAdminUI(t, fakeStore, auth, reloader, auditStore)
	cookies, csrfToken := getCSRFCookiesAndToken(t, e, "/admin/clients/new", auth.sessionCookies())

	invalidForm := url.Values{}
	invalidForm.Set("name", "Missing ID")
	recInvalid := doUIRequest(t, e, http.MethodPost, "/admin/clients/new", withCSRF(invalidForm, csrfToken), cookies)
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

	recOK := doUIRequest(t, e, http.MethodPost, "/admin/clients/new", withCSRF(validForm, csrfToken), cookies)
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
	cookies, csrfToken := getCSRFCookiesAndToken(t, e, "/admin/clients/edit-me/edit", auth.sessionCookies())

	form := url.Values{}
	form.Set("name", "After")
	form.Set("enabled", "true")
	form.Set("require_pkce", "true")
	form.Set("auth_method", "none")
	form.Set("grant_types", "authorization_code")
	form.Set("response_types", "code")
	form.Set("scopes", "openid profile")

	rec := doUIRequest(t, e, http.MethodPost, "/admin/clients/edit-me/edit", withCSRF(form, csrfToken), cookies)
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
	cookies, csrfToken := getCSRFCookiesAndToken(t, e, "/admin/clients/redir/redirect-uris", auth.sessionCookies())

	recBad := doUIRequest(t, e, http.MethodPost, "/admin/clients/redir/redirect-uris", withCSRF(url.Values{"redirect_uris": []string{" \n \n"}}, csrfToken), cookies)
	if recBad.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for empty redirect uris, got %d", recBad.Code)
	}

	okForm := url.Values{}
	okForm.Set("redirect_uris", "https://example.com/new1\nhttps://example.com/new2\nhttps://example.com/new2")
	recOK := doUIRequest(t, e, http.MethodPost, "/admin/clients/redir/redirect-uris", withCSRF(okForm, csrfToken), cookies)
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
	cookies, csrfToken := getCSRFCookiesAndToken(t, e, "/admin/clients/conf/secrets/new", auth.sessionCookies())

	genForm := url.Values{}
	genForm.Set("label", "generated")
	genForm.Set("generate", "true")
	recGen := doUIRequest(t, e, http.MethodPost, "/admin/clients/conf/secrets", withCSRF(genForm, csrfToken), cookies)
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
	recPub := doUIRequest(t, e, http.MethodPost, "/admin/clients/pub/secrets", withCSRF(pubForm, csrfToken), cookies)
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
	cookies, csrfToken := getCSRFCookiesAndToken(t, e, "/admin/clients/revoke", auth.sessionCookies())

	recOK := doUIRequest(t, e, http.MethodPost, fmt.Sprintf("/admin/clients/revoke/secrets/%d/revoke", secrets[0].ID), withCSRF(nil, csrfToken), cookies)
	if recOK.Code != http.StatusSeeOther {
		t.Fatalf("expected 303 for first revoke, got %d body=%s", recOK.Code, recOK.Body.String())
	}

	recConflict := doUIRequest(t, e, http.MethodPost, fmt.Sprintf("/admin/clients/revoke/secrets/%d/revoke", secrets[1].ID), withCSRF(nil, csrfToken), cookies)
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
	protected.Use(h.CSRFMiddleware())
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

func getCSRFCookiesAndToken(t *testing.T, e *echo.Echo, path string, baseCookies []*http.Cookie) ([]*http.Cookie, string) {
	t.Helper()

	rec := doUIRequest(t, e, http.MethodGet, path, nil, baseCookies)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 while preparing csrf for %s, got %d body=%s", path, rec.Code, rec.Body.String())
	}

	token := extractCSRFTokenFromPage(rec.Body.String())
	if token == "" {
		t.Fatalf("expected csrf token in html for %s", path)
	}

	csrfCookie := responseCookie(rec, adminCSRFCookieName)
	if csrfCookie == nil || strings.TrimSpace(csrfCookie.Value) == "" {
		t.Fatalf("expected %s cookie after GET %s", adminCSRFCookieName, path)
	}

	return mergeCookies(baseCookies, csrfCookie), token
}

func withCSRF(form url.Values, token string) url.Values {
	out := url.Values{}
	for key, values := range form {
		out[key] = append([]string(nil), values...)
	}
	out.Set(adminCSRFFieldName, strings.TrimSpace(token))
	return out
}

func mergeCookies(base []*http.Cookie, updates ...*http.Cookie) []*http.Cookie {
	out := make([]*http.Cookie, 0, len(base)+len(updates))
	out = append(out, base...)
	for _, update := range updates {
		if update == nil {
			continue
		}
		replaced := false
		for i, existing := range out {
			if existing == nil {
				continue
			}
			if existing.Name == update.Name {
				out[i] = update
				replaced = true
				break
			}
		}
		if !replaced {
			out = append(out, update)
		}
	}
	return out
}

func responseCookie(rec *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == name {
			copyCookie := *cookie
			return &copyCookie
		}
	}
	return nil
}

type fakeUIAuth struct {
	logoutCalled            bool
	user                    store.AdminUser
	passkeys                []store.AdminCredentialInfo
	sessions                []store.AdminSessionInfo
	recentReauthAt          *time.Time
	reauthMaxAge            time.Duration
	disableAutoRecentReauth bool
}

func (a *fakeUIAuth) SessionUser(c echo.Context) (*store.AdminUser, bool) {
	cookie, err := c.Cookie("admin_session")
	if err != nil || strings.TrimSpace(cookie.Value) != "ok" {
		return nil, false
	}
	user := a.user
	if strings.TrimSpace(user.ID) == "" {
		user = store.AdminUser{ID: "admin-1", Login: "admin", DisplayName: "Admin", Role: store.AdminRoleOwner}
	}
	user.Role = store.NormalizeAdminRole(user.Role)
	admin.SetAdminActor(c, "admin_user", user.ID)
	admin.SetAdminActorRole(c, user.Role)
	c.Set("admin_user", &user)
	c.Set("admin_user_role", user.Role)
	if !a.disableAutoRecentReauth && a.recentReauthAt == nil {
		now := time.Now().UTC()
		a.recentReauthAt = &now
	}
	return &user, true
}

func (a *fakeUIAuth) LogoutSession(c echo.Context) error {
	a.logoutCalled = true
	c.SetCookie(&http.Cookie{Name: "admin_session", Value: "", Path: "/admin", MaxAge: -1})
	return nil
}

func (a *fakeUIAuth) ListPasskeys(c echo.Context) ([]store.AdminCredentialInfo, error) {
	out := make([]store.AdminCredentialInfo, 0, len(a.passkeys))
	for _, item := range a.passkeys {
		copyItem := item
		if item.LastUsedAt != nil {
			ts := item.LastUsedAt.UTC()
			copyItem.LastUsedAt = &ts
		}
		copyItem.Transports = append([]string(nil), item.Transports...)
		out = append(out, copyItem)
	}
	return out, nil
}

func (a *fakeUIAuth) DeletePasskey(c echo.Context, credentialID int64) error {
	if credentialID <= 0 {
		return store.ErrAdminCredentialNotFound
	}
	if len(a.passkeys) <= 1 {
		return store.ErrAdminCredentialLast
	}
	idx := -1
	for i, item := range a.passkeys {
		if item.ID == credentialID {
			idx = i
			break
		}
	}
	if idx < 0 {
		return store.ErrAdminCredentialNotFound
	}
	a.passkeys = append(a.passkeys[:idx], a.passkeys[idx+1:]...)
	return nil
}

func (a *fakeUIAuth) ReauthMaxAge() time.Duration {
	if a.reauthMaxAge <= 0 {
		return 5 * time.Minute
	}
	return a.reauthMaxAge
}

func (a *fakeUIAuth) HasRecentReauth(c echo.Context, maxAge time.Duration) bool {
	if maxAge <= 0 {
		maxAge = a.ReauthMaxAge()
	}
	if a.recentReauthAt == nil {
		return false
	}
	return time.Since(a.recentReauthAt.UTC()) <= maxAge
}

func (a *fakeUIAuth) CurrentSessionID(c echo.Context) (string, bool) {
	for _, item := range a.sessions {
		if item.Current {
			return strings.TrimSpace(item.SessionID), true
		}
	}
	return "ok", true
}

func (a *fakeUIAuth) ListSessions(c echo.Context) ([]store.AdminSessionInfo, error) {
	out := make([]store.AdminSessionInfo, 0, len(a.sessions))
	for _, item := range a.sessions {
		copyItem := item
		out = append(out, copyItem)
	}
	return out, nil
}

func (a *fakeUIAuth) LogoutSessionByID(c echo.Context, sessionID string) error {
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return errors.New("invalid session id")
	}
	idx := -1
	wasCurrent := false
	for i, item := range a.sessions {
		if strings.TrimSpace(item.SessionID) == sessionID {
			idx = i
			wasCurrent = item.Current
			break
		}
	}
	if idx < 0 {
		return errors.New("session not found")
	}
	a.sessions = append(a.sessions[:idx], a.sessions[idx+1:]...)
	if wasCurrent {
		c.SetCookie(&http.Cookie{Name: "admin_session", Value: "", Path: "/admin", MaxAge: -1})
	}
	return nil
}

func (a *fakeUIAuth) LogoutOtherSessions(c echo.Context) (int, error) {
	currentID, ok := a.CurrentSessionID(c)
	if !ok {
		return 0, errors.New("missing current session")
	}
	filtered := make([]store.AdminSessionInfo, 0, len(a.sessions))
	removed := 0
	for _, item := range a.sessions {
		if strings.TrimSpace(item.SessionID) == currentID {
			item.Current = true
			filtered = append(filtered, item)
			continue
		}
		removed++
	}
	a.sessions = filtered
	return removed, nil
}

func (a *fakeUIAuth) InvalidateSessionsForAdminUser(ctx context.Context, adminUserID string) (int, error) {
	if strings.TrimSpace(adminUserID) == "" {
		return 0, errors.New("admin user id is required")
	}
	removed := len(a.sessions)
	a.sessions = []store.AdminSessionInfo{}
	return removed, nil
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

func (a *fakeAuditStore) ListAdminAuditEntries(ctx context.Context, opts store.AdminAuditListOptions) ([]store.AdminAuditEntry, error) {
	limit := opts.Limit
	offset := opts.Offset
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}

	action := strings.TrimSpace(opts.Action)
	resourceType := strings.TrimSpace(opts.ResourceType)
	resourceID := strings.TrimSpace(opts.ResourceID)
	actor := strings.ToLower(strings.TrimSpace(opts.Actor))

	filtered := make([]store.AdminAuditEntry, 0, len(a.entries))
	for _, entry := range a.entries {
		if action != "" && !strings.Contains(strings.ToLower(strings.TrimSpace(entry.Action)), strings.ToLower(action)) {
			continue
		}
		if resourceType != "" && strings.TrimSpace(entry.ResourceType) != resourceType {
			continue
		}
		if resourceID != "" && !strings.Contains(strings.ToLower(strings.TrimSpace(entry.ResourceID)), strings.ToLower(resourceID)) {
			continue
		}
		if opts.Success != nil && entry.Success != *opts.Success {
			continue
		}
		if actor != "" {
			combinedActor := strings.ToLower(strings.TrimSpace(entry.ActorType) + ":" + strings.TrimSpace(entry.ActorID))
			actorID := strings.ToLower(strings.TrimSpace(entry.ActorID))
			if !strings.Contains(combinedActor, actor) && !strings.Contains(actorID, actor) {
				continue
			}
		}

		item := entry
		item.DetailsJSON = append([]byte(nil), entry.DetailsJSON...)
		filtered = append(filtered, item)
	}

	sort.Slice(filtered, func(i, j int) bool { return filtered[i].ID > filtered[j].ID })

	if offset >= len(filtered) {
		return []store.AdminAuditEntry{}, nil
	}
	end := offset + limit
	if end > len(filtered) {
		end = len(filtered)
	}
	return append([]store.AdminAuditEntry(nil), filtered[offset:end]...), nil
}

func (a *fakeAuditStore) CountAdminAuditFailuresSince(ctx context.Context, since time.Time) (int, error) {
	if since.IsZero() {
		since = time.Now().UTC().Add(-24 * time.Hour)
	}
	count := 0
	for _, entry := range a.entries {
		if entry.Success {
			continue
		}
		if entry.CreatedAt.UTC().Before(since.UTC()) {
			continue
		}
		count++
	}
	return count, nil
}

type fakeUIStore struct {
	clients              map[string]store.OIDCClient
	secrets              map[string][]store.OIDCClientSecret
	nextSecretID         int64
	adminUsers           map[string]*store.AdminUser
	adminUsersByLogin    map[string]string
	adminCredentialCount map[string]int
	adminInvites         map[int64]store.AdminInvite
	nextAdminUserID      int
	nextInviteID         int64
}

func newFakeUIStore() *fakeUIStore {
	now := time.Now().UTC()
	rootAdmin := &store.AdminUser{
		ID:          "admin-1",
		Login:       "admin",
		DisplayName: "Admin",
		Enabled:     true,
		Role:        store.AdminRoleOwner,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	return &fakeUIStore{
		clients:              map[string]store.OIDCClient{},
		secrets:              map[string][]store.OIDCClientSecret{},
		nextSecretID:         1,
		adminUsers:           map[string]*store.AdminUser{"admin-1": rootAdmin},
		adminUsersByLogin:    map[string]string{"admin": "admin-1"},
		adminCredentialCount: map[string]int{"admin-1": 1},
		adminInvites:         map[int64]store.AdminInvite{},
		nextAdminUserID:      1,
		nextInviteID:         1,
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

func (s *fakeUIStore) CreateAdminUser(login string, displayName string) (*store.AdminUser, error) {
	login = strings.ToLower(strings.TrimSpace(login))
	displayName = strings.TrimSpace(displayName)
	if login == "" {
		return nil, errors.New("admin login is required")
	}
	if _, exists := s.adminUsersByLogin[login]; exists {
		return nil, errors.New("admin login already exists")
	}
	s.nextAdminUserID++
	now := time.Now().UTC()
	user := &store.AdminUser{
		ID:          fmt.Sprintf("admin-%d", s.nextAdminUserID),
		Login:       login,
		DisplayName: displayName,
		Enabled:     true,
		Role:        store.AdminRoleAdmin,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if user.DisplayName == "" {
		user.DisplayName = user.Login
	}
	s.adminUsers[user.ID] = user
	s.adminUsersByLogin[user.Login] = user.ID
	s.adminCredentialCount[user.ID] = 0
	copyUser := *user
	return &copyUser, nil
}

func (s *fakeUIStore) GetAdminUser(id string) (*store.AdminUser, error) {
	id = strings.TrimSpace(id)
	user, ok := s.adminUsers[id]
	if !ok {
		return nil, store.ErrAdminUserNotFound
	}
	copyUser := *user
	copyUser.CredentialCount = s.adminCredentialCount[id]
	copyUser.Role = store.NormalizeAdminRole(copyUser.Role)
	return &copyUser, nil
}

func (s *fakeUIStore) GetAdminUserByLogin(login string) (*store.AdminUser, error) {
	login = strings.ToLower(strings.TrimSpace(login))
	id, ok := s.adminUsersByLogin[login]
	if !ok {
		return nil, store.ErrAdminUserNotFound
	}
	return s.GetAdminUser(id)
}

func (s *fakeUIStore) ListAdminUsers() ([]store.AdminUser, error) {
	out := make([]store.AdminUser, 0, len(s.adminUsers))
	for id, user := range s.adminUsers {
		item := *user
		item.CredentialCount = s.adminCredentialCount[id]
		item.Role = store.NormalizeAdminRole(item.Role)
		active := 0
		now := time.Now().UTC()
		for _, invite := range s.adminInvites {
			if strings.TrimSpace(invite.AdminUserID) != id {
				continue
			}
			if invite.UsedAt == nil && invite.RevokedAt == nil && invite.ExpiresAt.After(now) {
				active++
			}
		}
		item.ActiveInviteCount = active
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool {
		return strings.ToLower(strings.TrimSpace(out[i].Login)) < strings.ToLower(strings.TrimSpace(out[j].Login))
	})
	return out, nil
}

func (s *fakeUIStore) SetAdminUserEnabled(id string, enabled bool) error {
	id = strings.TrimSpace(id)
	user, ok := s.adminUsers[id]
	if !ok {
		return store.ErrAdminUserNotFound
	}
	user.Enabled = enabled
	user.UpdatedAt = time.Now().UTC()
	return nil
}

func (s *fakeUIStore) CountEnabledAdminUsers() (int, error) {
	count := 0
	for _, user := range s.adminUsers {
		if user.Enabled {
			count++
		}
	}
	return count, nil
}

func (s *fakeUIStore) CountEnabledAdminUsersByRole(role string) (int, error) {
	role = strings.TrimSpace(strings.ToLower(role))
	if !store.IsValidAdminRole(role) {
		return 0, store.ErrAdminRoleInvalid
	}
	count := 0
	for _, user := range s.adminUsers {
		if !user.Enabled {
			continue
		}
		if store.NormalizeAdminRole(user.Role) == role {
			count++
		}
	}
	return count, nil
}

func (s *fakeUIStore) SetAdminUserRole(id string, role string) error {
	id = strings.TrimSpace(id)
	role = strings.TrimSpace(strings.ToLower(role))
	if id == "" {
		return store.ErrAdminUserNotFound
	}
	if !store.IsValidAdminRole(role) {
		return store.ErrAdminRoleInvalid
	}
	user, ok := s.adminUsers[id]
	if !ok {
		return store.ErrAdminUserNotFound
	}
	user.Role = role
	user.UpdatedAt = time.Now().UTC()
	return nil
}

func (s *fakeUIStore) CountAdminCredentialsForUser(adminUserID string) (int, error) {
	adminUserID = strings.TrimSpace(adminUserID)
	if adminUserID == "" {
		return 0, store.ErrAdminUserNotFound
	}
	if _, ok := s.adminUsers[adminUserID]; !ok {
		return 0, store.ErrAdminUserNotFound
	}
	return s.adminCredentialCount[adminUserID], nil
}

func (s *fakeUIStore) CountActiveAdminInvites(ctx context.Context) (int, error) {
	now := time.Now().UTC()
	count := 0
	for _, invite := range s.adminInvites {
		if invite.UsedAt == nil && invite.RevokedAt == nil && invite.ExpiresAt.After(now) {
			count++
		}
	}
	return count, nil
}

func (s *fakeUIStore) CountExpiredUnusedAdminInvites(ctx context.Context) (int, error) {
	now := time.Now().UTC()
	count := 0
	for _, invite := range s.adminInvites {
		if invite.UsedAt == nil && invite.RevokedAt == nil && !invite.ExpiresAt.After(now) {
			count++
		}
	}
	return count, nil
}

func (s *fakeUIStore) ListActiveAdminInvites(ctx context.Context, limit int) ([]store.ActiveAdminInviteOverview, error) {
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	now := time.Now().UTC()
	out := make([]store.ActiveAdminInviteOverview, 0, len(s.adminInvites))
	for _, invite := range s.adminInvites {
		if invite.UsedAt != nil || invite.RevokedAt != nil || !invite.ExpiresAt.After(now) {
			continue
		}
		targetUser, ok := s.adminUsers[strings.TrimSpace(invite.AdminUserID)]
		if !ok {
			continue
		}
		creatorUser, ok := s.adminUsers[strings.TrimSpace(invite.CreatedByAdminUserID)]
		if !ok {
			continue
		}
		out = append(out, store.ActiveAdminInviteOverview{
			ID:                   invite.ID,
			AdminUserID:          strings.TrimSpace(invite.AdminUserID),
			AdminLogin:           strings.TrimSpace(targetUser.Login),
			CreatedByAdminUserID: strings.TrimSpace(invite.CreatedByAdminUserID),
			CreatedByLogin:       strings.TrimSpace(creatorUser.Login),
			CreatedAt:            invite.CreatedAt,
			ExpiresAt:            invite.ExpiresAt,
			Note:                 strings.TrimSpace(invite.Note),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ExpiresAt.Equal(out[j].ExpiresAt) {
			if out[i].CreatedAt.Equal(out[j].CreatedAt) {
				return out[i].ID > out[j].ID
			}
			return out[i].CreatedAt.After(out[j].CreatedAt)
		}
		return out[i].ExpiresAt.Before(out[j].ExpiresAt)
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (s *fakeUIStore) CreateAdminInvite(ctx context.Context, adminUserID string, createdBy string, tokenHash string, expiresAt time.Time, note string) (*store.AdminInvite, error) {
	adminUserID = strings.TrimSpace(adminUserID)
	createdBy = strings.TrimSpace(createdBy)
	tokenHash = strings.TrimSpace(tokenHash)
	note = strings.TrimSpace(note)
	if adminUserID == "" || createdBy == "" || tokenHash == "" {
		return nil, errors.New("invalid admin invite payload")
	}
	if _, ok := s.adminUsers[adminUserID]; !ok {
		return nil, store.ErrAdminUserNotFound
	}
	if _, ok := s.adminUsers[createdBy]; !ok {
		return nil, store.ErrAdminUserNotFound
	}
	for _, existing := range s.adminInvites {
		if strings.TrimSpace(existing.TokenHash) == tokenHash {
			return nil, errors.New("invite token already exists")
		}
	}
	now := time.Now().UTC()
	invite := store.AdminInvite{
		ID:                   s.nextInviteID,
		TokenHash:            tokenHash,
		AdminUserID:          adminUserID,
		CreatedByAdminUserID: createdBy,
		CreatedAt:            now,
		ExpiresAt:            expiresAt.UTC(),
		Note:                 note,
	}
	s.nextInviteID++
	s.adminInvites[invite.ID] = invite
	copyInvite := invite
	return &copyInvite, nil
}

func (s *fakeUIStore) GetAdminInviteByID(ctx context.Context, inviteID int64) (*store.AdminInvite, error) {
	if inviteID <= 0 {
		return nil, store.ErrAdminInviteNotFound
	}
	invite, ok := s.adminInvites[inviteID]
	if !ok {
		return nil, store.ErrAdminInviteNotFound
	}
	copyInvite := invite
	return &copyInvite, nil
}

func (s *fakeUIStore) GetActiveAdminInviteByTokenHash(ctx context.Context, tokenHash string) (*store.AdminInvite, error) {
	tokenHash = strings.TrimSpace(tokenHash)
	if tokenHash == "" {
		return nil, store.ErrAdminInviteNotFound
	}
	now := time.Now().UTC()
	for _, invite := range s.adminInvites {
		if strings.TrimSpace(invite.TokenHash) != tokenHash {
			continue
		}
		if invite.UsedAt != nil || invite.RevokedAt != nil || !invite.ExpiresAt.After(now) {
			return nil, store.ErrAdminInviteNotFound
		}
		copyInvite := invite
		return &copyInvite, nil
	}
	return nil, store.ErrAdminInviteNotFound
}

func (s *fakeUIStore) RevokeAdminInvite(ctx context.Context, inviteID int64) error {
	if inviteID <= 0 {
		return store.ErrAdminInviteNotFound
	}
	invite, ok := s.adminInvites[inviteID]
	if !ok {
		return store.ErrAdminInviteNotFound
	}
	now := time.Now().UTC()
	if invite.UsedAt != nil || invite.RevokedAt != nil || !invite.ExpiresAt.After(now) {
		return store.ErrAdminInviteInactive
	}
	invite.RevokedAt = &now
	s.adminInvites[inviteID] = invite
	return nil
}

func (s *fakeUIStore) ListAdminInvites(ctx context.Context, adminUserID string) ([]store.AdminInvite, error) {
	adminUserID = strings.TrimSpace(adminUserID)
	out := make([]store.AdminInvite, 0, len(s.adminInvites))
	for _, invite := range s.adminInvites {
		if strings.TrimSpace(invite.AdminUserID) != adminUserID {
			continue
		}
		copyInvite := invite
		out = append(out, copyInvite)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].ID > out[j].ID
		}
		return out[i].CreatedAt.After(out[j].CreatedAt)
	})
	return out, nil
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

func extractCSRFTokenFromPage(body string) string {
	marker := `name="csrf_token" value="`
	start := strings.Index(body, marker)
	if start < 0 {
		return ""
	}
	start += len(marker)
	end := strings.Index(body[start:], `"`)
	if end < 0 {
		return ""
	}
	return strings.TrimSpace(body[start : start+end])
}

func extractInputValueByID(body string, id string) string {
	id = strings.TrimSpace(id)
	if id == "" {
		return ""
	}
	marker := `id="` + id + `"`
	pos := strings.Index(body, marker)
	if pos < 0 {
		return ""
	}
	slice := body[pos:]
	valueMarker := `value="`
	valuePos := strings.Index(slice, valueMarker)
	if valuePos < 0 {
		return ""
	}
	valuePos += len(valueMarker)
	valueEnd := strings.Index(slice[valuePos:], `"`)
	if valueEnd < 0 {
		return ""
	}
	return strings.TrimSpace(slice[valuePos : valuePos+valueEnd])
}

func TestAuditDetailsJSONNeverContainsSecretMaterial(t *testing.T) {
	details := map[string]any{
		"label":        "x",
		"plain_secret": "hidden",
		"secret_hash":  "hashed",
		"secret":       "raw",
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
