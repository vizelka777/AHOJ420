package adminui

import (
	"bytes"
	"context"
	"encoding/hex"
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

func TestHealthRequiresSession(t *testing.T) {
	e := setupTestAdminUI(t, newFakeUIStore(), &fakeUIAuth{}, &fakeReloader{}, &fakeAuditStore{})

	rec := doUIRequest(t, e, http.MethodGet, "/admin/health", nil, nil)
	if rec.Code != http.StatusFound {
		t.Fatalf("expected 302 redirect, got %d", rec.Code)
	}
	if location := rec.Header().Get(echo.HeaderLocation); location != "/admin/login" {
		t.Fatalf("expected redirect to /admin/login, got %s", location)
	}
}

func TestHealthRendersSnapshotBlocks(t *testing.T) {
	auth := &fakeUIAuth{}
	e, h := setupTestAdminUIWithHandler(t, newFakeUIStore(), auth, &fakeReloader{}, &fakeAuditStore{})
	h.SetHealthProvider(fakeHealthProvider{
		snapshot: &SystemHealthSnapshot{
			GeneratedAt: time.Now().UTC(),
			Postgres: HealthCheckResult{
				Status:    HealthStatusOK,
				Message:   "Postgres query ok",
				LatencyMS: 2,
				CheckedAt: time.Now().UTC(),
			},
			Redis: HealthCheckResult{
				Status:    HealthStatusDown,
				Message:   "connection refused",
				LatencyMS: 1,
				CheckedAt: time.Now().UTC(),
			},
			Mailer: HealthCheckResult{
				Status:    HealthStatusDisabled,
				Message:   "not configured",
				CheckedAt: time.Now().UTC(),
			},
			SMS: HealthCheckResult{
				Status:    HealthStatusOK,
				Message:   "configured",
				CheckedAt: time.Now().UTC(),
			},
			Retention: RetentionHealth{
				AdminAudit: RetentionTableHealth{
					Table:         "admin_audit_log",
					RetentionDays: 180,
					Enabled:       true,
				},
				UserSecurityEvents: RetentionTableHealth{
					Table:         "user_security_events",
					RetentionDays: 0,
					Enabled:       false,
				},
				LastRun: &MaintenanceRunHealth{
					FinishedAt:   time.Now().UTC(),
					Success:      true,
					DryRun:       false,
					DeletedTotal: 15,
				},
			},
			RecentFailures: []RecentFailureItem{
				{
					Time:    time.Now().UTC(),
					Source:  "admin_audit",
					Event:   "admin.user.delete.failure",
					Message: "session_cleanup_failed",
					Link:    "/admin/audit?success=failure",
				},
			},
		},
	})

	rec := doUIRequest(t, e, http.MethodGet, "/admin/health", nil, auth.sessionCookies())
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, expected := range []string{
		"Health / Ops",
		"Postgres",
		"Redis",
		"Mailer",
		"SMS",
		"Retention",
		"Recent Failures",
		"admin_audit_log",
		"user_security_events",
		"admin.user.delete.failure",
	} {
		if !strings.Contains(body, expected) {
			t.Fatalf("expected %q on health page, body=%s", expected, body)
		}
	}
}

func TestHealthNonOwnerStillAccessible(t *testing.T) {
	auth := &fakeUIAuth{
		user: store.AdminUser{ID: "admin-2", Login: "ops-admin", DisplayName: "Ops Admin", Role: store.AdminRoleAdmin},
	}
	e, h := setupTestAdminUIWithHandler(t, newFakeUIStore(), auth, &fakeReloader{}, &fakeAuditStore{})
	h.SetHealthProvider(fakeHealthProvider{
		snapshot: &SystemHealthSnapshot{
			GeneratedAt: time.Now().UTC(),
			Postgres: HealthCheckResult{
				Status:    HealthStatusOK,
				Message:   "Postgres query ok",
				CheckedAt: time.Now().UTC(),
			},
			Redis: HealthCheckResult{
				Status:    HealthStatusOK,
				Message:   "Redis ping ok",
				CheckedAt: time.Now().UTC(),
			},
		},
	})

	rec := doUIRequest(t, e, http.MethodGet, "/admin/health", nil, auth.sessionCookies())
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
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

func TestUsersListRequiresSession(t *testing.T) {
	e := setupTestAdminUI(t, newFakeUIStore(), &fakeUIAuth{}, &fakeReloader{}, &fakeAuditStore{})

	rec := doUIRequest(t, e, http.MethodGet, "/admin/users", nil, nil)
	if rec.Code != http.StatusFound {
		t.Fatalf("expected 302 redirect, got %d", rec.Code)
	}
	if location := rec.Header().Get(echo.HeaderLocation); location != "/admin/login" {
		t.Fatalf("expected redirect to /admin/login, got %s", location)
	}
}

func TestUsersListSearchWorksByIDEmailAndPhone(t *testing.T) {
	fakeStore := newFakeUIStore()
	userA := fakeStore.seedSupportUser("user-a", "alice@login.local", "alice@example.com", "+111")
	userB := fakeStore.seedSupportUser("user-b", "bob@login.local", "bob@example.com", "+222")
	fakeStore.userCredentials[userA.ID] = []store.CredentialRecord{
		{ID: []byte{0x01, 0x02}, CreatedAt: time.Now().UTC().Add(-2 * time.Hour)},
	}
	fakeStore.userLinkedClients[userA.ID] = []store.UserOIDCClient{
		{ClientID: "client-a", FirstSeenAt: time.Now().UTC().Add(-6 * time.Hour), LastSeenAt: time.Now().UTC().Add(-1 * time.Hour)},
	}

	auth := &fakeUIAuth{
		user: store.AdminUser{ID: "admin-1", Login: "admin", DisplayName: "Admin", Role: store.AdminRoleAdmin},
		userSessions: map[string][]store.UserSessionInfo{
			userA.ID: {
				{SessionID: "sess-a", CreatedAt: time.Now().UTC().Add(-3 * time.Hour), LastSeenAt: time.Now().UTC().Add(-15 * time.Minute)},
			},
		},
	}
	e := setupTestAdminUI(t, fakeStore, auth, &fakeReloader{}, &fakeAuditStore{})

	recByEmail := doUIRequest(t, e, http.MethodGet, "/admin/users?q=alice@example.com", nil, auth.sessionCookies())
	if recByEmail.Code != http.StatusOK {
		t.Fatalf("expected 200 for email search, got %d body=%s", recByEmail.Code, recByEmail.Body.String())
	}
	if !strings.Contains(recByEmail.Body.String(), userA.ID) || strings.Contains(recByEmail.Body.String(), userB.ID) {
		t.Fatalf("email search did not filter as expected, body=%s", recByEmail.Body.String())
	}

	recByID := doUIRequest(t, e, http.MethodGet, "/admin/users?q=user-b", nil, auth.sessionCookies())
	if recByID.Code != http.StatusOK {
		t.Fatalf("expected 200 for id search, got %d body=%s", recByID.Code, recByID.Body.String())
	}
	if !strings.Contains(recByID.Body.String(), userB.ID) || strings.Contains(recByID.Body.String(), userA.ID) {
		t.Fatalf("id search did not filter as expected, body=%s", recByID.Body.String())
	}

	recByPhone := doUIRequest(t, e, http.MethodGet, "/admin/users?q=%2B111", nil, auth.sessionCookies())
	if recByPhone.Code != http.StatusOK {
		t.Fatalf("expected 200 for phone search, got %d body=%s", recByPhone.Code, recByPhone.Body.String())
	}
	if !strings.Contains(recByPhone.Body.String(), userA.ID) || strings.Contains(recByPhone.Body.String(), userB.ID) {
		t.Fatalf("phone search did not filter as expected, body=%s", recByPhone.Body.String())
	}
}

func TestUserDetailRendersSummaryPasskeysSessionsAndClients(t *testing.T) {
	fakeStore := newFakeUIStore()
	user := fakeStore.seedSupportUser("user-detail", "detail@login.local", "detail@example.com", "+420")
	fakeStore.userCredentials[user.ID] = []store.CredentialRecord{
		{ID: []byte{0x11, 0x22, 0x33}, DeviceName: "Phone", CreatedAt: time.Now().UTC().Add(-4 * time.Hour)},
		{ID: []byte{0x44, 0x55, 0x66}, DeviceName: "Laptop", CreatedAt: time.Now().UTC().Add(-3 * time.Hour)},
	}
	fakeStore.userLinkedClients[user.ID] = []store.UserOIDCClient{
		{ClientID: "cli-1", ClientHost: "app.example.com", FirstSeenAt: time.Now().UTC().Add(-8 * time.Hour), LastSeenAt: time.Now().UTC().Add(-2 * time.Hour)},
	}

	auth := &fakeUIAuth{
		user: store.AdminUser{ID: "admin-1", Login: "admin", DisplayName: "Admin", Role: store.AdminRoleAdmin},
		userSessions: map[string][]store.UserSessionInfo{
			user.ID: {
				{
					SessionID:  "u-sess-1",
					CreatedAt:  time.Now().UTC().Add(-5 * time.Hour),
					LastSeenAt: time.Now().UTC().Add(-30 * time.Minute),
					ExpiresAt:  time.Now().UTC().Add(30 * time.Minute),
					RemoteIP:   "127.0.0.1",
					UserAgent:  "Mozilla/5.0",
				},
			},
		},
	}
	e := setupTestAdminUI(t, fakeStore, auth, &fakeReloader{}, &fakeAuditStore{})

	rec := doUIRequest(t, e, http.MethodGet, "/admin/users/"+user.ID, nil, auth.sessionCookies())
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for user detail, got %d body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, expected := range []string{
		"Summary",
		"Recent security events",
		"Passkeys",
		"Sessions",
		"Linked OIDC Clients",
		"/admin/users/" + user.ID + "/sessions/logout-all",
		"/admin/users/" + user.ID + "/sessions/u-sess-1/logout",
		"/admin/users/" + user.ID + "/passkeys/",
		"cli-1",
	} {
		if !strings.Contains(body, expected) {
			t.Fatalf("expected %q in user detail html, body=%s", expected, body)
		}
	}
}

func TestUserDetailTimelineRendersEvents(t *testing.T) {
	fakeStore := newFakeUIStore()
	user := fakeStore.seedSupportUser("user-timeline", "timeline@login.local", "timeline@example.com", "+421")
	success := true
	failure := false
	_ = fakeStore.CreateUserSecurityEvent(context.Background(), store.UserSecurityEvent{
		UserID:      user.ID,
		EventType:   store.UserSecurityEventLoginFailure,
		Category:    store.UserSecurityCategoryAuth,
		Success:     &failure,
		ActorType:   "user",
		ActorID:     user.ID,
		DetailsJSON: json.RawMessage(`{"reason":"assertion_failed"}`),
		CreatedAt:   time.Now().UTC().Add(-3 * time.Minute),
	})
	_ = fakeStore.CreateUserSecurityEvent(context.Background(), store.UserSecurityEvent{
		UserID:      user.ID,
		EventType:   store.UserSecurityEventLoginSuccess,
		Category:    store.UserSecurityCategoryAuth,
		Success:     &success,
		ActorType:   "user",
		ActorID:     user.ID,
		SessionID:   "timeline-session",
		DetailsJSON: json.RawMessage(`{"source":"login_finish"}`),
		CreatedAt:   time.Now().UTC().Add(-2 * time.Minute),
	})
	_ = fakeStore.CreateUserSecurityEvent(context.Background(), store.UserSecurityEvent{
		UserID:      user.ID,
		EventType:   store.UserSecurityEventRecoveryReq,
		Category:    store.UserSecurityCategoryRecovery,
		Success:     &success,
		ActorType:   "user",
		ActorID:     user.ID,
		DetailsJSON: json.RawMessage(`{"channel":"email"}`),
		CreatedAt:   time.Now().UTC().Add(-1 * time.Minute),
	})

	auth := &fakeUIAuth{}
	e := setupTestAdminUI(t, fakeStore, auth, &fakeReloader{}, &fakeAuditStore{})

	rec := doUIRequest(t, e, http.MethodGet, "/admin/users/"+user.ID, nil, auth.sessionCookies())
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for user detail timeline, got %d body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, expected := range []string{
		"Recent security events",
		"Login failed",
		"Login succeeded",
		"Recovery requested",
	} {
		if !strings.Contains(body, expected) {
			t.Fatalf("expected %q in timeline output, body=%s", expected, body)
		}
	}
}

func TestUserDetailTimelineEmptyFallback(t *testing.T) {
	fakeStore := newFakeUIStore()
	user := fakeStore.seedSupportUser("user-empty-events", "empty@login.local", "", "")
	auth := &fakeUIAuth{}
	e := setupTestAdminUI(t, fakeStore, auth, &fakeReloader{}, &fakeAuditStore{})

	rec := doUIRequest(t, e, http.MethodGet, "/admin/users/"+user.ID+"?events=recovery", nil, auth.sessionCookies())
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for empty timeline view, got %d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "No recent security events.") {
		t.Fatalf("expected empty timeline fallback message, body=%s", rec.Body.String())
	}
}

func TestUserDetailTimelineCategoryFilter(t *testing.T) {
	fakeStore := newFakeUIStore()
	user := fakeStore.seedSupportUser("user-filter-events", "filter@login.local", "filter@example.com", "+900")
	success := true
	failure := false
	_ = fakeStore.CreateUserSecurityEvent(context.Background(), store.UserSecurityEvent{
		UserID:       user.ID,
		EventType:    store.UserSecurityEventPasskeyAdded,
		Category:     store.UserSecurityCategoryPasskey,
		Success:      &success,
		ActorType:    "user",
		ActorID:      user.ID,
		CredentialID: "cred-filter",
		CreatedAt:    time.Now().UTC().Add(-4 * time.Hour),
	})
	_ = fakeStore.CreateUserSecurityEvent(context.Background(), store.UserSecurityEvent{
		UserID:      user.ID,
		EventType:   store.UserSecurityEventLoginFailure,
		Category:    store.UserSecurityCategoryAuth,
		Success:     &failure,
		ActorType:   "user",
		ActorID:     user.ID,
		DetailsJSON: json.RawMessage(`{"reason":"assertion_failed"}`),
		CreatedAt:   time.Now().UTC().Add(-2 * time.Hour),
	})
	auth := &fakeUIAuth{}
	e := setupTestAdminUI(t, fakeStore, auth, &fakeReloader{}, &fakeAuditStore{})

	recPasskeys := doUIRequest(t, e, http.MethodGet, "/admin/users/"+user.ID+"?events=passkeys", nil, auth.sessionCookies())
	if recPasskeys.Code != http.StatusOK {
		t.Fatalf("expected 200 for passkeys filter, got %d body=%s", recPasskeys.Code, recPasskeys.Body.String())
	}
	bodyPasskeys := recPasskeys.Body.String()
	if !strings.Contains(bodyPasskeys, "Passkey added") {
		t.Fatalf("expected passkey event in passkeys filter, body=%s", bodyPasskeys)
	}
	if strings.Contains(bodyPasskeys, "Login failed") {
		t.Fatalf("did not expect auth event in passkeys filter, body=%s", bodyPasskeys)
	}

	recAuth := doUIRequest(t, e, http.MethodGet, "/admin/users/"+user.ID+"?events=auth", nil, auth.sessionCookies())
	if recAuth.Code != http.StatusOK {
		t.Fatalf("expected 200 for auth filter, got %d body=%s", recAuth.Code, recAuth.Body.String())
	}
	bodyAuth := recAuth.Body.String()
	if !strings.Contains(bodyAuth, "Login failed") {
		t.Fatalf("expected auth event in auth filter, body=%s", bodyAuth)
	}
	if strings.Contains(bodyAuth, "Passkey added") {
		t.Fatalf("did not expect passkey-created event in auth filter, body=%s", bodyAuth)
	}
}

func TestUserDetailTimelinePrefersStructuredEvents(t *testing.T) {
	fakeStore := newFakeUIStore()
	user := fakeStore.seedSupportUser("user-structured", "structured@login.local", "structured@example.com", "+904")
	success := true
	_ = fakeStore.CreateUserSecurityEvent(context.Background(), store.UserSecurityEvent{
		UserID:       user.ID,
		EventType:    store.UserSecurityEventPasskeyAdded,
		Category:     store.UserSecurityCategoryPasskey,
		Success:      &success,
		ActorType:    "user",
		ActorID:      user.ID,
		CredentialID: "cred-structured",
		CreatedAt:    time.Now().UTC().Add(-2 * time.Minute),
	})
	// Inferred metadata exists but should not be used when structured events are present.
	fakeStore.userLinkedClients[user.ID] = []store.UserOIDCClient{
		{ClientID: "client-inferred", FirstSeenAt: time.Now().UTC().Add(-5 * time.Minute), LastSeenAt: time.Now().UTC().Add(-4 * time.Minute)},
	}

	auth := &fakeUIAuth{}
	e := setupTestAdminUI(t, fakeStore, auth, &fakeReloader{}, &fakeAuditStore{})

	rec := doUIRequest(t, e, http.MethodGet, "/admin/users/"+user.ID, nil, auth.sessionCookies())
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for structured timeline, got %d body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Passkey added") {
		t.Fatalf("expected structured passkey event on timeline, body=%s", body)
	}
	if strings.Contains(body, "OIDC client linked to user") {
		t.Fatalf("did not expect inferred fallback events when structured events exist, body=%s", body)
	}
}

func TestUserDetailTimelineHidesSensitiveFields(t *testing.T) {
	fakeStore := newFakeUIStore()
	user := fakeStore.seedSupportUser("user-sensitive", "sensitive@login.local", "sensitive@example.com", "+901")
	success := false
	_ = fakeStore.CreateUserSecurityEvent(context.Background(), store.UserSecurityEvent{
		UserID:       user.ID,
		EventType:    store.UserSecurityEventPasskeyRevoked,
		Category:     store.UserSecurityCategoryAdmin,
		Success:      &success,
		ActorType:    "admin_user",
		ActorID:      "admin-1",
		CredentialID: "deadbeef",
		DetailsJSON:  json.RawMessage(`{"error":"operation_failed","token":"TOP_TOKEN","secret":"TOP_SECRET","authorization":"Bearer leaked"}`),
		CreatedAt:    time.Now().UTC().Add(-2 * time.Minute),
	})
	auth := &fakeUIAuth{}
	e := setupTestAdminUI(t, fakeStore, auth, &fakeReloader{}, &fakeAuditStore{})

	rec := doUIRequest(t, e, http.MethodGet, "/admin/users/"+user.ID, nil, auth.sessionCookies())
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for sensitive details test, got %d body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if strings.Contains(body, "TOP_TOKEN") || strings.Contains(body, "TOP_SECRET") || strings.Contains(body, "Bearer leaked") {
		t.Fatalf("sensitive details leaked into timeline output: %s", body)
	}
	if !strings.Contains(body, "operation_failed") {
		t.Fatalf("expected safe error detail to remain visible, body=%s", body)
	}
}

func TestUserDetailTimelineIncludesAdminSupportActions(t *testing.T) {
	fakeStore := newFakeUIStore()
	target := fakeStore.seedSupportUser("user-admin-events", "admin.events@login.local", "admin.events@example.com", "+902")
	_ = fakeStore.seedSupportUser("user-other-events", "other@login.local", "other@example.com", "+903")
	success := true
	_ = fakeStore.CreateUserSecurityEvent(context.Background(), store.UserSecurityEvent{
		UserID:      target.ID,
		EventType:   store.UserSecurityEventSessionRevoked,
		Category:    store.UserSecurityCategoryAdmin,
		Success:     &success,
		ActorType:   "admin_user",
		ActorID:     "admin-1",
		SessionID:   "sess-1",
		DetailsJSON: json.RawMessage(`{"action":"admin.user.session.logout"}`),
		CreatedAt:   time.Now().UTC().Add(-1 * time.Minute),
	})
	_ = fakeStore.CreateUserSecurityEvent(context.Background(), store.UserSecurityEvent{
		UserID:      target.ID,
		EventType:   store.UserSecurityEventSessionLogoutAll,
		Category:    store.UserSecurityCategoryAdmin,
		Success:     &success,
		ActorType:   "admin_user",
		ActorID:     "admin-1",
		DetailsJSON: json.RawMessage(`{"removed_count":2}`),
		CreatedAt:   time.Now().UTC().Add(-2 * time.Minute),
	})
	_ = fakeStore.CreateUserSecurityEvent(context.Background(), store.UserSecurityEvent{
		UserID:       target.ID,
		EventType:    store.UserSecurityEventPasskeyRevoked,
		Category:     store.UserSecurityCategoryAdmin,
		Success:      &success,
		ActorType:    "admin_user",
		ActorID:      "admin-1",
		CredentialID: "cred-1",
		DetailsJSON:  json.RawMessage(`{"action":"admin.user.passkey.revoke"}`),
		CreatedAt:    time.Now().UTC().Add(-3 * time.Minute),
	})
	_ = fakeStore.CreateUserSecurityEvent(context.Background(), store.UserSecurityEvent{
		UserID:      "user-other-events",
		EventType:   store.UserSecurityEventSessionRevoked,
		Category:    store.UserSecurityCategoryAdmin,
		Success:     &success,
		ActorType:   "admin_user",
		ActorID:     "admin-1",
		SessionID:   "sess-foreign",
		DetailsJSON: json.RawMessage(`{"action":"admin.user.session.logout"}`),
		CreatedAt:   time.Now().UTC().Add(-4 * time.Minute),
	})
	auth := &fakeUIAuth{}
	e := setupTestAdminUI(t, fakeStore, auth, &fakeReloader{}, &fakeAuditStore{})

	rec := doUIRequest(t, e, http.MethodGet, "/admin/users/"+target.ID+"?events=admin", nil, auth.sessionCookies())
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for admin events timeline, got %d body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, expected := range []string{
		"Admin revoked user session",
		"Admin logged out all user sessions",
		"Admin revoked user passkey",
	} {
		if !strings.Contains(body, expected) {
			t.Fatalf("expected admin support event %q in timeline, body=%s", expected, body)
		}
	}
	if strings.Contains(body, "sess-foreign") {
		t.Fatalf("timeline should not include admin events for another user, body=%s", body)
	}
}

func TestUserSessionLogoutActionWritesAudit(t *testing.T) {
	fakeStore := newFakeUIStore()
	user := fakeStore.seedSupportUser("user-logout-one", "logout-one@login.local", "logout.one@example.com", "+555")
	auth := &fakeUIAuth{
		userSessions: map[string][]store.UserSessionInfo{
			user.ID: {
				{SessionID: "sess-1", CreatedAt: time.Now().UTC().Add(-2 * time.Hour), LastSeenAt: time.Now().UTC().Add(-15 * time.Minute)},
				{SessionID: "sess-2", CreatedAt: time.Now().UTC().Add(-90 * time.Minute), LastSeenAt: time.Now().UTC().Add(-10 * time.Minute)},
			},
		},
	}
	auditStore := &fakeAuditStore{}
	e := setupTestAdminUI(t, fakeStore, auth, &fakeReloader{}, auditStore)
	cookies, csrfToken := getCSRFCookiesAndToken(t, e, "/admin/users/"+user.ID, auth.sessionCookies())

	rec := doUIRequest(t, e, http.MethodPost, "/admin/users/"+user.ID+"/sessions/sess-2/logout", withCSRF(nil, csrfToken), cookies)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expected 303 on user session logout, got %d body=%s", rec.Code, rec.Body.String())
	}
	if len(auth.userSessions[user.ID]) != 1 {
		t.Fatalf("expected one session remaining, got %+v", auth.userSessions[user.ID])
	}
	if !hasAuditAction(auditStore.entries, "admin.user.session.logout.success", true) {
		t.Fatalf("expected admin.user.session.logout.success audit entry")
	}
	if !hasUserSecurityEvent(fakeStore.userSecurityEvents, user.ID, store.UserSecurityEventSessionRevoked, true) {
		t.Fatalf("expected mirrored user security event session_revoked success")
	}
}

func TestUserLogoutAllSessionsRequiresRecentReauth(t *testing.T) {
	fakeStore := newFakeUIStore()
	user := fakeStore.seedSupportUser("user-logout-all", "logout-all@login.local", "logout.all@example.com", "+666")
	auth := &fakeUIAuth{
		disableAutoRecentReauth: true,
		userSessions: map[string][]store.UserSessionInfo{
			user.ID: {
				{SessionID: "sess-a", CreatedAt: time.Now().UTC().Add(-2 * time.Hour), LastSeenAt: time.Now().UTC().Add(-12 * time.Minute)},
				{SessionID: "sess-b", CreatedAt: time.Now().UTC().Add(-90 * time.Minute), LastSeenAt: time.Now().UTC().Add(-10 * time.Minute)},
			},
		},
	}
	auditStore := &fakeAuditStore{}
	e := setupTestAdminUI(t, fakeStore, auth, &fakeReloader{}, auditStore)
	cookies, csrfToken := getCSRFCookiesAndToken(t, e, "/admin/users/"+user.ID, auth.sessionCookies())

	recBlocked := doUIRequest(t, e, http.MethodPost, "/admin/users/"+user.ID+"/sessions/logout-all", withCSRF(nil, csrfToken), cookies)
	if recBlocked.Code != http.StatusForbidden {
		t.Fatalf("expected 403 without recent reauth, got %d body=%s", recBlocked.Code, recBlocked.Body.String())
	}

	now := time.Now().UTC()
	auth.recentReauthAt = &now
	recOK := doUIRequest(t, e, http.MethodPost, "/admin/users/"+user.ID+"/sessions/logout-all", withCSRF(nil, csrfToken), cookies)
	if recOK.Code != http.StatusSeeOther {
		t.Fatalf("expected 303 with recent reauth, got %d body=%s", recOK.Code, recOK.Body.String())
	}
	if len(auth.userSessions[user.ID]) != 0 {
		t.Fatalf("expected all user sessions removed, got %+v", auth.userSessions[user.ID])
	}
	if !hasAuditAction(auditStore.entries, "admin.user.session.logout_all.success", true) {
		t.Fatalf("expected admin.user.session.logout_all.success audit entry")
	}
	if !hasUserSecurityEvent(fakeStore.userSecurityEvents, user.ID, store.UserSecurityEventSessionLogoutAll, true) {
		t.Fatalf("expected mirrored user security event session_logout_all success")
	}
}

func TestUserPasskeyRevokeRequiresRecentReauthAndWritesAudit(t *testing.T) {
	fakeStore := newFakeUIStore()
	user := fakeStore.seedSupportUser("user-passkey", "passkey@login.local", "passkey@example.com", "+777")
	fakeStore.userCredentials[user.ID] = []store.CredentialRecord{
		{ID: []byte{0x0a, 0x0b, 0x0c}, DeviceName: "Phone", CreatedAt: time.Now().UTC().Add(-4 * time.Hour)},
		{ID: []byte{0x0d, 0x0e, 0x0f}, DeviceName: "Laptop", CreatedAt: time.Now().UTC().Add(-3 * time.Hour)},
	}
	auth := &fakeUIAuth{disableAutoRecentReauth: true}
	auditStore := &fakeAuditStore{}
	e := setupTestAdminUI(t, fakeStore, auth, &fakeReloader{}, auditStore)
	cookies, csrfToken := getCSRFCookiesAndToken(t, e, "/admin/users/"+user.ID, auth.sessionCookies())

	targetCredentialID := hex.EncodeToString(fakeStore.userCredentials[user.ID][0].ID)
	recBlocked := doUIRequest(t, e, http.MethodPost, "/admin/users/"+user.ID+"/passkeys/"+targetCredentialID+"/revoke", withCSRF(nil, csrfToken), cookies)
	if recBlocked.Code != http.StatusForbidden {
		t.Fatalf("expected 403 without recent reauth for revoke, got %d body=%s", recBlocked.Code, recBlocked.Body.String())
	}

	now := time.Now().UTC()
	auth.recentReauthAt = &now
	recOK := doUIRequest(t, e, http.MethodPost, "/admin/users/"+user.ID+"/passkeys/"+targetCredentialID+"/revoke", withCSRF(nil, csrfToken), cookies)
	if recOK.Code != http.StatusSeeOther {
		t.Fatalf("expected 303 with recent reauth for revoke, got %d body=%s", recOK.Code, recOK.Body.String())
	}
	if len(fakeStore.userCredentials[user.ID]) != 1 {
		t.Fatalf("expected one passkey remaining after revoke, got %+v", fakeStore.userCredentials[user.ID])
	}
	if !hasAuditAction(auditStore.entries, "admin.user.passkey.revoke.success", true) {
		t.Fatalf("expected admin.user.passkey.revoke.success audit entry")
	}
	if !hasUserSecurityEvent(fakeStore.userSecurityEvents, user.ID, store.UserSecurityEventPasskeyRevoked, true) {
		t.Fatalf("expected mirrored user security event passkey_revoked success")
	}
}

func TestUserBlockRequiresRecentReauthInvalidatesSessionsAndWritesAudit(t *testing.T) {
	fakeStore := newFakeUIStore()
	user := fakeStore.seedSupportUser("user-block", "block@login.local", "block@example.com", "+100")
	auth := &fakeUIAuth{
		disableAutoRecentReauth: true,
		userSessions: map[string][]store.UserSessionInfo{
			user.ID: {
				{SessionID: "sess-a", CreatedAt: time.Now().UTC().Add(-2 * time.Hour), LastSeenAt: time.Now().UTC().Add(-5 * time.Minute)},
				{SessionID: "sess-b", CreatedAt: time.Now().UTC().Add(-90 * time.Minute), LastSeenAt: time.Now().UTC().Add(-2 * time.Minute)},
			},
		},
	}
	auditStore := &fakeAuditStore{}
	e := setupTestAdminUI(t, fakeStore, auth, &fakeReloader{}, auditStore)
	cookies, csrfToken := getCSRFCookiesAndToken(t, e, "/admin/users/"+user.ID, auth.sessionCookies())

	blockForm := withCSRF(url.Values{"reason": {"security incident"}}, csrfToken)
	recBlocked := doUIRequest(t, e, http.MethodPost, "/admin/users/"+user.ID+"/block", blockForm, cookies)
	if recBlocked.Code != http.StatusForbidden {
		t.Fatalf("expected 403 without recent reauth for block, got %d body=%s", recBlocked.Code, recBlocked.Body.String())
	}

	now := time.Now().UTC()
	auth.recentReauthAt = &now
	recOK := doUIRequest(t, e, http.MethodPost, "/admin/users/"+user.ID+"/block", blockForm, cookies)
	if recOK.Code != http.StatusSeeOther {
		t.Fatalf("expected 303 with recent reauth for block, got %d body=%s", recOK.Code, recOK.Body.String())
	}
	updatedUser, err := fakeStore.GetUserProfileForAdmin(user.ID)
	if err != nil {
		t.Fatalf("get blocked user profile failed: %v", err)
	}
	if !updatedUser.IsBlocked {
		t.Fatalf("expected user to be blocked")
	}
	if updatedUser.BlockedReason != "security incident" {
		t.Fatalf("expected blocked reason to be stored, got %q", updatedUser.BlockedReason)
	}
	if updatedUser.BlockedAt == nil || updatedUser.BlockedAt.IsZero() {
		t.Fatalf("expected blocked_at to be set")
	}
	if len(auth.userSessions[user.ID]) != 0 {
		t.Fatalf("expected all user sessions invalidated on block, got %+v", auth.userSessions[user.ID])
	}
	if !hasAuditAction(auditStore.entries, "admin.user.block.success", true) {
		t.Fatalf("expected admin.user.block.success audit entry")
	}
	if !hasUserSecurityEvent(fakeStore.userSecurityEvents, user.ID, store.UserSecurityEventAccountBlocked, true) {
		t.Fatalf("expected account_blocked user timeline event")
	}
}

func TestUserUnblockRequiresRecentReauthAndWritesAudit(t *testing.T) {
	fakeStore := newFakeUIStore()
	user := fakeStore.seedSupportUser("user-unblock", "unblock@login.local", "unblock@example.com", "+101")
	if err := fakeStore.SetUserBlocked(context.Background(), user.ID, true, "manual block", "admin-1"); err != nil {
		t.Fatalf("seed blocked state failed: %v", err)
	}

	auth := &fakeUIAuth{disableAutoRecentReauth: true}
	auditStore := &fakeAuditStore{}
	e := setupTestAdminUI(t, fakeStore, auth, &fakeReloader{}, auditStore)
	cookies, csrfToken := getCSRFCookiesAndToken(t, e, "/admin/users/"+user.ID, auth.sessionCookies())

	recBlocked := doUIRequest(t, e, http.MethodPost, "/admin/users/"+user.ID+"/unblock", withCSRF(nil, csrfToken), cookies)
	if recBlocked.Code != http.StatusForbidden {
		t.Fatalf("expected 403 without recent reauth for unblock, got %d body=%s", recBlocked.Code, recBlocked.Body.String())
	}

	now := time.Now().UTC()
	auth.recentReauthAt = &now
	recOK := doUIRequest(t, e, http.MethodPost, "/admin/users/"+user.ID+"/unblock", withCSRF(nil, csrfToken), cookies)
	if recOK.Code != http.StatusSeeOther {
		t.Fatalf("expected 303 with recent reauth for unblock, got %d body=%s", recOK.Code, recOK.Body.String())
	}
	updatedUser, err := fakeStore.GetUserProfileForAdmin(user.ID)
	if err != nil {
		t.Fatalf("get unblocked user profile failed: %v", err)
	}
	if updatedUser.IsBlocked {
		t.Fatalf("expected user to be unblocked")
	}
	if updatedUser.BlockedAt != nil || updatedUser.BlockedReason != "" || updatedUser.BlockedByAdminUserID != "" {
		t.Fatalf("expected block metadata to be cleared on unblock, got %+v", updatedUser)
	}
	if !hasAuditAction(auditStore.entries, "admin.user.unblock.success", true) {
		t.Fatalf("expected admin.user.unblock.success audit entry")
	}
	if !hasUserSecurityEvent(fakeStore.userSecurityEvents, user.ID, store.UserSecurityEventAccountUnblocked, true) {
		t.Fatalf("expected account_unblocked user timeline event")
	}
}

func TestOwnerCanOpenUserDeletePage(t *testing.T) {
	fakeStore := newFakeUIStore()
	user := fakeStore.seedSupportUser("user-delete-page", "delete.page@login.local", "delete.page@example.com", "+201")
	auth := &fakeUIAuth{}
	e := setupTestAdminUI(t, fakeStore, auth, &fakeReloader{}, &fakeAuditStore{})

	rec := doUIRequest(t, e, http.MethodGet, "/admin/users/"+user.ID+"/delete", nil, auth.sessionCookies())
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for owner delete page, got %d body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Delete User") {
		t.Fatalf("expected delete page heading, body=%s", body)
	}
	if !strings.Contains(body, userDeleteConfirmPhrase(user.ID)) {
		t.Fatalf("expected delete confirmation phrase on page, body=%s", body)
	}
}

func TestAdminCannotAccessUserDelete(t *testing.T) {
	fakeStore := newFakeUIStore()
	user := fakeStore.seedSupportUser("user-delete-forbidden", "delete.forbidden@login.local", "delete.forbidden@example.com", "+202")
	auth := &fakeUIAuth{
		user: store.AdminUser{ID: "admin-2", Login: "ops", DisplayName: "Ops", Role: store.AdminRoleAdmin},
	}
	e := setupTestAdminUI(t, fakeStore, auth, &fakeReloader{}, &fakeAuditStore{})

	recGet := doUIRequest(t, e, http.MethodGet, "/admin/users/"+user.ID+"/delete", nil, auth.sessionCookies())
	if recGet.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for non-owner delete page, got %d body=%s", recGet.Code, recGet.Body.String())
	}

	cookies, csrfToken := getCSRFCookiesAndToken(t, e, "/admin/users/"+user.ID, auth.sessionCookies())
	form := withCSRF(url.Values{"confirm_phrase": {userDeleteConfirmPhrase(user.ID)}}, csrfToken)
	recPost := doUIRequest(t, e, http.MethodPost, "/admin/users/"+user.ID+"/delete", form, cookies)
	if recPost.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for non-owner delete post, got %d body=%s", recPost.Code, recPost.Body.String())
	}
}

func TestUserDeleteRequiresRecentReauth(t *testing.T) {
	fakeStore := newFakeUIStore()
	user := fakeStore.seedSupportUser("user-delete-reauth", "delete.reauth@login.local", "delete.reauth@example.com", "+203")
	auth := &fakeUIAuth{
		disableAutoRecentReauth: true,
	}
	e := setupTestAdminUI(t, fakeStore, auth, &fakeReloader{}, &fakeAuditStore{})
	cookies, csrfToken := getCSRFCookiesAndToken(t, e, "/admin/users/"+user.ID+"/delete", auth.sessionCookies())
	form := withCSRF(url.Values{"confirm_phrase": {userDeleteConfirmPhrase(user.ID)}}, csrfToken)

	recBlocked := doUIRequest(t, e, http.MethodPost, "/admin/users/"+user.ID+"/delete", form, cookies)
	if recBlocked.Code != http.StatusForbidden {
		t.Fatalf("expected 403 without recent reauth, got %d body=%s", recBlocked.Code, recBlocked.Body.String())
	}
	if _, err := fakeStore.GetUserProfileForAdmin(user.ID); err != nil {
		t.Fatalf("expected user to still exist when reauth is missing, err=%v", err)
	}

	now := time.Now().UTC()
	auth.recentReauthAt = &now
	recOK := doUIRequest(t, e, http.MethodPost, "/admin/users/"+user.ID+"/delete", form, cookies)
	if recOK.Code != http.StatusSeeOther {
		t.Fatalf("expected 303 with recent reauth, got %d body=%s", recOK.Code, recOK.Body.String())
	}
}

func TestUserDeleteRequiresConfirmationPhrase(t *testing.T) {
	fakeStore := newFakeUIStore()
	user := fakeStore.seedSupportUser("user-delete-confirm", "delete.confirm@login.local", "delete.confirm@example.com", "+204")
	auth := &fakeUIAuth{}
	e := setupTestAdminUI(t, fakeStore, auth, &fakeReloader{}, &fakeAuditStore{})
	cookies, csrfToken := getCSRFCookiesAndToken(t, e, "/admin/users/"+user.ID+"/delete", auth.sessionCookies())

	form := withCSRF(url.Values{"confirm_phrase": {"DELETE WRONG"}}, csrfToken)
	rec := doUIRequest(t, e, http.MethodPost, "/admin/users/"+user.ID+"/delete", form, cookies)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for wrong confirmation phrase, got %d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(strings.ToLower(rec.Body.String()), "confirmation phrase does not match") {
		t.Fatalf("expected confirmation mismatch message, body=%s", rec.Body.String())
	}
	if fakeStore.deleteUserCalls != 0 {
		t.Fatalf("expected delete not to run on mismatch, delete calls=%d", fakeStore.deleteUserCalls)
	}
}

func TestUserDeleteSuccessRemovesUserAndWritesAudit(t *testing.T) {
	fakeStore := newFakeUIStore()
	user := fakeStore.seedSupportUser("user-delete-success", "delete.success@login.local", "delete.success@example.com", "+205")
	fakeStore.userCredentials[user.ID] = []store.CredentialRecord{
		{ID: []byte{0xaa, 0x01}, CreatedAt: time.Now().UTC().Add(-4 * time.Hour)},
		{ID: []byte{0xaa, 0x02}, CreatedAt: time.Now().UTC().Add(-2 * time.Hour)},
	}
	fakeStore.userLinkedClients[user.ID] = []store.UserOIDCClient{
		{ClientID: "client-a", ClientHost: "app.local", FirstSeenAt: time.Now().UTC().Add(-24 * time.Hour), LastSeenAt: time.Now().UTC().Add(-1 * time.Hour)},
	}
	ok := true
	_ = fakeStore.CreateUserSecurityEvent(context.Background(), store.UserSecurityEvent{
		UserID:    user.ID,
		EventType: store.UserSecurityEventLoginSuccess,
		Category:  store.UserSecurityCategoryAuth,
		Success:   &ok,
		ActorType: "user",
		ActorID:   user.ID,
	})
	auth := &fakeUIAuth{
		userSessions: map[string][]store.UserSessionInfo{
			user.ID: {
				{SessionID: "sess-del-1", CreatedAt: time.Now().UTC().Add(-2 * time.Hour), LastSeenAt: time.Now().UTC().Add(-10 * time.Minute)},
				{SessionID: "sess-del-2", CreatedAt: time.Now().UTC().Add(-90 * time.Minute), LastSeenAt: time.Now().UTC().Add(-3 * time.Minute)},
			},
		},
	}
	auditStore := &fakeAuditStore{}
	e := setupTestAdminUI(t, fakeStore, auth, &fakeReloader{}, auditStore)
	cookies, csrfToken := getCSRFCookiesAndToken(t, e, "/admin/users/"+user.ID+"/delete", auth.sessionCookies())
	form := withCSRF(url.Values{"confirm_phrase": {userDeleteConfirmPhrase(user.ID)}}, csrfToken)

	rec := doUIRequest(t, e, http.MethodPost, "/admin/users/"+user.ID+"/delete", form, cookies)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expected 303 for successful delete, got %d body=%s", rec.Code, rec.Body.String())
	}
	if location := rec.Header().Get(echo.HeaderLocation); location != "/admin/users" {
		t.Fatalf("expected redirect to /admin/users, got %s", location)
	}
	if _, err := fakeStore.GetUserProfileForAdmin(user.ID); !errors.Is(err, store.ErrUserNotFound) {
		t.Fatalf("expected user row to be deleted, got err=%v", err)
	}
	if len(fakeStore.userCredentials[user.ID]) != 0 {
		t.Fatalf("expected user credentials to be deleted")
	}
	if len(fakeStore.userLinkedClients[user.ID]) != 0 {
		t.Fatalf("expected linked clients to be deleted")
	}
	if hasUserSecurityEvent(fakeStore.userSecurityEvents, user.ID, store.UserSecurityEventLoginSuccess, true) {
		t.Fatalf("expected user security events to be deleted via cascade")
	}
	if auth.logoutAllCalls != 1 {
		t.Fatalf("expected full session cleanup helper to be called once, got %d", auth.logoutAllCalls)
	}
	if !hasAuditAction(auditStore.entries, "admin.user.delete.success", true) {
		t.Fatalf("expected admin.user.delete.success audit entry")
	}
}

func TestUserDeleteAvatarCleanupFailureDoesNotRollbackDelete(t *testing.T) {
	fakeStore := newFakeUIStore()
	user := fakeStore.seedSupportUser("user-delete-avatar-fail", "delete.avatar@login.local", "delete.avatar@example.com", "+208")
	user.AvatarKey = "avatars/" + user.ID + ".webp"
	fakeStore.users[user.ID] = user

	auth := &fakeUIAuth{
		userSessions: map[string][]store.UserSessionInfo{
			user.ID: {
				{SessionID: "sess-avatar-1", CreatedAt: time.Now().UTC().Add(-2 * time.Hour), LastSeenAt: time.Now().UTC().Add(-5 * time.Minute)},
			},
		},
	}
	auditStore := &fakeAuditStore{}
	e, h := setupTestAdminUIWithHandler(t, fakeStore, auth, &fakeReloader{}, auditStore)
	h.avatarDelete = func(ctx context.Context, avatarKey string) error {
		return errors.New("avatar delete failed")
	}
	cookies, csrfToken := getCSRFCookiesAndToken(t, e, "/admin/users/"+user.ID+"/delete", auth.sessionCookies())
	form := withCSRF(url.Values{"confirm_phrase": {userDeleteConfirmPhrase(user.ID)}}, csrfToken)

	rec := doUIRequest(t, e, http.MethodPost, "/admin/users/"+user.ID+"/delete", form, cookies)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expected 303 for delete with avatar cleanup warning, got %d body=%s", rec.Code, rec.Body.String())
	}
	if _, err := fakeStore.GetUserProfileForAdmin(user.ID); !errors.Is(err, store.ErrUserNotFound) {
		t.Fatalf("expected user to be deleted despite avatar cleanup failure, err=%v", err)
	}
	if !hasAuditAction(auditStore.entries, "admin.user.delete.success", true) {
		t.Fatalf("expected success audit entry")
	}
}

func TestUserDeleteDBFailureDoesNotRunCleanup(t *testing.T) {
	fakeStore := newFakeUIStore()
	user := fakeStore.seedSupportUser("user-delete-db-fail", "delete.dbfail@login.local", "delete.dbfail@example.com", "+206")
	fakeStore.deleteUserErr = errors.New("db delete failed")
	auth := &fakeUIAuth{
		userSessions: map[string][]store.UserSessionInfo{
			user.ID: {
				{SessionID: "sess-db-1", CreatedAt: time.Now().UTC().Add(-2 * time.Hour), LastSeenAt: time.Now().UTC().Add(-5 * time.Minute)},
			},
		},
	}
	auditStore := &fakeAuditStore{}
	e := setupTestAdminUI(t, fakeStore, auth, &fakeReloader{}, auditStore)
	cookies, csrfToken := getCSRFCookiesAndToken(t, e, "/admin/users/"+user.ID+"/delete", auth.sessionCookies())
	form := withCSRF(url.Values{"confirm_phrase": {userDeleteConfirmPhrase(user.ID)}}, csrfToken)

	rec := doUIRequest(t, e, http.MethodPost, "/admin/users/"+user.ID+"/delete", form, cookies)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 on DB delete failure, got %d body=%s", rec.Code, rec.Body.String())
	}
	if auth.logoutAllCalls != 0 {
		t.Fatalf("expected cleanup not to run when DB delete fails, calls=%d", auth.logoutAllCalls)
	}
	if _, err := fakeStore.GetUserProfileForAdmin(user.ID); err != nil {
		t.Fatalf("expected user to remain after DB failure, err=%v", err)
	}
	if !hasAuditAction(auditStore.entries, "admin.user.delete.failure", false) {
		t.Fatalf("expected admin.user.delete.failure audit entry")
	}
}

func TestUserDeleteCleanupFailureIsSurfaced(t *testing.T) {
	fakeStore := newFakeUIStore()
	user := fakeStore.seedSupportUser("user-delete-cleanup-fail", "delete.cleanup@login.local", "delete.cleanup@example.com", "+207")
	auth := &fakeUIAuth{
		logoutAllErr: errors.New("redis cleanup failed"),
		userSessions: map[string][]store.UserSessionInfo{
			user.ID: {
				{SessionID: "sess-cleanup-1", CreatedAt: time.Now().UTC().Add(-2 * time.Hour), LastSeenAt: time.Now().UTC().Add(-5 * time.Minute)},
			},
		},
	}
	auditStore := &fakeAuditStore{}
	e := setupTestAdminUI(t, fakeStore, auth, &fakeReloader{}, auditStore)
	cookies, csrfToken := getCSRFCookiesAndToken(t, e, "/admin/users/"+user.ID+"/delete", auth.sessionCookies())
	form := withCSRF(url.Values{"confirm_phrase": {userDeleteConfirmPhrase(user.ID)}}, csrfToken)

	rec := doUIRequest(t, e, http.MethodPost, "/admin/users/"+user.ID+"/delete", form, cookies)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 when cleanup fails after delete, got %d body=%s", rec.Code, rec.Body.String())
	}
	if _, err := fakeStore.GetUserProfileForAdmin(user.ID); !errors.Is(err, store.ErrUserNotFound) {
		t.Fatalf("expected user row to be deleted even when cleanup fails, err=%v", err)
	}
	if !strings.Contains(strings.ToLower(rec.Body.String()), "session cleanup failed") {
		t.Fatalf("expected explicit cleanup failure message, body=%s", rec.Body.String())
	}
	if !hasAuditAction(auditStore.entries, "admin.user.delete.failure", false) {
		t.Fatalf("expected admin.user.delete.failure audit entry")
	}
}

func TestUsersListAndDetailShowBlockedState(t *testing.T) {
	fakeStore := newFakeUIStore()
	blocked := fakeStore.seedSupportUser("user-list-blocked", "list.blocked@login.local", "blocked@example.com", "+102")
	if err := fakeStore.SetUserBlocked(context.Background(), blocked.ID, true, "abuse", "admin-1"); err != nil {
		t.Fatalf("seed blocked user failed: %v", err)
	}
	active := fakeStore.seedSupportUser("user-list-active", "list.active@login.local", "active@example.com", "+103")
	auth := &fakeUIAuth{}
	e := setupTestAdminUI(t, fakeStore, auth, &fakeReloader{}, &fakeAuditStore{})

	listRec := doUIRequest(t, e, http.MethodGet, "/admin/users?q=user-list", nil, auth.sessionCookies())
	if listRec.Code != http.StatusOK {
		t.Fatalf("expected 200 for users list, got %d body=%s", listRec.Code, listRec.Body.String())
	}
	listBody := listRec.Body.String()
	if !strings.Contains(listBody, blocked.ID) || !strings.Contains(listBody, active.ID) {
		t.Fatalf("expected both users in list output, body=%s", listBody)
	}
	if !strings.Contains(listBody, "blocked") {
		t.Fatalf("expected blocked badge in users list, body=%s", listBody)
	}

	detailRec := doUIRequest(t, e, http.MethodGet, "/admin/users/"+blocked.ID, nil, auth.sessionCookies())
	if detailRec.Code != http.StatusOK {
		t.Fatalf("expected 200 for blocked detail, got %d body=%s", detailRec.Code, detailRec.Body.String())
	}
	detailBody := detailRec.Body.String()
	for _, expected := range []string{"Status", "blocked", "Blocked Reason", "abuse", "/admin/users/" + blocked.ID + "/unblock"} {
		if !strings.Contains(detailBody, expected) {
			t.Fatalf("expected %q on blocked detail page, body=%s", expected, detailBody)
		}
	}
}

func TestUsersMutatingRoutesRequireCSRF(t *testing.T) {
	fakeStore := newFakeUIStore()
	user := fakeStore.seedSupportUser("user-csrf", "csrf@login.local", "csrf@example.com", "+999")
	fakeStore.userCredentials[user.ID] = []store.CredentialRecord{
		{ID: []byte{0xaa, 0xbb}, CreatedAt: time.Now().UTC().Add(-2 * time.Hour)},
		{ID: []byte{0xcc, 0xdd}, CreatedAt: time.Now().UTC().Add(-1 * time.Hour)},
	}
	auth := &fakeUIAuth{
		userSessions: map[string][]store.UserSessionInfo{
			user.ID: {
				{SessionID: "sess-x", CreatedAt: time.Now().UTC().Add(-90 * time.Minute), LastSeenAt: time.Now().UTC().Add(-2 * time.Minute)},
			},
		},
	}
	e := setupTestAdminUI(t, fakeStore, auth, &fakeReloader{}, &fakeAuditStore{})

	noCSRFLogoutOne := doUIRequest(t, e, http.MethodPost, "/admin/users/"+user.ID+"/sessions/sess-x/logout", nil, auth.sessionCookies())
	if noCSRFLogoutOne.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for logout-one without csrf, got %d body=%s", noCSRFLogoutOne.Code, noCSRFLogoutOne.Body.String())
	}

	noCSRFLogoutAll := doUIRequest(t, e, http.MethodPost, "/admin/users/"+user.ID+"/sessions/logout-all", nil, auth.sessionCookies())
	if noCSRFLogoutAll.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for logout-all without csrf, got %d body=%s", noCSRFLogoutAll.Code, noCSRFLogoutAll.Body.String())
	}

	credentialID := hex.EncodeToString(fakeStore.userCredentials[user.ID][0].ID)
	noCSRFRevoke := doUIRequest(t, e, http.MethodPost, "/admin/users/"+user.ID+"/passkeys/"+credentialID+"/revoke", nil, auth.sessionCookies())
	if noCSRFRevoke.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for passkey revoke without csrf, got %d body=%s", noCSRFRevoke.Code, noCSRFRevoke.Body.String())
	}

	noCSRFBlock := doUIRequest(t, e, http.MethodPost, "/admin/users/"+user.ID+"/block", url.Values{"reason": {"incident"}}, auth.sessionCookies())
	if noCSRFBlock.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for block without csrf, got %d body=%s", noCSRFBlock.Code, noCSRFBlock.Body.String())
	}

	noCSRFUnblock := doUIRequest(t, e, http.MethodPost, "/admin/users/"+user.ID+"/unblock", nil, auth.sessionCookies())
	if noCSRFUnblock.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for unblock without csrf, got %d body=%s", noCSRFUnblock.Code, noCSRFUnblock.Body.String())
	}

	noCSRFDelete := doUIRequest(t, e, http.MethodPost, "/admin/users/"+user.ID+"/delete", url.Values{"confirm_phrase": {userDeleteConfirmPhrase(user.ID)}}, auth.sessionCookies())
	if noCSRFDelete.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for delete without csrf, got %d body=%s", noCSRFDelete.Code, noCSRFDelete.Body.String())
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
	e, _ := setupTestAdminUIWithHandler(t, fakeStore, auth, reloader, auditStore)
	return e
}

func setupTestAdminUIWithHandler(t *testing.T, fakeStore *fakeUIStore, auth *fakeUIAuth, reloader *fakeReloader, auditStore *fakeAuditStore) (*echo.Echo, *Handler) {
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
	return e, h
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
	userSessions            map[string][]store.UserSessionInfo
	logoutAllCalls          int
	logoutAllErr            error
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

func (a *fakeUIAuth) CountActiveUserSessionsByUserIDs(ctx context.Context, userIDs []string) (map[string]int, error) {
	out := make(map[string]int, len(userIDs))
	for _, userID := range userIDs {
		normalized := strings.TrimSpace(userID)
		if normalized == "" {
			continue
		}
		out[normalized] = len(a.userSessions[normalized])
	}
	return out, nil
}

func (a *fakeUIAuth) ListUserSessionsForAdmin(ctx context.Context, userID string) ([]store.UserSessionInfo, error) {
	userID = strings.TrimSpace(userID)
	items := a.userSessions[userID]
	out := make([]store.UserSessionInfo, 0, len(items))
	for _, item := range items {
		out = append(out, item)
	}
	return out, nil
}

func (a *fakeUIAuth) LogoutUserSessionForAdmin(ctx context.Context, userID string, sessionID string) error {
	userID = strings.TrimSpace(userID)
	sessionID = strings.TrimSpace(sessionID)
	if userID == "" || sessionID == "" {
		return errors.New("invalid user/session id")
	}
	items := a.userSessions[userID]
	idx := -1
	for i, item := range items {
		if strings.TrimSpace(item.SessionID) == sessionID {
			idx = i
			break
		}
	}
	if idx < 0 {
		return errors.New("session not found")
	}
	if a.userSessions == nil {
		a.userSessions = map[string][]store.UserSessionInfo{}
	}
	a.userSessions[userID] = append(items[:idx], items[idx+1:]...)
	return nil
}

func (a *fakeUIAuth) LogoutAllUserSessionsForAdmin(ctx context.Context, userID string) (int, error) {
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return 0, errors.New("invalid user id")
	}
	a.logoutAllCalls++
	if a.logoutAllErr != nil {
		return 0, a.logoutAllErr
	}
	removed := len(a.userSessions[userID])
	if a.userSessions == nil {
		a.userSessions = map[string][]store.UserSessionInfo{}
	}
	a.userSessions[userID] = []store.UserSessionInfo{}
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

type fakeHealthProvider struct {
	snapshot *SystemHealthSnapshot
	err      error
}

func (f fakeHealthProvider) GetSystemHealthSnapshot(ctx context.Context) (*SystemHealthSnapshot, error) {
	return f.snapshot, f.err
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
	users                map[string]store.AdminUserProfile
	userCredentials      map[string][]store.CredentialRecord
	userLinkedClients    map[string][]store.UserOIDCClient
	userSecurityEvents   []store.UserSecurityEvent
	nextUserSecurityID   int64
	deleteUserErr        error
	deleteUserCalls      int
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
		users:                map[string]store.AdminUserProfile{},
		userCredentials:      map[string][]store.CredentialRecord{},
		userLinkedClients:    map[string][]store.UserOIDCClient{},
		userSecurityEvents:   []store.UserSecurityEvent{},
		nextUserSecurityID:   1,
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

func (s *fakeUIStore) seedSupportUser(id string, loginID string, profileEmail string, phone string) store.AdminUserProfile {
	id = strings.TrimSpace(id)
	if id == "" {
		id = fmt.Sprintf("user-%d", len(s.users)+1)
	}
	now := time.Now().UTC()
	item := store.AdminUserProfile{
		ID:                   id,
		LoginID:              strings.TrimSpace(loginID),
		DisplayName:          "User " + id,
		ProfileEmail:         strings.TrimSpace(profileEmail),
		Phone:                strings.TrimSpace(phone),
		ShareProfile:         false,
		ProfileEmailVerified: strings.TrimSpace(profileEmail) != "",
		PhoneVerified:        strings.TrimSpace(phone) != "",
		CreatedAt:            now,
	}
	s.users[id] = item
	return item
}

func (s *fakeUIStore) ListUsersForAdmin(filter store.AdminUserSupportListFilter) ([]store.AdminUserSupportListItem, error) {
	limit := filter.Limit
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	offset := filter.Offset
	if offset < 0 {
		offset = 0
	}
	query := strings.ToLower(strings.TrimSpace(filter.Query))

	items := make([]store.AdminUserSupportListItem, 0, len(s.users))
	for _, user := range s.users {
		id := strings.TrimSpace(user.ID)
		loginID := strings.TrimSpace(user.LoginID)
		profileEmail := strings.TrimSpace(user.ProfileEmail)
		phone := strings.TrimSpace(user.Phone)

		if query != "" {
			if !strings.Contains(strings.ToLower(id), query) &&
				!strings.Contains(strings.ToLower(loginID), query) &&
				!strings.Contains(strings.ToLower(profileEmail), query) &&
				!strings.Contains(strings.ToLower(phone), query) {
				continue
			}
		}

		items = append(items, store.AdminUserSupportListItem{
			ID:                   id,
			LoginID:              loginID,
			ProfileEmail:         profileEmail,
			Phone:                phone,
			CreatedAt:            user.CreatedAt,
			ProfileEmailVerified: user.ProfileEmailVerified,
			PhoneVerified:        user.PhoneVerified,
			IsBlocked:            user.IsBlocked,
			PasskeyCount:         len(s.userCredentials[id]),
			LinkedClientCount:    len(s.userLinkedClients[id]),
		})
	}

	sort.Slice(items, func(i, j int) bool {
		if items[i].CreatedAt.Equal(items[j].CreatedAt) {
			return items[i].ID > items[j].ID
		}
		return items[i].CreatedAt.After(items[j].CreatedAt)
	})

	if offset >= len(items) {
		return []store.AdminUserSupportListItem{}, nil
	}
	end := offset + limit
	if end > len(items) {
		end = len(items)
	}
	out := make([]store.AdminUserSupportListItem, 0, end-offset)
	out = append(out, items[offset:end]...)
	return out, nil
}

func (s *fakeUIStore) GetUserProfileForAdmin(userID string) (*store.AdminUserProfile, error) {
	userID = strings.TrimSpace(userID)
	item, ok := s.users[userID]
	if !ok {
		return nil, store.ErrUserNotFound
	}
	copyItem := item
	return &copyItem, nil
}

func (s *fakeUIStore) DeleteUser(userID string) error {
	userID = strings.TrimSpace(userID)
	s.deleteUserCalls++
	if s.deleteUserErr != nil {
		return s.deleteUserErr
	}
	if _, ok := s.users[userID]; !ok {
		return store.ErrUserNotFound
	}
	delete(s.users, userID)
	delete(s.userCredentials, userID)
	delete(s.userLinkedClients, userID)

	filtered := make([]store.UserSecurityEvent, 0, len(s.userSecurityEvents))
	for _, event := range s.userSecurityEvents {
		if strings.TrimSpace(event.UserID) == userID {
			continue
		}
		filtered = append(filtered, event)
	}
	s.userSecurityEvents = filtered
	return nil
}

func (s *fakeUIStore) SetUserBlocked(ctx context.Context, userID string, blocked bool, reason string, blockedByAdminUserID string) error {
	userID = strings.TrimSpace(userID)
	item, ok := s.users[userID]
	if !ok {
		return store.ErrUserNotFound
	}
	if blocked {
		item.IsBlocked = true
		now := time.Now().UTC()
		item.BlockedAt = &now
		item.BlockedReason = strings.TrimSpace(reason)
		item.BlockedByAdminUserID = strings.TrimSpace(blockedByAdminUserID)
		if adminUser, ok := s.adminUsers[item.BlockedByAdminUserID]; ok {
			item.BlockedByAdminLogin = strings.TrimSpace(adminUser.Login)
		} else {
			item.BlockedByAdminLogin = ""
		}
	} else {
		item.IsBlocked = false
		item.BlockedAt = nil
		item.BlockedReason = ""
		item.BlockedByAdminUserID = ""
		item.BlockedByAdminLogin = ""
	}
	s.users[userID] = item
	return nil
}

func (s *fakeUIStore) ListCredentialRecords(userID string) ([]store.CredentialRecord, error) {
	userID = strings.TrimSpace(userID)
	items := s.userCredentials[userID]
	out := make([]store.CredentialRecord, 0, len(items))
	for _, item := range items {
		copyItem := item
		copyItem.ID = append([]byte(nil), item.ID...)
		if item.LastUsedAt != nil {
			ts := item.LastUsedAt.UTC()
			copyItem.LastUsedAt = &ts
		}
		out = append(out, copyItem)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].CreatedAt.After(out[j].CreatedAt)
	})
	return out, nil
}

func (s *fakeUIStore) DeleteCredentialByUserAndID(userID string, credID []byte) error {
	userID = strings.TrimSpace(userID)
	if userID == "" || len(credID) == 0 {
		return store.ErrCredentialNotFound
	}
	items := s.userCredentials[userID]
	idx := -1
	for i, item := range items {
		if bytes.Equal(item.ID, credID) {
			idx = i
			break
		}
	}
	if idx < 0 {
		return store.ErrCredentialNotFound
	}
	if len(items) <= 1 {
		return store.ErrCannotDeleteLastCredential
	}
	s.userCredentials[userID] = append(items[:idx], items[idx+1:]...)
	return nil
}

func (s *fakeUIStore) ListUserOIDCClients(userID string) ([]store.UserOIDCClient, error) {
	userID = strings.TrimSpace(userID)
	items := s.userLinkedClients[userID]
	out := make([]store.UserOIDCClient, 0, len(items))
	for _, item := range items {
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].LastSeenAt.Equal(out[j].LastSeenAt) {
			return out[i].ClientID < out[j].ClientID
		}
		return out[i].LastSeenAt.After(out[j].LastSeenAt)
	})
	return out, nil
}

func (s *fakeUIStore) CreateUserSecurityEvent(ctx context.Context, entry store.UserSecurityEvent) error {
	entry.UserID = strings.TrimSpace(entry.UserID)
	entry.EventType = strings.TrimSpace(entry.EventType)
	entry.Category = store.NormalizeUserSecurityCategory(entry.Category)
	entry.ActorType = strings.TrimSpace(entry.ActorType)
	entry.ActorID = strings.TrimSpace(entry.ActorID)
	entry.SessionID = strings.TrimSpace(entry.SessionID)
	entry.CredentialID = strings.TrimSpace(entry.CredentialID)
	entry.ClientID = strings.TrimSpace(entry.ClientID)
	entry.RemoteIP = strings.TrimSpace(entry.RemoteIP)
	if entry.UserID == "" || entry.EventType == "" {
		return errors.New("invalid user security event")
	}
	if entry.Category == "" || entry.Category == store.UserSecurityCategoryAll {
		entry.Category = store.UserSecurityCategoryAuth
	}
	if entry.ActorType == "" {
		entry.ActorType = "user"
	}
	if entry.CreatedAt.IsZero() {
		entry.CreatedAt = time.Now().UTC()
	}
	entry.ID = s.nextUserSecurityID
	s.nextUserSecurityID++
	entry.DetailsJSON = append([]byte(nil), entry.DetailsJSON...)
	s.userSecurityEvents = append(s.userSecurityEvents, entry)
	return nil
}

func (s *fakeUIStore) ListUserSecurityEvents(ctx context.Context, userID string, filter store.UserSecurityEventFilter) ([]store.UserSecurityEvent, error) {
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return []store.UserSecurityEvent{}, nil
	}
	limit := filter.Limit
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	offset := filter.Offset
	if offset < 0 {
		offset = 0
	}
	category := store.NormalizeUserSecurityFilterCategory(filter.Category)

	items := make([]store.UserSecurityEvent, 0, len(s.userSecurityEvents))
	for _, event := range s.userSecurityEvents {
		if strings.TrimSpace(event.UserID) != userID {
			continue
		}
		if category != "" && store.NormalizeUserSecurityCategory(event.Category) != category {
			continue
		}
		item := event
		item.DetailsJSON = append([]byte(nil), event.DetailsJSON...)
		if event.Success != nil {
			success := *event.Success
			item.Success = &success
		}
		items = append(items, item)
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].ID == items[j].ID {
			return items[i].CreatedAt.After(items[j].CreatedAt)
		}
		return items[i].ID > items[j].ID
	})
	if offset >= len(items) {
		return []store.UserSecurityEvent{}, nil
	}
	end := offset + limit
	if end > len(items) {
		end = len(items)
	}
	out := make([]store.UserSecurityEvent, 0, end-offset)
	out = append(out, items[offset:end]...)
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

func hasAuditAction(entries []store.AdminAuditEntry, action string, success bool) bool {
	for _, entry := range entries {
		if strings.TrimSpace(entry.Action) == strings.TrimSpace(action) && entry.Success == success {
			return true
		}
	}
	return false
}

func hasUserSecurityEvent(entries []store.UserSecurityEvent, userID string, eventType string, success bool) bool {
	for _, entry := range entries {
		if strings.TrimSpace(entry.UserID) != strings.TrimSpace(userID) {
			continue
		}
		if strings.TrimSpace(entry.EventType) != strings.TrimSpace(eventType) {
			continue
		}
		if entry.Success == nil || *entry.Success != success {
			continue
		}
		return true
	}
	return false
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
