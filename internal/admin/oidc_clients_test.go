package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/houbamydar/AHOJ420/internal/store"
	"github.com/labstack/echo/v4"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/time/rate"
)

const testAdminToken = "admin-token-123"
const testAdminHost = "admin.example.test"

func TestAdminUnauthorized(t *testing.T) {
	api := setupTestAdminAPI(newFakeOIDCClientStore(), testAdminToken)

	rec := doJSONRequest(t, api, http.MethodGet, "/admin/api/oidc/clients", "", nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d body=%s", rec.Code, rec.Body.String())
	}

	recBad := doJSONRequest(t, api, http.MethodGet, "/admin/api/oidc/clients", "wrong-token", nil)
	if recBad.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for wrong token, got %d body=%s", recBad.Code, recBad.Body.String())
	}
}

func TestAdminDisabledWithoutToken(t *testing.T) {
	api := setupTestAdminAPIWithConfig(
		newFakeOIDCClientStore(),
		"",
		testAdminHost,
		&fakeOIDCClientReloader{},
		&fakeAdminAuditStore{},
		AdminRateLimitConfig{Rate: rate.Limit(1000), Burst: 1000, ExpiresIn: time.Minute},
	)
	rec := doJSONRequest(t, api, http.MethodGet, "/admin/api/oidc/clients", testAdminToken, nil)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 when admin api token is missing, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestAdminDisabledWithoutHost(t *testing.T) {
	api := setupTestAdminAPIWithConfig(
		newFakeOIDCClientStore(),
		testAdminToken,
		"",
		&fakeOIDCClientReloader{},
		&fakeAdminAuditStore{},
		AdminRateLimitConfig{Rate: rate.Limit(1000), Burst: 1000, ExpiresIn: time.Minute},
	)
	rec := doJSONRequest(t, api, http.MethodGet, "/admin/api/oidc/clients", testAdminToken, nil)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 when admin api host is missing, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestAdminHostGuard(t *testing.T) {
	api := setupTestAdminAPIWithConfig(
		newFakeOIDCClientStore(),
		testAdminToken,
		testAdminHost,
		&fakeOIDCClientReloader{},
		&fakeAdminAuditStore{},
		AdminRateLimitConfig{Rate: rate.Limit(1000), Burst: 1000, ExpiresIn: time.Minute},
	)

	recOK := doJSONRequestWithHost(t, api, http.MethodGet, "/admin/api/oidc/clients", testAdminToken, nil, testAdminHost)
	if recOK.Code != http.StatusOK {
		t.Fatalf("expected 200 for correct admin host, got %d body=%s", recOK.Code, recOK.Body.String())
	}

	recWithPort := doJSONRequestWithHost(t, api, http.MethodGet, "/admin/api/oidc/clients", testAdminToken, nil, testAdminHost+":443")
	if recWithPort.Code != http.StatusOK {
		t.Fatalf("expected 200 for admin host with port, got %d body=%s", recWithPort.Code, recWithPort.Body.String())
	}

	recWrong := doJSONRequestWithHost(t, api, http.MethodGet, "/admin/api/oidc/clients", testAdminToken, nil, "ahoj420.eu")
	if recWrong.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for wrong host, got %d body=%s", recWrong.Code, recWrong.Body.String())
	}
}

func TestListClientsWithoutSecretHash(t *testing.T) {
	fake := newFakeOIDCClientStore()
	err := fake.CreateOIDCClient(store.OIDCClient{
		ID:            "mushroom-bff",
		Name:          "Mushroom BFF",
		Enabled:       true,
		Confidential:  true,
		RequirePKCE:   true,
		AuthMethod:    "basic",
		GrantTypes:    []string{"authorization_code", "refresh_token"},
		ResponseTypes: []string{"code"},
		Scopes:        []string{"openid", "profile"},
		RedirectURIs:  []string{"https://api.houbamzdar.cz/auth/callback"},
	}, []store.OIDCClientSecretInput{{PlainSecret: "secret-1", Label: "primary"}, {PlainSecret: "secret-2", Label: "rotated"}})
	if err != nil {
		t.Fatalf("CreateOIDCClient failed: %v", err)
	}
	secrets, _ := fake.ListOIDCClientSecrets("mushroom-bff")
	if len(secrets) < 2 {
		t.Fatalf("expected 2 secrets")
	}
	if err := fake.RevokeOIDCClientSecret("mushroom-bff", secrets[0].ID); err != nil {
		t.Fatalf("RevokeOIDCClientSecret failed: %v", err)
	}

	api := setupTestAdminAPI(fake, testAdminToken)
	rec := doJSONRequest(t, api, http.MethodGet, "/admin/api/oidc/clients", testAdminToken, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}

	body := rec.Body.String()
	if strings.Contains(body, "secret_hash") {
		t.Fatalf("response must not expose secret_hash: %s", body)
	}
	if strings.Contains(body, "plain_secret") {
		t.Fatalf("response must not expose plain_secret: %s", body)
	}

	var parsed struct {
		Clients []oidcClientDTO `json:"clients"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &parsed); err != nil {
		t.Fatalf("unmarshal list response: %v", err)
	}
	if len(parsed.Clients) != 1 {
		t.Fatalf("expected 1 client, got %d", len(parsed.Clients))
	}
	if parsed.Clients[0].ActiveSecretCount != 1 || parsed.Clients[0].RevokedSecretCount != 1 {
		t.Fatalf("unexpected secret counts: %+v", parsed.Clients[0])
	}
}

func TestGetClientDetailSafeSecrets(t *testing.T) {
	fake := newFakeOIDCClientStore()
	if err := fake.CreateOIDCClient(store.OIDCClient{
		ID:            "client-secure",
		Name:          "Secure Client",
		Enabled:       true,
		Confidential:  true,
		RequirePKCE:   true,
		AuthMethod:    "basic",
		GrantTypes:    []string{"authorization_code"},
		ResponseTypes: []string{"code"},
		Scopes:        []string{"openid"},
		RedirectURIs:  []string{"https://example.com/callback"},
	}, []store.OIDCClientSecretInput{{PlainSecret: "top-secret", Label: "initial"}}); err != nil {
		t.Fatalf("CreateOIDCClient failed: %v", err)
	}

	api := setupTestAdminAPI(fake, testAdminToken)
	rec := doJSONRequest(t, api, http.MethodGet, "/admin/api/oidc/clients/client-secure", testAdminToken, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}

	body := rec.Body.String()
	if strings.Contains(body, "secret_hash") || strings.Contains(body, "plain_secret") {
		t.Fatalf("detail response leaks secret internals: %s", body)
	}

	var parsed oidcClientDetailResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &parsed); err != nil {
		t.Fatalf("unmarshal detail response: %v", err)
	}
	if parsed.Client.ID != "client-secure" {
		t.Fatalf("unexpected client id: %s", parsed.Client.ID)
	}
	if len(parsed.Secrets) != 1 {
		t.Fatalf("expected one secret metadata, got %d", len(parsed.Secrets))
	}
	if parsed.Secrets[0].Status != "active" {
		t.Fatalf("expected active status, got %+v", parsed.Secrets[0])
	}
}

func TestCreatePublicClient(t *testing.T) {
	api := setupTestAdminAPI(newFakeOIDCClientStore(), testAdminToken)

	rec := doJSONRequest(t, api, http.MethodPost, "/admin/api/oidc/clients", testAdminToken, map[string]any{
		"id":             "public-a",
		"name":           "Public A",
		"enabled":        true,
		"confidential":   false,
		"require_pkce":   true,
		"auth_method":    "none",
		"grant_types":    []string{"authorization_code"},
		"response_types": []string{"code"},
		"scopes":         []string{"openid"},
		"redirect_uris":  []string{"https://example.com/callback"},
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d body=%s", rec.Code, rec.Body.String())
	}

	recInvalid := doJSONRequest(t, api, http.MethodPost, "/admin/api/oidc/clients", testAdminToken, map[string]any{
		"id":             "public-b",
		"name":           "Public B",
		"enabled":        true,
		"confidential":   false,
		"require_pkce":   true,
		"auth_method":    "none",
		"grant_types":    []string{"authorization_code"},
		"response_types": []string{"code"},
		"scopes":         []string{"openid"},
		"redirect_uris":  []string{"https://example.com/callback"},
		"initial_secret": "not-allowed",
	})
	if recInvalid.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for public client with secret, got %d body=%s", recInvalid.Code, recInvalid.Body.String())
	}
}

func TestCreateConfidentialClient(t *testing.T) {
	api := setupTestAdminAPI(newFakeOIDCClientStore(), testAdminToken)

	recMissing := doJSONRequest(t, api, http.MethodPost, "/admin/api/oidc/clients", testAdminToken, map[string]any{
		"id":             "conf-a",
		"name":           "Conf A",
		"enabled":        true,
		"confidential":   true,
		"require_pkce":   true,
		"auth_method":    "basic",
		"grant_types":    []string{"authorization_code"},
		"response_types": []string{"code"},
		"scopes":         []string{"openid"},
		"redirect_uris":  []string{"https://example.com/callback"},
	})
	if recMissing.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing confidential secret, got %d body=%s", recMissing.Code, recMissing.Body.String())
	}

	recOK := doJSONRequest(t, api, http.MethodPost, "/admin/api/oidc/clients", testAdminToken, map[string]any{
		"id":                   "conf-b",
		"name":                 "Conf B",
		"enabled":              true,
		"confidential":         true,
		"require_pkce":         true,
		"auth_method":          "basic",
		"grant_types":          []string{"authorization_code"},
		"response_types":       []string{"code"},
		"scopes":               []string{"openid"},
		"redirect_uris":        []string{"https://example.com/callback"},
		"initial_secret":       "initial-secret",
		"initial_secret_label": "bootstrap",
	})
	if recOK.Code != http.StatusCreated {
		t.Fatalf("expected 201 for confidential create, got %d body=%s", recOK.Code, recOK.Body.String())
	}
}

func TestAddSecret(t *testing.T) {
	fake := newFakeOIDCClientStore()
	if err := fake.CreateOIDCClient(store.OIDCClient{
		ID:            "conf-client",
		Name:          "Conf",
		Enabled:       true,
		Confidential:  true,
		RequirePKCE:   true,
		AuthMethod:    "basic",
		GrantTypes:    []string{"authorization_code"},
		ResponseTypes: []string{"code"},
		Scopes:        []string{"openid"},
		RedirectURIs:  []string{"https://example.com/callback"},
	}, []store.OIDCClientSecretInput{{PlainSecret: "one", Label: "initial"}}); err != nil {
		t.Fatalf("CreateOIDCClient failed: %v", err)
	}
	if err := fake.CreateOIDCClient(store.OIDCClient{
		ID:            "public-client",
		Name:          "Public",
		Enabled:       true,
		Confidential:  false,
		RequirePKCE:   true,
		AuthMethod:    "none",
		GrantTypes:    []string{"authorization_code"},
		ResponseTypes: []string{"code"},
		Scopes:        []string{"openid"},
		RedirectURIs:  []string{"https://example.com/public"},
	}, nil); err != nil {
		t.Fatalf("Create public client failed: %v", err)
	}

	api := setupTestAdminAPI(fake, testAdminToken)

	recGen := doJSONRequest(t, api, http.MethodPost, "/admin/api/oidc/clients/conf-client/secrets", testAdminToken, map[string]any{
		"generate": true,
		"label":    "generated",
	})
	if recGen.Code != http.StatusCreated {
		t.Fatalf("expected 201 for generated secret, got %d body=%s", recGen.Code, recGen.Body.String())
	}
	var genResp addOIDCClientSecretResponse
	if err := json.Unmarshal(recGen.Body.Bytes(), &genResp); err != nil {
		t.Fatalf("unmarshal generated secret response: %v", err)
	}
	if strings.TrimSpace(genResp.PlainSecret) == "" {
		t.Fatalf("expected plain_secret in generate=true response")
	}

	detail := doJSONRequest(t, api, http.MethodGet, "/admin/api/oidc/clients/conf-client", testAdminToken, nil)
	if detail.Code != http.StatusOK {
		t.Fatalf("expected 200 detail, got %d body=%s", detail.Code, detail.Body.String())
	}
	if strings.Contains(detail.Body.String(), genResp.PlainSecret) {
		t.Fatalf("plain secret must not be present in later responses")
	}

	recPublic := doJSONRequest(t, api, http.MethodPost, "/admin/api/oidc/clients/public-client/secrets", testAdminToken, map[string]any{
		"secret": "should-fail",
	})
	if recPublic.Code != http.StatusConflict {
		t.Fatalf("expected 409 for public client secret add, got %d body=%s", recPublic.Code, recPublic.Body.String())
	}
}

func TestRevokeSecret(t *testing.T) {
	fake := newFakeOIDCClientStore()
	if err := fake.CreateOIDCClient(store.OIDCClient{
		ID:            "conf-revoke",
		Name:          "Conf Revoke",
		Enabled:       true,
		Confidential:  true,
		RequirePKCE:   true,
		AuthMethod:    "basic",
		GrantTypes:    []string{"authorization_code"},
		ResponseTypes: []string{"code"},
		Scopes:        []string{"openid"},
		RedirectURIs:  []string{"https://example.com/callback"},
	}, []store.OIDCClientSecretInput{{PlainSecret: "one", Label: "one"}, {PlainSecret: "two", Label: "two"}}); err != nil {
		t.Fatalf("CreateOIDCClient failed: %v", err)
	}

	secrets, _ := fake.ListOIDCClientSecrets("conf-revoke")
	if len(secrets) != 2 {
		t.Fatalf("expected 2 secrets, got %d", len(secrets))
	}

	api := setupTestAdminAPI(fake, testAdminToken)
	rec := doJSONRequest(t, api, http.MethodPost, fmt.Sprintf("/admin/api/oidc/clients/conf-revoke/secrets/%d/revoke", secrets[0].ID), testAdminToken, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for revoke, got %d body=%s", rec.Code, rec.Body.String())
	}

	recLast := doJSONRequest(t, api, http.MethodPost, fmt.Sprintf("/admin/api/oidc/clients/conf-revoke/secrets/%d/revoke", secrets[1].ID), testAdminToken, nil)
	if recLast.Code != http.StatusConflict {
		t.Fatalf("expected 409 for last active secret revoke, got %d body=%s", recLast.Code, recLast.Body.String())
	}
}

func TestUpdateClient(t *testing.T) {
	fake := newFakeOIDCClientStore()
	if err := fake.CreateOIDCClient(store.OIDCClient{
		ID:            "upd-client",
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
		t.Fatalf("CreateOIDCClient failed: %v", err)
	}

	api := setupTestAdminAPI(fake, testAdminToken)

	rec := doJSONRequest(t, api, http.MethodPut, "/admin/api/oidc/clients/upd-client", testAdminToken, map[string]any{
		"name":    "After",
		"enabled": false,
		"scopes":  []string{"openid", "profile"},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 update, got %d body=%s", rec.Code, rec.Body.String())
	}
	var parsed oidcClientDetailResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &parsed); err != nil {
		t.Fatalf("unmarshal update response: %v", err)
	}
	if parsed.Client.Name != "After" || parsed.Client.Enabled {
		t.Fatalf("unexpected updated client: %+v", parsed.Client)
	}
	if len(parsed.Client.Scopes) != 2 {
		t.Fatalf("expected updated scopes, got %+v", parsed.Client.Scopes)
	}

	recInvalid := doJSONRequest(t, api, http.MethodPut, "/admin/api/oidc/clients/upd-client", testAdminToken, map[string]any{
		"auth_method": "invalid-auth",
	})
	if recInvalid.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid auth_method, got %d body=%s", recInvalid.Code, recInvalid.Body.String())
	}
}

func TestReplaceRedirectURIs(t *testing.T) {
	fake := newFakeOIDCClientStore()
	if err := fake.CreateOIDCClient(store.OIDCClient{
		ID:            "redir-client",
		Name:          "Redirect Client",
		Enabled:       true,
		Confidential:  false,
		RequirePKCE:   true,
		AuthMethod:    "none",
		GrantTypes:    []string{"authorization_code"},
		ResponseTypes: []string{"code"},
		Scopes:        []string{"openid"},
		RedirectURIs:  []string{"https://example.com/old"},
	}, nil); err != nil {
		t.Fatalf("CreateOIDCClient failed: %v", err)
	}

	api := setupTestAdminAPI(fake, testAdminToken)

	recEmpty := doJSONRequest(t, api, http.MethodPut, "/admin/api/oidc/clients/redir-client/redirect-uris", testAdminToken, map[string]any{
		"redirect_uris": []string{},
	})
	if recEmpty.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for empty redirect uris, got %d body=%s", recEmpty.Code, recEmpty.Body.String())
	}

	recOK := doJSONRequest(t, api, http.MethodPut, "/admin/api/oidc/clients/redir-client/redirect-uris", testAdminToken, map[string]any{
		"redirect_uris": []string{"https://example.com/new1", "https://example.com/new2"},
	})
	if recOK.Code != http.StatusOK {
		t.Fatalf("expected 200 for redirect uri replace, got %d body=%s", recOK.Code, recOK.Body.String())
	}

	var parsed oidcClientDetailResponse
	if err := json.Unmarshal(recOK.Body.Bytes(), &parsed); err != nil {
		t.Fatalf("unmarshal replace response: %v", err)
	}
	if len(parsed.Client.RedirectURIs) != 2 {
		t.Fatalf("expected 2 redirect uris, got %+v", parsed.Client.RedirectURIs)
	}
}

func TestMutationEndpointsCallReloader(t *testing.T) {
	fake := newFakeOIDCClientStore()
	if err := fake.CreateOIDCClient(store.OIDCClient{
		ID:            "upd-client",
		Name:          "Update Client",
		Enabled:       true,
		Confidential:  false,
		RequirePKCE:   true,
		AuthMethod:    "none",
		GrantTypes:    []string{"authorization_code"},
		ResponseTypes: []string{"code"},
		Scopes:        []string{"openid"},
		RedirectURIs:  []string{"https://example.com/callback"},
	}, nil); err != nil {
		t.Fatalf("CreateOIDCClient(upd-client) failed: %v", err)
	}
	if err := fake.CreateOIDCClient(store.OIDCClient{
		ID:            "conf-client",
		Name:          "Conf Client",
		Enabled:       true,
		Confidential:  true,
		RequirePKCE:   true,
		AuthMethod:    "basic",
		GrantTypes:    []string{"authorization_code"},
		ResponseTypes: []string{"code"},
		Scopes:        []string{"openid"},
		RedirectURIs:  []string{"https://example.com/conf"},
	}, []store.OIDCClientSecretInput{{PlainSecret: "one", Label: "one"}, {PlainSecret: "two", Label: "two"}}); err != nil {
		t.Fatalf("CreateOIDCClient(conf-client) failed: %v", err)
	}
	reloader := &fakeOIDCClientReloader{}
	api := setupTestAdminAPIWithReloader(fake, testAdminToken, reloader)

	createRec := doJSONRequest(t, api, http.MethodPost, "/admin/api/oidc/clients", testAdminToken, map[string]any{
		"id":             "new-public",
		"name":           "New Public",
		"enabled":        true,
		"confidential":   false,
		"require_pkce":   true,
		"auth_method":    "none",
		"grant_types":    []string{"authorization_code"},
		"response_types": []string{"code"},
		"scopes":         []string{"openid"},
		"redirect_uris":  []string{"https://example.com/new"},
	})
	if createRec.Code != http.StatusCreated {
		t.Fatalf("create expected 201, got %d body=%s", createRec.Code, createRec.Body.String())
	}
	if reloader.calls != 1 {
		t.Fatalf("expected reload calls=1 after create, got %d", reloader.calls)
	}

	updateRec := doJSONRequest(t, api, http.MethodPut, "/admin/api/oidc/clients/upd-client", testAdminToken, map[string]any{
		"name": "Updated Name",
	})
	if updateRec.Code != http.StatusOK {
		t.Fatalf("update expected 200, got %d body=%s", updateRec.Code, updateRec.Body.String())
	}
	if reloader.calls != 2 {
		t.Fatalf("expected reload calls=2 after update, got %d", reloader.calls)
	}

	redirectRec := doJSONRequest(t, api, http.MethodPut, "/admin/api/oidc/clients/upd-client/redirect-uris", testAdminToken, map[string]any{
		"redirect_uris": []string{"https://example.com/new-callback"},
	})
	if redirectRec.Code != http.StatusOK {
		t.Fatalf("redirect replace expected 200, got %d body=%s", redirectRec.Code, redirectRec.Body.String())
	}
	if reloader.calls != 3 {
		t.Fatalf("expected reload calls=3 after redirect replace, got %d", reloader.calls)
	}

	addSecretRec := doJSONRequest(t, api, http.MethodPost, "/admin/api/oidc/clients/conf-client/secrets", testAdminToken, map[string]any{
		"secret": "three",
		"label":  "three",
	})
	if addSecretRec.Code != http.StatusCreated {
		t.Fatalf("add secret expected 201, got %d body=%s", addSecretRec.Code, addSecretRec.Body.String())
	}
	if reloader.calls != 4 {
		t.Fatalf("expected reload calls=4 after add secret, got %d", reloader.calls)
	}

	secrets, err := fake.ListOIDCClientSecrets("conf-client")
	if err != nil {
		t.Fatalf("ListOIDCClientSecrets failed: %v", err)
	}
	if len(secrets) < 2 {
		t.Fatalf("expected at least 2 secrets to test revoke, got %d", len(secrets))
	}

	revokeRec := doJSONRequest(t, api, http.MethodPost, fmt.Sprintf("/admin/api/oidc/clients/conf-client/secrets/%d/revoke", secrets[len(secrets)-1].ID), testAdminToken, nil)
	if revokeRec.Code != http.StatusOK {
		t.Fatalf("revoke expected 200, got %d body=%s", revokeRec.Code, revokeRec.Body.String())
	}
	if reloader.calls != 5 {
		t.Fatalf("expected reload calls=5 after revoke secret, got %d", reloader.calls)
	}
}

func TestMutationEndpointsReturn500WhenReloadFails(t *testing.T) {
	type mutationCase struct {
		name    string
		prepare func(t *testing.T, fake *fakeOIDCClientStore) (method string, path string, payload any)
	}

	cases := []mutationCase{
		{
			name: "create",
			prepare: func(t *testing.T, fake *fakeOIDCClientStore) (string, string, any) {
				return http.MethodPost, "/admin/api/oidc/clients", map[string]any{
					"id":             "reload-create",
					"name":           "Reload Create",
					"enabled":        true,
					"confidential":   false,
					"require_pkce":   true,
					"auth_method":    "none",
					"grant_types":    []string{"authorization_code"},
					"response_types": []string{"code"},
					"scopes":         []string{"openid"},
					"redirect_uris":  []string{"https://example.com/create"},
				}
			},
		},
		{
			name: "update",
			prepare: func(t *testing.T, fake *fakeOIDCClientStore) (string, string, any) {
				if err := fake.CreateOIDCClient(store.OIDCClient{
					ID:            "upd-fail",
					Name:          "Update Fail",
					Enabled:       true,
					Confidential:  false,
					RequirePKCE:   true,
					AuthMethod:    "none",
					GrantTypes:    []string{"authorization_code"},
					ResponseTypes: []string{"code"},
					Scopes:        []string{"openid"},
					RedirectURIs:  []string{"https://example.com/update"},
				}, nil); err != nil {
					t.Fatalf("seed update client failed: %v", err)
				}
				return http.MethodPut, "/admin/api/oidc/clients/upd-fail", map[string]any{"name": "Updated"}
			},
		},
		{
			name: "replace_redirects",
			prepare: func(t *testing.T, fake *fakeOIDCClientStore) (string, string, any) {
				if err := fake.CreateOIDCClient(store.OIDCClient{
					ID:            "redir-fail",
					Name:          "Redirect Fail",
					Enabled:       true,
					Confidential:  false,
					RequirePKCE:   true,
					AuthMethod:    "none",
					GrantTypes:    []string{"authorization_code"},
					ResponseTypes: []string{"code"},
					Scopes:        []string{"openid"},
					RedirectURIs:  []string{"https://example.com/old"},
				}, nil); err != nil {
					t.Fatalf("seed redirect client failed: %v", err)
				}
				return http.MethodPut, "/admin/api/oidc/clients/redir-fail/redirect-uris", map[string]any{
					"redirect_uris": []string{"https://example.com/new"},
				}
			},
		},
		{
			name: "add_secret",
			prepare: func(t *testing.T, fake *fakeOIDCClientStore) (string, string, any) {
				if err := fake.CreateOIDCClient(store.OIDCClient{
					ID:            "secret-fail",
					Name:          "Secret Fail",
					Enabled:       true,
					Confidential:  true,
					RequirePKCE:   true,
					AuthMethod:    "basic",
					GrantTypes:    []string{"authorization_code"},
					ResponseTypes: []string{"code"},
					Scopes:        []string{"openid"},
					RedirectURIs:  []string{"https://example.com/conf"},
				}, []store.OIDCClientSecretInput{{PlainSecret: "one", Label: "one"}}); err != nil {
					t.Fatalf("seed secret client failed: %v", err)
				}
				return http.MethodPost, "/admin/api/oidc/clients/secret-fail/secrets", map[string]any{"secret": "two"}
			},
		},
		{
			name: "revoke_secret",
			prepare: func(t *testing.T, fake *fakeOIDCClientStore) (string, string, any) {
				if err := fake.CreateOIDCClient(store.OIDCClient{
					ID:            "revoke-fail",
					Name:          "Revoke Fail",
					Enabled:       true,
					Confidential:  true,
					RequirePKCE:   true,
					AuthMethod:    "basic",
					GrantTypes:    []string{"authorization_code"},
					ResponseTypes: []string{"code"},
					Scopes:        []string{"openid"},
					RedirectURIs:  []string{"https://example.com/conf"},
				}, []store.OIDCClientSecretInput{{PlainSecret: "one", Label: "one"}, {PlainSecret: "two", Label: "two"}}); err != nil {
					t.Fatalf("seed revoke client failed: %v", err)
				}
				secrets, err := fake.ListOIDCClientSecrets("revoke-fail")
				if err != nil {
					t.Fatalf("seed revoke secret listing failed: %v", err)
				}
				if len(secrets) < 2 {
					t.Fatalf("expected at least two secrets for revoke test")
				}
				return http.MethodPost, fmt.Sprintf("/admin/api/oidc/clients/revoke-fail/secrets/%d/revoke", secrets[0].ID), nil
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := newFakeOIDCClientStore()
			method, path, payload := tc.prepare(t, fake)

			reloader := &fakeOIDCClientReloader{err: errors.New("reload failed")}
			api := setupTestAdminAPIWithReloader(fake, testAdminToken, reloader)
			rec := doJSONRequest(t, api, method, path, testAdminToken, payload)

			if rec.Code != http.StatusInternalServerError {
				t.Fatalf("expected 500, got %d body=%s", rec.Code, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), "runtime reload failed") {
				t.Fatalf("expected runtime reload failure message, got body=%s", rec.Body.String())
			}
			if reloader.calls != 1 {
				t.Fatalf("expected reloader to be called once, got %d", reloader.calls)
			}
		})
	}
}

func TestInvalidMutationRequestDoesNotCallReloader(t *testing.T) {
	reloader := &fakeOIDCClientReloader{}
	api := setupTestAdminAPIWithReloader(newFakeOIDCClientStore(), testAdminToken, reloader)

	rec := doJSONRequest(t, api, http.MethodPost, "/admin/api/oidc/clients", testAdminToken, map[string]any{
		"name": "missing-id",
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid create request, got %d body=%s", rec.Code, rec.Body.String())
	}
	if reloader.calls != 0 {
		t.Fatalf("reloader must not be called on invalid request, got calls=%d", reloader.calls)
	}
}

func TestAuditInsertOnSuccessDoesNotLeakSecrets(t *testing.T) {
	auditStore := &fakeAdminAuditStore{}
	api := setupTestAdminAPIWithConfig(
		newFakeOIDCClientStore(),
		testAdminToken,
		testAdminHost,
		&fakeOIDCClientReloader{},
		auditStore,
		AdminRateLimitConfig{Rate: rate.Limit(1000), Burst: 1000, ExpiresIn: time.Minute},
	)

	secret := "super-secret-value"
	rec := doJSONRequest(t, api, http.MethodPost, "/admin/api/oidc/clients", testAdminToken, map[string]any{
		"id":                   "audit-conf",
		"name":                 "Audit Confidential",
		"enabled":              true,
		"confidential":         true,
		"require_pkce":         true,
		"auth_method":          "basic",
		"grant_types":          []string{"authorization_code"},
		"response_types":       []string{"code"},
		"scopes":               []string{"openid"},
		"redirect_uris":        []string{"https://example.com/callback"},
		"initial_secret":       secret,
		"initial_secret_label": "initial",
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d body=%s", rec.Code, rec.Body.String())
	}
	if len(auditStore.entries) == 0 {
		t.Fatalf("expected at least one audit entry")
	}

	entry := auditStore.entries[len(auditStore.entries)-1]
	if !entry.Success {
		t.Fatalf("expected successful audit entry, got %+v", entry)
	}
	if entry.Action != "admin.oidc_client.create" {
		t.Fatalf("unexpected action: %s", entry.Action)
	}
	details := string(entry.DetailsJSON)
	if strings.Contains(details, secret) {
		t.Fatalf("audit details leaked plaintext secret: %s", details)
	}
	if strings.Contains(details, "secret_hash") {
		t.Fatalf("audit details leaked secret_hash: %s", details)
	}
}

func TestAuditInsertOnFailure(t *testing.T) {
	auditStore := &fakeAdminAuditStore{}
	api := setupTestAdminAPIWithConfig(
		newFakeOIDCClientStore(),
		testAdminToken,
		testAdminHost,
		&fakeOIDCClientReloader{},
		auditStore,
		AdminRateLimitConfig{Rate: rate.Limit(1000), Burst: 1000, ExpiresIn: time.Minute},
	)

	rec := doJSONRequest(t, api, http.MethodPost, "/admin/api/oidc/clients", testAdminToken, map[string]any{
		"name": "missing-id",
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d body=%s", rec.Code, rec.Body.String())
	}
	if len(auditStore.entries) == 0 {
		t.Fatalf("expected audit entry for failed mutation")
	}
	entry := auditStore.entries[len(auditStore.entries)-1]
	if entry.Success {
		t.Fatalf("expected failure audit entry, got %+v", entry)
	}
	if entry.Action != "admin.oidc_client.create" {
		t.Fatalf("unexpected action in failure audit: %s", entry.Action)
	}
}

func TestRequestIDAddedAndStoredInAudit(t *testing.T) {
	auditStore := &fakeAdminAuditStore{}
	api := setupTestAdminAPIWithConfig(
		newFakeOIDCClientStore(),
		testAdminToken,
		testAdminHost,
		&fakeOIDCClientReloader{},
		auditStore,
		AdminRateLimitConfig{Rate: rate.Limit(1000), Burst: 1000, ExpiresIn: time.Minute},
	)

	rec := doJSONRequest(t, api, http.MethodPost, "/admin/api/oidc/clients", testAdminToken, map[string]any{
		"id":             "reqid-public",
		"name":           "Request ID Public",
		"enabled":        true,
		"confidential":   false,
		"require_pkce":   true,
		"auth_method":    "none",
		"grant_types":    []string{"authorization_code"},
		"response_types": []string{"code"},
		"scopes":         []string{"openid"},
		"redirect_uris":  []string{"https://example.com/callback"},
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d body=%s", rec.Code, rec.Body.String())
	}

	requestID := strings.TrimSpace(rec.Header().Get(echo.HeaderXRequestID))
	if requestID == "" {
		t.Fatalf("expected response request id header")
	}
	if len(auditStore.entries) == 0 {
		t.Fatalf("expected audit entry for mutation")
	}
	entry := auditStore.entries[len(auditStore.entries)-1]
	if strings.TrimSpace(entry.RequestID) == "" {
		t.Fatalf("expected request id in audit entry")
	}
	if entry.RequestID != requestID {
		t.Fatalf("request id mismatch: response=%s audit=%s", requestID, entry.RequestID)
	}
}

func TestAdminRateLimit(t *testing.T) {
	api := setupTestAdminAPIWithConfig(
		newFakeOIDCClientStore(),
		testAdminToken,
		testAdminHost,
		&fakeOIDCClientReloader{},
		&fakeAdminAuditStore{},
		AdminRateLimitConfig{Rate: rate.Limit(1), Burst: 1, ExpiresIn: time.Minute},
	)

	rec1 := doJSONRequestWithHostAndIP(t, api, http.MethodGet, "/admin/api/oidc/clients", testAdminToken, nil, testAdminHost, "198.51.100.10:10001")
	if rec1.Code != http.StatusOK {
		t.Fatalf("expected first request to pass, got %d body=%s", rec1.Code, rec1.Body.String())
	}

	rec2 := doJSONRequestWithHostAndIP(t, api, http.MethodGet, "/admin/api/oidc/clients", testAdminToken, nil, testAdminHost, "198.51.100.10:10001")
	if rec2.Code != http.StatusTooManyRequests {
		t.Fatalf("expected second request to be rate-limited, got %d body=%s", rec2.Code, rec2.Body.String())
	}
}

func setupTestAdminAPI(fakeStore *fakeOIDCClientStore, token string) *echo.Echo {
	return setupTestAdminAPIWithConfig(
		fakeStore,
		token,
		testAdminHost,
		&fakeOIDCClientReloader{},
		&fakeAdminAuditStore{},
		AdminRateLimitConfig{Rate: rate.Limit(1000), Burst: 1000, ExpiresIn: time.Minute},
	)
}

func setupTestAdminAPIWithReloader(fakeStore *fakeOIDCClientStore, token string, reloader *fakeOIDCClientReloader) *echo.Echo {
	return setupTestAdminAPIWithConfig(
		fakeStore,
		token,
		testAdminHost,
		reloader,
		&fakeAdminAuditStore{},
		AdminRateLimitConfig{Rate: rate.Limit(1000), Burst: 1000, ExpiresIn: time.Minute},
	)
}

func setupTestAdminAPIWithConfig(
	fakeStore *fakeOIDCClientStore,
	token string,
	host string,
	reloader *fakeOIDCClientReloader,
	auditStore *fakeAdminAuditStore,
	limiterConfig AdminRateLimitConfig,
) *echo.Echo {
	e := echo.New()
	group := e.Group("/admin/api")
	group.Use(AdminRequestIDMiddleware())
	group.Use(AdminAPIMiddleware(token, host))
	group.Use(AdminRateLimitMiddleware(limiterConfig))
	RegisterOIDCClientRoutes(group, NewOIDCClientHandler(fakeStore, reloader, auditStore))
	return e
}

func doJSONRequest(t *testing.T, e *echo.Echo, method string, path string, token string, payload any) *httptest.ResponseRecorder {
	return doJSONRequestWithHostAndIP(t, e, method, path, token, payload, testAdminHost, "203.0.113.10:1234")
}

func doJSONRequestWithHost(t *testing.T, e *echo.Echo, method string, path string, token string, payload any, host string) *httptest.ResponseRecorder {
	return doJSONRequestWithHostAndIP(t, e, method, path, token, payload, host, "203.0.113.10:1234")
}

func doJSONRequestWithHostAndIP(t *testing.T, e *echo.Echo, method string, path string, token string, payload any, host string, remoteAddr string) *httptest.ResponseRecorder {
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
	req.Host = host
	req.RemoteAddr = remoteAddr
	if strings.TrimSpace(token) != "" {
		req.Header.Set(echo.HeaderAuthorization, "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	return rec
}

type fakeOIDCClientStore struct {
	clients      map[string]store.OIDCClient
	secrets      map[string][]store.OIDCClientSecret
	nextSecretID int64
}

func newFakeOIDCClientStore() *fakeOIDCClientStore {
	return &fakeOIDCClientStore{
		clients:      make(map[string]store.OIDCClient),
		secrets:      make(map[string][]store.OIDCClientSecret),
		nextSecretID: 1,
	}
}

func (f *fakeOIDCClientStore) ListOIDCClients() ([]store.OIDCClient, error) {
	ids := make([]string, 0, len(f.clients))
	for id := range f.clients {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]store.OIDCClient, 0, len(ids))
	for _, id := range ids {
		out = append(out, cloneClient(f.clients[id]))
	}
	return out, nil
}

func (f *fakeOIDCClientStore) GetOIDCClient(id string) (*store.OIDCClient, error) {
	id = strings.TrimSpace(id)
	client, ok := f.clients[id]
	if !ok {
		return nil, store.ErrOIDCClientNotFound
	}
	out := cloneClient(client)
	return &out, nil
}

func (f *fakeOIDCClientStore) ListOIDCClientSecrets(clientID string) ([]store.OIDCClientSecret, error) {
	clientID = strings.TrimSpace(clientID)
	secrets := f.secrets[clientID]
	out := make([]store.OIDCClientSecret, 0, len(secrets))
	for _, item := range secrets {
		clone := item
		if item.RevokedAt != nil {
			ts := item.RevokedAt.UTC()
			clone.RevokedAt = &ts
		}
		out = append(out, clone)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].ID > out[j].ID
		}
		return out[i].CreatedAt.After(out[j].CreatedAt)
	})
	return out, nil
}

func (f *fakeOIDCClientStore) CreateOIDCClient(client store.OIDCClient, secrets []store.OIDCClientSecretInput) error {
	client.ID = strings.TrimSpace(client.ID)
	if client.ID == "" {
		return errors.New("client id is required")
	}
	if _, exists := f.clients[client.ID]; exists {
		return errors.New("duplicate client id")
	}
	client.RedirectURIs = normalizeStringList(client.RedirectURIs)
	if len(client.RedirectURIs) == 0 {
		return errors.New("at least one redirect_uri is required")
	}
	client.AuthMethod = strings.ToLower(strings.TrimSpace(client.AuthMethod))
	if client.AuthMethod == "" {
		if client.Confidential {
			client.AuthMethod = "basic"
		} else {
			client.AuthMethod = "none"
		}
	}
	if client.AuthMethod != "none" && client.AuthMethod != "basic" && client.AuthMethod != "post" {
		return errors.New("unsupported auth_method")
	}
	if !client.Confidential {
		client.AuthMethod = "none"
		if len(secrets) > 0 {
			return errors.New("public client must not define secrets")
		}
	}
	if client.Confidential && client.AuthMethod == "none" {
		return errors.New("confidential client cannot use auth_method none")
	}
	if client.Confidential && len(secrets) == 0 {
		return errors.New("confidential client requires at least one secret")
	}
	if len(client.GrantTypes) == 0 {
		client.GrantTypes = []string{"authorization_code"}
	}
	if len(client.ResponseTypes) == 0 {
		client.ResponseTypes = []string{"code"}
	}
	if len(client.Scopes) == 0 {
		client.Scopes = []string{"openid", "profile", "email", "phone", "offline_access"}
	}
	if contains(client.GrantTypes, "refresh_token") && !contains(client.Scopes, "offline_access") {
		client.Scopes = append(client.Scopes, "offline_access")
	}

	now := time.Now().UTC()
	client.CreatedAt = now
	client.UpdatedAt = now
	f.clients[client.ID] = cloneClient(client)

	for _, secret := range secrets {
		plain := strings.TrimSpace(secret.PlainSecret)
		if plain == "" {
			continue
		}
		hash, err := bcrypt.GenerateFromPassword([]byte(plain), bcrypt.DefaultCost)
		if err != nil {
			return err
		}
		f.secrets[client.ID] = append(f.secrets[client.ID], store.OIDCClientSecret{
			ID:         f.nextSecretID,
			ClientID:   client.ID,
			SecretHash: string(hash),
			Label:      strings.TrimSpace(secret.Label),
			CreatedAt:  now,
		})
		f.nextSecretID++
	}

	return nil
}

func (f *fakeOIDCClientStore) UpdateOIDCClient(client store.OIDCClient) error {
	client.ID = strings.TrimSpace(client.ID)
	existing, ok := f.clients[client.ID]
	if !ok {
		return store.ErrOIDCClientNotFound
	}
	client.RedirectURIs = normalizeStringList(client.RedirectURIs)
	if len(client.RedirectURIs) == 0 {
		return errors.New("at least one redirect_uri is required")
	}
	client.AuthMethod = strings.ToLower(strings.TrimSpace(client.AuthMethod))
	if client.AuthMethod != "none" && client.AuthMethod != "basic" && client.AuthMethod != "post" {
		return errors.New("unsupported auth_method")
	}
	if !client.Confidential {
		client.AuthMethod = "none"
		f.secrets[client.ID] = nil
	}
	if client.Confidential {
		active := 0
		for _, secret := range f.secrets[client.ID] {
			if secret.RevokedAt == nil {
				active++
			}
		}
		if active == 0 {
			return errors.New("confidential client requires at least one active secret")
		}
	}
	if len(client.GrantTypes) == 0 {
		client.GrantTypes = []string{"authorization_code"}
	}
	if len(client.ResponseTypes) == 0 {
		client.ResponseTypes = []string{"code"}
	}
	if len(client.Scopes) == 0 {
		client.Scopes = []string{"openid", "profile", "email", "phone", "offline_access"}
	}
	if contains(client.GrantTypes, "refresh_token") && !contains(client.Scopes, "offline_access") {
		client.Scopes = append(client.Scopes, "offline_access")
	}

	client.CreatedAt = existing.CreatedAt
	client.UpdatedAt = time.Now().UTC()
	f.clients[client.ID] = cloneClient(client)
	return nil
}

func (f *fakeOIDCClientStore) ReplaceOIDCClientRedirectURIs(clientID string, uris []string) error {
	clientID = strings.TrimSpace(clientID)
	client, ok := f.clients[clientID]
	if !ok {
		return store.ErrOIDCClientNotFound
	}
	normalized := normalizeStringList(uris)
	if len(normalized) == 0 {
		return errors.New("at least one redirect_uri is required")
	}
	client.RedirectURIs = normalized
	client.UpdatedAt = time.Now().UTC()
	f.clients[clientID] = cloneClient(client)
	return nil
}

func (f *fakeOIDCClientStore) AddOIDCClientSecret(clientID string, plainSecret string, label string) error {
	clientID = strings.TrimSpace(clientID)
	client, ok := f.clients[clientID]
	if !ok {
		return store.ErrOIDCClientNotFound
	}
	if !client.Confidential {
		return errors.New("public client must not have secrets")
	}
	plainSecret = strings.TrimSpace(plainSecret)
	if plainSecret == "" {
		return errors.New("secret is required")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(plainSecret), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	f.secrets[clientID] = append(f.secrets[clientID], store.OIDCClientSecret{
		ID:         f.nextSecretID,
		ClientID:   clientID,
		SecretHash: string(hash),
		Label:      strings.TrimSpace(label),
		CreatedAt:  time.Now().UTC(),
	})
	f.nextSecretID++

	client.UpdatedAt = time.Now().UTC()
	f.clients[clientID] = cloneClient(client)
	return nil
}

func (f *fakeOIDCClientStore) RevokeOIDCClientSecret(clientID string, secretID int64) error {
	clientID = strings.TrimSpace(clientID)
	client, ok := f.clients[clientID]
	if !ok {
		return store.ErrOIDCClientNotFound
	}
	if !client.Confidential {
		return errors.New("public client has no secrets")
	}

	idx := -1
	active := 0
	for i, secret := range f.secrets[clientID] {
		if secret.RevokedAt == nil {
			active++
		}
		if secret.ID == secretID && secret.RevokedAt == nil {
			idx = i
		}
	}
	if idx < 0 {
		return store.ErrOIDCClientSecretNotFound
	}
	if active <= 1 {
		return errors.New("confidential client must keep at least one active secret")
	}

	now := time.Now().UTC()
	f.secrets[clientID][idx].RevokedAt = &now
	client.UpdatedAt = now
	f.clients[clientID] = cloneClient(client)
	return nil
}

func cloneClient(in store.OIDCClient) store.OIDCClient {
	out := in
	out.GrantTypes = append([]string(nil), in.GrantTypes...)
	out.ResponseTypes = append([]string(nil), in.ResponseTypes...)
	out.Scopes = append([]string(nil), in.Scopes...)
	out.RedirectURIs = append([]string(nil), in.RedirectURIs...)
	return out
}

func contains(items []string, needle string) bool {
	for _, item := range items {
		if strings.TrimSpace(item) == needle {
			return true
		}
	}
	return false
}

type fakeOIDCClientReloader struct {
	calls int
	err   error
}

func (f *fakeOIDCClientReloader) ReloadClients(ctx context.Context) error {
	f.calls++
	return f.err
}

type fakeAdminAuditStore struct {
	entries []store.AdminAuditEntry
	err     error
}

func (f *fakeAdminAuditStore) CreateAdminAuditEntry(ctx context.Context, entry store.AdminAuditEntry) error {
	if f.err != nil {
		return f.err
	}
	clone := entry
	clone.DetailsJSON = append([]byte(nil), entry.DetailsJSON...)
	f.entries = append(f.entries, clone)
	return nil
}
