package oidc

import (
	"context"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/houbamydar/AHOJ420/internal/store"
	"github.com/redis/go-redis/v9"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"golang.org/x/crypto/bcrypt"
)

func TestCreateAuthRequestRequiresPKCE(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	storage := &MemStorage{
		redis: rdb,
		clients: map[string]*StaticClient{
			"client2": {
				id:          "client2",
				requirePKCE: true,
			},
		},
	}

	_, err := storage.CreateAuthRequest(context.Background(), &oidc.AuthRequest{
		ClientID:     "client2",
		RedirectURI:  "https://houbamzdar.cz/callback2.html",
		ResponseType: oidc.ResponseTypeCode,
		Scopes:       []string{oidc.ScopeOpenID},
	}, "client2")
	if err == nil {
		t.Fatal("expected error when PKCE is missing")
	}
}

func TestAuthRequestStoredInRedisAcrossStorageInstances(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	clients := map[string]*StaticClient{
		"client2": {
			id:          "client2",
			requirePKCE: true,
		},
	}

	st1 := &MemStorage{redis: rdb, clients: clients}
	req, err := st1.CreateAuthRequest(context.Background(), &oidc.AuthRequest{
		ClientID:            "client2",
		RedirectURI:         "https://houbamzdar.cz/callback2.html",
		ResponseType:        oidc.ResponseTypeCode,
		Scopes:              []string{oidc.ScopeOpenID},
		CodeChallenge:       "challenge",
		CodeChallengeMethod: oidc.CodeChallengeMethodS256,
	}, "client2")
	if err != nil {
		t.Fatalf("CreateAuthRequest failed: %v", err)
	}

	st2 := &MemStorage{redis: rdb, clients: clients}
	read, err := st2.AuthRequestByID(context.Background(), req.GetID())
	if err != nil {
		t.Fatalf("AuthRequestByID failed after new storage instance: %v", err)
	}

	if read.GetID() != req.GetID() {
		t.Fatalf("unexpected id: got %s want %s", read.GetID(), req.GetID())
	}
}

func TestAuthCodeSingleUse(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	clients := map[string]*StaticClient{
		"client2": {
			id:          "client2",
			requirePKCE: true,
		},
	}

	st := &MemStorage{redis: rdb, clients: clients}
	req, err := st.CreateAuthRequest(context.Background(), &oidc.AuthRequest{
		ClientID:            "client2",
		RedirectURI:         "https://houbamzdar.cz/callback2.html",
		ResponseType:        oidc.ResponseTypeCode,
		Scopes:              []string{oidc.ScopeOpenID},
		CodeChallenge:       "challenge",
		CodeChallengeMethod: oidc.CodeChallengeMethodS256,
	}, "client2")
	if err != nil {
		t.Fatalf("CreateAuthRequest failed: %v", err)
	}

	if err := st.SaveAuthCode(context.Background(), req.GetID(), "code123"); err != nil {
		t.Fatalf("SaveAuthCode failed: %v", err)
	}

	first, err := st.AuthRequestByCode(context.Background(), "code123")
	if err != nil {
		t.Fatalf("first AuthRequestByCode should succeed: %v", err)
	}
	if first.GetID() != req.GetID() {
		t.Fatalf("unexpected auth request id: got %s want %s", first.GetID(), req.GetID())
	}

	if _, err := st.AuthRequestByCode(context.Background(), "code123"); err == nil {
		t.Fatal("second AuthRequestByCode should fail for single-use code")
	}
}

func TestUserinfoClaimsByScopes(t *testing.T) {
	st := &MemStorage{
		avatarBase: "https://avatar.ahoj420.eu/",
		userStore: &UserStore{
			get: func(userID string) (*store.User, error) {
				now := time.Unix(1700000000, 0).UTC()
				return &store.User{
					ID:              userID,
					LoginID:         "anon-alice",
					ProfileEmail:    "alice@example.com",
					DisplayName:     "alice",
					Phone:           "+420777123456",
					EmailVerified:   true,
					PhoneVerified:   false,
					AvatarKey:       "avatars/u-1.webp",
					AvatarUpdatedAt: &now,
				}, nil
			},
		},
	}

	userinfo := &oidc.UserInfo{}
	scopes := []string{oidc.ScopeOpenID, oidc.ScopeProfile, oidc.ScopeEmail, oidc.ScopePhone}
	if err := st.SetUserinfoFromScopes(context.Background(), userinfo, "u-1", "client2", scopes); err != nil {
		t.Fatalf("SetUserinfoFromScopes failed: %v", err)
	}

	if userinfo.Subject != "u-1" {
		t.Fatalf("unexpected sub: %s", userinfo.Subject)
	}
	if userinfo.Name != "alice" || userinfo.PreferredUsername != "alice" {
		t.Fatalf("unexpected profile claims: name=%q preferred=%q", userinfo.Name, userinfo.PreferredUsername)
	}
	if userinfo.Email != "alice@example.com" || !bool(userinfo.EmailVerified) {
		t.Fatalf("unexpected email claims: %+v", userinfo)
	}
	if userinfo.PhoneNumber != "+420777123456" || bool(userinfo.PhoneNumberVerified) {
		t.Fatalf("unexpected phone claims: %+v", userinfo)
	}
	if userinfo.Picture == "" {
		t.Fatalf("missing picture in userinfo: %+v", userinfo)
	}

	privateClaims, err := st.GetPrivateClaimsFromScopes(context.Background(), "u-1", "client2", scopes)
	if err != nil {
		t.Fatalf("GetPrivateClaimsFromScopes failed: %v", err)
	}
	if privateClaims["preferred_username"] != "alice" {
		t.Fatalf("missing preferred_username claim")
	}
	if privateClaims["email"] != "alice@example.com" {
		t.Fatalf("missing email claim")
	}
	if privateClaims["phone_number"] != "+420777123456" {
		t.Fatalf("missing phone_number claim")
	}
	if privateClaims["picture"] == "" {
		t.Fatalf("missing picture claim")
	}
}

func TestPictureClaimAbsentWhenAvatarMissing(t *testing.T) {
	st := &MemStorage{
		avatarBase: "https://avatar.ahoj420.eu/",
		userStore: &UserStore{
			get: func(userID string) (*store.User, error) {
				return &store.User{
					ID:          userID,
					LoginID:     "bob@example.com",
					DisplayName: "bob",
				}, nil
			},
		},
	}

	userinfo := &oidc.UserInfo{}
	if err := st.SetUserinfoFromScopes(context.Background(), userinfo, "u-2", "client2", []string{oidc.ScopeProfile}); err != nil {
		t.Fatalf("SetUserinfoFromScopes failed: %v", err)
	}
	if userinfo.Picture != "" {
		t.Fatalf("picture must be absent, got %q", userinfo.Picture)
	}

	privateClaims, err := st.GetPrivateClaimsFromScopes(context.Background(), "u-2", "client2", []string{oidc.ScopeProfile})
	if err != nil {
		t.Fatalf("GetPrivateClaimsFromScopes failed: %v", err)
	}
	if _, ok := privateClaims["picture"]; ok {
		t.Fatalf("picture claim must be absent: %+v", privateClaims)
	}
}

func TestNewMemStorageBootstrapsEmptyDBFromJSONInProd(t *testing.T) {
	t.Setenv("OIDC_CLIENTS_BOOTSTRAP", "1")
	t.Setenv("OIDC_CLIENTS_JSON", `[
		{
			"id": "client2",
			"enabled": true,
			"redirect_uris": ["https://houbamzdar.cz/callback2.html"],
			"confidential": false,
			"require_pkce": true,
			"auth_method": "none",
			"grant_types": ["authorization_code"],
			"response_types": ["code"],
			"scopes": ["openid", "profile", "email", "phone"]
		}
	]`)

	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	registry := newFakeOIDCClientStore()

	storage, err := NewMemStorage(rdb, &UserStore{}, registry, true, "")
	if err != nil {
		t.Fatalf("NewMemStorage failed: %v", err)
	}
	if registry.bootstrapCalls != 1 {
		t.Fatalf("expected bootstrap to run once, got %d", registry.bootstrapCalls)
	}
	if len(registry.clients) != 1 {
		t.Fatalf("expected 1 client in registry after bootstrap, got %d", len(registry.clients))
	}
	if _, err := storage.GetClientByClientID(context.Background(), "client2"); err != nil {
		t.Fatalf("GetClientByClientID(client2) failed after bootstrap: %v", err)
	}
}

func TestNewMemStorageUsesDBWhenNotEmptyAndSkipsBootstrap(t *testing.T) {
	t.Setenv("OIDC_CLIENTS_BOOTSTRAP", "1")
	t.Setenv("OIDC_CLIENTS_JSON", `[
		{
			"id":"json-client",
			"enabled": true,
			"redirect_uris":["https://example.com/callback"],
			"confidential":false,
			"require_pkce":true,
			"auth_method":"none",
			"grant_types":["authorization_code"],
			"response_types":["code"],
			"scopes":["openid"]
		}
	]`)

	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	registry := newFakeOIDCClientStore()
	registry.clients["db-client"] = store.OIDCClient{
		ID:            "db-client",
		Name:          "DB Client",
		Enabled:       true,
		Confidential:  false,
		RequirePKCE:   true,
		AuthMethod:    "none",
		GrantTypes:    []string{"authorization_code"},
		ResponseTypes: []string{"code"},
		Scopes:        []string{"openid"},
		RedirectURIs:  []string{"https://db.example/callback"},
	}

	storage, err := NewMemStorage(rdb, &UserStore{}, registry, true, "")
	if err != nil {
		t.Fatalf("NewMemStorage failed: %v", err)
	}
	if registry.bootstrapCalls != 0 {
		t.Fatalf("bootstrap must be skipped for non-empty DB, got calls=%d", registry.bootstrapCalls)
	}

	if _, err := storage.GetClientByClientID(context.Background(), "db-client"); err != nil {
		t.Fatalf("expected db-client to be loaded: %v", err)
	}
	if _, err := storage.GetClientByClientID(context.Background(), "json-client"); err == nil {
		t.Fatalf("json bootstrap client must not override non-empty DB runtime set")
	}
}

func TestAuthorizeClientIDSecretUsesHashedActiveSecrets(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	registry := newFakeOIDCClientStore()
	longSecret := strings.Repeat("x", 90)
	registry.clients["conf-client"] = store.OIDCClient{
		ID:            "conf-client",
		Name:          "Confidential Client",
		Enabled:       true,
		Confidential:  true,
		RequirePKCE:   true,
		AuthMethod:    "basic",
		GrantTypes:    []string{"authorization_code"},
		ResponseTypes: []string{"code"},
		Scopes:        []string{"openid"},
		RedirectURIs:  []string{"https://conf.example/callback"},
	}
	revokedAt := time.Now().Add(-1 * time.Hour).UTC()
	registry.secrets["conf-client"] = []store.OIDCClientSecret{
		{
			ID:         1,
			ClientID:   "conf-client",
			SecretHash: mustHashSecret(t, longSecret),
			Label:      "active",
		},
		{
			ID:         2,
			ClientID:   "conf-client",
			SecretHash: mustHashSecret(t, "old-secret"),
			Label:      "revoked",
			RevokedAt:  &revokedAt,
		},
	}

	storage, err := NewMemStorage(rdb, &UserStore{}, registry, false, "")
	if err != nil {
		t.Fatalf("NewMemStorage failed: %v", err)
	}

	if err := storage.AuthorizeClientIDSecret(context.Background(), "conf-client", longSecret); err != nil {
		t.Fatalf("good secret must pass: %v", err)
	}
	if err := storage.AuthorizeClientIDSecret(context.Background(), "conf-client", "wrong-secret"); err == nil {
		t.Fatal("wrong secret must fail")
	}
	if err := storage.AuthorizeClientIDSecret(context.Background(), "conf-client", "old-secret"); err == nil {
		t.Fatal("revoked secret must fail")
	}
}

func TestPublicClientAuthMethodNoneWithoutSecrets(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	registry := newFakeOIDCClientStore()
	registry.clients["public-client"] = store.OIDCClient{
		ID:            "public-client",
		Name:          "Public Client",
		Enabled:       true,
		Confidential:  false,
		RequirePKCE:   true,
		AuthMethod:    "none",
		GrantTypes:    []string{"authorization_code"},
		ResponseTypes: []string{"code"},
		Scopes:        []string{"openid"},
		RedirectURIs:  []string{"https://public.example/callback"},
	}

	storage, err := NewMemStorage(rdb, &UserStore{}, registry, false, "")
	if err != nil {
		t.Fatalf("NewMemStorage failed: %v", err)
	}
	if _, err := storage.GetClientByClientID(context.Background(), "public-client"); err != nil {
		t.Fatalf("public client lookup failed: %v", err)
	}
	if err := storage.AuthorizeClientIDSecret(context.Background(), "public-client", ""); err != nil {
		t.Fatalf("public client with auth_method=none must not require secret: %v", err)
	}
}

func TestDisabledClientNotLoadedIntoRuntimeClients(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	registry := newFakeOIDCClientStore()
	registry.clients["enabled-client"] = store.OIDCClient{
		ID:            "enabled-client",
		Name:          "Enabled Client",
		Enabled:       true,
		Confidential:  false,
		RequirePKCE:   true,
		AuthMethod:    "none",
		GrantTypes:    []string{"authorization_code"},
		ResponseTypes: []string{"code"},
		Scopes:        []string{"openid"},
		RedirectURIs:  []string{"https://enabled.example/callback"},
	}
	registry.clients["disabled-client"] = store.OIDCClient{
		ID:            "disabled-client",
		Name:          "Disabled Client",
		Enabled:       false,
		Confidential:  false,
		RequirePKCE:   true,
		AuthMethod:    "none",
		GrantTypes:    []string{"authorization_code"},
		ResponseTypes: []string{"code"},
		Scopes:        []string{"openid"},
		RedirectURIs:  []string{"https://disabled.example/callback"},
	}

	storage, err := NewMemStorage(rdb, &UserStore{}, registry, false, "")
	if err != nil {
		t.Fatalf("NewMemStorage failed: %v", err)
	}
	if _, err := storage.GetClientByClientID(context.Background(), "enabled-client"); err != nil {
		t.Fatalf("enabled client lookup failed: %v", err)
	}
	if _, err := storage.GetClientByClientID(context.Background(), "disabled-client"); err == nil {
		t.Fatal("disabled client must not be exposed as runtime client")
	}
}

func TestRuntimeClientFromDBKeepsRedirectScopesAndGrantTypes(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	registry := newFakeOIDCClientStore()
	registry.clients["mushroom-bff"] = store.OIDCClient{
		ID:            "mushroom-bff",
		Name:          "Mushroom BFF",
		Enabled:       true,
		Confidential:  true,
		RequirePKCE:   true,
		AuthMethod:    "basic",
		GrantTypes:    []string{"authorization_code", "refresh_token"},
		ResponseTypes: []string{"code"},
		Scopes:        []string{"openid", "profile", "email", "phone"},
		RedirectURIs:  []string{"https://api.houbamzdar.cz/auth/callback"},
	}
	registry.secrets["mushroom-bff"] = []store.OIDCClientSecret{
		{
			ID:         1,
			ClientID:   "mushroom-bff",
			SecretHash: mustHashSecret(t, "bff-secret"),
			Label:      "active",
		},
	}

	storage, err := NewMemStorage(rdb, &UserStore{}, registry, false, "")
	if err != nil {
		t.Fatalf("NewMemStorage failed: %v", err)
	}

	client, err := storage.GetClientByClientID(context.Background(), "mushroom-bff")
	if err != nil {
		t.Fatalf("GetClientByClientID failed: %v", err)
	}
	staticClient, ok := client.(*StaticClient)
	if !ok {
		t.Fatalf("unexpected client type: %T", client)
	}
	if staticClient.AuthMethod() != oidc.AuthMethodBasic {
		t.Fatalf("unexpected auth method: %s", staticClient.AuthMethod())
	}
	if len(staticClient.RedirectURIs()) != 1 || staticClient.RedirectURIs()[0] != "https://api.houbamzdar.cz/auth/callback" {
		t.Fatalf("unexpected redirect uris: %+v", staticClient.RedirectURIs())
	}
	if !containsGrantType(staticClient.GrantTypes(), oidc.GrantTypeRefreshToken) {
		t.Fatalf("refresh_token grant must be enabled: %+v", staticClient.GrantTypes())
	}
	if !staticClient.IsScopeAllowed("openid") || !staticClient.IsScopeAllowed("profile") {
		t.Fatalf("expected default scopes to be allowed")
	}
	if !staticClient.IsScopeAllowed("offline_access") {
		t.Fatal("offline_access must be allowed when refresh_token grant is configured")
	}
}

type fakeOIDCClientStore struct {
	clients        map[string]store.OIDCClient
	secrets        map[string][]store.OIDCClientSecret
	bootstrapCalls int
}

func newFakeOIDCClientStore() *fakeOIDCClientStore {
	return &fakeOIDCClientStore{
		clients: make(map[string]store.OIDCClient),
		secrets: make(map[string][]store.OIDCClientSecret),
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
		out = append(out, cloneOIDCClient(f.clients[id]))
	}
	return out, nil
}

func (f *fakeOIDCClientStore) ListEnabledOIDCClients() ([]store.OIDCClient, error) {
	all, err := f.ListOIDCClients()
	if err != nil {
		return nil, err
	}
	out := make([]store.OIDCClient, 0, len(all))
	for _, client := range all {
		if client.Enabled {
			out = append(out, client)
		}
	}
	return out, nil
}

func (f *fakeOIDCClientStore) ListOIDCClientSecrets(clientID string) ([]store.OIDCClientSecret, error) {
	clientID = strings.TrimSpace(clientID)
	secrets := f.secrets[clientID]
	out := make([]store.OIDCClientSecret, 0, len(secrets))
	for _, secret := range secrets {
		item := secret
		if secret.RevokedAt != nil {
			ts := secret.RevokedAt.UTC()
			item.RevokedAt = &ts
		}
		out = append(out, item)
	}
	return out, nil
}

func (f *fakeOIDCClientStore) BootstrapOIDCClients(clients []store.OIDCClientBootstrapInput) (int, error) {
	f.bootstrapCalls++
	if len(f.clients) > 0 {
		return 0, nil
	}

	now := time.Now().UTC()
	var secretID int64 = 1
	for _, in := range clients {
		clientID := strings.TrimSpace(in.ID)
		if clientID == "" {
			return 0, errTest("bootstrap client id is required")
		}
		redirects := make([]string, 0, len(in.RedirectURIs))
		for _, uri := range in.RedirectURIs {
			trimmed := strings.TrimSpace(uri)
			if trimmed == "" {
				continue
			}
			redirects = append(redirects, trimmed)
		}
		if len(redirects) == 0 {
			return 0, errTest("bootstrap redirect uri is required")
		}

		f.clients[clientID] = store.OIDCClient{
			ID:            clientID,
			Name:          strings.TrimSpace(in.Name),
			Enabled:       in.Enabled,
			Confidential:  in.Confidential,
			RequirePKCE:   in.RequirePKCE,
			AuthMethod:    strings.ToLower(strings.TrimSpace(in.AuthMethod)),
			GrantTypes:    append([]string(nil), in.GrantTypes...),
			ResponseTypes: append([]string(nil), in.ResponseTypes...),
			Scopes:        append([]string(nil), in.Scopes...),
			RedirectURIs:  redirects,
			CreatedAt:     now,
			UpdatedAt:     now,
		}

		if !in.Confidential {
			continue
		}
		if len(in.Secrets) == 0 {
			return 0, errTest("confidential bootstrap client requires secrets")
		}
		for _, secret := range in.Secrets {
			hashBytes, err := bcrypt.GenerateFromPassword([]byte(secret.PlainSecret), bcrypt.DefaultCost)
			if err != nil {
				return 0, err
			}
			f.secrets[clientID] = append(f.secrets[clientID], store.OIDCClientSecret{
				ID:         secretID,
				ClientID:   clientID,
				SecretHash: string(hashBytes),
				Label:      secret.Label,
				CreatedAt:  now,
			})
			secretID++
		}
	}
	return len(clients), nil
}

func cloneOIDCClient(in store.OIDCClient) store.OIDCClient {
	out := in
	out.GrantTypes = append([]string(nil), in.GrantTypes...)
	out.ResponseTypes = append([]string(nil), in.ResponseTypes...)
	out.Scopes = append([]string(nil), in.Scopes...)
	out.RedirectURIs = append([]string(nil), in.RedirectURIs...)
	return out
}

func containsGrantType(items []oidc.GrantType, needle oidc.GrantType) bool {
	for _, item := range items {
		if item == needle {
			return true
		}
	}
	return false
}

func mustHashSecret(t *testing.T, plain string) string {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword(secretMaterialForBcrypt(plain), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("GenerateFromPassword failed: %v", err)
	}
	return string(hash)
}

type testError string

func (e testError) Error() string {
	return string(e)
}

func errTest(msg string) error {
	return testError(msg)
}
