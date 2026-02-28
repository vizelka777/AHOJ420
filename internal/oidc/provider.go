package oidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/houbamydar/AHOJ420/internal/avatar"
	"github.com/houbamydar/AHOJ420/internal/store"
	"github.com/redis/go-redis/v9"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
	"golang.org/x/crypto/bcrypt"
)

const (
	oidcStateTTL   = 10 * time.Minute
	envDev         = "dev"
	envProd        = "prod"
	authRequestKey = "oidc:ar:"
	authCodeKey    = "oidc:code:"
	authReqCodeKey = "oidc:ar_code:"
)

type contextKey string

const userIDContextKey contextKey = "user_id"

type Provider struct {
	op.OpenIDProvider
	Storage op.Storage
}

func WithUserID(ctx context.Context, userID string) context.Context {
	return context.WithValue(ctx, userIDContextKey, userID)
}

func UserIDFromContext(ctx context.Context) (string, bool) {
	userID, ok := ctx.Value(userIDContextKey).(string)
	if !ok || userID == "" {
		return "", false
	}
	return userID, true
}

func NewProvider(baseURL string, s *store.Store, r *redis.Client) (*Provider, error) {
	envMode := strings.ToLower(strings.TrimSpace(os.Getenv("AHOJ_ENV")))
	if envMode == "" {
		envMode = envDev
	}
	prodMode := envMode == envProd

	userStore := &UserStore{store: s}
	avatarPublicBase := strings.TrimSpace(os.Getenv("AVATAR_PUBLIC_BASE"))
	if prodMode && avatarPublicBase == "" {
		return nil, errors.New("AVATAR_PUBLIC_BASE must be set in prod")
	}
	storage, err := NewMemStorage(r, userStore, s, prodMode, avatarPublicBase)
	if err != nil {
		return nil, err
	}

	currentKeyID := os.Getenv("OIDC_KEY_ID")
	if currentKeyID == "" {
		currentKeyID = "sig_key_current"
	}

	currentKey, err := loadCurrentKey(prodMode)
	if err != nil {
		return nil, err
	}

	keys := []*SimpleKey{{
		id:  currentKeyID,
		alg: jose.RS256,
		use: "sig",
		key: currentKey,
	}}

	if prev, ok := loadPreviousKey(); ok {
		keys = append(keys, prev)
	}

	cryptoKey, err := loadCryptoKey(prodMode)
	if err != nil {
		return nil, err
	}

	config := &op.Config{
		CryptoKey:                sha256.Sum256([]byte(cryptoKey)),
		DefaultLogoutRedirectURI: baseURL,
		CodeMethodS256:           true,
		AuthMethodPost:           true,
		AuthMethodPrivateKeyJWT:  true,
		GrantTypeRefreshToken:    true,
		SupportedScopes:          []string{oidc.ScopeOpenID, oidc.ScopeProfile, oidc.ScopeEmail, oidc.ScopePhone, oidc.ScopeOfflineAccess},
	}

	provider, err := op.NewOpenIDProvider(
		baseURL,
		config,
		storage,
		op.WithHttpInterceptors(func(handler http.Handler) http.Handler {
			return handler
		}),
	)
	if err != nil {
		return nil, err
	}

	storage.signingKey = keys[0]
	storage.keys = keys

	return &Provider{OpenIDProvider: provider, Storage: storage}, nil
}

func loadCurrentKey(prodMode bool) (*rsa.PrivateKey, error) {
	currentKeyPath := strings.TrimSpace(os.Getenv("OIDC_PRIVKEY_PATH"))
	if currentKeyPath != "" {
		currentKey, err := loadRSAPrivateKey(currentKeyPath)
		if err != nil {
			if prodMode {
				return nil, fmt.Errorf("OIDC_PRIVKEY_PATH is invalid in prod: %w", err)
			}
			log.Printf("DEV mode: failed to load OIDC key from %s, fallback to ephemeral key: %v", currentKeyPath, err)
		} else {
			return currentKey, nil
		}
	}

	if prodMode {
		return nil, errors.New("OIDC_PRIVKEY_PATH must be set in prod")
	}

	log.Println("DEV mode: generating ephemeral OIDC RSA key; tokens become invalid after restart")
	currentKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	return currentKey, nil
}

func loadPreviousKey() (*SimpleKey, bool) {
	prevKeyPath := strings.TrimSpace(os.Getenv("OIDC_PREV_PRIVKEY_PATH"))
	if prevKeyPath == "" {
		return nil, false
	}

	prevKeyID := os.Getenv("OIDC_PREV_KEY_ID")
	if prevKeyID == "" {
		prevKeyID = "sig_key_previous"
	}

	prevKey, err := loadRSAPrivateKey(prevKeyPath)
	if err != nil {
		log.Printf("Failed to load previous OIDC key from %s: %v", prevKeyPath, err)
		return nil, false
	}

	return &SimpleKey{id: prevKeyID, alg: jose.RS256, use: "sig", key: prevKey}, true
}

func loadCryptoKey(prodMode bool) (string, error) {
	cryptoKey := strings.TrimSpace(os.Getenv("OIDC_CRYPTO_KEY"))
	if len(cryptoKey) >= 32 {
		return cryptoKey, nil
	}

	if prodMode {
		return "", errors.New("OIDC_CRYPTO_KEY must be set and be >= 32 bytes in prod")
	}

	randBytes := make([]byte, 32)
	if _, err := rand.Read(randBytes); err != nil {
		return "", err
	}
	ephemeral := base64.RawURLEncoding.EncodeToString(randBytes)
	log.Println("DEV mode: generated ephemeral OIDC_CRYPTO_KEY; browser oidc cookies become invalid after restart")
	return ephemeral, nil
}

func loadRSAPrivateKey(path string) (*rsa.PrivateKey, error) {
	keyData, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read key file: %w", err)
	}
	block, _ := pem.Decode(keyData)
	if block == nil {
		return nil, fmt.Errorf("parse pem: no block found")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	keyInterface, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	key, ok := keyInterface.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is not RSA")
	}
	return key, nil
}

func (p *Provider) SetAuthRequestDone(id, userID string) error {
	if s, ok := p.Storage.(*MemStorage); ok {
		return s.SetAuthRequestDone(id, userID)
	}
	return fmt.Errorf("storage does not support SetAuthRequestDone")
}

func (p *Provider) AuthRequestClientHost(id string) (string, error) {
	s, ok := p.Storage.(*MemStorage)
	if !ok {
		return "", fmt.Errorf("storage does not support AuthRequestClientHost")
	}
	return s.AuthRequestClientHost(context.Background(), id)
}

type UserStore struct {
	store *store.Store
	get   func(userID string) (*store.User, error)
}

func (u *UserStore) GetUser(userID string) (*store.User, error) {
	if u == nil {
		return nil, fmt.Errorf("user store is nil")
	}
	if u.get != nil {
		return u.get(userID)
	}
	return u.store.GetUser(userID)
}

func (u *UserStore) TrackOIDCClient(userID, clientID, clientHost string) error {
	if u == nil || u.store == nil {
		return nil
	}
	return u.store.UpsertUserOIDCClient(userID, clientID, clientHost)
}

type SimpleKey struct {
	id  string
	alg jose.SignatureAlgorithm
	use string
	key interface{}
}

func (k *SimpleKey) ID() string                                  { return k.id }
func (k *SimpleKey) Algorithm() jose.SignatureAlgorithm          { return k.alg }
func (k *SimpleKey) SignatureAlgorithm() jose.SignatureAlgorithm { return k.alg }
func (k *SimpleKey) Use() string                                 { return k.use }
func (k *SimpleKey) Key() interface{}                            { return k.key }

type SimpleAuthRequest struct {
	ID                  string                   `json:"id"`
	Subject             string                   `json:"subject"`
	DoneVal             bool                     `json:"done"`
	ACR                 string                   `json:"acr"`
	AMR                 []string                 `json:"amr,omitempty"`
	AuthTime            time.Time                `json:"auth_time"`
	Scopes              []string                 `json:"scopes"`
	ResponseType        oidc.ResponseType        `json:"response_type"`
	RedirectURI         string                   `json:"redirect_uri"`
	State               string                   `json:"state"`
	Nonce               string                   `json:"nonce"`
	CodeChallenge       string                   `json:"code_challenge"`
	CodeChallengeMethod oidc.CodeChallengeMethod `json:"code_challenge_method"`
	Audience            []string                 `json:"audience"`
	ClientID            string                   `json:"client_id"`
}

func (r *SimpleAuthRequest) GetID() string                      { return r.ID }
func (r *SimpleAuthRequest) GetACR() string                     { return r.ACR }
func (r *SimpleAuthRequest) GetSubject() string                 { return r.Subject }
func (r *SimpleAuthRequest) Done() bool                         { return r.DoneVal }
func (r *SimpleAuthRequest) GetAMR() []string                   { return r.AMR }
func (r *SimpleAuthRequest) GetAuthTime() time.Time             { return r.AuthTime }
func (r *SimpleAuthRequest) GetAudience() []string              { return r.Audience }
func (r *SimpleAuthRequest) GetScopes() []string                { return r.Scopes }
func (r *SimpleAuthRequest) GetResponseType() oidc.ResponseType { return r.ResponseType }
func (r *SimpleAuthRequest) GetRedirectURI() string             { return r.RedirectURI }
func (r *SimpleAuthRequest) GetState() string                   { return r.State }
func (r *SimpleAuthRequest) GetResponseMode() oidc.ResponseMode { return "" }
func (r *SimpleAuthRequest) GetNonce() string                   { return r.Nonce }
func (r *SimpleAuthRequest) GetCodeChallenge() *oidc.CodeChallenge {
	if r.CodeChallenge == "" {
		return nil
	}
	return &oidc.CodeChallenge{Challenge: r.CodeChallenge, Method: r.CodeChallengeMethod}
}
func (r *SimpleAuthRequest) GetClientID() string { return r.ClientID }

type clientConfig struct {
	ID            string   `json:"id"`
	Name          string   `json:"name,omitempty"`
	Enabled       *bool    `json:"enabled,omitempty"`
	RedirectURIs  []string `json:"redirect_uris"`
	Confidential  bool     `json:"confidential"`
	Secrets       []string `json:"secrets,omitempty"`
	RequirePKCE   *bool    `json:"require_pkce,omitempty"`
	AuthMethod    string   `json:"auth_method"`
	GrantTypes    []string `json:"grant_types"`
	ResponseTypes []string `json:"response_types"`
	Scopes        []string `json:"scopes"`
}

type MemStorage struct {
	clientsMu   sync.RWMutex
	clients     map[string]*StaticClient
	redis       *redis.Client
	userStore   *UserStore
	clientStore OIDCClientStore
	avatarBase  string
	signingKey  *SimpleKey
	keys        []*SimpleKey
}

type OIDCClientStore interface {
	ListOIDCClients() ([]store.OIDCClient, error)
	ListEnabledOIDCClients() ([]store.OIDCClient, error)
	ListOIDCClientSecrets(clientID string) ([]store.OIDCClientSecret, error)
	BootstrapOIDCClients(clients []store.OIDCClientBootstrapInput) (int, error)
}

type runtimeClientInput struct {
	ID            string
	Confidential  bool
	SecretHashes  []string
	RedirectURIs  []string
	RequirePKCE   bool
	AuthMethod    string
	GrantTypes    []string
	ResponseTypes []string
	Scopes        []string
}

func NewMemStorage(rdb *redis.Client, us *UserStore, clientStore OIDCClientStore, prodMode bool, avatarBase string) (*MemStorage, error) {
	clients, err := loadRuntimeClients(clientStore, prodMode)
	if err != nil {
		return nil, err
	}
	if len(clients) == 0 {
		return nil, errors.New("no enabled oidc clients found in database")
	}
	log.Printf("OIDC clients loaded: %s", strings.Join(sortedClientIDs(clients), ", "))

	return &MemStorage{
		clients:     clients,
		redis:       rdb,
		userStore:   us,
		clientStore: clientStore,
		avatarBase:  strings.TrimSpace(avatarBase),
	}, nil
}

func loadRuntimeClients(clientStore OIDCClientStore, prodMode bool) (map[string]*StaticClient, error) {
	if clientStore == nil {
		return nil, errors.New("oidc client store is nil")
	}

	allClients, err := clientStore.ListOIDCClients()
	if err != nil {
		return nil, fmt.Errorf("list oidc clients: %w", err)
	}

	if len(allClients) == 0 {
		if err := bootstrapOIDCClients(clientStore, prodMode); err != nil {
			return nil, err
		}
	} else if hasOIDCClientBootstrapEnv() {
		log.Printf("OIDC bootstrap env detected but skipped: database already has %d clients", len(allClients))
	}

	return buildRuntimeClientsFromStore(clientStore)
}

func buildRuntimeClientsFromStore(clientStore OIDCClientStore) (map[string]*StaticClient, error) {
	if clientStore == nil {
		return nil, errors.New("oidc client store is nil")
	}

	enabledClients, err := clientStore.ListEnabledOIDCClients()
	if err != nil {
		return nil, fmt.Errorf("list enabled oidc clients: %w", err)
	}

	clients := make(map[string]*StaticClient, len(enabledClients))
	for _, dbClient := range enabledClients {
		secrets, err := clientStore.ListOIDCClientSecrets(dbClient.ID)
		if err != nil {
			return nil, fmt.Errorf("list oidc client secrets for %q: %w", dbClient.ID, err)
		}
		client, err := buildClientFromDB(dbClient, secrets)
		if err != nil {
			return nil, fmt.Errorf("client %q: %w", dbClient.ID, err)
		}
		if _, exists := clients[client.id]; exists {
			return nil, fmt.Errorf("duplicate client id %q", client.id)
		}
		clients[client.id] = client
	}
	return clients, nil
}

func bootstrapOIDCClients(clientStore OIDCClientStore, prodMode bool) error {
	bootstrapEnabled := isEnvEnabled("OIDC_CLIENTS_BOOTSTRAP")
	bootstrapClients, source, explicitSource, err := loadBootstrapClients(prodMode)
	if err != nil {
		return err
	}

	if prodMode {
		if !bootstrapEnabled {
			return errors.New("oidc clients table is empty in prod: set OIDC_CLIENTS_BOOTSTRAP=1 and provide OIDC_CLIENTS_JSON or OIDC_CLIENTS_FILE")
		}
		if !explicitSource {
			return errors.New("oidc clients table is empty in prod: OIDC_CLIENTS_JSON or OIDC_CLIENTS_FILE bootstrap source is required")
		}
	}

	inserted, err := clientStore.BootstrapOIDCClients(bootstrapClients)
	if err != nil {
		return fmt.Errorf("bootstrap oidc clients from %s: %w", source, err)
	}
	if inserted == 0 {
		log.Printf("OIDC bootstrap from %s skipped (database already initialized)", source)
	} else {
		log.Printf("OIDC bootstrap from %s inserted %d clients", source, inserted)
	}
	return nil
}

func loadBootstrapClients(prodMode bool) ([]store.OIDCClientBootstrapInput, string, bool, error) {
	rawJSON := strings.TrimSpace(os.Getenv("OIDC_CLIENTS_JSON"))
	filePath := strings.TrimSpace(os.Getenv("OIDC_CLIENTS_FILE"))

	switch {
	case rawJSON != "":
		clients, err := parseBootstrapClients(rawJSON)
		return clients, "OIDC_CLIENTS_JSON", true, err
	case filePath != "":
		b, err := os.ReadFile(filePath)
		if err != nil {
			return nil, "", true, fmt.Errorf("read OIDC_CLIENTS_FILE: %w", err)
		}
		clients, parseErr := parseBootstrapClients(string(b))
		return clients, fmt.Sprintf("OIDC_CLIENTS_FILE(%s)", filePath), true, parseErr
	case prodMode:
		return nil, "", false, nil
	default:
		return defaultDevBootstrapClients(), "default-dev", false, nil
	}
}

func parseBootstrapClients(raw string) ([]store.OIDCClientBootstrapInput, error) {
	var cfgs []clientConfig
	if err := json.Unmarshal([]byte(raw), &cfgs); err != nil {
		return nil, fmt.Errorf("parse oidc clients bootstrap: %w", err)
	}
	if len(cfgs) == 0 {
		return nil, errors.New("oidc client bootstrap config is empty")
	}

	clients := make([]store.OIDCClientBootstrapInput, 0, len(cfgs))
	for _, cfg := range cfgs {
		clientID := strings.TrimSpace(cfg.ID)
		secrets := make([]store.OIDCClientSecretInput, 0, len(cfg.Secrets))
		for idx, secret := range cfg.Secrets {
			trimmed := strings.TrimSpace(secret)
			if trimmed == "" {
				continue
			}
			label := ""
			if len(cfg.Secrets) > 1 {
				label = fmt.Sprintf("bootstrap-%d", idx+1)
			}
			secrets = append(secrets, store.OIDCClientSecretInput{
				PlainSecret: trimmed,
				Label:       label,
			})
		}
		if cfg.Confidential && len(secrets) == 0 && strings.EqualFold(clientID, "mushroom-bff") {
			if secret := strings.TrimSpace(os.Getenv("OIDC_CLIENT_MUSHROOM_BFF_SECRET")); secret != "" {
				secrets = append(secrets, store.OIDCClientSecretInput{
					PlainSecret: secret,
					Label:       "env:OIDC_CLIENT_MUSHROOM_BFF_SECRET",
				})
			}
		}
		enabled := true
		if cfg.Enabled != nil {
			enabled = *cfg.Enabled
		}
		requirePKCE := true
		if cfg.RequirePKCE != nil {
			requirePKCE = *cfg.RequirePKCE
		}
		clients = append(clients, store.OIDCClientBootstrapInput{
			ID:            clientID,
			Name:          strings.TrimSpace(cfg.Name),
			Enabled:       enabled,
			Confidential:  cfg.Confidential,
			RequirePKCE:   requirePKCE,
			AuthMethod:    strings.TrimSpace(cfg.AuthMethod),
			GrantTypes:    append([]string(nil), cfg.GrantTypes...),
			ResponseTypes: append([]string(nil), cfg.ResponseTypes...),
			Scopes:        append([]string(nil), cfg.Scopes...),
			RedirectURIs:  append([]string(nil), cfg.RedirectURIs...),
			Secrets:       secrets,
		})
	}
	return clients, nil
}

func defaultDevBootstrapClients() []store.OIDCClientBootstrapInput {
	return []store.OIDCClientBootstrapInput{
		{
			ID:            "test",
			Name:          "Postman Test",
			Enabled:       true,
			Confidential:  true,
			RedirectURIs:  []string{"https://oauth.pstmn.io/v1/callback", "https://jwt.io", "http://localhost:3000/api/auth/callback/custom"},
			RequirePKCE:   true,
			AuthMethod:    "basic",
			GrantTypes:    []string{"authorization_code"},
			ResponseTypes: []string{"code"},
			Scopes:        []string{oidc.ScopeOpenID, oidc.ScopeProfile, oidc.ScopeEmail, oidc.ScopePhone, oidc.ScopeOfflineAccess},
			Secrets: []store.OIDCClientSecretInput{
				{PlainSecret: "secret", Label: "dev-default"},
			},
		},
		{
			ID:            "postman",
			Name:          "Postman",
			Enabled:       true,
			Confidential:  true,
			RedirectURIs:  []string{"https://oauth.pstmn.io/v1/callback"},
			RequirePKCE:   true,
			AuthMethod:    "basic",
			GrantTypes:    []string{"authorization_code"},
			ResponseTypes: []string{"code"},
			Scopes:        []string{oidc.ScopeOpenID, oidc.ScopeProfile, oidc.ScopeEmail, oidc.ScopePhone, oidc.ScopeOfflineAccess},
			Secrets: []store.OIDCClientSecretInput{
				{PlainSecret: "secret", Label: "dev-default"},
			},
		},
		{
			ID:            "houbamzdar",
			Name:          "Houbamzdar",
			Enabled:       true,
			Confidential:  false,
			RedirectURIs:  []string{"https://houbamzdar.cz/callback.html"},
			RequirePKCE:   true,
			AuthMethod:    "none",
			GrantTypes:    []string{"authorization_code"},
			ResponseTypes: []string{"code"},
			Scopes:        []string{oidc.ScopeOpenID, oidc.ScopeProfile, oidc.ScopeEmail, oidc.ScopePhone},
		},
		{
			ID:            "client1",
			Name:          "Client 1",
			Enabled:       true,
			Confidential:  false,
			RedirectURIs:  []string{"https://houbamzdar.cz/callback1.html"},
			RequirePKCE:   true,
			AuthMethod:    "none",
			GrantTypes:    []string{"authorization_code"},
			ResponseTypes: []string{"code"},
			Scopes:        []string{oidc.ScopeOpenID, oidc.ScopeProfile, oidc.ScopeEmail, oidc.ScopePhone},
		},
		{
			ID:            "client2",
			Name:          "Client 2",
			Enabled:       true,
			Confidential:  false,
			RedirectURIs:  []string{"https://houbamzdar.cz/callback2.html"},
			RequirePKCE:   true,
			AuthMethod:    "none",
			GrantTypes:    []string{"authorization_code"},
			ResponseTypes: []string{"code"},
			Scopes:        []string{oidc.ScopeOpenID, oidc.ScopeProfile, oidc.ScopeEmail, oidc.ScopePhone},
		},
		{
			ID:            "mushroom-bff",
			Name:          "Mushroom BFF",
			Enabled:       true,
			Confidential:  true,
			RequirePKCE:   true,
			AuthMethod:    "basic",
			GrantTypes:    []string{"authorization_code", "refresh_token"},
			ResponseTypes: []string{"code"},
			RedirectURIs:  []string{"https://api.houbamzdar.cz/auth/callback"},
			Scopes:        []string{oidc.ScopeOpenID, oidc.ScopeProfile, oidc.ScopeEmail, oidc.ScopePhone, oidc.ScopeOfflineAccess},
			Secrets: []store.OIDCClientSecretInput{
				{PlainSecret: "dev-mushroom-bff-secret", Label: "dev-default"},
			},
		},
	}
}

func hasOIDCClientBootstrapEnv() bool {
	return strings.TrimSpace(os.Getenv("OIDC_CLIENTS_JSON")) != "" ||
		strings.TrimSpace(os.Getenv("OIDC_CLIENTS_FILE")) != "" ||
		isEnvEnabled("OIDC_CLIENTS_BOOTSTRAP")
}

func isEnvEnabled(key string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(key))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func buildClientFromDB(client store.OIDCClient, secrets []store.OIDCClientSecret) (*StaticClient, error) {
	secretHashes := make([]string, 0, len(secrets))
	for _, secret := range secrets {
		if secret.RevokedAt != nil {
			continue
		}
		hash := strings.TrimSpace(secret.SecretHash)
		if hash == "" {
			continue
		}
		secretHashes = append(secretHashes, hash)
	}

	return buildRuntimeClient(runtimeClientInput{
		ID:            client.ID,
		Confidential:  client.Confidential,
		SecretHashes:  secretHashes,
		RedirectURIs:  client.RedirectURIs,
		RequirePKCE:   client.RequirePKCE,
		AuthMethod:    client.AuthMethod,
		GrantTypes:    client.GrantTypes,
		ResponseTypes: client.ResponseTypes,
		Scopes:        client.Scopes,
	})
}

func buildRuntimeClient(in runtimeClientInput) (*StaticClient, error) {
	in.ID = strings.TrimSpace(in.ID)
	if in.ID == "" {
		return nil, errors.New("id is required")
	}
	in.RedirectURIs = uniqueTrimmedStrings(in.RedirectURIs)
	if len(in.RedirectURIs) == 0 {
		return nil, errors.New("at least one redirect_uri is required")
	}

	authMethod, err := parseAuthMethod(in.AuthMethod)
	if err != nil {
		return nil, err
	}
	if !in.Confidential {
		authMethod = oidc.AuthMethodNone
		in.SecretHashes = nil
	}
	in.SecretHashes = uniqueTrimmedStrings(in.SecretHashes)
	if in.Confidential && authMethod == oidc.AuthMethodNone {
		return nil, errors.New("confidential client cannot use auth_method none")
	}
	if in.Confidential && len(in.SecretHashes) == 0 {
		return nil, errors.New("confidential client requires secrets")
	}
	if !in.Confidential && len(in.SecretHashes) > 0 {
		return nil, errors.New("public client must not define secrets")
	}

	responseTypes, err := parseResponseTypes(in.ResponseTypes)
	if err != nil {
		return nil, err
	}
	grantTypes, err := parseGrantTypes(in.GrantTypes)
	if err != nil {
		return nil, err
	}
	allowedScopes := parseAllowedScopes(in.Scopes)
	for _, gt := range grantTypes {
		if gt == oidc.GrantTypeRefreshToken {
			allowedScopes[oidc.ScopeOfflineAccess] = struct{}{}
			break
		}
	}

	return &StaticClient{
		id:              in.ID,
		secretHashes:    in.SecretHashes,
		redirectURIs:    in.RedirectURIs,
		responseTypes:   responseTypes,
		grantTypes:      grantTypes,
		applicationType: op.ApplicationTypeWeb,
		authMethod:      authMethod,
		requirePKCE:     in.RequirePKCE,
		allowedScopes:   allowedScopes,
	}, nil
}

func parseAllowedScopes(scopes []string) map[string]struct{} {
	if len(scopes) == 0 {
		scopes = []string{oidc.ScopeOpenID, oidc.ScopeProfile, oidc.ScopeEmail, oidc.ScopePhone, oidc.ScopeOfflineAccess}
	}
	out := make(map[string]struct{}, len(scopes))
	for _, scope := range scopes {
		trimmed := strings.TrimSpace(scope)
		if trimmed == "" {
			continue
		}
		out[trimmed] = struct{}{}
	}
	return out
}

func parseAuthMethod(raw string) (oidc.AuthMethod, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "basic", "client_secret_basic":
		return oidc.AuthMethodBasic, nil
	case "post", "client_secret_post":
		return oidc.AuthMethodPost, nil
	case "none":
		return oidc.AuthMethodNone, nil
	default:
		return "", fmt.Errorf("unsupported auth_method %q", raw)
	}
}

func parseResponseTypes(raw []string) ([]oidc.ResponseType, error) {
	if len(raw) == 0 {
		raw = []string{"code"}
	}
	res := make([]oidc.ResponseType, 0, len(raw))
	for _, item := range raw {
		switch strings.ToLower(strings.TrimSpace(item)) {
		case "code":
			res = append(res, oidc.ResponseTypeCode)
		case "id_token":
			res = append(res, oidc.ResponseTypeIDTokenOnly)
		case "id_token token":
			res = append(res, oidc.ResponseTypeIDToken)
		default:
			return nil, fmt.Errorf("unsupported response_type %q", item)
		}
	}
	return res, nil
}

func parseGrantTypes(raw []string) ([]oidc.GrantType, error) {
	if len(raw) == 0 {
		raw = []string{"authorization_code"}
	}
	res := make([]oidc.GrantType, 0, len(raw))
	for _, item := range raw {
		switch strings.ToLower(strings.TrimSpace(item)) {
		case "authorization_code":
			res = append(res, oidc.GrantTypeCode)
		case "implicit":
			res = append(res, oidc.GrantTypeImplicit)
		case "refresh_token":
			res = append(res, oidc.GrantTypeRefreshToken)
		case "urn:ietf:params:oauth:grant-type:jwt-bearer":
			res = append(res, oidc.GrantTypeBearer)
		default:
			return nil, fmt.Errorf("unsupported grant_type %q", item)
		}
	}
	return res, nil
}

func uniqueTrimmedStrings(items []string) []string {
	out := make([]string, 0, len(items))
	seen := make(map[string]struct{}, len(items))
	for _, item := range items {
		trimmed := strings.TrimSpace(item)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		out = append(out, trimmed)
	}
	return out
}

func sortedClientIDs(clients map[string]*StaticClient) []string {
	ids := make([]string, 0, len(clients))
	for id := range clients {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func (s *MemStorage) runtimeClient(clientID string) (*StaticClient, bool) {
	s.clientsMu.RLock()
	client, ok := s.clients[clientID]
	s.clientsMu.RUnlock()
	return client, ok
}

func (s *MemStorage) setRuntimeClients(clients map[string]*StaticClient) {
	s.clientsMu.Lock()
	s.clients = clients
	s.clientsMu.Unlock()
}

func (s *MemStorage) ReloadClients(ctx context.Context) error {
	if s == nil {
		return errors.New("mem storage is nil")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	clients, err := buildRuntimeClientsFromStore(s.clientStore)
	if err != nil {
		return err
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	s.setRuntimeClients(clients)

	ids := sortedClientIDs(clients)
	if len(ids) == 0 {
		log.Printf("OIDC clients reloaded: no enabled clients")
	} else {
		log.Printf("OIDC clients reloaded: %s", strings.Join(ids, ", "))
	}
	return nil
}

func (s *MemStorage) Health(ctx context.Context) error {
	return s.redis.Ping(ctx).Err()
}

func (s *MemStorage) CreateAuthRequest(ctx context.Context, authRequest *oidc.AuthRequest, clientID string) (op.AuthRequest, error) {
	if clientID == "" && authRequest != nil {
		clientID = authRequest.ClientID
	}
	client, ok := s.runtimeClient(clientID)
	if !ok {
		return nil, fmt.Errorf("client not found")
	}
	if authRequest == nil {
		return nil, fmt.Errorf("auth request is nil")
	}

	if client.requirePKCE {
		if authRequest.CodeChallenge == "" || authRequest.CodeChallengeMethod != oidc.CodeChallengeMethodS256 {
			return nil, fmt.Errorf("pkce (S256) is required for client %s", clientID)
		}
	}

	subject, _ := UserIDFromContext(ctx)
	now := time.Now().UTC()
	req := &SimpleAuthRequest{
		ID:                  randomID("auth"),
		Subject:             subject,
		DoneVal:             subject != "",
		ACR:                 "",
		AMR:                 nil,
		AuthTime:            time.Time{},
		Scopes:              authRequest.Scopes,
		ResponseType:        authRequest.ResponseType,
		RedirectURI:         authRequest.RedirectURI,
		State:               authRequest.State,
		Nonce:               authRequest.Nonce,
		CodeChallenge:       authRequest.CodeChallenge,
		CodeChallengeMethod: authRequest.CodeChallengeMethod,
		ClientID:            clientID,
		Audience:            []string{clientID},
	}
	if req.DoneVal {
		req.AuthTime = now
	}

	if err := s.saveAuthRequest(ctx, req, oidcStateTTL); err != nil {
		return nil, err
	}
	return req, nil
}

func (s *MemStorage) AuthRequestByID(ctx context.Context, id string) (op.AuthRequest, error) {
	req, err := s.getAuthRequest(ctx, id)
	if err != nil {
		return nil, err
	}
	return req, nil
}

func (s *MemStorage) AuthRequestByCode(ctx context.Context, code string) (op.AuthRequest, error) {
	id, err := redisGetDel(ctx, s.redis, codeKey(code))
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, fmt.Errorf("invalid or expired code")
		}
		return nil, err
	}
	if id == "" {
		return nil, fmt.Errorf("invalid or expired code")
	}
	return s.AuthRequestByID(ctx, id)
}

func (s *MemStorage) SaveAuthCode(ctx context.Context, id, code string) error {
	if _, err := s.AuthRequestByID(ctx, id); err != nil {
		return err
	}
	pipe := s.redis.TxPipeline()
	pipe.Set(ctx, codeKey(code), id, oidcStateTTL)
	pipe.Set(ctx, authReqCodeKeyFor(id), code, oidcStateTTL)
	_, err := pipe.Exec(ctx)
	return err
}

func (s *MemStorage) DeleteAuthRequest(ctx context.Context, id string) error {
	code, err := redisGetDel(ctx, s.redis, authReqCodeKeyFor(id))
	if err != nil && !errors.Is(err, redis.Nil) {
		return err
	}
	pipe := s.redis.TxPipeline()
	pipe.Del(ctx, authReqKey(id))
	if code != "" {
		pipe.Del(ctx, codeKey(code))
	}
	_, execErr := pipe.Exec(ctx)
	return execErr
}

func (s *MemStorage) SetAuthRequestDone(id, userID string) error {
	ctx := context.Background()
	req, err := s.getAuthRequest(ctx, id)
	if err != nil {
		return err
	}
	req.Subject = userID
	req.DoneVal = true
	req.AuthTime = time.Now().UTC()
	if err := s.saveAuthRequest(ctx, req, oidcStateTTL); err != nil {
		return err
	}

	clientHost := ""
	if parsed, parseErr := url.Parse(req.RedirectURI); parseErr == nil {
		clientHost = strings.TrimSpace(parsed.Host)
	}
	if err := s.userStore.TrackOIDCClient(userID, req.ClientID, clientHost); err != nil {
		log.Printf("failed to track oidc client usage for user %s and client %s: %v", userID, req.ClientID, err)
	}
	return nil
}

func (s *MemStorage) AuthRequestClientHost(ctx context.Context, id string) (string, error) {
	req, err := s.getAuthRequest(ctx, id)
	if err != nil {
		return "", err
	}
	parsed, err := url.Parse(req.RedirectURI)
	if err != nil {
		return "", err
	}
	return parsed.Host, nil
}

func (s *MemStorage) saveAuthRequest(ctx context.Context, req *SimpleAuthRequest, ttl time.Duration) error {
	payload, err := json.Marshal(req)
	if err != nil {
		return err
	}
	return s.redis.Set(ctx, authReqKey(req.ID), payload, ttl).Err()
}

func (s *MemStorage) getAuthRequest(ctx context.Context, id string) (*SimpleAuthRequest, error) {
	payload, err := s.redis.Get(ctx, authReqKey(id)).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, fmt.Errorf("auth request not found")
		}
		return nil, err
	}
	var req SimpleAuthRequest
	if err := json.Unmarshal(payload, &req); err != nil {
		return nil, err
	}
	return &req, nil
}

func authReqKey(id string) string {
	return authRequestKey + id
}

func codeKey(code string) string {
	return authCodeKey + code
}

func authReqCodeKeyFor(id string) string {
	return authReqCodeKey + id
}

func redisGetDel(ctx context.Context, rdb *redis.Client, key string) (string, error) {
	value, err := rdb.Do(ctx, "GETDEL", key).Text()
	if err == nil {
		return value, nil
	}
	if errors.Is(err, redis.Nil) {
		return "", redis.Nil
	}
	if !isUnknownRedisCommand(err) {
		return "", err
	}

	res, evalErr := rdb.Eval(ctx, `local v = redis.call("GET", KEYS[1]); if v then redis.call("DEL", KEYS[1]); end; return v`, []string{key}).Result()
	if evalErr != nil {
		if errors.Is(evalErr, redis.Nil) {
			return "", redis.Nil
		}
		return "", evalErr
	}
	if res == nil {
		return "", redis.Nil
	}
	str, ok := res.(string)
	if !ok {
		return "", fmt.Errorf("unexpected redis result type %T", res)
	}
	return str, nil
}

func isUnknownRedisCommand(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "unknown command") || strings.Contains(msg, "unsupported command")
}

func randomID(prefix string) string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%s_%d", prefix, time.Now().UnixNano())
	}
	return fmt.Sprintf("%s_%s", prefix, base64.RawURLEncoding.EncodeToString(b))
}

func publicEmailForClaims(user *store.User) string {
	if user == nil {
		return ""
	}
	return strings.TrimSpace(user.ProfileEmail)
}

func isRefreshTokenUsed(rec *RefreshTokenRecord) bool {
	if rec == nil {
		return false
	}
	return !rec.UsedAt.IsZero() || rec.RotatedToTokenID != ""
}

func invalidRefreshGrantError() error {
	return oidc.ErrInvalidGrant().WithParent(op.ErrInvalidRefreshToken)
}

func (s *MemStorage) CreateAccessToken(ctx context.Context, request op.TokenRequest) (string, time.Time, error) {
	accessTokenID, err := generateAccessTokenID()
	if err != nil {
		return "", time.Time{}, err
	}
	return accessTokenID, time.Now().Add(1 * time.Hour), nil
}

func (s *MemStorage) CreateAccessAndRefreshTokens(ctx context.Context, request op.TokenRequest, currentRefreshToken string) (accessTokenID string, newRefreshTokenID string, expiration time.Time, err error) {
	now := time.Now().UTC()
	accessTokenID, err = generateAccessTokenID()
	if err != nil {
		return "", "", time.Time{}, err
	}
	expiration = now.Add(1 * time.Hour)

	subject := strings.TrimSpace(request.GetSubject())
	if subject == "" {
		return "", "", time.Time{}, fmt.Errorf("subject is required for refresh token")
	}

	clientID := ""
	if withClientID, ok := request.(interface{ GetClientID() string }); ok {
		clientID = strings.TrimSpace(withClientID.GetClientID())
	}
	if clientID == "" {
		for _, aud := range request.GetAudience() {
			if strings.TrimSpace(aud) != "" {
				clientID = strings.TrimSpace(aud)
				break
			}
		}
	}
	if clientID == "" {
		return "", "", time.Time{}, fmt.Errorf("client id is required for refresh token")
	}

	authTime := now
	if withAuthTime, ok := request.(interface{ GetAuthTime() time.Time }); ok {
		reqAuthTime := withAuthTime.GetAuthTime().UTC()
		if !reqAuthTime.IsZero() {
			authTime = reqAuthTime
		}
	}

	scopes := append([]string(nil), request.GetScopes()...)
	audience := append([]string(nil), request.GetAudience()...)
	amr := []string(nil)
	if withAMR, ok := request.(interface{ GetAMR() []string }); ok {
		amr = append([]string(nil), withAMR.GetAMR()...)
	}

	// Auth code flow: issue first refresh token.
	if currentRefreshToken == "" {
		refreshTokenID, genErr := generateRefreshTokenID()
		if genErr != nil {
			return "", "", time.Time{}, genErr
		}
		rec := &RefreshTokenRecord{
			TokenID:       refreshTokenID,
			UserID:        subject,
			Subject:       subject,
			ClientID:      clientID,
			Scopes:        scopes,
			Audience:      audience,
			AMR:           amr,
			AuthTime:      authTime,
			IssuedAt:      now,
			ExpiresAt:     now.Add(refreshTokenTTL),
			ParentTokenID: "",
			FamilyID:      refreshTokenID,
		}
		if len(rec.Audience) == 0 {
			rec.Audience = []string{clientID}
		}
		if err := s.saveRefreshToken(ctx, rec); err != nil {
			return "", "", time.Time{}, err
		}
		return accessTokenID, refreshTokenID, expiration, nil
	}

	// Refresh grant: validate current token and rotate.
	currentRec, err := s.getRefreshToken(ctx, currentRefreshToken)
	if err != nil {
		if errors.Is(err, ErrRefreshTokenNotFound) {
			return "", "", time.Time{}, invalidRefreshGrantError()
		}
		return "", "", time.Time{}, err
	}
	if currentRec.FamilyID == "" {
		return "", "", time.Time{}, invalidRefreshGrantError()
	}
	if currentRec.ClientID != clientID || strings.TrimSpace(currentRec.GetSubject()) != subject {
		return "", "", time.Time{}, invalidRefreshGrantError()
	}

	familyRevoked, err := s.isRefreshTokenFamilyRevoked(ctx, currentRec.FamilyID)
	if err != nil {
		return "", "", time.Time{}, err
	}
	if familyRevoked {
		return "", "", time.Time{}, invalidRefreshGrantError()
	}
	if !currentRec.ExpiresAt.After(now) {
		_ = s.deleteRefreshToken(ctx, currentRefreshToken)
		return "", "", time.Time{}, invalidRefreshGrantError()
	}
	if !currentRec.RevokedAt.IsZero() {
		return "", "", time.Time{}, invalidRefreshGrantError()
	}
	if isRefreshTokenUsed(currentRec) {
		_ = s.revokeRefreshTokenFamily(ctx, currentRec.FamilyID, currentRec.ExpiresAt)
		currentRec.ReuseDetectedAt = now
		_ = s.saveRefreshToken(ctx, currentRec)
		return "", "", time.Time{}, invalidRefreshGrantError()
	}

	newTokenID, genErr := generateRefreshTokenID()
	if genErr != nil {
		return "", "", time.Time{}, genErr
	}

	newRec := &RefreshTokenRecord{
		TokenID:          newTokenID,
		UserID:           strings.TrimSpace(currentRec.GetSubject()),
		Subject:          strings.TrimSpace(currentRec.GetSubject()),
		ClientID:         currentRec.ClientID,
		Scopes:           scopes,
		Audience:         audience,
		AMR:              append([]string(nil), currentRec.GetAMR()...),
		AuthTime:         currentRec.AuthTime,
		IssuedAt:         now,
		ExpiresAt:        now.Add(refreshTokenTTL),
		ParentTokenID:    currentRec.TokenID,
		FamilyID:         currentRec.FamilyID,
		RotatedToTokenID: "",
	}
	if len(newRec.Scopes) == 0 {
		newRec.Scopes = append([]string(nil), currentRec.Scopes...)
	}
	if len(newRec.Audience) == 0 {
		newRec.Audience = append([]string(nil), currentRec.Audience...)
	}
	if len(newRec.Audience) == 0 {
		newRec.Audience = []string{newRec.ClientID}
	}

	if err := s.saveRefreshToken(ctx, newRec); err != nil {
		return "", "", time.Time{}, err
	}

	currentRec.UsedAt = now
	currentRec.RotatedToTokenID = newTokenID
	if err := s.saveRefreshToken(ctx, currentRec); err != nil {
		return "", "", time.Time{}, err
	}

	return accessTokenID, newTokenID, expiration, nil
}

func (s *MemStorage) TokenRequestByRefreshToken(ctx context.Context, refreshTokenID string) (op.RefreshTokenRequest, error) {
	rec, err := s.getRefreshToken(ctx, refreshTokenID)
	if err != nil {
		if errors.Is(err, ErrRefreshTokenNotFound) {
			return nil, op.ErrInvalidRefreshToken
		}
		return nil, err
	}

	now := time.Now().UTC()
	if rec.FamilyID == "" {
		return nil, op.ErrInvalidRefreshToken
	}

	familyRevoked, err := s.isRefreshTokenFamilyRevoked(ctx, rec.FamilyID)
	if err != nil {
		return nil, err
	}
	if familyRevoked {
		return nil, op.ErrInvalidRefreshToken
	}
	if !rec.ExpiresAt.After(now) {
		_ = s.deleteRefreshToken(ctx, refreshTokenID)
		return nil, op.ErrInvalidRefreshToken
	}
	if !rec.RevokedAt.IsZero() {
		return nil, op.ErrInvalidRefreshToken
	}
	if isRefreshTokenUsed(rec) {
		_ = s.revokeRefreshTokenFamily(ctx, rec.FamilyID, rec.ExpiresAt)
		rec.ReuseDetectedAt = now
		_ = s.saveRefreshToken(ctx, rec)
		return nil, op.ErrInvalidRefreshToken
	}

	return rec, nil
}

func (s *MemStorage) TerminateSession(ctx context.Context, userID, clientID string) error {
	return nil
}

func (s *MemStorage) RevokeToken(ctx context.Context, token, userID, clientID string) *oidc.Error {
	return nil
}

func (s *MemStorage) GetRefreshTokenInfo(ctx context.Context, clientID, token string) (userID, tokenID string, err error) {
	rec, err := s.getRefreshToken(ctx, token)
	if err != nil {
		if errors.Is(err, ErrRefreshTokenNotFound) {
			return "", "", op.ErrInvalidRefreshToken
		}
		return "", "", err
	}

	now := time.Now().UTC()
	if rec.FamilyID == "" {
		return "", "", op.ErrInvalidRefreshToken
	}
	familyRevoked, err := s.isRefreshTokenFamilyRevoked(ctx, rec.FamilyID)
	if err != nil {
		return "", "", err
	}
	if familyRevoked {
		return "", "", op.ErrInvalidRefreshToken
	}
	if !rec.ExpiresAt.After(now) {
		_ = s.deleteRefreshToken(ctx, token)
		return "", "", op.ErrInvalidRefreshToken
	}
	if !rec.RevokedAt.IsZero() {
		return "", "", op.ErrInvalidRefreshToken
	}
	if isRefreshTokenUsed(rec) {
		return "", "", op.ErrInvalidRefreshToken
	}
	if strings.TrimSpace(clientID) != "" && rec.ClientID != strings.TrimSpace(clientID) {
		return "", "", op.ErrInvalidRefreshToken
	}

	subject := strings.TrimSpace(rec.GetSubject())
	if subject == "" {
		return "", "", op.ErrInvalidRefreshToken
	}
	if rec.TokenID == "" {
		return "", "", op.ErrInvalidRefreshToken
	}

	return subject, rec.TokenID, nil
}

func (s *MemStorage) GetClientByClientID(ctx context.Context, clientID string) (op.Client, error) {
	if client, ok := s.runtimeClient(clientID); ok {
		return client, nil
	}
	return nil, fmt.Errorf("client not found")
}

func (s *MemStorage) AuthorizeClientIDSecret(ctx context.Context, clientID, clientSecret string) error {
	client, ok := s.runtimeClient(clientID)
	if !ok {
		return fmt.Errorf("client not found")
	}
	if client.authMethod == oidc.AuthMethodNone {
		return nil
	}
	plainSecret := strings.TrimSpace(clientSecret)
	if plainSecret == "" {
		return fmt.Errorf("invalid secret")
	}
	material := secretMaterialForBcrypt(plainSecret)
	for _, secretHash := range client.secretHashes {
		if bcrypt.CompareHashAndPassword([]byte(secretHash), material) == nil {
			return nil
		}
	}
	return fmt.Errorf("invalid secret")
}

func secretMaterialForBcrypt(plainSecret string) []byte {
	trimmed := strings.TrimSpace(plainSecret)
	if len(trimmed) <= 72 {
		return []byte(trimmed)
	}
	sum := sha256.Sum256([]byte(trimmed))
	encoded := base64.RawURLEncoding.EncodeToString(sum[:])
	return []byte("sha256:" + encoded)
}

func (s *MemStorage) SetUserinfoFromScopes(ctx context.Context, userinfo *oidc.UserInfo, userID, clientID string, scopes []string) error {
	user, err := s.userStore.GetUser(userID)
	if err != nil {
		return err
	}
	userinfo.Subject = user.ID
	for _, scope := range scopes {
		switch scope {
		case oidc.ScopeProfile:
			userinfo.Name = user.DisplayName
			userinfo.PreferredUsername = user.DisplayName
			if picture := avatar.BuildPublicURL(s.avatarBase, user.AvatarKey, user.AvatarUpdatedAt); picture != "" {
				userinfo.Picture = picture
			}
		case oidc.ScopeEmail:
			if email := publicEmailForClaims(user); email != "" {
				userinfo.Email = email
				userinfo.EmailVerified = oidc.Bool(user.EmailVerified)
			}
		case oidc.ScopePhone:
			if strings.TrimSpace(user.Phone) != "" {
				userinfo.PhoneNumber = user.Phone
				userinfo.PhoneNumberVerified = oidc.Bool(user.PhoneVerified)
			}
		}
	}
	return nil
}
func (s *MemStorage) SetUserinfoFromToken(ctx context.Context, userinfo *oidc.UserInfo, tokenID, subject, origin string) error {
	return nil
}

func (s *MemStorage) SetIntrospectionFromToken(ctx context.Context, userinfo *oidc.IntrospectionResponse, tokenID, subject, clientID string) error {
	userinfo.Subject = subject
	return nil
}

func (s *MemStorage) GetPrivateClaimsFromScopes(ctx context.Context, userID, clientID string, scopes []string) (map[string]interface{}, error) {
	user, err := s.userStore.GetUser(userID)
	if err != nil {
		return nil, err
	}

	claims := map[string]interface{}{}
	for _, scope := range scopes {
		switch scope {
		case oidc.ScopeProfile:
			claims["name"] = user.DisplayName
			claims["preferred_username"] = user.DisplayName
			if picture := avatar.BuildPublicURL(s.avatarBase, user.AvatarKey, user.AvatarUpdatedAt); picture != "" {
				claims["picture"] = picture
			}
		case oidc.ScopeEmail:
			if email := publicEmailForClaims(user); email != "" {
				claims["email"] = email
				claims["email_verified"] = user.EmailVerified
			}
		case oidc.ScopePhone:
			if strings.TrimSpace(user.Phone) != "" {
				claims["phone_number"] = user.Phone
				claims["phone_number_verified"] = user.PhoneVerified
			}
		}
	}
	return claims, nil
}
func (s *MemStorage) GetKeyByIDAndClientID(ctx context.Context, keyID, clientID string) (*jose.JSONWebKey, error) {
	for _, key := range s.keys {
		if key.id != keyID {
			continue
		}
		jwk := jose.JSONWebKey{
			Key:       key.key,
			KeyID:     key.id,
			Algorithm: string(key.alg),
			Use:       key.use,
		}
		return &jwk, nil
	}
	return nil, fmt.Errorf("key not found")
}

func (s *MemStorage) ValidateJWTProfileScopes(ctx context.Context, userID string, scopes []string) ([]string, error) {
	return scopes, nil
}

func (s *MemStorage) SigningKey(ctx context.Context) (op.SigningKey, error) {
	if s.signingKey == nil {
		return nil, fmt.Errorf("no key")
	}
	return s.signingKey, nil
}

func (s *MemStorage) SignatureAlgorithms(ctx context.Context) ([]jose.SignatureAlgorithm, error) {
	return []jose.SignatureAlgorithm{jose.RS256}, nil
}

func (s *MemStorage) KeySet(ctx context.Context) ([]op.Key, error) {
	if len(s.keys) == 0 {
		return []op.Key{}, nil
	}
	keys := make([]op.Key, 0, len(s.keys))
	for _, key := range s.keys {
		pubKey := key.key
		if rsaKey, ok := key.key.(*rsa.PrivateKey); ok {
			pubKey = &rsaKey.PublicKey
		}
		keys = append(keys, &SimpleKey{
			id:  key.id,
			alg: key.alg,
			use: key.use,
			key: pubKey,
		})
	}
	return keys, nil
}

type StaticClient struct {
	id              string
	secretHashes    []string
	redirectURIs    []string
	responseTypes   []oidc.ResponseType
	grantTypes      []oidc.GrantType
	applicationType op.ApplicationType
	authMethod      oidc.AuthMethod
	requirePKCE     bool
	allowedScopes   map[string]struct{}
}

func (c *StaticClient) GetID() string                        { return c.id }
func (c *StaticClient) RedirectURIs() []string               { return c.redirectURIs }
func (c *StaticClient) PostLogoutRedirectURIs() []string     { return []string{} }
func (c *StaticClient) ApplicationType() op.ApplicationType  { return c.applicationType }
func (c *StaticClient) AuthMethod() oidc.AuthMethod          { return c.authMethod }
func (c *StaticClient) ResponseTypes() []oidc.ResponseType   { return c.responseTypes }
func (c *StaticClient) GrantTypes() []oidc.GrantType         { return c.grantTypes }
func (c *StaticClient) AccessTokenType() op.AccessTokenType  { return op.AccessTokenTypeBearer }
func (c *StaticClient) IDTokenLifetime() time.Duration       { return 1 * time.Hour }
func (c *StaticClient) DevMode() bool                        { return true }
func (c *StaticClient) IDTokenUserinfoClaimsAssertion() bool { return true }
func (c *StaticClient) ClockSkew() time.Duration             { return 0 }
func (c *StaticClient) IsScopeAllowed(scope string) bool {
	_, ok := c.allowedScopes[scope]
	return ok
}
func (c *StaticClient) RestrictAdditionalIdTokenScopes() func(scopes []string) []string {
	return func(scopes []string) []string { return scopes }
}
func (c *StaticClient) RestrictAdditionalAccessTokenScopes() func(scopes []string) []string {
	return func(scopes []string) []string { return scopes }
}
func (c *StaticClient) LoginURL(id string) string {
	return "/?mode=login&auth_request_id=" + id + "&return_to=%2Fauthorize%2Fcallback%3Fid%3D" + id
}
