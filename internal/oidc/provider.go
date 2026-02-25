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
	"os"
	"sort"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/houbamydar/AHOJ420/internal/avatar"
	"github.com/houbamydar/AHOJ420/internal/store"
	"github.com/redis/go-redis/v9"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
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
	storage, err := NewMemStorage(r, userStore, prodMode, avatarPublicBase)
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
	RedirectURIs  []string `json:"redirect_uris"`
	Confidential  bool     `json:"confidential"`
	Secrets       []string `json:"secrets,omitempty"`
	RequirePKCE   bool     `json:"require_pkce"`
	AuthMethod    string   `json:"auth_method"`
	GrantTypes    []string `json:"grant_types"`
	ResponseTypes []string `json:"response_types"`
	Scopes        []string `json:"scopes"`
}

type MemStorage struct {
	clients    map[string]*StaticClient
	redis      *redis.Client
	userStore  *UserStore
	avatarBase string
	signingKey *SimpleKey
	keys       []*SimpleKey
}

func NewMemStorage(rdb *redis.Client, us *UserStore, prodMode bool, avatarBase string) (*MemStorage, error) {
	clients, err := loadClients(prodMode)
	if err != nil {
		return nil, err
	}
	log.Printf("OIDC clients loaded: %s", strings.Join(sortedClientIDs(clients), ", "))

	return &MemStorage{
		clients:    clients,
		redis:      rdb,
		userStore:  us,
		avatarBase: strings.TrimSpace(avatarBase),
	}, nil
}

func loadClients(prodMode bool) (map[string]*StaticClient, error) {
	rawJSON := strings.TrimSpace(os.Getenv("OIDC_CLIENTS_JSON"))
	filePath := strings.TrimSpace(os.Getenv("OIDC_CLIENTS_FILE"))

	switch {
	case rawJSON != "":
		return parseClients(rawJSON)
	case filePath != "":
		b, err := os.ReadFile(filePath)
		if err != nil {
			return nil, fmt.Errorf("read OIDC_CLIENTS_FILE: %w", err)
		}
		return parseClients(string(b))
	case prodMode:
		return nil, errors.New("OIDC_CLIENTS_JSON or OIDC_CLIENTS_FILE is required in prod")
	default:
		return defaultDevClients(), nil
	}
}

func parseClients(raw string) (map[string]*StaticClient, error) {
	var cfgs []clientConfig
	if err := json.Unmarshal([]byte(raw), &cfgs); err != nil {
		return nil, fmt.Errorf("parse OIDC clients: %w", err)
	}
	if len(cfgs) == 0 {
		return nil, errors.New("OIDC client config is empty")
	}

	clients := make(map[string]*StaticClient, len(cfgs))
	for _, cfg := range cfgs {
		client, err := buildClient(cfg)
		if err != nil {
			return nil, fmt.Errorf("client %q: %w", cfg.ID, err)
		}
		if _, exists := clients[client.id]; exists {
			return nil, fmt.Errorf("duplicate client id %q", client.id)
		}
		clients[client.id] = client
	}
	return clients, nil
}

func defaultDevClients() map[string]*StaticClient {
	clients := []clientConfig{
		{
			ID:            "test",
			Confidential:  true,
			Secrets:       []string{"secret"},
			RedirectURIs:  []string{"https://oauth.pstmn.io/v1/callback", "https://jwt.io", "http://localhost:3000/api/auth/callback/custom"},
			RequirePKCE:   true,
			AuthMethod:    "basic",
			GrantTypes:    []string{"authorization_code"},
			ResponseTypes: []string{"code"},
		},
		{
			ID:            "postman",
			Confidential:  true,
			Secrets:       []string{"secret"},
			RedirectURIs:  []string{"https://oauth.pstmn.io/v1/callback"},
			RequirePKCE:   true,
			AuthMethod:    "basic",
			GrantTypes:    []string{"authorization_code"},
			ResponseTypes: []string{"code"},
		},
		{
			ID:            "houbamzdar",
			Confidential:  false,
			RedirectURIs:  []string{"https://houbamzdar.cz/callback.html"},
			RequirePKCE:   true,
			AuthMethod:    "none",
			GrantTypes:    []string{"authorization_code"},
			ResponseTypes: []string{"code"},
		},
		{
			ID:            "client1",
			Confidential:  false,
			RedirectURIs:  []string{"https://houbamzdar.cz/callback1.html"},
			RequirePKCE:   true,
			AuthMethod:    "none",
			GrantTypes:    []string{"authorization_code"},
			ResponseTypes: []string{"code"},
		},
		{
			ID:            "client2",
			Confidential:  false,
			RedirectURIs:  []string{"https://houbamzdar.cz/callback2.html"},
			RequirePKCE:   true,
			AuthMethod:    "none",
			GrantTypes:    []string{"authorization_code"},
			ResponseTypes: []string{"code"},
		},
		{
			ID:            "mushroom-bff",
			Confidential:  true,
			RequirePKCE:   true,
			AuthMethod:    "basic",
			GrantTypes:    []string{"authorization_code", "refresh_token"},
			ResponseTypes: []string{"code"},
			RedirectURIs:  []string{"https://api.houbamzdar.cz/auth/callback"},
			Scopes:        []string{oidc.ScopeOpenID, oidc.ScopeProfile, oidc.ScopeEmail, oidc.ScopePhone, oidc.ScopeOfflineAccess},
		},
	}

	out := make(map[string]*StaticClient, len(clients))
	for _, cfg := range clients {
		client, _ := buildClient(cfg)
		out[client.id] = client
	}
	return out
}

func buildClient(cfg clientConfig) (*StaticClient, error) {
	cfg.ID = strings.TrimSpace(cfg.ID)
	if cfg.ID == "" {
		return nil, errors.New("id is required")
	}
	if len(cfg.RedirectURIs) == 0 {
		return nil, errors.New("at least one redirect_uri is required")
	}

	authMethod, err := parseAuthMethod(cfg.AuthMethod)
	if err != nil {
		return nil, err
	}
	if !cfg.Confidential {
		authMethod = oidc.AuthMethodNone
		cfg.Secrets = nil
	}
	if cfg.Confidential && len(cfg.Secrets) == 0 && strings.EqualFold(cfg.ID, "mushroom-bff") {
		if secret := strings.TrimSpace(os.Getenv("OIDC_CLIENT_MUSHROOM_BFF_SECRET")); secret != "" {
			cfg.Secrets = []string{secret}
		}
	}
	if cfg.Confidential && authMethod == oidc.AuthMethodNone {
		return nil, errors.New("confidential client cannot use auth_method none")
	}
	if cfg.Confidential && len(cfg.Secrets) == 0 {
		return nil, errors.New("confidential client requires secrets")
	}

	responseTypes, err := parseResponseTypes(cfg.ResponseTypes)
	if err != nil {
		return nil, err
	}
	grantTypes, err := parseGrantTypes(cfg.GrantTypes)
	if err != nil {
		return nil, err
	}
	allowedScopes := parseAllowedScopes(cfg.Scopes)

	return &StaticClient{
		id:              cfg.ID,
		secrets:         cfg.Secrets,
		redirectURIs:    cfg.RedirectURIs,
		responseTypes:   responseTypes,
		grantTypes:      grantTypes,
		applicationType: op.ApplicationTypeWeb,
		authMethod:      authMethod,
		requirePKCE:     cfg.RequirePKCE,
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

func sortedClientIDs(clients map[string]*StaticClient) []string {
	ids := make([]string, 0, len(clients))
	for id := range clients {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func (s *MemStorage) Health(ctx context.Context) error {
	return s.redis.Ping(ctx).Err()
}

func (s *MemStorage) CreateAuthRequest(ctx context.Context, authRequest *oidc.AuthRequest, clientID string) (op.AuthRequest, error) {
	if clientID == "" && authRequest != nil {
		clientID = authRequest.ClientID
	}
	client, ok := s.clients[clientID]
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
	return s.saveAuthRequest(ctx, req, oidcStateTTL)
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

func (s *MemStorage) CreateAccessToken(ctx context.Context, request op.TokenRequest) (string, time.Time, error) {
	return "access_token_" + request.GetSubject(), time.Now().Add(1 * time.Hour), nil
}

func (s *MemStorage) CreateAccessAndRefreshTokens(ctx context.Context, request op.TokenRequest, currentRefreshToken string) (accessTokenID string, newRefreshTokenID string, expiration time.Time, err error) {
	return "at_" + request.GetSubject(), "rt_" + request.GetSubject(), time.Now().Add(1 * time.Hour), nil
}

func (s *MemStorage) TokenRequestByRefreshToken(ctx context.Context, refreshTokenID string) (op.RefreshTokenRequest, error) {
	return nil, fmt.Errorf("not implemented")
}

func (s *MemStorage) TerminateSession(ctx context.Context, userID, clientID string) error {
	return nil
}

func (s *MemStorage) RevokeToken(ctx context.Context, token, userID, clientID string) *oidc.Error {
	return nil
}

func (s *MemStorage) GetRefreshTokenInfo(ctx context.Context, clientID, token string) (userID, tokenID string, err error) {
	return "", "", fmt.Errorf("not implemented")
}

func (s *MemStorage) GetClientByClientID(ctx context.Context, clientID string) (op.Client, error) {
	if client, ok := s.clients[clientID]; ok {
		return client, nil
	}
	return nil, fmt.Errorf("client not found")
}

func (s *MemStorage) AuthorizeClientIDSecret(ctx context.Context, clientID, clientSecret string) error {
	client, ok := s.clients[clientID]
	if !ok {
		return fmt.Errorf("client not found")
	}
	if client.authMethod == oidc.AuthMethodNone {
		return nil
	}
	for _, secret := range client.secrets {
		if secret == clientSecret {
			return nil
		}
	}
	return fmt.Errorf("invalid secret")
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
		                        email := user.Email
		                        if user.ProfileEmail != "" {
		                                email = user.ProfileEmail
		                        }
		                        userinfo.Email = email
		                        userinfo.EmailVerified = oidc.Bool(user.EmailVerified)		case oidc.ScopePhone:
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
		                        email := user.Email
		                        if user.ProfileEmail != "" {
		                                email = user.ProfileEmail
		                        }
		                        claims["email"] = email
		                        claims["email_verified"] = user.EmailVerified		case oidc.ScopePhone:
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
	secrets         []string
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
