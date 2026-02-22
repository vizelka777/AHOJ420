package oidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/houbamydar/AHOJ420/internal/store"
	"github.com/redis/go-redis/v9"
	"github.com/zitadel/oidc/v3/pkg/op"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

type Provider struct {
	op.OpenIDProvider
	Storage op.Storage
}

func NewProvider(baseURL string, s *store.Store, r *redis.Client) (*Provider, error) {
	userStore := &UserStore{store: s}
	storage := NewMemStorage(userStore)

	// 1. Load current signing key (or fallback ephemeral for dev)
	currentKeyID := os.Getenv("OIDC_KEY_ID")
	if currentKeyID == "" {
		currentKeyID = "sig_key_current"
	}

	var currentKey *rsa.PrivateKey
	var err error
	currentKeyPath := os.Getenv("OIDC_PRIVKEY_PATH")
	if currentKeyPath != "" {
		currentKey, err = loadRSAPrivateKey(currentKeyPath)
		if err != nil {
			log.Printf("Failed to load current OIDC key from %s: %v", currentKeyPath, err)
		}
	}

	if currentKey == nil {
		log.Println("WARNING: Generating ephemeral RSA key. All tokens will be invalid after restart.")
		currentKey, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, err
		}
	}

	keys := []*SimpleKey{
		{
			id:  currentKeyID,
			alg: jose.RS256,
			use: "sig",
			key: currentKey,
		},
	}

	// 2. Optionally load previous key for zero-downtime rotation validation.
	prevKeyPath := os.Getenv("OIDC_PREV_PRIVKEY_PATH")
	if prevKeyPath != "" {
		prevKeyID := os.Getenv("OIDC_PREV_KEY_ID")
		if prevKeyID == "" {
			prevKeyID = "sig_key_previous"
		}
		prevKey, prevErr := loadRSAPrivateKey(prevKeyPath)
		if prevErr != nil {
			log.Printf("Failed to load previous OIDC key from %s: %v", prevKeyPath, prevErr)
		} else {
			keys = append(keys, &SimpleKey{
				id:  prevKeyID,
				alg: jose.RS256,
				use: "sig",
				key: prevKey,
			})
		}
	}

	// 3. Cookie crypto key
	cryptoKeyStr := os.Getenv("OIDC_CRYPTO_KEY")
	if len(cryptoKeyStr) < 32 {
		log.Println("WARNING: OIDC_CRYPTO_KEY not set or too short. Using insecure default.")
		cryptoKeyStr = "secret_cookie_crypto_key_12345678" // Must be 32 bytes for some algs
	}

	config := &op.Config{
		CryptoKey:                sha256.Sum256([]byte(cryptoKeyStr)),
		DefaultLogoutRedirectURI: baseURL,
		CodeMethodS256:           true,
		AuthMethodPost:           true,
		AuthMethodPrivateKeyJWT:  true,
		GrantTypeRefreshToken:    true,
		SupportedScopes:          []string{oidc.ScopeOpenID, oidc.ScopeProfile, oidc.ScopeEmail, oidc.ScopePhone},
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

// SetAuthRequestDone marks an auth request as authenticated and assigns a subject.
func (p *Provider) SetAuthRequestDone(id, userID string) error {
	if s, ok := p.Storage.(*MemStorage); ok {
		return s.SetAuthRequestDone(id, userID)
	}
	return fmt.Errorf("storage does not support SetAuthRequestDone")
}

// UserStore adapts our DB store to OIDC needs
type UserStore struct {
	store *store.Store
}

// SimpleKey implements op.SigningKey and op.Key
type SimpleKey struct {
    id string
    alg jose.SignatureAlgorithm
    use string
    key interface{}
}
func (k *SimpleKey) ID() string { return k.id }
func (k *SimpleKey) Algorithm() jose.SignatureAlgorithm { return k.alg }
func (k *SimpleKey) SignatureAlgorithm() jose.SignatureAlgorithm { return k.alg }
func (k *SimpleKey) Use() string { return k.use }
func (k *SimpleKey) Key() interface{} { return k.key }


// A concrete AuthRequest to implement the interface
type SimpleAuthRequest struct {
    ID string
    Subject string
    DoneVal bool
    ACR string
    AMR []string
    AuthTime time.Time
    
    // Request params
    Scopes []string
    ResponseType oidc.ResponseType
    RedirectURI string
    State string
    Nonce string
    CodeChallenge string
    CodeChallengeMethod oidc.CodeChallengeMethod
    Audience []string
    ClientID string
}

func (r *SimpleAuthRequest) GetID() string { return r.ID }
func (r *SimpleAuthRequest) GetACR() string { return r.ACR }
func (r *SimpleAuthRequest) GetSubject() string { return r.Subject }
func (r *SimpleAuthRequest) Done() bool { return r.DoneVal }
func (r *SimpleAuthRequest) GetAMR() []string { return r.AMR }
func (r *SimpleAuthRequest) GetAuthTime() time.Time { return r.AuthTime }
func (r *SimpleAuthRequest) GetAudience() []string { return r.Audience }
func (r *SimpleAuthRequest) GetScopes() []string { return r.Scopes }
func (r *SimpleAuthRequest) GetResponseType() oidc.ResponseType { return r.ResponseType }
func (r *SimpleAuthRequest) GetRedirectURI() string { return r.RedirectURI }
func (r *SimpleAuthRequest) GetState() string { return r.State }
func (r *SimpleAuthRequest) GetResponseMode() oidc.ResponseMode { return "" }
func (r *SimpleAuthRequest) GetNonce() string { return r.Nonce }
func (r *SimpleAuthRequest) GetCodeChallenge() *oidc.CodeChallenge {
    return &oidc.CodeChallenge{
        Challenge: r.CodeChallenge,
        Method:    r.CodeChallengeMethod,
    }
}
func (r *SimpleAuthRequest) GetClientID() string { return r.ClientID }


type MemStorage struct {
	clients      map[string]*StaticClient
	authRequests map[string]*SimpleAuthRequest
	codes        map[string]*SimpleAuthRequest
	userStore *UserStore
    signingKey *SimpleKey
	keys       []*SimpleKey
}

func NewMemStorage(us *UserStore) *MemStorage {
	st := &MemStorage{
		clients: map[string]*StaticClient{
			"test": {
				id:           "test",
                secrets:      []string{"secret"},
				redirectURIs: []string{"https://oauth.pstmn.io/v1/callback", "https://jwt.io", "http://localhost:3000/api/auth/callback/custom"},
				responseTypes: []oidc.ResponseType{oidc.ResponseTypeCode},
				grantTypes:    []oidc.GrantType{oidc.GrantTypeCode},
                applicationType: op.ApplicationTypeWeb,
                authMethod: oidc.AuthMethodBasic,
			},
			"postman": {
				id:           "postman",
				secrets:      []string{"secret"},
				redirectURIs: []string{"https://oauth.pstmn.io/v1/callback"},
				responseTypes: []oidc.ResponseType{oidc.ResponseTypeCode},
				grantTypes:    []oidc.GrantType{oidc.GrantTypeCode},
				applicationType: op.ApplicationTypeWeb,
				authMethod: oidc.AuthMethodBasic,
			},
			"houbamzdar": {
				id:           "houbamzdar",
				secrets:      []string{"secret"},
				redirectURIs: []string{"https://houbamzdar.cz/callback.html"},
				responseTypes: []oidc.ResponseType{oidc.ResponseTypeCode},
				grantTypes:    []oidc.GrantType{oidc.GrantTypeCode},
				applicationType: op.ApplicationTypeWeb,
				authMethod: oidc.AuthMethodBasic,
			},
			"client1": {
				id:           "client1",
				secrets:      []string{"secret"},
				redirectURIs: []string{"https://houbamzdar.cz/callback1.html"},
				responseTypes: []oidc.ResponseType{oidc.ResponseTypeCode},
				grantTypes:    []oidc.GrantType{oidc.GrantTypeCode},
				applicationType: op.ApplicationTypeWeb,
				authMethod: oidc.AuthMethodBasic,
			},
			"client2": {
				id:           "client2",
				secrets:      []string{"secret"},
				redirectURIs: []string{"https://houbamzdar.cz/callback2.html"},
				responseTypes: []oidc.ResponseType{oidc.ResponseTypeCode},
				grantTypes:    []oidc.GrantType{oidc.GrantTypeCode},
				applicationType: op.ApplicationTypeWeb,
				authMethod: oidc.AuthMethodBasic,
			},
		},
		authRequests: make(map[string]*SimpleAuthRequest),
		codes:        make(map[string]*SimpleAuthRequest),
		userStore:    us,
	}
	log.Printf("OIDC clients: test, postman, houbamzdar")
	return st
}

func (s *MemStorage) Health(ctx context.Context) error { return nil }

func (s *MemStorage) CreateAuthRequest(ctx context.Context, authRequest *oidc.AuthRequest, clientID string) (op.AuthRequest, error) {
    subject := ""
    if uid, ok := ctx.Value("user_id").(string); ok {
        subject = uid
    }
    if clientID == "" && authRequest != nil {
        clientID = authRequest.ClientID
    }

    req := &SimpleAuthRequest{
        ID:          fmt.Sprintf("auth_%d", time.Now().UnixNano()),
        Subject:     subject, 
        ACR:         "",
        AMR:         nil,
        AuthTime:    time.Time{},
        
        Scopes:      authRequest.Scopes,
        ResponseType: authRequest.ResponseType,
        RedirectURI: authRequest.RedirectURI,
        State:       authRequest.State,
        Nonce:       authRequest.Nonce,
        CodeChallenge: authRequest.CodeChallenge,
        CodeChallengeMethod: authRequest.CodeChallengeMethod,
        ClientID:    clientID,
        Audience:    []string{clientID}, 
    }
    if subject != "" {
        req.DoneVal = true
        req.AuthTime = time.Now()
    }
	s.authRequests[req.ID] = req
	return req, nil
}

func (s *MemStorage) AuthRequestByID(ctx context.Context, id string) (op.AuthRequest, error) {
	if req, ok := s.authRequests[id]; ok {
		return req, nil
	}
	return nil, fmt.Errorf("auth request not found")
}

func (s *MemStorage) AuthRequestByCode(ctx context.Context, code string) (op.AuthRequest, error) {
	if req, ok := s.codes[code]; ok {
		return req, nil
	}
	return nil, fmt.Errorf("auth request not found code")
}

func (s *MemStorage) SaveAuthCode(ctx context.Context, id string, code string) error {
	if req, ok := s.authRequests[id]; ok {
		s.codes[code] = req
		return nil
	}
	return fmt.Errorf("auth request not found for code save")
}

func (s *MemStorage) DeleteAuthRequest(ctx context.Context, id string) error {
	delete(s.authRequests, id)
	return nil
}

// SetAuthRequestDone sets subject and marks the auth request as done.
func (s *MemStorage) SetAuthRequestDone(id, userID string) error {
	if req, ok := s.authRequests[id]; ok {
		req.Subject = userID
		req.DoneVal = true
		req.AuthTime = time.Now()
		return nil
	}
	return fmt.Errorf("auth request not found")
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

func (s *MemStorage) TerminateSession(ctx context.Context, userID string, clientID string) error {
	return nil
}

func (s *MemStorage) RevokeToken(ctx context.Context, token string, userID string, clientID string) *oidc.Error {
	return nil
}

func (s *MemStorage) GetRefreshTokenInfo(ctx context.Context, clientID string, token string) (userID string, tokenID string, err error) {
     return "", "", fmt.Errorf("not implemented")
}

func (s *MemStorage) GetClientByClientID(ctx context.Context, clientID string) (op.Client, error) {
	log.Printf("GetClientByClientID called with: %q", clientID)
	if client, ok := s.clients[clientID]; ok {
		return client, nil
	}
	log.Printf("Known client IDs: %v", keys(s.clients))
	return nil, fmt.Errorf("client not found")
}

func keys(m map[string]*StaticClient) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func (s *MemStorage) AuthorizeClientIDSecret(ctx context.Context, clientID, clientSecret string) error {
	client, ok := s.clients[clientID]
	if !ok {
		return fmt.Errorf("client not found")
	}
	for _, s := range client.secrets {
		if s == clientSecret {
			return nil
		}
	}
	return fmt.Errorf("invalid secret")
}

func (s *MemStorage) SetUserinfoFromScopes(ctx context.Context, userinfo *oidc.UserInfo, userID, clientID string, scopes []string) error {
	user, err := s.userStore.store.GetUser(userID)
	if err != nil {
		return err
	}
	userinfo.Subject = user.ID
	for _, scope := range scopes {
		switch scope {
		case oidc.ScopeProfile:
			if user.ShareProfile {
				userinfo.Name = user.DisplayName
				userinfo.PreferredUsername = user.DisplayName
			}
		case oidc.ScopeEmail:
			if user.ShareProfile && user.ProfileEmail != "" {
				userinfo.Email = user.ProfileEmail
				userinfo.EmailVerified = oidc.Bool(user.EmailVerified)
			}
		case oidc.ScopePhone:
			if user.ShareProfile && user.Phone != "" {
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
	user, err := s.userStore.store.GetUser(userID)
	if err != nil {
		return nil, err
	}

	claims := map[string]interface{}{}
	if !user.ShareProfile {
		return claims, nil
	}

	for _, scope := range scopes {
		switch scope {
		case oidc.ScopeProfile:
			claims["name"] = user.DisplayName
			claims["preferred_username"] = user.DisplayName
		case oidc.ScopeEmail:
			if user.ProfileEmail != "" {
				claims["email"] = user.ProfileEmail
				claims["email_verified"] = user.EmailVerified
			}
		case oidc.ScopePhone:
			if user.Phone != "" {
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
		keys = append(keys, key)
	}
	return keys, nil
}

// StaticClient implementation
type StaticClient struct {
    id string
    secrets []string
    redirectURIs []string
    responseTypes []oidc.ResponseType
    grantTypes []oidc.GrantType
    applicationType op.ApplicationType
    authMethod oidc.AuthMethod
}

func (c *StaticClient) GetID() string { return c.id }
func (c *StaticClient) RedirectURIs() []string { return c.redirectURIs }
func (c *StaticClient) PostLogoutRedirectURIs() []string { return []string{} }
func (c *StaticClient) ApplicationType() op.ApplicationType { return c.applicationType }
func (c *StaticClient) AuthMethod() oidc.AuthMethod { return c.authMethod }
func (c *StaticClient) ResponseTypes() []oidc.ResponseType { return c.responseTypes }
func (c *StaticClient) GrantTypes() []oidc.GrantType { return c.grantTypes }
func (c *StaticClient) LoginURL(id string) string {
	// redirect to login UI and include auth_request_id for callback completion
	return "/?mode=login&auth_request_id=" + id + "&return_to=%2Fauthorize%2Fcallback%3Fid%3D" + id
}
func (c *StaticClient) AccessTokenType() op.AccessTokenType { return op.AccessTokenTypeBearer }
func (c *StaticClient) IDTokenLifetime() time.Duration { return 1 * time.Hour }
func (c *StaticClient) DevMode() bool { return true }
func (c *StaticClient) RestrictAdditionalIdTokenScopes() func(scopes []string) []string { return func(s []string) []string { return s } }
func (c *StaticClient) RestrictAdditionalAccessTokenScopes() func(scopes []string) []string { return func(s []string) []string { return s } }
func (c *StaticClient) IsScopeAllowed(scope string) bool { return true }
func (c *StaticClient) IDTokenUserinfoClaimsAssertion() bool { return false }
func (c *StaticClient) ClockSkew() time.Duration { return 0 }
