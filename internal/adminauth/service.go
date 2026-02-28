package adminauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/houbamydar/AHOJ420/internal/admin"
	"github.com/houbamydar/AHOJ420/internal/store"
	"github.com/labstack/echo/v4"
	"github.com/redis/go-redis/v9"
)

const (
	adminSessionCookieName       = "admin_session"
	adminRegSessionCookieName    = "admin_reg_session_id"
	adminLoginSessionCookieName  = "admin_login_session_id"
	adminAddPasskeyCookieName    = "admin_passkey_add_session_id"
	adminReauthSessionCookieName = "admin_reauth_session_id"
	adminInviteSessionCookieName = "admin_invite_session_id"
	userSessionKeyPrefix         = "sess:"
	userRecoveryKeyPrefix        = "recovery:"
	userSessionMetaPrefix        = "sessmeta:"
	userSessionListPrefix        = "sesslist:"
	userSessionAllPrefix         = "sessall:"
	userSessionDevicePrefix      = "sessdev:"
)

var (
	errAdminBootstrapClosed = errors.New("admin bootstrap is not available")
	errAdminSessionInvalid  = errors.New("admin session is invalid")
)

type adminStore interface {
	CountAdminUsers() (int, error)
	CountAdminCredentials() (int, error)
	CreateAdminUser(login string, displayName string) (*store.AdminUser, error)
	SetAdminUserRole(id string, role string) error
	GetAdminUser(id string) (*store.AdminUser, error)
	GetAdminUserByLogin(login string) (*store.AdminUser, error)
	GetAdminUserByCredentialID(credentialID []byte) (*store.AdminUser, error)
	AddAdminCredential(adminUserID string, credential *webauthn.Credential) error
	UpdateAdminCredential(credential *webauthn.Credential) error
	ListAdminCredentials(adminUserID string) ([]store.AdminCredentialInfo, error)
	DeleteAdminCredential(adminUserID string, credentialID int64) error
	CountAdminCredentialsForUser(adminUserID string) (int, error)
	GetActiveAdminInviteByTokenHash(ctx context.Context, tokenHash string) (*store.AdminInvite, error)
	MarkAdminInviteUsed(ctx context.Context, inviteID int64, usedAt time.Time) error
	CreateAdminAuditEntry(ctx context.Context, entry store.AdminAuditEntry) error
}

type webAuthnAPI interface {
	BeginRegistration(user webauthn.User, opts ...webauthn.RegistrationOption) (*protocol.CredentialCreation, *webauthn.SessionData, error)
	FinishRegistration(user webauthn.User, session webauthn.SessionData, response *http.Request) (*webauthn.Credential, error)
	BeginDiscoverableLogin(opts ...webauthn.LoginOption) (*protocol.CredentialAssertion, *webauthn.SessionData, error)
	FinishDiscoverableLogin(handler webauthn.DiscoverableUserHandler, session webauthn.SessionData, response *http.Request) (*webauthn.Credential, error)
}

type Service struct {
	wa                 webAuthnAPI
	store              adminStore
	stateStore         adminSessionStateStore
	bootstrapLogin     string
	sessionIdleTTL     time.Duration
	sessionAbsoluteTTL time.Duration
	reauthTTL          time.Duration
}

type registrationSession struct {
	AdminUserID string               `json:"admin_user_id"`
	Session     webauthn.SessionData `json:"session"`
}

type reauthSession struct {
	AdminUserID    string               `json:"admin_user_id"`
	AdminSessionID string               `json:"admin_session_id"`
	Session        webauthn.SessionData `json:"session"`
}

type inviteRegistrationSession struct {
	InviteID    int64                `json:"invite_id"`
	AdminUserID string               `json:"admin_user_id"`
	TokenHash   string               `json:"token_hash"`
	Session     webauthn.SessionData `json:"session"`
}

type userDeviceSessionMeta struct {
	SessionID    string `json:"session_id"`
	UserID       string `json:"user_id"`
	DeviceID     string `json:"device_id"`
	CredentialID string `json:"credential_id"`
	UserAgent    string `json:"user_agent"`
	IP           string `json:"ip"`
	CreatedAtUTC int64  `json:"created_at_utc"`
	LastSeenUTC  int64  `json:"last_seen_utc"`
}

type sessionRecord struct {
	AdminUserID     string `json:"admin_user_id"`
	CreatedAtUTC    int64  `json:"created_at_utc"`
	LastSeenAtUTC   int64  `json:"last_seen_at_utc"`
	RecentAuthAtUTC int64  `json:"recent_auth_at_utc"`
	RemoteIP        string `json:"remote_ip"`
	UserAgent       string `json:"user_agent"`
}

type adminSessionStateStore interface {
	Set(ctx context.Context, key string, value []byte, ttl time.Duration) error
	Get(ctx context.Context, key string) ([]byte, error)
	Del(ctx context.Context, key string) error
	Keys(ctx context.Context, pattern string) ([]string, error)
	TTL(ctx context.Context, key string) (time.Duration, error)
}

type redisAdminSessionStateStore struct {
	client *redis.Client
}

func newRedisAdminSessionStateStore(client *redis.Client) (*redisAdminSessionStateStore, error) {
	if client == nil {
		return nil, fmt.Errorf("adminauth requires redis client")
	}
	return &redisAdminSessionStateStore{client: client}, nil
}

func (s *redisAdminSessionStateStore) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	return s.client.Set(ctx, key, value, ttl).Err()
}

func (s *redisAdminSessionStateStore) Get(ctx context.Context, key string) ([]byte, error) {
	return s.client.Get(ctx, key).Bytes()
}

func (s *redisAdminSessionStateStore) Del(ctx context.Context, key string) error {
	return s.client.Del(ctx, key).Err()
}

func (s *redisAdminSessionStateStore) Keys(ctx context.Context, pattern string) ([]string, error) {
	out := make([]string, 0, 16)
	iter := s.client.Scan(ctx, 0, strings.TrimSpace(pattern), 0).Iterator()
	for iter.Next(ctx) {
		out = append(out, strings.TrimSpace(iter.Val()))
	}
	if err := iter.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *redisAdminSessionStateStore) TTL(ctx context.Context, key string) (time.Duration, error) {
	return s.client.TTL(ctx, strings.TrimSpace(key)).Result()
}

func New(s *store.Store, r *redis.Client) (*Service, error) {
	if s == nil {
		return nil, fmt.Errorf("adminauth requires store")
	}
	rpID := strings.TrimSpace(os.Getenv("RP_ID"))
	rpOrigins := collectAdminRPOrigins(
		strings.TrimSpace(os.Getenv("RP_ORIGIN")),
		strings.TrimSpace(os.Getenv("ADMIN_RP_ORIGINS")),
		strings.TrimSpace(os.Getenv("ADMIN_API_HOST")),
	)
	if rpID == "" || len(rpOrigins) == 0 {
		return nil, fmt.Errorf("adminauth requires RP_ID and at least one admin RP origin")
	}

	wa, err := webauthn.New(&webauthn.Config{
		RPDisplayName: "Ahoj420 Admin",
		RPID:          rpID,
		RPOrigins:     rpOrigins,
	})
	if err != nil {
		return nil, err
	}

	idleTTL := 30 * time.Minute
	if parsed := parsePositiveInt(strings.TrimSpace(os.Getenv("ADMIN_SESSION_IDLE_MINUTES"))); parsed > 0 {
		idleTTL = time.Duration(parsed) * time.Minute
	}

	absoluteTTL := 12 * time.Hour
	if parsed := parsePositiveInt(strings.TrimSpace(os.Getenv("ADMIN_SESSION_ABSOLUTE_HOURS"))); parsed > 0 {
		absoluteTTL = time.Duration(parsed) * time.Hour
	}

	reauthTTL := 5 * time.Minute
	if parsed := parsePositiveInt(strings.TrimSpace(os.Getenv("ADMIN_REAUTH_TTL_MINUTES"))); parsed > 0 {
		reauthTTL = time.Duration(parsed) * time.Minute
	}
	stateStore, err := newRedisAdminSessionStateStore(r)
	if err != nil {
		return nil, err
	}

	return &Service{
		wa:                 wa,
		store:              s,
		stateStore:         stateStore,
		bootstrapLogin:     strings.ToLower(strings.TrimSpace(os.Getenv("ADMIN_BOOTSTRAP_LOGIN"))),
		sessionIdleTTL:     idleTTL,
		sessionAbsoluteTTL: absoluteTTL,
		reauthTTL:          reauthTTL,
	}, nil
}

func RegisterRoutes(group *echo.Group, svc *Service) {
	group.POST("/register/begin", svc.BeginRegistration)
	group.POST("/register/finish", svc.FinishRegistration)
	group.POST("/login/begin", svc.BeginLogin)
	group.POST("/login/finish", svc.FinishLogin)
	group.POST("/invite/register/begin", svc.BeginInviteRegistration)
	group.POST("/invite/register/finish", svc.FinishInviteRegistration)
	group.POST("/reauth/begin", svc.BeginReauth)
	group.POST("/reauth/finish", svc.FinishReauth)
	group.POST("/passkeys/register/begin", svc.BeginAddPasskey)
	group.POST("/passkeys/register/finish", svc.FinishAddPasskey)
	group.POST("/logout", svc.Logout)
}

func (s *Service) AttachSessionActorMiddleware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			_, _ = s.SessionUser(c)
			return next(c)
		}
	}
}

func (s *Service) SessionUser(c echo.Context) (*store.AdminUser, bool) {
	adminUser, _, err := s.sessionUser(c)
	if err != nil || adminUser == nil {
		return nil, false
	}
	admin.SetAdminActor(c, "admin_user", adminUser.ID)
	admin.SetAdminActorRole(c, adminUser.Role)
	c.Set("admin_user", adminUser)
	c.Set("admin_user_role", strings.TrimSpace(strings.ToLower(adminUser.Role)))
	return adminUser, true
}

func (s *Service) RequireSessionMiddleware(loginPath string) echo.MiddlewareFunc {
	target := strings.TrimSpace(loginPath)
	if target == "" {
		target = "/admin/login"
	}

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			if _, ok := s.SessionUser(c); ok {
				return next(c)
			}

			return c.Redirect(http.StatusFound, target)
		}
	}
}

func (s *Service) BeginRegistration(c echo.Context) error {
	adminUser, err := s.ensureBootstrapUser()
	if err != nil {
		s.auditAuth(c, "admin.auth.register.failure", false, "bootstrap", "", map[string]any{"error": err.Error()})
		if errors.Is(err, errAdminBootstrapClosed) {
			return c.JSON(http.StatusConflict, map[string]string{"message": "bootstrap registration is unavailable"})
		}
		if strings.Contains(strings.ToLower(err.Error()), "bootstrap login") {
			return c.JSON(http.StatusServiceUnavailable, map[string]string{"message": "admin bootstrap login is not configured"})
		}
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "failed to prepare admin bootstrap"})
	}

	options, session, err := s.wa.BeginRegistration(adminUser,
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			ResidentKey:      protocol.ResidentKeyRequirementRequired,
			UserVerification: protocol.VerificationRequired,
		}),
	)
	if err != nil {
		s.auditAuth(c, "admin.auth.register.failure", false, "admin_user", adminUser.ID, map[string]any{"error": "begin_registration_failed"})
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "failed to begin registration"})
	}

	sessionID, err := newRandomID()
	if err != nil {
		s.auditAuth(c, "admin.auth.register.failure", false, "admin_user", adminUser.ID, map[string]any{"error": "session_id_generation_failed"})
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "failed to create registration session"})
	}

	payload, err := json.Marshal(registrationSession{
		AdminUserID: adminUser.ID,
		Session:     *session,
	})
	if err != nil {
		s.auditAuth(c, "admin.auth.register.failure", false, "admin_user", adminUser.ID, map[string]any{"error": "session_encode_failed"})
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "failed to encode registration session"})
	}
	if err := s.stateStore.Set(c.Request().Context(), adminRegRedisKey(sessionID), payload, 5*time.Minute); err != nil {
		s.auditAuth(c, "admin.auth.register.failure", false, "admin_user", adminUser.ID, map[string]any{"error": "session_store_failed"})
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "failed to store registration session"})
	}

	setCookie(c, &http.Cookie{
		Name:     adminRegSessionCookieName,
		Value:    sessionID,
		Path:     "/admin/auth",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   300,
	})

	return c.JSON(http.StatusOK, options)
}

func (s *Service) FinishRegistration(c echo.Context) error {
	regCookie, err := c.Cookie(adminRegSessionCookieName)
	if err != nil || strings.TrimSpace(regCookie.Value) == "" {
		s.auditAuth(c, "admin.auth.register.failure", false, "bootstrap", "", map[string]any{"error": "missing_registration_cookie"})
		return c.JSON(http.StatusBadRequest, map[string]string{"message": "registration session is missing"})
	}

	key := adminRegRedisKey(strings.TrimSpace(regCookie.Value))
	payload, err := s.stateStore.Get(c.Request().Context(), key)
	if err != nil {
		s.auditAuth(c, "admin.auth.register.failure", false, "bootstrap", "", map[string]any{"error": "registration_session_expired"})
		clearCookie(c, adminRegSessionCookieName, "/admin/auth")
		return c.JSON(http.StatusBadRequest, map[string]string{"message": "registration session expired"})
	}
	_ = s.stateStore.Del(c.Request().Context(), key)
	clearCookie(c, adminRegSessionCookieName, "/admin/auth")

	var reg registrationSession
	if err := json.Unmarshal(payload, &reg); err != nil {
		s.auditAuth(c, "admin.auth.register.failure", false, "bootstrap", "", map[string]any{"error": "registration_session_invalid"})
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "registration session is invalid"})
	}

	adminUser, err := s.store.GetAdminUser(reg.AdminUserID)
	if err != nil {
		s.auditAuth(c, "admin.auth.register.failure", false, "bootstrap", reg.AdminUserID, map[string]any{"error": "admin_user_not_found"})
		return c.JSON(http.StatusBadRequest, map[string]string{"message": "admin user not found"})
	}
	if !adminUser.Enabled {
		s.auditAuth(c, "admin.auth.register.failure", false, "admin_user", adminUser.ID, map[string]any{"error": "admin_user_disabled"})
		return c.JSON(http.StatusForbidden, map[string]string{"message": "admin user is disabled"})
	}

	credential, err := s.wa.FinishRegistration(adminUser, reg.Session, c.Request())
	if err != nil {
		s.auditAuth(c, "admin.auth.register.failure", false, "admin_user", adminUser.ID, map[string]any{"error": "finish_registration_failed"})
		return c.JSON(http.StatusBadRequest, map[string]string{"message": "registration verification failed"})
	}

	if err := s.store.AddAdminCredential(adminUser.ID, credential); err != nil {
		s.auditAuth(c, "admin.auth.register.failure", false, "admin_user", adminUser.ID, map[string]any{"error": "credential_store_failed"})
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "failed to store admin credential"})
	}

	if _, err := s.setSession(c, adminUser.ID); err != nil {
		s.auditAuth(c, "admin.auth.register.failure", false, "admin_user", adminUser.ID, map[string]any{"error": "session_create_failed"})
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "failed to create admin session"})
	}

	admin.SetAdminActor(c, "admin_user", adminUser.ID)
	s.auditAuth(c, "admin.auth.register.success", true, "admin_user", adminUser.ID, map[string]any{"login": adminUser.Login})
	return c.JSON(http.StatusOK, map[string]any{
		"status":       "ok",
		"admin_id":     adminUser.ID,
		"login":        adminUser.Login,
		"display_name": adminUser.DisplayName,
	})
}

func (s *Service) BeginLogin(c echo.Context) error {
	options, session, err := s.wa.BeginDiscoverableLogin(webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		s.auditAuth(c, "admin.auth.login.failure", false, "unknown", "", map[string]any{"error": "begin_login_failed"})
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "failed to begin admin login"})
	}

	sessionID, err := newRandomID()
	if err != nil {
		s.auditAuth(c, "admin.auth.login.failure", false, "unknown", "", map[string]any{"error": "session_id_generation_failed"})
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "failed to create login session"})
	}

	payload, _ := json.Marshal(*session)
	if err := s.stateStore.Set(c.Request().Context(), adminLoginRedisKey(sessionID), payload, 5*time.Minute); err != nil {
		s.auditAuth(c, "admin.auth.login.failure", false, "unknown", "", map[string]any{"error": "session_store_failed"})
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "failed to store login session"})
	}

	setCookie(c, &http.Cookie{
		Name:     adminLoginSessionCookieName,
		Value:    sessionID,
		Path:     "/admin/auth",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   300,
	})
	return c.JSON(http.StatusOK, options)
}

func (s *Service) FinishLogin(c echo.Context) error {
	loginCookie, err := c.Cookie(adminLoginSessionCookieName)
	if err != nil || strings.TrimSpace(loginCookie.Value) == "" {
		s.auditAuth(c, "admin.auth.login.failure", false, "unknown", "", map[string]any{"error": "missing_login_cookie"})
		return c.JSON(http.StatusBadRequest, map[string]string{"message": "login session is missing"})
	}

	key := adminLoginRedisKey(strings.TrimSpace(loginCookie.Value))
	sessionPayload, err := s.stateStore.Get(c.Request().Context(), key)
	if err != nil {
		s.auditAuth(c, "admin.auth.login.failure", false, "unknown", "", map[string]any{"error": "login_session_expired"})
		clearCookie(c, adminLoginSessionCookieName, "/admin/auth")
		return c.JSON(http.StatusBadRequest, map[string]string{"message": "login session expired"})
	}
	_ = s.stateStore.Del(c.Request().Context(), key)
	clearCookie(c, adminLoginSessionCookieName, "/admin/auth")

	var session webauthn.SessionData
	if err := json.Unmarshal(sessionPayload, &session); err != nil {
		s.auditAuth(c, "admin.auth.login.failure", false, "unknown", "", map[string]any{"error": "login_session_invalid"})
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "login session is invalid"})
	}

	var adminUser *store.AdminUser
	credential, err := s.wa.FinishDiscoverableLogin(func(rawID []byte, userHandle []byte) (webauthn.User, error) {
		var (
			u   *store.AdminUser
			err error
		)
		if len(userHandle) > 0 {
			u, err = s.store.GetAdminUser(string(userHandle))
		} else {
			u, err = s.store.GetAdminUserByCredentialID(rawID)
		}
		if err != nil {
			return nil, err
		}
		if !u.Enabled {
			return nil, store.ErrAdminUserDisabled
		}
		adminUser = u
		return u, nil
	}, session, c.Request())
	if err != nil {
		s.auditAuth(c, "admin.auth.login.failure", false, "unknown", "", map[string]any{"error": "finish_login_failed"})
		return c.JSON(http.StatusUnauthorized, map[string]string{"message": "admin login failed"})
	}

	if adminUser == nil {
		s.auditAuth(c, "admin.auth.login.failure", false, "unknown", "", map[string]any{"error": "admin_user_not_resolved"})
		return c.JSON(http.StatusUnauthorized, map[string]string{"message": "admin login failed"})
	}

	if err := s.store.UpdateAdminCredential(credential); err != nil && !errors.Is(err, store.ErrAdminCredentialNotFound) {
		s.auditAuth(c, "admin.auth.login.failure", false, "admin_user", adminUser.ID, map[string]any{"error": "credential_update_failed"})
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "failed to update admin credential"})
	}

	if _, err := s.setSession(c, adminUser.ID); err != nil {
		s.auditAuth(c, "admin.auth.login.failure", false, "admin_user", adminUser.ID, map[string]any{"error": "session_create_failed"})
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "failed to create admin session"})
	}

	admin.SetAdminActor(c, "admin_user", adminUser.ID)
	s.auditAuth(c, "admin.auth.login.success", true, "admin_user", adminUser.ID, map[string]any{"login": adminUser.Login})
	return c.JSON(http.StatusOK, map[string]any{
		"status":       "ok",
		"admin_id":     adminUser.ID,
		"login":        adminUser.Login,
		"display_name": adminUser.DisplayName,
	})
}

func (s *Service) BeginInviteRegistration(c echo.Context) error {
	token := readInviteToken(c)
	if token == "" {
		s.auditAdminAction(c, "admin.invite.accept.failure", false, "unknown", "", "admin_invite", "", map[string]any{"error": "missing_invite_token"})
		return c.JSON(http.StatusBadRequest, map[string]string{"message": "invite token is required"})
	}

	tokenHash := hashInviteToken(token)
	invite, err := s.store.GetActiveAdminInviteByTokenHash(c.Request().Context(), tokenHash)
	if err != nil {
		s.auditAdminAction(c, "admin.invite.accept.failure", false, "unknown", "", "admin_invite", "", map[string]any{"error": "invite_not_found"})
		return c.JSON(http.StatusBadRequest, map[string]string{"message": "invite is invalid or expired"})
	}

	adminUser, err := s.store.GetAdminUser(invite.AdminUserID)
	if err != nil {
		s.auditAdminAction(c, "admin.invite.accept.failure", false, "unknown", "", "admin_invite", strconv.FormatInt(invite.ID, 10), map[string]any{"error": "admin_user_not_found"})
		return c.JSON(http.StatusBadRequest, map[string]string{"message": "invite is invalid"})
	}
	if !adminUser.Enabled {
		s.auditAdminAction(c, "admin.invite.accept.failure", false, "admin_user", adminUser.ID, "admin_invite", strconv.FormatInt(invite.ID, 10), map[string]any{"error": "admin_user_disabled"})
		return c.JSON(http.StatusForbidden, map[string]string{"message": "admin user is disabled"})
	}

	credentialCount, err := s.store.CountAdminCredentialsForUser(adminUser.ID)
	if err != nil {
		s.auditAdminAction(c, "admin.invite.accept.failure", false, "admin_user", adminUser.ID, "admin_invite", strconv.FormatInt(invite.ID, 10), map[string]any{"error": "credential_count_failed"})
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "failed to verify invite target"})
	}
	if credentialCount > 0 {
		s.auditAdminAction(c, "admin.invite.accept.failure", false, "admin_user", adminUser.ID, "admin_invite", strconv.FormatInt(invite.ID, 10), map[string]any{"error": "admin_credentials_exist"})
		return c.JSON(http.StatusConflict, map[string]string{"message": "invite can only be used for admin without passkeys"})
	}

	options, session, err := s.wa.BeginRegistration(adminUser,
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			ResidentKey:      protocol.ResidentKeyRequirementRequired,
			UserVerification: protocol.VerificationRequired,
		}),
	)
	if err != nil {
		s.auditAdminAction(c, "admin.invite.accept.failure", false, "admin_user", adminUser.ID, "admin_invite", strconv.FormatInt(invite.ID, 10), map[string]any{"error": "begin_registration_failed"})
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "failed to begin invite registration"})
	}

	sessionID, err := newRandomID()
	if err != nil {
		s.auditAdminAction(c, "admin.invite.accept.failure", false, "admin_user", adminUser.ID, "admin_invite", strconv.FormatInt(invite.ID, 10), map[string]any{"error": "session_id_generation_failed"})
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "failed to create invite registration session"})
	}

	payload, err := json.Marshal(inviteRegistrationSession{
		InviteID:    invite.ID,
		AdminUserID: adminUser.ID,
		TokenHash:   tokenHash,
		Session:     *session,
	})
	if err != nil {
		s.auditAdminAction(c, "admin.invite.accept.failure", false, "admin_user", adminUser.ID, "admin_invite", strconv.FormatInt(invite.ID, 10), map[string]any{"error": "session_encode_failed"})
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "failed to encode invite session"})
	}
	if err := s.stateStore.Set(c.Request().Context(), adminInviteRedisKey(sessionID), payload, 5*time.Minute); err != nil {
		s.auditAdminAction(c, "admin.invite.accept.failure", false, "admin_user", adminUser.ID, "admin_invite", strconv.FormatInt(invite.ID, 10), map[string]any{"error": "session_store_failed"})
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "failed to store invite session"})
	}

	setCookie(c, &http.Cookie{
		Name:     adminInviteSessionCookieName,
		Value:    sessionID,
		Path:     "/admin/auth",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   300,
	})
	return c.JSON(http.StatusOK, options)
}

func (s *Service) FinishInviteRegistration(c echo.Context) error {
	token := readInviteToken(c)
	if token == "" {
		s.auditAdminAction(c, "admin.invite.accept.failure", false, "unknown", "", "admin_invite", "", map[string]any{"error": "missing_invite_token"})
		return c.JSON(http.StatusBadRequest, map[string]string{"message": "invite token is required"})
	}
	tokenHash := hashInviteToken(token)

	inviteCookie, err := c.Cookie(adminInviteSessionCookieName)
	if err != nil || strings.TrimSpace(inviteCookie.Value) == "" {
		s.auditAdminAction(c, "admin.invite.accept.failure", false, "unknown", "", "admin_invite", "", map[string]any{"error": "missing_invite_session_cookie"})
		return c.JSON(http.StatusBadRequest, map[string]string{"message": "invite registration session is missing"})
	}

	key := adminInviteRedisKey(strings.TrimSpace(inviteCookie.Value))
	payload, err := s.stateStore.Get(c.Request().Context(), key)
	if err != nil {
		clearCookie(c, adminInviteSessionCookieName, "/admin/auth")
		s.auditAdminAction(c, "admin.invite.accept.failure", false, "unknown", "", "admin_invite", "", map[string]any{"error": "invite_session_expired"})
		return c.JSON(http.StatusBadRequest, map[string]string{"message": "invite registration session expired"})
	}
	_ = s.stateStore.Del(c.Request().Context(), key)
	clearCookie(c, adminInviteSessionCookieName, "/admin/auth")

	var inviteSession inviteRegistrationSession
	if err := json.Unmarshal(payload, &inviteSession); err != nil {
		s.auditAdminAction(c, "admin.invite.accept.failure", false, "unknown", "", "admin_invite", "", map[string]any{"error": "invite_session_invalid"})
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "invite registration session is invalid"})
	}
	if !constantTimeEqual(inviteSession.TokenHash, tokenHash) {
		s.auditAdminAction(c, "admin.invite.accept.failure", false, "unknown", "", "admin_invite", strconv.FormatInt(inviteSession.InviteID, 10), map[string]any{"error": "invite_token_mismatch"})
		return c.JSON(http.StatusBadRequest, map[string]string{"message": "invite token mismatch"})
	}

	invite, err := s.store.GetActiveAdminInviteByTokenHash(c.Request().Context(), tokenHash)
	if err != nil {
		s.auditAdminAction(c, "admin.invite.accept.failure", false, "unknown", "", "admin_invite", strconv.FormatInt(inviteSession.InviteID, 10), map[string]any{"error": "invite_not_found"})
		return c.JSON(http.StatusBadRequest, map[string]string{"message": "invite is invalid or expired"})
	}
	if invite.ID != inviteSession.InviteID || strings.TrimSpace(invite.AdminUserID) != strings.TrimSpace(inviteSession.AdminUserID) {
		s.auditAdminAction(c, "admin.invite.accept.failure", false, "unknown", "", "admin_invite", strconv.FormatInt(invite.ID, 10), map[string]any{"error": "invite_session_mismatch"})
		return c.JSON(http.StatusBadRequest, map[string]string{"message": "invite session mismatch"})
	}

	adminUser, err := s.store.GetAdminUser(invite.AdminUserID)
	if err != nil {
		s.auditAdminAction(c, "admin.invite.accept.failure", false, "unknown", "", "admin_invite", strconv.FormatInt(invite.ID, 10), map[string]any{"error": "admin_user_not_found"})
		return c.JSON(http.StatusBadRequest, map[string]string{"message": "invite target admin is missing"})
	}
	if !adminUser.Enabled {
		s.auditAdminAction(c, "admin.invite.accept.failure", false, "admin_user", adminUser.ID, "admin_invite", strconv.FormatInt(invite.ID, 10), map[string]any{"error": "admin_user_disabled"})
		return c.JSON(http.StatusForbidden, map[string]string{"message": "admin user is disabled"})
	}

	credentialCount, err := s.store.CountAdminCredentialsForUser(adminUser.ID)
	if err != nil {
		s.auditAdminAction(c, "admin.invite.accept.failure", false, "admin_user", adminUser.ID, "admin_invite", strconv.FormatInt(invite.ID, 10), map[string]any{"error": "credential_count_failed"})
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "failed to verify invite target"})
	}
	if credentialCount > 0 {
		s.auditAdminAction(c, "admin.invite.accept.failure", false, "admin_user", adminUser.ID, "admin_invite", strconv.FormatInt(invite.ID, 10), map[string]any{"error": "admin_credentials_exist"})
		return c.JSON(http.StatusConflict, map[string]string{"message": "invite can only be used for admin without passkeys"})
	}

	credential, err := s.wa.FinishRegistration(adminUser, inviteSession.Session, c.Request())
	if err != nil {
		s.auditAdminAction(c, "admin.invite.accept.failure", false, "admin_user", adminUser.ID, "admin_invite", strconv.FormatInt(invite.ID, 10), map[string]any{"error": "finish_registration_failed"})
		return c.JSON(http.StatusBadRequest, map[string]string{"message": "invite registration verification failed"})
	}

	if err := s.store.AddAdminCredential(adminUser.ID, credential); err != nil {
		s.auditAdminAction(c, "admin.invite.accept.failure", false, "admin_user", adminUser.ID, "admin_invite", strconv.FormatInt(invite.ID, 10), map[string]any{"error": "credential_store_failed"})
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "failed to store admin credential"})
	}

	if err := s.store.MarkAdminInviteUsed(c.Request().Context(), invite.ID, time.Now().UTC()); err != nil {
		s.auditAdminAction(c, "admin.invite.accept.failure", false, "admin_user", adminUser.ID, "admin_invite", strconv.FormatInt(invite.ID, 10), map[string]any{"error": "invite_mark_used_failed"})
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "failed to mark invite as used"})
	}

	if _, err := s.setSession(c, adminUser.ID); err != nil {
		s.auditAdminAction(c, "admin.invite.accept.failure", false, "admin_user", adminUser.ID, "admin_invite", strconv.FormatInt(invite.ID, 10), map[string]any{"error": "session_create_failed"})
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "failed to create admin session"})
	}

	s.auditAdminAction(c, "admin.invite.accept.success", true, "admin_user", adminUser.ID, "admin_invite", strconv.FormatInt(invite.ID, 10), map[string]any{
		"invite_id":  invite.ID,
		"expires_at": invite.ExpiresAt.Format(time.RFC3339),
	})
	admin.SetAdminActor(c, "admin_user", adminUser.ID)
	return c.JSON(http.StatusOK, map[string]any{
		"status":       "ok",
		"admin_id":     adminUser.ID,
		"login":        adminUser.Login,
		"display_name": adminUser.DisplayName,
	})
}

func (s *Service) BeginReauth(c echo.Context) error {
	adminUser, currentSessionID, err := s.sessionUser(c)
	if err != nil || adminUser == nil {
		s.auditAdminAction(c, "admin.auth.reauth.failure", false, "unknown", "", "admin_session", "", map[string]any{"error": "missing_session"})
		return c.JSON(http.StatusUnauthorized, map[string]string{"message": "admin session is required"})
	}

	options, session, err := s.wa.BeginDiscoverableLogin(webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		s.auditAdminAction(c, "admin.auth.reauth.failure", false, "admin_user", adminUser.ID, "admin_session", currentSessionID, map[string]any{"error": "begin_reauth_failed"})
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "failed to begin admin re-auth"})
	}

	sessionID, err := newRandomID()
	if err != nil {
		s.auditAdminAction(c, "admin.auth.reauth.failure", false, "admin_user", adminUser.ID, "admin_session", currentSessionID, map[string]any{"error": "session_id_generation_failed"})
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "failed to create re-auth session"})
	}

	payload, err := json.Marshal(reauthSession{
		AdminUserID:    adminUser.ID,
		AdminSessionID: currentSessionID,
		Session:        *session,
	})
	if err != nil {
		s.auditAdminAction(c, "admin.auth.reauth.failure", false, "admin_user", adminUser.ID, "admin_session", currentSessionID, map[string]any{"error": "session_encode_failed"})
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "failed to encode re-auth session"})
	}
	if err := s.stateStore.Set(c.Request().Context(), adminReauthRedisKey(sessionID), payload, 5*time.Minute); err != nil {
		s.auditAdminAction(c, "admin.auth.reauth.failure", false, "admin_user", adminUser.ID, "admin_session", currentSessionID, map[string]any{"error": "session_store_failed"})
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "failed to store re-auth session"})
	}

	setCookie(c, &http.Cookie{
		Name:     adminReauthSessionCookieName,
		Value:    sessionID,
		Path:     "/admin/auth",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   300,
	})
	return c.JSON(http.StatusOK, options)
}

func (s *Service) FinishReauth(c echo.Context) error {
	adminUser, currentSessionID, err := s.sessionUser(c)
	if err != nil || adminUser == nil {
		s.auditAdminAction(c, "admin.auth.reauth.failure", false, "unknown", "", "admin_session", "", map[string]any{"error": "missing_session"})
		return c.JSON(http.StatusUnauthorized, map[string]string{"message": "admin session is required"})
	}

	reauthCookie, err := c.Cookie(adminReauthSessionCookieName)
	if err != nil || strings.TrimSpace(reauthCookie.Value) == "" {
		s.auditAdminAction(c, "admin.auth.reauth.failure", false, "admin_user", adminUser.ID, "admin_session", currentSessionID, map[string]any{"error": "missing_reauth_cookie"})
		return c.JSON(http.StatusBadRequest, map[string]string{"message": "re-auth session is missing"})
	}

	key := adminReauthRedisKey(strings.TrimSpace(reauthCookie.Value))
	payload, err := s.stateStore.Get(c.Request().Context(), key)
	if err != nil {
		clearCookie(c, adminReauthSessionCookieName, "/admin/auth")
		s.auditAdminAction(c, "admin.auth.reauth.failure", false, "admin_user", adminUser.ID, "admin_session", currentSessionID, map[string]any{"error": "reauth_session_expired"})
		return c.JSON(http.StatusBadRequest, map[string]string{"message": "re-auth session expired"})
	}
	_ = s.stateStore.Del(c.Request().Context(), key)
	clearCookie(c, adminReauthSessionCookieName, "/admin/auth")

	var reauth reauthSession
	if err := json.Unmarshal(payload, &reauth); err != nil {
		s.auditAdminAction(c, "admin.auth.reauth.failure", false, "admin_user", adminUser.ID, "admin_session", currentSessionID, map[string]any{"error": "reauth_session_invalid"})
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "re-auth session is invalid"})
	}

	if strings.TrimSpace(reauth.AdminUserID) != strings.TrimSpace(adminUser.ID) || strings.TrimSpace(reauth.AdminSessionID) != strings.TrimSpace(currentSessionID) {
		s.auditAdminAction(c, "admin.auth.reauth.failure", false, "admin_user", adminUser.ID, "admin_session", currentSessionID, map[string]any{"error": "session_mismatch"})
		return c.JSON(http.StatusForbidden, map[string]string{"message": "re-auth session mismatch"})
	}

	var resolvedAdmin *store.AdminUser
	credential, err := s.wa.FinishDiscoverableLogin(func(rawID []byte, userHandle []byte) (webauthn.User, error) {
		var (
			u   *store.AdminUser
			err error
		)
		if len(userHandle) > 0 {
			u, err = s.store.GetAdminUser(string(userHandle))
		} else {
			u, err = s.store.GetAdminUserByCredentialID(rawID)
		}
		if err != nil {
			return nil, err
		}
		if !u.Enabled {
			return nil, store.ErrAdminUserDisabled
		}
		resolvedAdmin = u
		return u, nil
	}, reauth.Session, c.Request())
	if err != nil {
		s.auditAdminAction(c, "admin.auth.reauth.failure", false, "admin_user", adminUser.ID, "admin_session", currentSessionID, map[string]any{"error": "finish_reauth_failed"})
		return c.JSON(http.StatusUnauthorized, map[string]string{"message": "admin re-auth failed"})
	}

	if resolvedAdmin == nil || strings.TrimSpace(resolvedAdmin.ID) != strings.TrimSpace(adminUser.ID) {
		s.auditAdminAction(c, "admin.auth.reauth.failure", false, "admin_user", adminUser.ID, "admin_session", currentSessionID, map[string]any{"error": "resolved_user_mismatch"})
		return c.JSON(http.StatusForbidden, map[string]string{"message": "admin re-auth failed"})
	}

	if err := s.store.UpdateAdminCredential(credential); err != nil && !errors.Is(err, store.ErrAdminCredentialNotFound) {
		s.auditAdminAction(c, "admin.auth.reauth.failure", false, "admin_user", adminUser.ID, "admin_session", currentSessionID, map[string]any{"error": "credential_update_failed"})
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "failed to update admin credential"})
	}

	reauthenticatedAt := time.Now().UTC()
	if err := s.markSessionRecentAuthAt(c.Request().Context(), currentSessionID, reauthenticatedAt); err != nil {
		s.auditAdminAction(c, "admin.auth.reauth.failure", false, "admin_user", adminUser.ID, "admin_session", currentSessionID, map[string]any{"error": "session_update_failed"})
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "failed to update admin session re-auth state"})
	}

	s.auditAdminAction(c, "admin.auth.reauth.success", true, "admin_user", adminUser.ID, "admin_session", currentSessionID, map[string]any{"reauth_at_utc": reauthenticatedAt.Unix()})
	return c.JSON(http.StatusOK, map[string]any{
		"status":             "ok",
		"reauthenticated_at": reauthenticatedAt.Format(time.RFC3339),
	})
}

func (s *Service) BeginAddPasskey(c echo.Context) error {
	adminUser, _, err := s.sessionUser(c)
	if err != nil || adminUser == nil {
		s.auditAdminAction(c, "admin.auth.passkey.add.failure", false, "unknown", "", "admin_credential", "", map[string]any{"error": "missing_session"})
		return c.JSON(http.StatusUnauthorized, map[string]string{"message": "admin session is required"})
	}

	options, session, err := s.wa.BeginRegistration(adminUser,
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			ResidentKey:      protocol.ResidentKeyRequirementRequired,
			UserVerification: protocol.VerificationRequired,
		}),
	)
	if err != nil {
		s.auditAdminAction(c, "admin.auth.passkey.add.failure", false, "admin_user", adminUser.ID, "admin_credential", "", map[string]any{"error": "begin_registration_failed"})
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "failed to begin passkey registration"})
	}

	sessionID, err := newRandomID()
	if err != nil {
		s.auditAdminAction(c, "admin.auth.passkey.add.failure", false, "admin_user", adminUser.ID, "admin_credential", "", map[string]any{"error": "session_id_generation_failed"})
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "failed to create registration session"})
	}

	payload, err := json.Marshal(registrationSession{
		AdminUserID: adminUser.ID,
		Session:     *session,
	})
	if err != nil {
		s.auditAdminAction(c, "admin.auth.passkey.add.failure", false, "admin_user", adminUser.ID, "admin_credential", "", map[string]any{"error": "session_encode_failed"})
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "failed to encode registration session"})
	}
	if err := s.stateStore.Set(c.Request().Context(), adminAddPasskeyRedisKey(sessionID), payload, 5*time.Minute); err != nil {
		s.auditAdminAction(c, "admin.auth.passkey.add.failure", false, "admin_user", adminUser.ID, "admin_credential", "", map[string]any{"error": "session_store_failed"})
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "failed to store registration session"})
	}

	setCookie(c, &http.Cookie{
		Name:     adminAddPasskeyCookieName,
		Value:    sessionID,
		Path:     "/admin/auth",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   300,
	})

	return c.JSON(http.StatusOK, options)
}

func (s *Service) FinishAddPasskey(c echo.Context) error {
	adminUser, _, err := s.sessionUser(c)
	if err != nil || adminUser == nil {
		s.auditAdminAction(c, "admin.auth.passkey.add.failure", false, "unknown", "", "admin_credential", "", map[string]any{"error": "missing_session"})
		return c.JSON(http.StatusUnauthorized, map[string]string{"message": "admin session is required"})
	}

	addCookie, err := c.Cookie(adminAddPasskeyCookieName)
	if err != nil || strings.TrimSpace(addCookie.Value) == "" {
		s.auditAdminAction(c, "admin.auth.passkey.add.failure", false, "admin_user", adminUser.ID, "admin_credential", "", map[string]any{"error": "missing_registration_cookie"})
		return c.JSON(http.StatusBadRequest, map[string]string{"message": "passkey registration session is missing"})
	}

	key := adminAddPasskeyRedisKey(strings.TrimSpace(addCookie.Value))
	payload, err := s.stateStore.Get(c.Request().Context(), key)
	if err != nil {
		clearCookie(c, adminAddPasskeyCookieName, "/admin/auth")
		s.auditAdminAction(c, "admin.auth.passkey.add.failure", false, "admin_user", adminUser.ID, "admin_credential", "", map[string]any{"error": "registration_session_expired"})
		return c.JSON(http.StatusBadRequest, map[string]string{"message": "passkey registration session expired"})
	}
	_ = s.stateStore.Del(c.Request().Context(), key)
	clearCookie(c, adminAddPasskeyCookieName, "/admin/auth")

	var reg registrationSession
	if err := json.Unmarshal(payload, &reg); err != nil {
		s.auditAdminAction(c, "admin.auth.passkey.add.failure", false, "admin_user", adminUser.ID, "admin_credential", "", map[string]any{"error": "registration_session_invalid"})
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "passkey registration session is invalid"})
	}
	if strings.TrimSpace(reg.AdminUserID) != strings.TrimSpace(adminUser.ID) {
		s.auditAdminAction(c, "admin.auth.passkey.add.failure", false, "admin_user", adminUser.ID, "admin_credential", "", map[string]any{"error": "session_user_mismatch"})
		return c.JSON(http.StatusForbidden, map[string]string{"message": "registration session does not belong to current admin"})
	}

	credential, err := s.wa.FinishRegistration(adminUser, reg.Session, c.Request())
	if err != nil {
		s.auditAdminAction(c, "admin.auth.passkey.add.failure", false, "admin_user", adminUser.ID, "admin_credential", "", map[string]any{"error": "finish_registration_failed"})
		return c.JSON(http.StatusBadRequest, map[string]string{"message": "passkey verification failed"})
	}

	if err := s.store.AddAdminCredential(adminUser.ID, credential); err != nil {
		s.auditAdminAction(c, "admin.auth.passkey.add.failure", false, "admin_user", adminUser.ID, "admin_credential", "", map[string]any{"error": "credential_store_failed"})
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "failed to store admin credential"})
	}

	credentialDisplayID := encodeCredentialID(credential.ID)
	s.auditAdminAction(c, "admin.auth.passkey.add.success", true, "admin_user", adminUser.ID, "admin_credential", credentialDisplayID, map[string]any{"credential_id": credentialDisplayID})
	return c.JSON(http.StatusOK, map[string]any{
		"status":        "ok",
		"credential_id": credentialDisplayID,
	})
}

func (s *Service) Logout(c echo.Context) error {
	if err := s.LogoutSession(c); err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"message": "not authenticated"})
	}
	return c.JSON(http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Service) LogoutSession(c echo.Context) error {
	adminUser, sessionID, err := s.sessionUser(c)
	if err != nil {
		clearCookie(c, adminSessionCookieName, "/admin")
		s.auditAuth(c, "admin.auth.logout", false, "unknown", "", map[string]any{"error": "missing_session"})
		return errAdminSessionInvalid
	}

	_ = s.stateStore.Del(c.Request().Context(), adminSessionRedisKey(sessionID))
	clearCookie(c, adminSessionCookieName, "/admin")

	admin.SetAdminActor(c, "admin_user", adminUser.ID)
	s.auditAuth(c, "admin.auth.logout", true, "admin_user", adminUser.ID, map[string]any{
		"login": adminUser.Login,
	})
	return nil
}

func (s *Service) CurrentSessionID(c echo.Context) (string, bool) {
	_, sessionID, err := s.sessionUser(c)
	if err != nil || strings.TrimSpace(sessionID) == "" {
		return "", false
	}
	return strings.TrimSpace(sessionID), true
}

func (s *Service) ReauthMaxAge() time.Duration {
	if s.reauthTTL <= 0 {
		return 5 * time.Minute
	}
	return s.reauthTTL
}

func (s *Service) HasRecentReauth(c echo.Context, maxAge time.Duration) bool {
	_, sessionID, err := s.sessionUser(c)
	if err != nil || strings.TrimSpace(sessionID) == "" {
		return false
	}
	record, _, err := s.loadSessionRecord(c.Request().Context(), sessionID)
	if err != nil {
		return false
	}
	if record.RecentAuthAtUTC <= 0 {
		return false
	}
	if maxAge <= 0 {
		maxAge = s.ReauthMaxAge()
	}
	if maxAge <= 0 {
		return false
	}
	recentAuthAt := time.Unix(record.RecentAuthAtUTC, 0).UTC()
	return time.Since(recentAuthAt) <= maxAge
}

func (s *Service) ListPasskeys(c echo.Context) ([]store.AdminCredentialInfo, error) {
	adminUser, _, err := s.sessionUser(c)
	if err != nil || adminUser == nil {
		return nil, errAdminSessionInvalid
	}
	return s.store.ListAdminCredentials(adminUser.ID)
}

func (s *Service) DeletePasskey(c echo.Context, credentialID int64) error {
	adminUser, _, err := s.sessionUser(c)
	if err != nil || adminUser == nil {
		s.auditAdminAction(c, "admin.auth.passkey.delete.failure", false, "unknown", "", "admin_credential", strconv.FormatInt(credentialID, 10), map[string]any{"error": "missing_session"})
		return errAdminSessionInvalid
	}
	if credentialID <= 0 {
		s.auditAdminAction(c, "admin.auth.passkey.delete.failure", false, "admin_user", adminUser.ID, "admin_credential", strconv.FormatInt(credentialID, 10), map[string]any{"error": "invalid_credential_id"})
		return store.ErrAdminCredentialNotFound
	}

	if err := s.store.DeleteAdminCredential(adminUser.ID, credentialID); err != nil {
		s.auditAdminAction(c, "admin.auth.passkey.delete.failure", false, "admin_user", adminUser.ID, "admin_credential", strconv.FormatInt(credentialID, 10), map[string]any{"error": securityErrorCode(err)})
		return err
	}

	s.auditAdminAction(c, "admin.auth.passkey.delete.success", true, "admin_user", adminUser.ID, "admin_credential", strconv.FormatInt(credentialID, 10), map[string]any{"credential_id": credentialID})
	return nil
}

func (s *Service) ListSessions(c echo.Context) ([]store.AdminSessionInfo, error) {
	adminUser, currentSessionID, err := s.sessionUser(c)
	if err != nil || adminUser == nil {
		return nil, errAdminSessionInvalid
	}
	return s.listAdminSessions(c.Request().Context(), adminUser.ID, currentSessionID)
}

func (s *Service) LogoutSessionByID(c echo.Context, sessionID string) error {
	adminUser, currentSessionID, err := s.sessionUser(c)
	if err != nil || adminUser == nil {
		s.auditAdminAction(c, "admin.auth.session.logout.failure", false, "unknown", "", "admin_session", strings.TrimSpace(sessionID), map[string]any{"error": "missing_session"})
		return errAdminSessionInvalid
	}

	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		s.auditAdminAction(c, "admin.auth.session.logout.failure", false, "admin_user", adminUser.ID, "admin_session", "", map[string]any{"error": "invalid_session_id"})
		return errAdminSessionInvalid
	}

	record, _, err := s.loadSessionRecord(c.Request().Context(), sessionID)
	if err != nil || strings.TrimSpace(record.AdminUserID) != strings.TrimSpace(adminUser.ID) {
		s.auditAdminAction(c, "admin.auth.session.logout.failure", false, "admin_user", adminUser.ID, "admin_session", sessionID, map[string]any{"error": "session_not_found"})
		return errAdminSessionInvalid
	}

	if err := s.stateStore.Del(c.Request().Context(), adminSessionRedisKey(sessionID)); err != nil {
		s.auditAdminAction(c, "admin.auth.session.logout.failure", false, "admin_user", adminUser.ID, "admin_session", sessionID, map[string]any{"error": "session_delete_failed"})
		return err
	}
	if sessionID == currentSessionID {
		clearCookie(c, adminSessionCookieName, "/admin")
	}

	s.auditAdminAction(c, "admin.auth.session.logout.success", true, "admin_user", adminUser.ID, "admin_session", sessionID, map[string]any{"current": sessionID == currentSessionID})
	return nil
}

func (s *Service) LogoutOtherSessions(c echo.Context) (int, error) {
	adminUser, currentSessionID, err := s.sessionUser(c)
	if err != nil || adminUser == nil {
		s.auditAdminAction(c, "admin.auth.session.logout_others.failure", false, "unknown", "", "admin_session", "", map[string]any{"error": "missing_session"})
		return 0, errAdminSessionInvalid
	}

	sessions, err := s.listAdminSessions(c.Request().Context(), adminUser.ID, currentSessionID)
	if err != nil {
		s.auditAdminAction(c, "admin.auth.session.logout_others.failure", false, "admin_user", adminUser.ID, "admin_session", "", map[string]any{"error": "session_list_failed"})
		return 0, err
	}

	removed := 0
	for _, session := range sessions {
		if session.Current {
			continue
		}
		if err := s.stateStore.Del(c.Request().Context(), adminSessionRedisKey(session.SessionID)); err != nil {
			s.auditAdminAction(c, "admin.auth.session.logout_others.failure", false, "admin_user", adminUser.ID, "admin_session", session.SessionID, map[string]any{"error": "session_delete_failed"})
			return removed, err
		}
		removed++
	}

	s.auditAdminAction(c, "admin.auth.session.logout_others.success", true, "admin_user", adminUser.ID, "admin_session", currentSessionID, map[string]any{"removed_count": removed})
	return removed, nil
}

func (s *Service) InvalidateSessionsForAdminUser(ctx context.Context, adminUserID string) (int, error) {
	adminUserID = strings.TrimSpace(adminUserID)
	if adminUserID == "" {
		return 0, errAdminSessionInvalid
	}

	keys, err := s.stateStore.Keys(ctx, adminSessionRedisKey("*"))
	if err != nil {
		return 0, err
	}
	removed := 0
	for _, key := range keys {
		sessionID := strings.TrimPrefix(strings.TrimSpace(key), "admin:sess:")
		if sessionID == "" {
			continue
		}
		record, _, err := s.loadSessionRecord(ctx, sessionID)
		if err != nil {
			continue
		}
		if strings.TrimSpace(record.AdminUserID) != adminUserID {
			continue
		}
		if err := s.stateStore.Del(ctx, adminSessionRedisKey(sessionID)); err != nil {
			return removed, err
		}
		removed++
	}
	return removed, nil
}

func (s *Service) ListUserSessionsForAdmin(ctx context.Context, userID string) ([]store.UserSessionInfo, error) {
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return []store.UserSessionInfo{}, nil
	}

	target := map[string]struct{}{userID: {}}
	grouped, err := s.listActiveUserSessions(ctx, target)
	if err != nil {
		return nil, err
	}
	items := grouped[userID]
	out := make([]store.UserSessionInfo, 0, len(items))
	out = append(out, items...)
	return out, nil
}

func (s *Service) CountActiveUserSessionsByUserIDs(ctx context.Context, userIDs []string) (map[string]int, error) {
	target := make(map[string]struct{}, len(userIDs))
	for _, userID := range userIDs {
		normalized := strings.TrimSpace(userID)
		if normalized == "" {
			continue
		}
		target[normalized] = struct{}{}
	}

	counts := make(map[string]int, len(target))
	if len(target) == 0 {
		return counts, nil
	}

	grouped, err := s.listActiveUserSessions(ctx, target)
	if err != nil {
		return nil, err
	}
	for userID := range target {
		counts[userID] = len(grouped[userID])
	}
	return counts, nil
}

func (s *Service) LogoutUserSessionForAdmin(ctx context.Context, userID string, sessionID string) error {
	userID = strings.TrimSpace(userID)
	sessionID = strings.TrimSpace(sessionID)
	if userID == "" || sessionID == "" {
		return errAdminSessionInvalid
	}

	metaPayload, err := s.stateStore.Get(ctx, userSessionMetaRedisKey(sessionID))
	if err != nil {
		return errAdminSessionInvalid
	}
	var meta userDeviceSessionMeta
	if err := json.Unmarshal(metaPayload, &meta); err != nil {
		return errAdminSessionInvalid
	}
	if strings.TrimSpace(meta.UserID) != userID {
		return errAdminSessionInvalid
	}

	ownerPayload, err := s.stateStore.Get(ctx, userSessionRedisKey(sessionID))
	if err != nil {
		return errAdminSessionInvalid
	}
	if strings.TrimSpace(string(ownerPayload)) != userID {
		return errAdminSessionInvalid
	}

	if err := s.stateStore.Del(ctx, userSessionRedisKey(sessionID)); err != nil {
		return err
	}
	_ = s.stateStore.Del(ctx, userRecoveryRedisKey(sessionID))
	_ = s.stateStore.Del(ctx, userSessionMetaRedisKey(sessionID))
	return nil
}

func (s *Service) LogoutAllUserSessionsForAdmin(ctx context.Context, userID string) (int, error) {
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return 0, errAdminSessionInvalid
	}
	return s.revokeAllUserSessionArtifacts(ctx, userID)
}

func addUserSessionID(set map[string]struct{}, value string) {
	normalized := strings.TrimSpace(value)
	if normalized == "" {
		return
	}
	set[normalized] = struct{}{}
}

func sessionIDFromKey(key string, prefix string) string {
	return strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(key), strings.TrimSpace(prefix)))
}

func (s *Service) revokeAllUserSessionArtifacts(ctx context.Context, userID string) (int, error) {
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return 0, errAdminSessionInvalid
	}

	sessionSet := make(map[string]struct{}, 16)

	sessionKeys, err := s.stateStore.Keys(ctx, userSessionRedisKey("*"))
	if err != nil {
		return 0, err
	}
	for _, key := range sessionKeys {
		sessionID := sessionIDFromKey(key, userSessionKeyPrefix)
		if sessionID == "" {
			continue
		}
		ownerPayload, getErr := s.stateStore.Get(ctx, userSessionRedisKey(sessionID))
		if getErr != nil {
			continue
		}
		if strings.TrimSpace(string(ownerPayload)) != userID {
			continue
		}
		addUserSessionID(sessionSet, sessionID)
	}

	metaKeys, err := s.stateStore.Keys(ctx, userSessionMetaRedisKey("*"))
	if err != nil {
		return 0, err
	}
	for _, key := range metaKeys {
		sessionID := sessionIDFromKey(key, userSessionMetaPrefix)
		if sessionID == "" {
			continue
		}
		metaPayload, getErr := s.stateStore.Get(ctx, userSessionMetaRedisKey(sessionID))
		if getErr != nil {
			continue
		}
		var meta userDeviceSessionMeta
		if err := json.Unmarshal(metaPayload, &meta); err != nil {
			continue
		}
		if strings.TrimSpace(meta.UserID) != userID {
			continue
		}
		addUserSessionID(sessionSet, meta.SessionID)
		addUserSessionID(sessionSet, sessionID)
	}

	deviceKeys, err := s.stateStore.Keys(ctx, userSessionDeviceRedisKey(userID, "*"))
	if err != nil {
		return 0, err
	}
	for _, key := range deviceKeys {
		sessionIDPayload, getErr := s.stateStore.Get(ctx, strings.TrimSpace(key))
		if getErr != nil {
			continue
		}
		addUserSessionID(sessionSet, string(sessionIDPayload))
	}

	sessionIDs := make([]string, 0, len(sessionSet))
	for sessionID := range sessionSet {
		sessionIDs = append(sessionIDs, sessionID)
	}
	sort.Strings(sessionIDs)

	removed := 0
	var firstErr error
	errCount := 0
	recordError := func(opErr error) {
		if opErr == nil {
			return
		}
		errCount++
		if firstErr == nil {
			firstErr = opErr
		}
	}

	for _, sessionID := range sessionIDs {
		if err := s.stateStore.Del(ctx, userSessionRedisKey(sessionID)); err != nil {
			recordError(err)
		}
		_ = s.stateStore.Del(ctx, userRecoveryRedisKey(sessionID))
		_ = s.stateStore.Del(ctx, userSessionMetaRedisKey(sessionID))
		removed++
	}

	if err := s.stateStore.Del(ctx, userSessionListRedisKey(userID)); err != nil {
		recordError(err)
	}
	if err := s.stateStore.Del(ctx, userSessionAllRedisKey(userID)); err != nil {
		recordError(err)
	}
	for _, key := range deviceKeys {
		if err := s.stateStore.Del(ctx, strings.TrimSpace(key)); err != nil {
			recordError(err)
		}
	}

	if errCount > 0 {
		return removed, fmt.Errorf("user session cleanup failed (%d errors): %w", errCount, firstErr)
	}
	return removed, nil
}

func (s *Service) listActiveUserSessions(ctx context.Context, targetUsers map[string]struct{}) (map[string][]store.UserSessionInfo, error) {
	result := make(map[string][]store.UserSessionInfo, len(targetUsers))
	if len(targetUsers) == 0 {
		return result, nil
	}

	metaKeys, err := s.stateStore.Keys(ctx, userSessionMetaRedisKey("*"))
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	seenSession := make(map[string]struct{}, len(metaKeys))

	for _, key := range metaKeys {
		sessionID := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(key), userSessionMetaPrefix))
		if sessionID == "" {
			continue
		}
		if _, ok := seenSession[sessionID]; ok {
			continue
		}
		seenSession[sessionID] = struct{}{}

		metaPayload, err := s.stateStore.Get(ctx, userSessionMetaRedisKey(sessionID))
		if err != nil {
			continue
		}
		var meta userDeviceSessionMeta
		if err := json.Unmarshal(metaPayload, &meta); err != nil {
			continue
		}

		userID := strings.TrimSpace(meta.UserID)
		if userID == "" {
			continue
		}
		if _, ok := targetUsers[userID]; !ok {
			continue
		}

		ownerPayload, err := s.stateStore.Get(ctx, userSessionRedisKey(sessionID))
		if err != nil {
			continue
		}
		if strings.TrimSpace(string(ownerPayload)) != userID {
			continue
		}

		createdAt := time.Time{}
		if meta.CreatedAtUTC > 0 {
			createdAt = time.Unix(meta.CreatedAtUTC, 0).UTC()
		}
		lastSeenAt := createdAt
		if meta.LastSeenUTC > 0 {
			lastSeenAt = time.Unix(meta.LastSeenUTC, 0).UTC()
		}

		expiresAt := time.Time{}
		if ttl, ttlErr := s.stateStore.TTL(ctx, userSessionRedisKey(sessionID)); ttlErr == nil && ttl > 0 {
			expiresAt = now.Add(ttl).UTC()
		}

		result[userID] = append(result[userID], store.UserSessionInfo{
			SessionID:  sessionID,
			CreatedAt:  createdAt,
			LastSeenAt: lastSeenAt,
			ExpiresAt:  expiresAt,
			RemoteIP:   strings.TrimSpace(meta.IP),
			UserAgent:  strings.TrimSpace(meta.UserAgent),
		})
	}

	for userID := range result {
		sort.Slice(result[userID], func(i, j int) bool {
			if result[userID][i].LastSeenAt.Equal(result[userID][j].LastSeenAt) {
				return result[userID][i].CreatedAt.After(result[userID][j].CreatedAt)
			}
			return result[userID][i].LastSeenAt.After(result[userID][j].LastSeenAt)
		})
	}
	return result, nil
}

func (s *Service) listAdminSessions(ctx context.Context, adminUserID string, currentSessionID string) ([]store.AdminSessionInfo, error) {
	adminUserID = strings.TrimSpace(adminUserID)
	if adminUserID == "" {
		return nil, errAdminSessionInvalid
	}

	keys, err := s.stateStore.Keys(ctx, adminSessionRedisKey("*"))
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	out := make([]store.AdminSessionInfo, 0, len(keys))
	for _, key := range keys {
		sessionID := strings.TrimPrefix(strings.TrimSpace(key), "admin:sess:")
		if sessionID == "" {
			continue
		}

		record, ttl, err := s.loadSessionRecord(ctx, sessionID)
		if err != nil {
			continue
		}
		if strings.TrimSpace(record.AdminUserID) != adminUserID {
			continue
		}
		createdAt := time.Unix(record.CreatedAtUTC, 0).UTC()
		lastSeenAt := createdAt
		if record.LastSeenAtUTC > 0 {
			lastSeenAt = time.Unix(record.LastSeenAtUTC, 0).UTC()
		}

		expiresAt := createdAt.Add(s.sessionAbsoluteTTL)
		if ttl > 0 {
			idleExpiresAt := now.Add(ttl).UTC()
			if idleExpiresAt.Before(expiresAt) {
				expiresAt = idleExpiresAt
			}
		}

		out = append(out, store.AdminSessionInfo{
			SessionID:  sessionID,
			CreatedAt:  createdAt,
			LastSeenAt: lastSeenAt,
			ExpiresAt:  expiresAt,
			RemoteIP:   strings.TrimSpace(record.RemoteIP),
			UserAgent:  strings.TrimSpace(record.UserAgent),
			Current:    strings.TrimSpace(currentSessionID) == sessionID,
		})
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].Current != out[j].Current {
			return out[i].Current
		}
		if out[i].LastSeenAt.Equal(out[j].LastSeenAt) {
			return out[i].CreatedAt.After(out[j].CreatedAt)
		}
		return out[i].LastSeenAt.After(out[j].LastSeenAt)
	})
	return out, nil
}

func (s *Service) loadSessionRecord(ctx context.Context, sessionID string) (sessionRecord, time.Duration, error) {
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return sessionRecord{}, 0, errAdminSessionInvalid
	}

	key := adminSessionRedisKey(sessionID)
	payload, err := s.stateStore.Get(ctx, key)
	if err != nil {
		return sessionRecord{}, 0, err
	}

	var record sessionRecord
	if err := json.Unmarshal(payload, &record); err != nil {
		_ = s.stateStore.Del(ctx, key)
		return sessionRecord{}, 0, err
	}
	record.AdminUserID = strings.TrimSpace(record.AdminUserID)
	if record.AdminUserID == "" || record.CreatedAtUTC <= 0 {
		_ = s.stateStore.Del(ctx, key)
		return sessionRecord{}, 0, errAdminSessionInvalid
	}
	if record.LastSeenAtUTC <= 0 {
		record.LastSeenAtUTC = record.CreatedAtUTC
	}
	if record.RecentAuthAtUTC < 0 {
		record.RecentAuthAtUTC = 0
	}
	record.RemoteIP = strings.TrimSpace(record.RemoteIP)
	record.UserAgent = strings.TrimSpace(record.UserAgent)

	ttl, err := s.stateStore.TTL(ctx, key)
	if err != nil {
		ttl = 0
	}
	return record, ttl, nil
}

func (s *Service) sessionUser(c echo.Context) (*store.AdminUser, string, error) {
	cookie, err := c.Cookie(adminSessionCookieName)
	if err != nil || strings.TrimSpace(cookie.Value) == "" {
		return nil, "", errAdminSessionInvalid
	}
	sessionID := strings.TrimSpace(cookie.Value)
	key := adminSessionRedisKey(sessionID)

	payload, err := s.stateStore.Get(c.Request().Context(), key)
	if err != nil {
		return nil, "", errAdminSessionInvalid
	}

	var record sessionRecord
	if err := json.Unmarshal(payload, &record); err != nil {
		_ = s.stateStore.Del(c.Request().Context(), key)
		return nil, "", errAdminSessionInvalid
	}
	record.AdminUserID = strings.TrimSpace(record.AdminUserID)
	if record.AdminUserID == "" || record.CreatedAtUTC <= 0 {
		_ = s.stateStore.Del(c.Request().Context(), key)
		return nil, "", errAdminSessionInvalid
	}
	if record.LastSeenAtUTC <= 0 {
		record.LastSeenAtUTC = record.CreatedAtUTC
	}
	if record.RecentAuthAtUTC < 0 {
		record.RecentAuthAtUTC = 0
	}
	record.RemoteIP = strings.TrimSpace(record.RemoteIP)
	record.UserAgent = strings.TrimSpace(record.UserAgent)

	createdAt := time.Unix(record.CreatedAtUTC, 0).UTC()
	if time.Since(createdAt) > s.sessionAbsoluteTTL {
		_ = s.stateStore.Del(c.Request().Context(), key)
		clearCookie(c, adminSessionCookieName, "/admin")
		return nil, "", errAdminSessionInvalid
	}

	adminUser, err := s.store.GetAdminUser(record.AdminUserID)
	if err != nil || !adminUser.Enabled {
		_ = s.stateStore.Del(c.Request().Context(), key)
		clearCookie(c, adminSessionCookieName, "/admin")
		return nil, "", errAdminSessionInvalid
	}

	record.LastSeenAtUTC = time.Now().UTC().Unix()
	if realIP := strings.TrimSpace(c.RealIP()); realIP != "" {
		record.RemoteIP = realIP
	}
	if ua := strings.TrimSpace(c.Request().UserAgent()); ua != "" {
		record.UserAgent = ua
	}
	updatedPayload, err := json.Marshal(record)
	if err != nil {
		return nil, "", err
	}
	if err := s.stateStore.Set(c.Request().Context(), key, updatedPayload, s.sessionIdleTTL); err != nil {
		return nil, "", err
	}
	setCookie(c, &http.Cookie{
		Name:     adminSessionCookieName,
		Value:    sessionID,
		Path:     "/admin",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(s.sessionIdleTTL.Seconds()),
	})

	return adminUser, sessionID, nil
}

func (s *Service) setSession(c echo.Context, adminUserID string) (string, error) {
	sessionID, err := newRandomID()
	if err != nil {
		return "", err
	}
	now := time.Now().UTC()
	record := sessionRecord{
		AdminUserID:     strings.TrimSpace(adminUserID),
		CreatedAtUTC:    now.Unix(),
		LastSeenAtUTC:   now.Unix(),
		RecentAuthAtUTC: now.Unix(),
		RemoteIP:        strings.TrimSpace(c.RealIP()),
		UserAgent:       strings.TrimSpace(c.Request().UserAgent()),
	}
	payload, err := json.Marshal(record)
	if err != nil {
		return "", err
	}

	if err := s.stateStore.Set(c.Request().Context(), adminSessionRedisKey(sessionID), payload, s.sessionIdleTTL); err != nil {
		return "", err
	}

	setCookie(c, &http.Cookie{
		Name:     adminSessionCookieName,
		Value:    sessionID,
		Path:     "/admin",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(s.sessionIdleTTL.Seconds()),
	})
	return sessionID, nil
}

func (s *Service) markSessionRecentAuthAt(ctx context.Context, sessionID string, at time.Time) error {
	record, ttl, err := s.loadSessionRecord(ctx, sessionID)
	if err != nil {
		return err
	}
	record.RecentAuthAtUTC = at.UTC().Unix()

	payload, err := json.Marshal(record)
	if err != nil {
		return err
	}

	ttlToUse := s.sessionIdleTTL
	if ttl > 0 {
		ttlToUse = ttl
	}
	return s.stateStore.Set(ctx, adminSessionRedisKey(sessionID), payload, ttlToUse)
}

func (s *Service) ensureBootstrapUser() (*store.AdminUser, error) {
	usersCount, err := s.store.CountAdminUsers()
	if err != nil {
		return nil, err
	}
	credentialsCount, err := s.store.CountAdminCredentials()
	if err != nil {
		return nil, err
	}

	bootstrapLogin := strings.TrimSpace(s.bootstrapLogin)
	if bootstrapLogin == "" {
		return nil, fmt.Errorf("admin bootstrap login is not configured")
	}

	switch {
	case usersCount == 0:
		adminUser, err := s.store.CreateAdminUser(bootstrapLogin, bootstrapLogin)
		if err != nil {
			return nil, err
		}
		if err := s.store.SetAdminUserRole(adminUser.ID, store.AdminRoleOwner); err != nil {
			return nil, err
		}
		adminUser.Role = store.AdminRoleOwner
		return adminUser, nil
	case usersCount == 1 && credentialsCount == 0:
		adminUser, err := s.store.GetAdminUserByLogin(bootstrapLogin)
		if err != nil {
			return nil, errAdminBootstrapClosed
		}
		return adminUser, nil
	default:
		return nil, errAdminBootstrapClosed
	}
}

func (s *Service) auditAuth(c echo.Context, action string, success bool, actorType string, actorID string, details map[string]any) {
	s.auditAdminAction(c, action, success, actorType, actorID, "admin_user", actorID, details)
}

func (s *Service) auditAdminAction(c echo.Context, action string, success bool, actorType string, actorID string, resourceType string, resourceID string, details map[string]any) {
	if s.store == nil {
		return
	}

	detailsJSON := map[string]any{}
	for key, value := range details {
		trimmed := strings.ToLower(strings.TrimSpace(key))
		if trimmed == "" {
			continue
		}
		if strings.Contains(trimmed, "secret") || strings.Contains(trimmed, "authorization") || strings.Contains(trimmed, "token") {
			continue
		}
		detailsJSON[trimmed] = value
	}
	payload, _ := json.Marshal(detailsJSON)
	if len(payload) == 0 {
		payload = json.RawMessage(`{}`)
	}

	entry := store.AdminAuditEntry{
		Action:       strings.TrimSpace(action),
		Success:      success,
		ActorType:    defaultString(strings.TrimSpace(actorType), "unknown"),
		ActorID:      strings.TrimSpace(actorID),
		RemoteIP:     strings.TrimSpace(c.RealIP()),
		RequestID:    requestID(c),
		ResourceType: defaultString(strings.TrimSpace(resourceType), "admin_user"),
		ResourceID:   strings.TrimSpace(resourceID),
		DetailsJSON:  payload,
	}
	if err := s.store.CreateAdminAuditEntry(c.Request().Context(), entry); err != nil {
		log.Printf("admin auth audit insert failed action=%s actor_type=%s actor_id=%s resource_type=%s resource_id=%s error=%v", entry.Action, entry.ActorType, entry.ActorID, entry.ResourceType, entry.ResourceID, err)
	}
}

func securityErrorCode(err error) string {
	if err == nil {
		return ""
	}
	switch {
	case errors.Is(err, store.ErrAdminCredentialNotFound):
		return "admin_credential_not_found"
	case errors.Is(err, store.ErrAdminCredentialLast):
		return "last_admin_credential"
	case errors.Is(err, store.ErrAdminUserNotFound):
		return "admin_user_not_found"
	case errors.Is(err, errAdminSessionInvalid):
		return "admin_session_invalid"
	default:
		return "internal_error"
	}
}

func parsePositiveInt(raw string) int {
	if raw == "" {
		return 0
	}
	v, err := strconv.Atoi(raw)
	if err != nil || v <= 0 {
		return 0
	}
	return v
}

func newRandomID() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func adminRegRedisKey(id string) string {
	return "admin:reg:" + strings.TrimSpace(id)
}

func adminLoginRedisKey(id string) string {
	return "admin:login:" + strings.TrimSpace(id)
}

func adminReauthRedisKey(id string) string {
	return "admin:reauth:" + strings.TrimSpace(id)
}

func adminInviteRedisKey(id string) string {
	return "admin:invite:reg:" + strings.TrimSpace(id)
}

func adminAddPasskeyRedisKey(id string) string {
	return "admin:passkey:add:" + strings.TrimSpace(id)
}

func adminSessionRedisKey(id string) string {
	return "admin:sess:" + strings.TrimSpace(id)
}

func userSessionRedisKey(id string) string {
	return userSessionKeyPrefix + strings.TrimSpace(id)
}

func userRecoveryRedisKey(id string) string {
	return userRecoveryKeyPrefix + strings.TrimSpace(id)
}

func userSessionMetaRedisKey(id string) string {
	return userSessionMetaPrefix + strings.TrimSpace(id)
}

func userSessionListRedisKey(userID string) string {
	return userSessionListPrefix + strings.TrimSpace(userID)
}

func userSessionAllRedisKey(userID string) string {
	return userSessionAllPrefix + strings.TrimSpace(userID)
}

func userSessionDeviceRedisKey(userID string, deviceID string) string {
	return userSessionDevicePrefix + strings.TrimSpace(userID) + ":" + strings.TrimSpace(deviceID)
}

func encodeCredentialID(raw []byte) string {
	if len(raw) == 0 {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

func setCookie(c echo.Context, cookie *http.Cookie) {
	c.SetCookie(cookie)
}

func clearCookie(c echo.Context, name string, path string) {
	c.SetCookie(&http.Cookie{
		Name:     name,
		Value:    "",
		Path:     path,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
}

func defaultString(value string, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func requestID(c echo.Context) string {
	if rid := strings.TrimSpace(c.Response().Header().Get(echo.HeaderXRequestID)); rid != "" {
		return rid
	}
	return strings.TrimSpace(c.Request().Header.Get(echo.HeaderXRequestID))
}

func readInviteToken(c echo.Context) string {
	if token := strings.TrimSpace(c.QueryParam("token")); token != "" {
		return token
	}
	if token := strings.TrimSpace(c.Request().Header.Get("X-Admin-Invite-Token")); token != "" {
		return token
	}
	return ""
}

func hashInviteToken(token string) string {
	token = strings.TrimSpace(token)
	if token == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func constantTimeEqual(left string, right string) bool {
	l := []byte(strings.TrimSpace(left))
	r := []byte(strings.TrimSpace(right))
	if len(l) == 0 || len(r) == 0 {
		return false
	}
	return subtle.ConstantTimeCompare(l, r) == 1
}

func collectAdminRPOrigins(baseRPOrigin string, adminRPOriginsRaw string, adminAPIHost string) []string {
	origins := make([]string, 0, 3)
	if normalized := normalizeOrigin(baseRPOrigin); normalized != "" {
		origins = append(origins, normalized)
	}

	for _, item := range strings.Split(adminRPOriginsRaw, ",") {
		if normalized := normalizeOrigin(item); normalized != "" {
			origins = append(origins, normalized)
		}
	}

	if originFromHost := originFromHost(adminAPIHost); originFromHost != "" {
		origins = append(origins, originFromHost)
	}

	uniq := make([]string, 0, len(origins))
	seen := make(map[string]struct{}, len(origins))
	for _, origin := range origins {
		if _, ok := seen[origin]; ok {
			continue
		}
		seen[origin] = struct{}{}
		uniq = append(uniq, origin)
	}
	return uniq
}

func normalizeOrigin(raw string) string {
	value := strings.TrimSpace(raw)
	if value == "" {
		return ""
	}
	parsed, err := url.Parse(value)
	if err != nil {
		return ""
	}
	scheme := strings.ToLower(strings.TrimSpace(parsed.Scheme))
	if scheme != "https" && scheme != "http" {
		return ""
	}
	host := strings.TrimSpace(parsed.Host)
	if host == "" {
		return ""
	}
	return scheme + "://" + strings.ToLower(host)
}

func originFromHost(rawHost string) string {
	rawHost = strings.TrimSpace(rawHost)
	if rawHost == "" {
		return ""
	}
	if normalized := normalizeOrigin(rawHost); normalized != "" {
		return normalized
	}
	hostOnly := strings.ToLower(strings.TrimSpace(rawHost))
	hostOnly = strings.TrimPrefix(hostOnly, "http://")
	hostOnly = strings.TrimPrefix(hostOnly, "https://")
	hostOnly = strings.TrimSuffix(hostOnly, "/")
	if hostOnly == "" {
		return ""
	}
	return "https://" + hostOnly
}
