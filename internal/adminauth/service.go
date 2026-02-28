package adminauth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
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
	adminSessionCookieName      = "admin_session"
	adminRegSessionCookieName   = "admin_reg_session_id"
	adminLoginSessionCookieName = "admin_login_session_id"
)

var (
	errAdminBootstrapClosed = errors.New("admin bootstrap is not available")
	errAdminSessionInvalid  = errors.New("admin session is invalid")
)

type adminStore interface {
	CountAdminUsers() (int, error)
	CountAdminCredentials() (int, error)
	CreateAdminUser(login string, displayName string) (*store.AdminUser, error)
	GetAdminUser(id string) (*store.AdminUser, error)
	GetAdminUserByLogin(login string) (*store.AdminUser, error)
	GetAdminUserByCredentialID(credentialID []byte) (*store.AdminUser, error)
	AddAdminCredential(adminUserID string, credential *webauthn.Credential) error
	UpdateAdminCredential(credential *webauthn.Credential) error
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
}

type registrationSession struct {
	AdminUserID string               `json:"admin_user_id"`
	Session     webauthn.SessionData `json:"session"`
}

type sessionRecord struct {
	AdminUserID  string `json:"admin_user_id"`
	CreatedAtUTC int64  `json:"created_at_utc"`
}

type adminSessionStateStore interface {
	Set(ctx context.Context, key string, value []byte, ttl time.Duration) error
	Get(ctx context.Context, key string) ([]byte, error)
	Del(ctx context.Context, key string) error
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
	}, nil
}

func RegisterRoutes(group *echo.Group, svc *Service) {
	group.POST("/register/begin", svc.BeginRegistration)
	group.POST("/register/finish", svc.FinishRegistration)
	group.POST("/login/begin", svc.BeginLogin)
	group.POST("/login/finish", svc.FinishLogin)
	group.POST("/logout", svc.Logout)
}

func (s *Service) AttachSessionActorMiddleware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			adminUser, _, err := s.sessionUser(c)
			if err == nil && adminUser != nil {
				admin.SetAdminActor(c, "admin_user", adminUser.ID)
				c.Set("admin_user", adminUser)
			}
			return next(c)
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

func (s *Service) Logout(c echo.Context) error {
	adminUser, sessionID, err := s.sessionUser(c)
	if err != nil {
		clearCookie(c, adminSessionCookieName, "/admin")
		s.auditAuth(c, "admin.auth.logout", false, "unknown", "", map[string]any{"error": "missing_session"})
		return c.JSON(http.StatusUnauthorized, map[string]string{"message": "not authenticated"})
	}

	_ = s.stateStore.Del(c.Request().Context(), adminSessionRedisKey(sessionID))
	clearCookie(c, adminSessionCookieName, "/admin")

	admin.SetAdminActor(c, "admin_user", adminUser.ID)
	s.auditAuth(c, "admin.auth.logout", true, "admin_user", adminUser.ID, map[string]any{
		"login": adminUser.Login,
	})
	return c.JSON(http.StatusOK, map[string]string{"status": "ok"})
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

	if err := s.stateStore.Set(c.Request().Context(), key, payload, s.sessionIdleTTL); err != nil {
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
	record := sessionRecord{
		AdminUserID:  strings.TrimSpace(adminUserID),
		CreatedAtUTC: time.Now().UTC().Unix(),
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
		return s.store.CreateAdminUser(bootstrapLogin, bootstrapLogin)
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
	if s.store == nil {
		return
	}

	detailsJSON := map[string]any{}
	for key, value := range details {
		trimmed := strings.TrimSpace(key)
		if trimmed == "" {
			continue
		}
		if strings.Contains(trimmed, "secret") || strings.Contains(trimmed, "authorization") {
			continue
		}
		detailsJSON[trimmed] = value
	}
	payload, _ := json.Marshal(detailsJSON)
	if len(payload) == 0 {
		payload = json.RawMessage(`{}`)
	}

	entry := store.AdminAuditEntry{
		Action:       action,
		Success:      success,
		ActorType:    defaultString(strings.TrimSpace(actorType), "unknown"),
		ActorID:      strings.TrimSpace(actorID),
		RemoteIP:     strings.TrimSpace(c.RealIP()),
		RequestID:    requestID(c),
		ResourceType: "admin_user",
		ResourceID:   strings.TrimSpace(actorID),
		DetailsJSON:  payload,
	}
	if err := s.store.CreateAdminAuditEntry(c.Request().Context(), entry); err != nil {
		log.Printf("admin auth audit insert failed action=%s actor_type=%s actor_id=%s error=%v", action, entry.ActorType, entry.ActorID, err)
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

func adminSessionRedisKey(id string) string {
	return "admin:sess:" + strings.TrimSpace(id)
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
