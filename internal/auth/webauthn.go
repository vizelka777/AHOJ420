package auth

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
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
	"github.com/labstack/echo/v4"
	"github.com/redis/go-redis/v9"

	"github.com/houbamydar/AHOJ420/internal/avatar"
	mp "github.com/houbamydar/AHOJ420/internal/oidc"
	"github.com/houbamydar/AHOJ420/internal/store"
)

type Service struct {
	wa         *webauthn.WebAuthn
	store      *store.Store
	redis      *redis.Client
	provider   *mp.Provider
	sessionTTL time.Duration
	avatarCfg  avatarConfig
	mailer     emailSender
	smsSender  smsSender
	devMode    bool
}

type avatarConfig struct {
	publicBase string
	endpoint   string
	zone       string
	accessKey  string
	maxBytes   int64
}

type profilePayload struct {
	DisplayName  string `json:"display_name"`
	Email        string `json:"email"`
	Phone        string `json:"phone"`
	ShareProfile bool   `json:"share_profile"`
}

type registrationSession struct {
	UserID  string               `json:"user_id"`
	Session webauthn.SessionData `json:"session"`
}

func New(s *store.Store, r *redis.Client, p *mp.Provider) (*Service, error) {
	env := strings.TrimSpace(strings.ToLower(os.Getenv("AHOJ_ENV")))
	devMode := env == "" || env == "dev"

	mailer, err := newEmailSenderFromEnv()
	if err != nil {
		return nil, err
	}
	if mailer == nil {
		if devMode {
			log.Printf("SMTP is not configured: using log-only delivery for recovery links")
		} else {
			log.Printf("SMTP is not configured: recovery links will not be delivered by email")
		}
	} else {
		log.Printf("SMTP mailer configured for auth emails")
	}

	smsSender, err := newSMSSenderFromEnv()
	if err != nil {
		return nil, err
	}
	if smsSender == nil {
		if devMode {
			log.Printf("GoSMS is not configured: using log-only delivery for phone verification codes")
		} else {
			log.Printf("GoSMS is not configured: phone verification SMS will not be delivered")
		}
	} else {
		log.Printf("GoSMS sender configured for phone verification")
	}

	w, err := webauthn.New(&webauthn.Config{
		RPDisplayName: "Ahoj420 Identity",
		RPID:          os.Getenv("RP_ID"), // auth.localhost
		RPOrigins:     []string{os.Getenv("RP_ORIGIN"), "https://auth.localhost"},
	})
	if err != nil {
		return nil, err
	}
	ttlMinutes := 60
	if raw := os.Getenv("SESSION_TTL_MINUTES"); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 {
			ttlMinutes = parsed
		}
	}
	return &Service{
		wa:         w,
		store:      s,
		redis:      r,
		provider:   p,
		sessionTTL: time.Duration(ttlMinutes) * time.Minute,
		mailer:     mailer,
		smsSender:  smsSender,
		devMode:    devMode,
		avatarCfg: avatarConfig{
			publicBase: strings.TrimSpace(os.Getenv("AVATAR_PUBLIC_BASE")),
			endpoint:   strings.TrimSpace(defaultString(os.Getenv("BUNNY_STORAGE_ENDPOINT"), "storage.bunnycdn.com")),
			zone:       strings.TrimSpace(os.Getenv("BUNNY_STORAGE_ZONE")),
			accessKey:  strings.TrimSpace(os.Getenv("BUNNY_STORAGE_ACCESS_KEY")),
			maxBytes:   2 * 1024 * 1024,
		},
	}, nil
}

func defaultString(v, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return v
}

func sanitizePublicEmail(email string) string {
	trimmed := strings.TrimSpace(strings.ToLower(email))
	if strings.HasPrefix(trimmed, "anon-") {
		return ""
	}
	return strings.TrimSpace(email)
}

func newSessionID() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func (s *Service) setUserSessionWithID(c echo.Context, userID string) (string, error) {
	userSessionID, err := newSessionID()
	if err != nil {
		return "", err
	}
	sessionKey := "sess:" + userSessionID
	if err := s.redis.Set(c.Request().Context(), sessionKey, userID, s.sessionTTL).Err(); err != nil {
		return "", err
	}
	c.SetCookie(&http.Cookie{
		Name:     "user_session",
		Value:    userSessionID,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(s.sessionTTL.Seconds()),
	})
	return userSessionID, nil
}

func (s *Service) setUserSession(c echo.Context, userID string) error {
	_, err := s.setUserSessionWithID(c, userID)
	return err
}

func (s *Service) sessionID(c echo.Context) (string, bool) {
	cookie, err := c.Cookie("user_session")
	if err != nil || cookie.Value == "" {
		return "", false
	}
	return cookie.Value, true
}

func (s *Service) isRecoveryMode(c echo.Context) (bool, string) {
	sessionID, ok := s.sessionID(c)
	if !ok {
		return false, ""
	}
	_, err := s.redis.Get(c.Request().Context(), "recovery:"+sessionID).Result()
	if err != nil {
		return false, sessionID
	}
	return true, sessionID
}

func (s *Service) InRecoveryMode(c echo.Context) bool {
	on, _ := s.isRecoveryMode(c)
	return on
}

func (s *Service) clearRecoveryMode(c echo.Context, sessionID string) {
	if sessionID == "" {
		return
	}
	_ = s.redis.Del(c.Request().Context(), "recovery:"+sessionID).Err()
}

func (s *Service) BeginRegistration(c echo.Context) error {
	var user *store.User
	var err error

	email := c.QueryParam("email")
	if email != "" {
		user, err = s.store.CreateUser(email)
	} else if userID, ok := s.SessionUserID(c); ok {
		user, err = s.store.GetUser(userID)
	} else {
		user, err = s.store.CreateAnonymousUser()
	}

	if err != nil || user == nil {
		return c.String(http.StatusBadRequest, "Registration session invalid")
	}

	// Convert credentials to descriptors
	var exclusions []protocol.CredentialDescriptor
	for _, cred := range user.Credentials {
		exclusions = append(exclusions, protocol.CredentialDescriptor{
			Type:         protocol.PublicKeyCredentialType,
			CredentialID: cred.ID,
		})
	}

	// 2. Generate Options
	options, session, err := s.wa.BeginRegistration(user,
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			ResidentKey:      protocol.ResidentKeyRequirementRequired, // For Discoverable Creds later
			UserVerification: protocol.VerificationRequired,
		}),
		webauthn.WithExclusions(exclusions),
	)
	if err != nil {
		return c.String(http.StatusInternalServerError, err.Error())
	}

	regSessionID, err := newSessionID()
	if err != nil {
		return c.String(http.StatusInternalServerError, "Failed to create registration session")
	}
	payload, err := json.Marshal(registrationSession{
		UserID:  user.ID,
		Session: *session,
	})
	if err != nil {
		return c.String(http.StatusInternalServerError, "Failed to encode registration session")
	}
	regKey := "reg:" + regSessionID
	if err := s.redis.Set(c.Request().Context(), regKey, payload, 5*time.Minute).Err(); err != nil {
		return c.String(http.StatusInternalServerError, "Failed to store registration session")
	}

	c.SetCookie(&http.Cookie{
		Name:     "reg_session_id",
		Value:    regSessionID,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   300,
	})

	return c.JSON(http.StatusOK, options)
}

func (s *Service) FinishRegistration(c echo.Context) error {
	regCookie, err := c.Cookie("reg_session_id")
	if err != nil || regCookie.Value == "" {
		return c.String(http.StatusBadRequest, "Session missing")
	}
	regKey := "reg:" + regCookie.Value

	sessionBytes, err := s.redis.Get(c.Request().Context(), regKey).Bytes()
	if err != nil {
		return c.String(http.StatusBadRequest, "Session expired")
	}

	var reg registrationSession
	if err := json.Unmarshal(sessionBytes, &reg); err != nil {
		return c.String(http.StatusInternalServerError, "Session invalid")
	}
	_ = s.redis.Del(c.Request().Context(), regKey).Err()
	c.SetCookie(&http.Cookie{
		Name:     "reg_session_id",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})

	user, err := s.store.GetUser(reg.UserID)
	if err != nil {
		return c.String(http.StatusInternalServerError, "User not found")
	}

	credential, err := s.wa.FinishRegistration(user, reg.Session, c.Request())
	if err != nil {
		return c.String(http.StatusBadRequest, fmt.Sprintf("Verification failed: %v", err))
	}

	if err := s.store.AddCredential(user.ID, credential); err != nil {
		return c.String(http.StatusInternalServerError, "Failed to save credential")
	}

	if sessionID, ok := s.sessionID(c); ok {
		s.clearRecoveryMode(c, sessionID)
	}

	if _, err := s.setUserSessionWithID(c, user.ID); err != nil {
		return c.String(http.StatusInternalServerError, "Failed to create session")
	}

	authReqID := c.QueryParam("auth_request_id")
	if authReqID == "" {
		if authCookie, cookieErr := c.Cookie("oidc_auth_request"); cookieErr == nil && authCookie.Value != "" {
			authReqID = authCookie.Value
		}
	}

	redirectURL := ""
	returnClientHost := ""
	manualReturnRequired := false
	if authReqID != "" && s.provider.SetAuthRequestDone(authReqID, user.ID) == nil {
		redirectURL = "/authorize/callback?id=" + authReqID
		if host, hostErr := s.provider.AuthRequestClientHost(authReqID); hostErr == nil && strings.TrimSpace(host) != "" {
			returnClientHost = host
			manualReturnRequired = true
		}
		c.SetCookie(&http.Cookie{Name: "oidc_auth_request", MaxAge: -1, Path: "/"})
	}

	return c.JSON(http.StatusOK, map[string]any{
		"status":                 "ok",
		"email":                  sanitizePublicEmail(user.Email),
		"display_name":           user.DisplayName,
		"needs_profile":          true,
		"redirect":               redirectURL,
		"manual_return_required": manualReturnRequired,
		"return_client_host":     returnClientHost,
	})
}

func (s *Service) BeginLogin(c echo.Context) error {
	if mode, _ := s.isRecoveryMode(c); mode {
		return c.JSON(http.StatusForbidden, map[string]any{
			"message":  "recovery setup required",
			"redirect": "/?mode=recovery",
		})
	}

	// 1. Check if email is provided (for non-discoverable login)
	email := c.QueryParam("email")

	var user *store.User
	var err error

	if email != "" {
		user, err = s.store.GetUserByEmail(email)
		if err != nil {
			// In a real app, do not return 404 to avoid enumeration, but for now it's fine
			return c.String(http.StatusNotFound, "User not found")
		}
	}

	// 2. Generate Credential Assertion Options
	// If user is nil, it means we are doing a "Discoverable Credential" flow (empty allow list)
	var opts []webauthn.LoginOption
	if user == nil {
		// Discoverable flow: UserVerification required usually implies we want to know who they are
		opts = append(opts, webauthn.WithUserVerification(protocol.VerificationRequired))
	} else {
		opts = append(opts, webauthn.WithUserVerification(protocol.VerificationPreferred))
	}

	var options *protocol.CredentialAssertion
	var session *webauthn.SessionData

	if user == nil {
		options, session, err = s.wa.BeginDiscoverableLogin(opts...)
	} else {
		options, session, err = s.wa.BeginLogin(user, opts...)
	}
	if err != nil {
		return c.String(http.StatusInternalServerError, err.Error())
	}

	requestID := "login_" + session.Challenge
	sessionJSON, _ := json.Marshal(session)
	s.redis.Set(c.Request().Context(), requestID, sessionJSON, 5*time.Minute)

	// Return the request ID in a cookie so FinishLogin can find the session
	c.SetCookie(&http.Cookie{
		Name:     "login_session_id",
		Value:    requestID,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   300,
	})

	return c.JSON(http.StatusOK, options)
}

func (s *Service) FinishLogin(c echo.Context) error {
	if mode, _ := s.isRecoveryMode(c); mode {
		return c.JSON(http.StatusForbidden, map[string]any{
			"message":  "recovery setup required",
			"redirect": "/?mode=recovery",
		})
	}

	// 1. Get Session ID
	cookie, err := c.Cookie("login_session_id")
	if err != nil {
		return c.String(http.StatusBadRequest, "Session missing")
	}
	sessionID := cookie.Value

	// 2. Load Session
	sessionJSON, err := s.redis.Get(c.Request().Context(), sessionID).Bytes()
	if err != nil {
		return c.String(http.StatusBadRequest, "Session expired")
	}

	var session webauthn.SessionData
	if err := json.Unmarshal(sessionJSON, &session); err != nil {
		return c.String(http.StatusInternalServerError, "Session invalid")
	}

	// 3. Verify Assertion (discoverable vs non-discoverable)
	var user *store.User
	var credential *webauthn.Credential

	if session.UserID == nil {
		// Discoverable credential flow
		handler := func(rawID, userHandle []byte) (webauthn.User, error) {
			var u *store.User
			var err error
			if len(userHandle) > 0 {
				u, err = s.store.GetUser(string(userHandle))
			} else {
				// Fallback to credential ID if userHandle is missing
				u, err = s.store.GetUserByCredentialID(rawID)
			}
			if err != nil {
				return nil, err
			}
			user = u
			return u, nil
		}

		credential, err = s.wa.FinishDiscoverableLogin(handler, session, c.Request())
	} else {
		// Non-discoverable flow: session has user ID
		user, err = s.store.GetUser(string(session.UserID))
		if err != nil {
			return c.String(http.StatusInternalServerError, "User not found")
		}
		credential, err = s.wa.FinishLogin(user, session, c.Request())
	}

	if err != nil {
		return c.String(http.StatusBadRequest, fmt.Sprintf("Login failed: %v", err))
	}
	if user == nil {
		return c.String(http.StatusInternalServerError, "User not found")
	}

	// 5. Update Counters
	if credential.Authenticator.CloneWarning {
		fmt.Println("CLONE WARNING for user", user.Email)
		return c.String(http.StatusForbidden, "Security Alert: Possible credential clone")
	}

	if err := s.store.UpdateCredential(credential); err != nil {
		fmt.Printf("Failed to update credential stats: %v\n", err)
	}

	if err := s.setUserSession(c, user.ID); err != nil {
		return c.String(http.StatusInternalServerError, "Failed to create session")
	}

	authReqID := c.QueryParam("auth_request_id")
	if authReqID == "" {
		if authCookie, cookieErr := c.Cookie("oidc_auth_request"); cookieErr == nil && authCookie.Value != "" {
			authReqID = authCookie.Value
		}
	}

	redirectURL := "/"
	if authReqID != "" {
		if err := s.provider.SetAuthRequestDone(authReqID, user.ID); err != nil {
			return c.String(http.StatusBadRequest, "OIDC auth request invalid")
		}
		redirectURL = "/authorize/callback?id=" + authReqID
		c.SetCookie(&http.Cookie{Name: "oidc_auth_request", MaxAge: -1, Path: "/"})
	}

	return c.JSON(http.StatusOK, map[string]string{
		"status":       "ok",
		"email":        sanitizePublicEmail(user.Email),
		"display_name": user.DisplayName,
		"redirect":     redirectURL,
	})
}

func (s *Service) Logout(c echo.Context) error {
	s.clearUserSession(c)
	return c.JSON(http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Service) LogoutRedirect(c echo.Context) error {
	s.clearUserSession(c)

	redirectTarget := safePostLogoutRedirect(c.QueryParam("post_logout_redirect_uri"))
	if state := strings.TrimSpace(c.QueryParam("state")); state != "" {
		u, err := url.Parse(redirectTarget)
		if err == nil {
			q := u.Query()
			q.Set("state", state)
			u.RawQuery = q.Encode()
			redirectTarget = u.String()
		}
	}
	return c.Redirect(http.StatusFound, redirectTarget)
}

func (s *Service) clearUserSession(c echo.Context) {
	if cookie, err := c.Cookie("user_session"); err == nil && cookie.Value != "" {
		_ = s.redis.Del(c.Request().Context(), "sess:"+cookie.Value).Err()
		_ = s.redis.Del(c.Request().Context(), "recovery:"+cookie.Value).Err()
	}
	c.SetCookie(&http.Cookie{
		Name:     "user_session",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

func safePostLogoutRedirect(raw string) string {
	const defaultRedirect = "https://ahoj420.eu/"
	allowed := map[string]struct{}{
		"https://houbamzdar.cz/":           {},
		"https://houbamzdar.cz/index.html": {},
		"http://localhost:3000/":           {},
		"http://127.0.0.1:3000/":           {},
	}
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return defaultRedirect
	}
	if _, ok := allowed[trimmed]; ok {
		return trimmed
	}
	return defaultRedirect
}

func (s *Service) DeleteAccount(c echo.Context) error {
	if mode, _ := s.isRecoveryMode(c); mode {
		return c.JSON(http.StatusForbidden, map[string]any{
			"message":  "recovery setup required",
			"redirect": "/?mode=recovery",
		})
	}

	userID, ok := s.SessionUserID(c)
	if !ok {
		return c.JSON(http.StatusUnauthorized, map[string]any{"message": "not authenticated"})
	}

	sessionCookie, _ := c.Cookie("user_session")
	if err := s.store.DeleteUser(userID); err != nil {
		return c.String(http.StatusInternalServerError, "Failed to delete account")
	}

	if sessionCookie != nil && sessionCookie.Value != "" {
		_ = s.redis.Del(c.Request().Context(), "sess:"+sessionCookie.Value).Err()
	}
	c.SetCookie(&http.Cookie{
		Name:     "user_session",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})

	return c.JSON(http.StatusOK, map[string]string{"status": "deleted"})
}

func (s *Service) SessionUserID(c echo.Context) (string, bool) {
	cookie, err := c.Cookie("user_session")
	if err != nil || cookie.Value == "" {
		return "", false
	}
	userID, err := s.redis.Get(c.Request().Context(), "sess:"+cookie.Value).Result()
	if err != nil || userID == "" {
		return "", false
	}
	return userID, true
}

func (s *Service) SessionStatus(c echo.Context) error {
	userID, ok := s.SessionUserID(c)
	if !ok {
		return c.JSON(http.StatusOK, map[string]any{
			"authenticated": false,
		})
	}

	user, err := s.store.GetUser(userID)
	if err != nil {
		return c.JSON(http.StatusOK, map[string]any{
			"authenticated": false,
		})
	}

	return c.JSON(http.StatusOK, map[string]any{
		"authenticated":  true,
		"recovery_mode":  s.InRecoveryMode(c),
		"email":          sanitizePublicEmail(user.Email),
		"display_name":   user.DisplayName,
		"profile_email":  user.ProfileEmail,
		"phone":          user.Phone,
		"share_profile":  user.ShareProfile,
		"email_verified": user.EmailVerified,
		"phone_verified": user.PhoneVerified,
		"picture_url":    avatar.BuildPublicURL(s.avatarCfg.publicBase, user.AvatarKey, user.AvatarUpdatedAt),
	})
}

func (s *Service) GetProfile(c echo.Context) error {
	if mode, _ := s.isRecoveryMode(c); mode {
		return c.JSON(http.StatusForbidden, map[string]any{
			"message":  "recovery setup required",
			"redirect": "/?mode=recovery",
		})
	}

	userID, ok := s.SessionUserID(c)
	if !ok {
		return c.JSON(http.StatusUnauthorized, map[string]any{"message": "not authenticated"})
	}

	user, err := s.store.GetUser(userID)
	if err != nil {
		return c.String(http.StatusInternalServerError, "User not found")
	}

	return c.JSON(http.StatusOK, map[string]any{
		"display_name":   user.DisplayName,
		"email":          user.ProfileEmail,
		"phone":          user.Phone,
		"share_profile":  user.ShareProfile,
		"email_verified": user.EmailVerified,
		"phone_verified": user.PhoneVerified,
		"picture_url":    avatar.BuildPublicURL(s.avatarCfg.publicBase, user.AvatarKey, user.AvatarUpdatedAt),
	})
}

func (s *Service) UpdateProfile(c echo.Context) error {
	if mode, _ := s.isRecoveryMode(c); mode {
		return c.JSON(http.StatusForbidden, map[string]any{
			"message":  "recovery setup required",
			"redirect": "/?mode=recovery",
		})
	}

	userID, ok := s.SessionUserID(c)
	if !ok {
		return c.JSON(http.StatusUnauthorized, map[string]any{"message": "not authenticated"})
	}

	var payload profilePayload
	if err := c.Bind(&payload); err != nil {
		return c.String(http.StatusBadRequest, "Invalid payload")
	}

	normalized, err := normalizeProfilePayload(payload)
	if err != nil {
		return c.String(http.StatusBadRequest, err.Error())
	}

	if err := s.store.UpdateProfile(userID, normalized.DisplayName, normalized.Email, normalized.Phone, normalized.ShareProfile); err != nil {
		return c.String(http.StatusInternalServerError, "Failed to save profile")
	}
	return c.JSON(http.StatusOK, map[string]any{"status": "ok"})
}
