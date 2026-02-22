package auth

import (
    "crypto/rand"
    "encoding/base64"
    "encoding/json"
    "fmt"
    "net/http"
    "os"
    "strconv"
    "time"

    "github.com/go-webauthn/webauthn/protocol"
    "github.com/go-webauthn/webauthn/webauthn"
    "github.com/labstack/echo/v4"
    "github.com/redis/go-redis/v9"
    
    "github.com/houbamydar/AHOJ420/internal/store"
    mp "github.com/houbamydar/AHOJ420/internal/oidc"
)

type Service struct {
    wa       *webauthn.WebAuthn
    store    *store.Store
    redis    *redis.Client
    provider *mp.Provider
    sessionTTL time.Duration
}

func New(s *store.Store, r *redis.Client, p *mp.Provider) (*Service, error) {
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
        wa: w,
        store: s,
        redis: r,
        provider: p,
        sessionTTL: time.Duration(ttlMinutes) * time.Minute,
    }, nil
}

func newSessionID() (string, error) {
    b := make([]byte, 32)
    if _, err := rand.Read(b); err != nil {
        return "", err
    }
    return base64.RawURLEncoding.EncodeToString(b), nil
}

func (s *Service) BeginRegistration(c echo.Context) error {
    var user *store.User
    var err error

    email := c.QueryParam("email")
    if email != "" {
        // Normal flow: Create or Get user by email
        user, err = s.store.CreateUser(email)
    } else {
        // Session flow: Check if user is already authenticated (e.g. Recovery)
        cookie, cookieErr := c.Cookie("user_id")
        if cookieErr == nil {
            user, err = s.store.GetUser(cookie.Value)
        } else {
            // Anonymous flow: create a new user without email input
            user, err = s.store.CreateAnonymousUser()
        }
    }

    if err != nil || user == nil {
        return c.String(http.StatusBadRequest, "Registration session invalid")
    }

    // Convert credentials to descriptors
    var exclusions []protocol.CredentialDescriptor
    for _, cred := range user.Credentials {
        exclusions = append(exclusions, protocol.CredentialDescriptor{
            Type: protocol.PublicKeyCredentialType,
            CredentialID: cred.ID,
        })
    }

    // 2. Generate Options
    options, session, err := s.wa.BeginRegistration(user, 
        webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
            ResidentKey: protocol.ResidentKeyRequirementRequired, // For Discoverable Creds later
            UserVerification: protocol.VerificationRequired,
        }),
        webauthn.WithExclusions(exclusions),
    )
    if err != nil {
        return c.String(http.StatusInternalServerError, err.Error())
    }

    // 3. Store Session in Redis (TTL 5 min)
    sessionJSON, _ := json.Marshal(session)
    // Use a simple key strategy: "reg_session:<UserID>" (Simplification: assumes 1 session per user for now)
    // Better: return a session ID to frontend? no, the frontend just returns the credo.
    // We can use the Challenge as key? No, we don't have it in the next request yet.
    // Standard way: Store in a secure cookie or return a SessionID.
    // For simplicity, let's use a cookie "registration_session".
    
    s.redis.Set(c.Request().Context(), "reg_session:"+user.ID, sessionJSON, 5*time.Minute)
    
    // Set a cookie so we know who is registering
    c.SetCookie(&http.Cookie{
        Name: "user_id",
        Value: user.ID,
        Path: "/",
        HttpOnly: true,
        Secure: true,
    })

    return c.JSON(http.StatusOK, options)
}

func (s *Service) FinishRegistration(c echo.Context) error {
    // 1. Get UserID from cookie
    cookie, err := c.Cookie("user_id")
    if err != nil {
        return c.String(http.StatusBadRequest, "Session missing")
    }
    userID := cookie.Value

    // 2. Get User & Session
    user, err := s.store.GetUser(userID)
    if err != nil {
        return c.String(http.StatusInternalServerError, "User not found")
    }

    sessionJSON, err := s.redis.Get(c.Request().Context(), "reg_session:"+userID).Bytes()
    if err != nil {
        return c.String(http.StatusBadRequest, "Session expired")
    }

    var session webauthn.SessionData
    if err := json.Unmarshal(sessionJSON, &session); err != nil {
        return c.String(http.StatusInternalServerError, "Session invalid")
    }

    // 3. Parse and Verify
    credential, err := s.wa.FinishRegistration(user, session, c.Request())
    if err != nil {
        return c.String(http.StatusBadRequest, fmt.Sprintf("Verification failed: %v", err))
    }

    // 4. Save Credential
    if err := s.store.AddCredential(user.ID, credential); err != nil {
        return c.String(http.StatusInternalServerError, "Failed to save credential")
    }

    return c.JSON(http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Service) BeginLogin(c echo.Context) error {
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

    // 3. Store Session
    // Use the Challenge from the session data which is always a string
    requestID := "login_" + session.Challenge
    
    // Convert session to JSON
    sessionJSON, _ := json.Marshal(session)
    s.redis.Set(c.Request().Context(), requestID, sessionJSON, 5*time.Minute)

    // Return the request ID in a cookie so FinishLogin can find the session
    c.SetCookie(&http.Cookie{
        Name: "login_session_id",
        Value: requestID,
        Path: "/",
        HttpOnly: true,
        Secure: true,
    })

    return c.JSON(http.StatusOK, options)
}

func (s *Service) FinishLogin(c echo.Context) error {
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

    userSessionID, err := newSessionID()
    if err != nil {
        return c.String(http.StatusInternalServerError, "Failed to create session")
    }
    sessionKey := "sess:" + userSessionID
    if err := s.redis.Set(c.Request().Context(), sessionKey, user.ID, s.sessionTTL).Err(); err != nil {
        return c.String(http.StatusInternalServerError, "Failed to persist session")
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
    
    // If login is part of OIDC flow, mark auth request as done
    if authReqID := c.QueryParam("auth_request_id"); authReqID != "" {
        if err := s.provider.SetAuthRequestDone(authReqID, user.ID); err != nil {
            return c.String(http.StatusBadRequest, "OIDC auth request invalid")
        }
    }

    // OIDC Resume Support
    // We check if "authRequestID" was extracted from the session or passed by client.
    // For now, let's look for a cookie set by the Authorize endpoint.
    authReqID := ""
    cookie, err = c.Cookie("oidc_auth_request")
    if err == nil && cookie.Value != "" {
        authReqID = cookie.Value
    }
    
    redirectURL := "/"
    if authReqID != "" {
        // Create an auth request specific callback
        // We need to tell the Provider that the user is authenticated.
        // We can do this by redirecting to a callback endpoint that calls `op.VerifyAuthRequest`.
        // Or simpler: We return the callback URL to the frontend, and frontend redirects there.
        // The callback URL is `/auth/callback?id=<authReqID>`.
        redirectURL = fmt.Sprintf("/auth/oidc/callback?id=%s&sub=%s", authReqID, user.ID)
        
        // Clear cookie
        c.SetCookie(&http.Cookie{Name: "oidc_auth_request", MaxAge: -1, Path: "/"})
    }

    return c.JSON(http.StatusOK, map[string]string{
        "status": "ok", 
        "email": user.Email,
        "redirect": redirectURL,
    })
}

func (s *Service) Logout(c echo.Context) error {
    if cookie, err := c.Cookie("user_session"); err == nil && cookie.Value != "" {
        _ = s.redis.Del(c.Request().Context(), "sess:"+cookie.Value).Err()
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

    return c.JSON(http.StatusOK, map[string]string{"status": "ok"})
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
        "authenticated": true,
        "email": user.Email,
    })
}
