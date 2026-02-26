package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"time"

	"github.com/houbamydar/AHOJ420/internal/auth"
	mp "github.com/houbamydar/AHOJ420/internal/oidc"
	"github.com/houbamydar/AHOJ420/internal/store"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	_ "github.com/lib/pq"
	"github.com/redis/go-redis/v9"
	"github.com/zitadel/oidc/v3/pkg/op"
	"golang.org/x/time/rate"
)

func main() {
	pgURL := os.Getenv("POSTGRES_URL")
	redisAddr := os.Getenv("REDIS_ADDR")

	db, err := sql.Open("postgres", pgURL)
	if err != nil {
		log.Fatalf("Failed to open DB: %v", err)
	}
	defer db.Close()

	schema, err := os.ReadFile("internal/store/schema.sql")
	if err == nil {
		if _, execErr := db.Exec(string(schema)); execErr != nil {
			log.Printf("Schema init error (might be already existing): %v", execErr)
		}
	}

	rdb := redis.NewClient(&redis.Options{Addr: redisAddr})
	if _, err := rdb.Ping(context.Background()).Result(); err != nil {
		log.Fatalf("Failed to connect to Redis: %v", err)
	}

	userStore := store.New(db)
	oidcProvider, err := mp.NewProvider("https://ahoj420.eu", userStore, rdb)
	if err != nil {
		log.Fatalf("Failed to init OIDC: %v", err)
	}
	authService, err := auth.New(userStore, rdb, oidcProvider)
	if err != nil {
		log.Fatalf("Failed to init auth: %v", err)
	}

	e := echo.New()
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins: []string{"https://ahoj420.eu", "https://houbamzdar.cz"},
		AllowMethods: []string{http.MethodGet, http.MethodPost, http.MethodOptions},
		AllowHeaders: []string{echo.HeaderOrigin, echo.HeaderContentType, echo.HeaderAccept, echo.HeaderAuthorization},
	}))
	e.Use(middleware.SecureWithConfig(middleware.SecureConfig{
		XSSProtection:      "1; mode=block",
		ContentTypeNosniff: "nosniff",
		XFrameOptions:      "DENY",
		HSTSMaxAge:         int((365 * 24 * time.Hour).Seconds()),
		HSTSPreloadEnabled: true,
		ContentSecurityPolicy: "default-src 'self'; " +
			"script-src 'self' 'unsafe-inline' https://unpkg.com https://cdn.tailwindcss.com https://cdn.jsdelivr.net; " +
			"style-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com; " +
			"img-src 'self' data: https://avatar.ahoj420.eu; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
	}))

	sensitiveLimiter := middleware.RateLimiter(middleware.NewRateLimiterMemoryStore(rate.Limit(3)))
	oidcHandler := echo.WrapHandler(oidcProvider)

	e.Static("/static", "web/static")
	landingHandler := func(c echo.Context) error {
		mode := c.QueryParam("mode")
		if mode == "login" {
			editProfile := c.QueryParam("edit_profile") == "1"
			if _, ok := authService.SessionUserID(c); ok && !authService.InRecoveryMode(c) && !editProfile {
				if returnTo := c.QueryParam("return_to"); isSafeReturnTo(returnTo) {
					return c.Redirect(http.StatusFound, returnTo)
				}
				if authRequestID := c.QueryParam("auth_request_id"); isSafeAuthRequestID(authRequestID) {
					return c.Redirect(http.StatusFound, "/authorize/callback?id="+url.QueryEscape(authRequestID))
				}
			}
		}
		return c.File("web/templates/index.html")
	}
	e.GET("/", landingHandler)
	e.GET("/qr-login", landingHandler)
	e.GET("/robots.txt", func(c echo.Context) error {
		return c.String(http.StatusOK, "User-agent: *\nDisallow: /\n")
	})

	e.GET("/auth/register/begin", authService.BeginRegistration, sensitiveLimiter)
	e.POST("/auth/register/finish", authService.FinishRegistration, sensitiveLimiter)
	e.GET("/auth/login/begin", authService.BeginLogin, sensitiveLimiter)
	e.POST("/auth/login/finish", authService.FinishLogin, sensitiveLimiter)
	e.POST("/auth/logout", authService.Logout)
	e.GET("/auth/delete-impact", authService.DeleteAccountImpact)
	e.POST("/auth/delete-account", authService.DeleteAccount)
	e.POST("/auth/avatar", authService.UploadAvatar)
	e.GET("/logout", authService.LogoutRedirect)
	e.GET("/end_session", authService.LogoutRedirect)
	e.GET("/auth/session", authService.SessionStatus)
	e.GET("/auth/profile", authService.GetProfile)
	e.POST("/auth/profile", authService.UpdateProfile)
	e.POST("/auth/profile/email/request-verify", authService.RequestProfileEmailVerify, sensitiveLimiter)
	e.POST("/auth/profile/phone/request-verify", authService.RequestProfilePhoneVerify, sensitiveLimiter)
	e.POST("/auth/profile/phone/verify", authService.VerifyProfilePhone, sensitiveLimiter)
	e.GET("/auth/profile/email/verify", authService.VerifyProfileEmail, sensitiveLimiter)
	e.GET("/auth/devices", authService.ListDeviceSessions)
	e.POST("/auth/devices/logout", authService.LogoutDeviceSession, sensitiveLimiter)
	e.POST("/auth/devices/remove", authService.RemoveDeviceSession, sensitiveLimiter)

	e.POST("/auth/recovery/request", authService.RequestRecovery, sensitiveLimiter)
	e.POST("/auth/recovery/verify-code", authService.VerifyRecoveryCode, sensitiveLimiter)
	e.GET("/auth/recovery/verify", authService.VerifyRecovery, sensitiveLimiter)
	e.GET("/auth/qr/generate", authService.GenerateQRLogin, sensitiveLimiter)
	e.POST("/auth/qr/approve", authService.ApproveQRLogin, sensitiveLimiter)
	e.GET("/auth/qr/status", authService.QRLoginStatus, sensitiveLimiter)

	e.Any("/.well-known/openid-configuration", discoveryHandler(oidcProvider))
	e.Any("/keys", oidcHandler)
	e.Any("/jwks", rewriteOIDCPath(oidcProvider, "/keys"))
	e.Any("/oauth/token", oidcHandler, sensitiveLimiter)
	e.Any("/token", rewriteOIDCPath(oidcProvider, "/oauth/token"), sensitiveLimiter)
	e.Any("/userinfo", oidcHandler)

	e.GET("/authorize", func(c echo.Context) error {
		if userID, ok := authService.SessionUserID(c); ok {
			if authService.InRecoveryMode(c) {
				return c.Redirect(http.StatusTemporaryRedirect, "/?mode=recovery")
			}
			req := c.Request().WithContext(mp.WithUserID(c.Request().Context(), userID))
			c.SetRequest(req)
			return oidcHandler(c)
		}

		c.Response().Before(func() {
			if c.Response().Status < 300 || c.Response().Status >= 400 {
				return
			}
			location := c.Response().Header().Get(echo.HeaderLocation)
			if location == "" {
				return
			}
			u, err := url.Parse(location)
			if err != nil {
				return
			}
			authRequestID := u.Query().Get("auth_request_id")
			if authRequestID == "" {
				return
			}
			if clientHost, hostErr := oidcProvider.AuthRequestClientHost(authRequestID); hostErr == nil && clientHost != "" {
				q := u.Query()
				q.Set("client_host", clientHost)
				u.RawQuery = q.Encode()
				c.Response().Header().Set(echo.HeaderLocation, u.String())
			}
			c.SetCookie(&http.Cookie{
				Name:     "oidc_auth_request",
				Value:    authRequestID,
				Path:     "/",
				HttpOnly: true,
				Secure:   true,
				SameSite: http.SameSiteLaxMode,
				MaxAge:   300,
			})
		})

		return oidcHandler(c)
	})

	e.GET("/authorize/callback", func(c echo.Context) error {
		op.AuthorizeCallback(c.Response(), c.Request(), oidcProvider.OpenIDProvider)
		return nil
	})

	log.Println("Server starting on :8080")
	e.Logger.Fatal(e.Start(":8080"))
}

func rewriteOIDCPath(provider http.Handler, path string) echo.HandlerFunc {
	return func(c echo.Context) error {
		req := c.Request().Clone(c.Request().Context())
		req.URL.Path = path
		req.URL.RawPath = path
		provider.ServeHTTP(c.Response(), req)
		return nil
	}
}

func discoveryHandler(provider http.Handler) echo.HandlerFunc {
	return func(c echo.Context) error {
		rec := newResponseRecorder()
		provider.ServeHTTP(rec, c.Request())

		if rec.statusCode == 0 {
			rec.statusCode = http.StatusOK
		}
		body := rec.body.Bytes()
		if rec.statusCode >= 200 && rec.statusCode < 300 {
			var doc map[string]any
			if err := json.Unmarshal(body, &doc); err == nil {
				doc["scopes_supported"] = []string{"openid", "profile", "email", "phone", "offline_access"}
				doc["claims_supported"] = []string{
					"sub", "iss", "aud", "exp", "iat",
					"preferred_username", "name", "picture",
					"email", "email_verified",
					"phone_number", "phone_number_verified",
				}
				if _, ok := doc["end_session_endpoint"]; !ok {
					doc["end_session_endpoint"] = "https://ahoj420.eu/end_session"
				}
				if encoded, err := json.Marshal(doc); err == nil {
					body = encoded
					rec.headers.Set(echo.HeaderContentType, echo.MIMEApplicationJSONCharsetUTF8)
				}
			}
		}

		for key, values := range rec.headers {
			for _, value := range values {
				c.Response().Header().Add(key, value)
			}
		}
		c.Response().WriteHeader(rec.statusCode)
		_, _ = c.Response().Write(body)
		return nil
	}
}

type responseRecorder struct {
	headers    http.Header
	body       *bytes.Buffer
	statusCode int
}

func newResponseRecorder() *responseRecorder {
	return &responseRecorder{
		headers: make(http.Header),
		body:    &bytes.Buffer{},
	}
}

func (r *responseRecorder) Header() http.Header {
	return r.headers
}

func (r *responseRecorder) Write(data []byte) (int, error) {
	return r.body.Write(data)
}

func (r *responseRecorder) WriteHeader(statusCode int) {
	r.statusCode = statusCode
}

func isSafeReturnTo(returnTo string) bool {
	if returnTo == "" {
		return false
	}
	if returnTo[0] != '/' {
		return false
	}
	if len(returnTo) > 1 && returnTo[1] == '/' {
		return false
	}
	if hasScheme(returnTo) {
		return false
	}
	return len(returnTo) >= len("/authorize/callback") && returnTo[:len("/authorize/callback")] == "/authorize/callback"
}

var authRequestIDPattern = regexp.MustCompile(`^auth_[A-Za-z0-9_-]+$`)

func isSafeAuthRequestID(id string) bool {
	return authRequestIDPattern.MatchString(id)
}

func hasScheme(v string) bool {
	for i := 0; i < len(v); i++ {
		ch := v[i]
		if ch == ':' {
			return true
		}
		if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '+' || ch == '-' || ch == '.') {
			return false
		}
	}
	return false
}
