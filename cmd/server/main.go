package main

import (
	"context"
	"database/sql"
	"log"
	"net/http"
	"net/url"
	"os"
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
			"script-src 'self' 'unsafe-inline' https://unpkg.com https://cdn.tailwindcss.com; " +
			"style-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com; " +
			"img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
	}))

	sensitiveLimiter := middleware.RateLimiter(middleware.NewRateLimiterMemoryStore(rate.Limit(3)))
	oidcHandler := echo.WrapHandler(oidcProvider)

	e.Static("/static", "web/static")
	e.GET("/", func(c echo.Context) error { return c.File("web/templates/index.html") })
	e.GET("/robots.txt", func(c echo.Context) error {
		return c.String(http.StatusOK, "User-agent: *\nDisallow: /\n")
	})

	e.GET("/auth/register/begin", authService.BeginRegistration, sensitiveLimiter)
	e.POST("/auth/register/finish", authService.FinishRegistration, sensitiveLimiter)
	e.GET("/auth/login/begin", authService.BeginLogin, sensitiveLimiter)
	e.POST("/auth/login/finish", authService.FinishLogin, sensitiveLimiter)
	e.POST("/auth/logout", authService.Logout)
	e.POST("/auth/delete-account", authService.DeleteAccount)
	e.GET("/auth/session", authService.SessionStatus)
	e.GET("/auth/profile", authService.GetProfile)
	e.POST("/auth/profile", authService.UpdateProfile)

	e.POST("/auth/recovery/request", authService.RequestRecovery, sensitiveLimiter)
	e.GET("/auth/recovery/verify", authService.VerifyRecovery, sensitiveLimiter)

	e.Any("/.well-known/openid-configuration", oidcHandler)
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
