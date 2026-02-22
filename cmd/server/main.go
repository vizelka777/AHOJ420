package main

import (
	"context"
	"database/sql"
	"log"
	"net/http"
	"net/http/httptest"
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
	// 1. Config
	pgURL := os.Getenv("POSTGRES_URL")
	redisAddr := os.Getenv("REDIS_ADDR")

	// 2. Database
	db, err := sql.Open("postgres", pgURL)
	if err != nil {
		log.Fatalf("Failed to open DB: %v", err)
	}
	defer db.Close()
    
    // Simple schema migration on startup (for now)
    schema, err := os.ReadFile("internal/store/schema.sql")
    if err == nil {
        if _, err := db.Exec(string(schema)); err != nil {
            log.Printf("Schema init error (might be already existing): %v", err)
        }
    }

	// 3. Redis
    rdb := redis.NewClient(&redis.Options{
        Addr: redisAddr,
    })
    if _, err := rdb.Ping(context.Background()).Result(); err != nil {
        log.Fatalf("Failed to connect to Redis: %v", err)
    }

    // 5. Services
    userStore := store.New(db)
    
    // Initialize OIDC
    oidcProvider, err := mp.NewProvider("https://ahoj420.eu", userStore, rdb)
    if err != nil {
        log.Fatalf("Failed to init OIDC: %v", err)
    }

    authService, err := auth.New(userStore, rdb, oidcProvider)
    if err != nil {
        log.Fatalf("Failed to init auth: %v", err)
    }

	// 4. Server
	e := echo.New()
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
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

	sensitiveLimiter := middleware.RateLimiter(middleware.NewRateLimiterMemoryStore(rate.Limit(0.7)))

	e.Static("/static", "web/static")

	e.GET("/", func(c echo.Context) error {
		return c.File("web/templates/index.html")
	})
	e.GET("/robots.txt", func(c echo.Context) error {
		return c.String(http.StatusOK, "User-agent: *\nDisallow: /\n")
	})

	// Auth Routes
	e.GET("/auth/register/begin", authService.BeginRegistration, sensitiveLimiter)
	e.POST("/auth/register/finish", authService.FinishRegistration, sensitiveLimiter)
	e.GET("/auth/login/begin", authService.BeginLogin, sensitiveLimiter)
	e.POST("/auth/login/finish", authService.FinishLogin, sensitiveLimiter)
	e.POST("/auth/logout", authService.Logout)
	e.GET("/auth/session", authService.SessionStatus)

	// Recovery Routes
	e.POST("/auth/recovery/request", authService.RequestRecovery, sensitiveLimiter)
	e.GET("/auth/recovery/verify", authService.VerifyRecovery, sensitiveLimiter)

	// OIDC Routes
	e.Any("/.well-known/openid-configuration", echo.WrapHandler(oidcProvider))
	e.Any("/jwks", echo.WrapHandler(oidcProvider))
	e.POST("/token", echo.WrapHandler(oidcProvider), sensitiveLimiter)
	e.GET("/userinfo", echo.WrapHandler(oidcProvider))

	// Authorization Endpoint
	authorizeHandler := echo.WrapHandler(oidcProvider)
	e.GET("/authorize", func(c echo.Context) error {
		if userID, ok := authService.SessionUserID(c); ok {
			recorder := httptest.NewRecorder()
			oidcProvider.ServeHTTP(recorder, c.Request())

			if recorder.Code >= 300 && recorder.Code < 400 {
				if loc := recorder.Header().Get("Location"); loc != "" {
					if u, err := url.Parse(loc); err == nil {
						if authReqID := u.Query().Get("auth_request_id"); authReqID != "" {
							if err := oidcProvider.SetAuthRequestDone(authReqID, userID); err == nil {
								return c.Redirect(http.StatusFound, "/authorize/callback?id="+url.QueryEscape(authReqID))
							}
						}
					}
				}
			}

			for k, values := range recorder.Header() {
				for _, v := range values {
					c.Response().Header().Add(k, v)
				}
			}
			c.Response().WriteHeader(recorder.Code)
			_, _ = c.Response().Write(recorder.Body.Bytes())
			return nil
		}
		return authorizeHandler(c)
	}, sensitiveLimiter)

	// Authorization Callback (after login UI)
	e.GET("/authorize/callback", func(c echo.Context) error {
		op.AuthorizeCallback(c.Response(), c.Request(), oidcProvider.OpenIDProvider)
		return nil
	})

	e.GET("/auth/oidc/callback", func(c echo.Context) error {
		return c.String(http.StatusOK, "Callback received")
	})

	log.Println("Server starting on :8080")
	e.Logger.Fatal(e.Start(":8080"))
}
