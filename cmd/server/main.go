package main

import (
	"context"
	"database/sql"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"net/url"

    "github.com/houbamydar/AHOJ420/internal/auth"
    "github.com/houbamydar/AHOJ420/internal/store"
    mp "github.com/houbamydar/AHOJ420/internal/oidc"
    
    "github.com/labstack/echo/v4"
    "github.com/labstack/echo/v4/middleware"
    _ "github.com/lib/pq"
    "github.com/redis/go-redis/v9"
    "github.com/zitadel/oidc/v3/pkg/op"
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

	e.Static("/static", "web/static")
    
    // Templates will be added next

	e.GET("/", func(c echo.Context) error {
		return c.File("web/templates/index.html")
	})

    // Auth Routes
    e.GET("/auth/register/begin", authService.BeginRegistration)
    e.POST("/auth/register/finish", authService.FinishRegistration)
    e.GET("/auth/login/begin", authService.BeginLogin)
    e.POST("/auth/login/finish", authService.FinishLogin)
    e.POST("/auth/logout", authService.Logout)
    e.GET("/auth/session", authService.SessionStatus)

    // Recovery Routes
    e.POST("/auth/recovery/request", authService.RequestRecovery)
    e.GET("/auth/recovery/verify", authService.VerifyRecovery)

    // OIDC Routes
    e.Any("/.well-known/openid-configuration", echo.WrapHandler(oidcProvider))
    e.Any("/jwks", echo.WrapHandler(oidcProvider))
    e.POST("/token", echo.WrapHandler(oidcProvider))
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
    })

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
