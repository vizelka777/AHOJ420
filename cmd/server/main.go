package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/houbamydar/AHOJ420/internal/admin"
	"github.com/houbamydar/AHOJ420/internal/adminauth"
	"github.com/houbamydar/AHOJ420/internal/adminui"
	"github.com/houbamydar/AHOJ420/internal/auth"
	"github.com/houbamydar/AHOJ420/internal/maintenance"
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
	if isCleanupRetentionMode(os.Args, os.Getenv("MODE")) {
		if err := runRetentionCleanupCommand(os.Args[1:]); err != nil {
			log.Fatalf("Retention cleanup failed: %v", err)
		}
		return
	}

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
	adminToken := strings.TrimSpace(os.Getenv("ADMIN_API_TOKEN"))
	adminHost := strings.TrimSpace(os.Getenv("ADMIN_API_HOST"))
	adminTokenEnabled := false
	if parsed, err := strconv.ParseBool(strings.TrimSpace(os.Getenv("ADMIN_API_TOKEN_ENABLED"))); err == nil {
		adminTokenEnabled = parsed
	}

	adminAuthService, err := adminauth.New(userStore, rdb)
	if err != nil {
		log.Fatalf("Failed to init admin auth: %v", err)
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
	e.POST("/auth/delete-account/reauth/begin", authService.BeginDeleteAccountReauth, sensitiveLimiter)
	e.POST("/auth/delete-account/reauth/finish", authService.FinishDeleteAccountReauth, sensitiveLimiter)
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
	e.GET("/auth/passkeys", authService.ListPasskeys)
	e.POST("/auth/passkeys/delete", authService.DeletePasskey, sensitiveLimiter)

	e.POST("/auth/recovery/request", authService.RequestRecovery, sensitiveLimiter)
	e.POST("/auth/recovery/verify-code", authService.VerifyRecoveryCode, sensitiveLimiter)
	e.GET("/auth/recovery/verify", authService.VerifyRecovery, sensitiveLimiter)
	e.GET("/auth/qr/generate", authService.GenerateQRLogin, sensitiveLimiter)
	e.POST("/auth/qr/approve", authService.ApproveQRLogin, sensitiveLimiter)
	e.GET("/auth/qr/status", authService.QRLoginStatus, sensitiveLimiter)

	var oidcReloader admin.OIDCClientReloader
	if reloader, ok := oidcProvider.Storage.(admin.OIDCClientReloader); ok {
		oidcReloader = reloader
	} else {
		log.Printf("OIDC storage does not implement admin runtime reload interface")
	}

	adminAuthGroup := e.Group("/admin/auth")
	adminAuthGroup.Use(admin.AdminRequestIDMiddleware())
	adminAuthGroup.Use(admin.AdminHostGuardMiddleware(adminHost))
	adminAuthGroup.Use(admin.AdminRateLimitMiddleware(admin.DefaultAdminRateLimitConfig))
	adminauth.RegisterRoutes(adminAuthGroup, adminAuthService)

	adminHandler := admin.NewOIDCClientHandler(userStore, oidcReloader, userStore)
	adminGroup := e.Group("/admin/api")
	adminGroup.Use(admin.AdminRequestIDMiddleware())
	adminGroup.Use(admin.AdminHostGuardMiddleware(adminHost))
	adminGroup.Use(admin.AdminRateLimitMiddleware(admin.DefaultAdminRateLimitConfig))
	adminGroup.Use(adminAuthService.AttachSessionActorMiddleware())
	adminGroup.Use(admin.AdminRequireActorMiddleware(adminToken, adminTokenEnabled))
	admin.RegisterOIDCClientRoutes(adminGroup, adminHandler)

	adminUIHandler, err := adminui.NewHandler(userStore, oidcReloader, userStore, adminAuthService)
	if err != nil {
		log.Fatalf("Failed to init admin UI: %v", err)
	}
	adminUIHandler.SetHealthProvider(adminui.NewSystemHealthService(
		db,
		rdb,
		userStore,
		userStore,
		adminui.SystemHealthConfig{
			MailerConfigured:                mailerConfiguredFromEnv(),
			SMSConfigured:                   smsConfiguredFromEnv(),
			AdminAuditRetentionDays:         retentionDaysFromEnv("ADMIN_AUDIT_RETENTION_DAYS", maintenance.DefaultRetentionDays),
			UserSecurityEventsRetentionDays: retentionDaysFromEnv("USER_SECURITY_EVENTS_RETENTION_DAYS", maintenance.DefaultRetentionDays),
		},
	))
	adminUIHandler.SetStatsProvider(adminui.NewStatsService(db, nil))
	adminUIGroup := e.Group("/admin")
	adminUIGroup.Use(admin.AdminRequestIDMiddleware())
	adminUIGroup.Use(admin.AdminHostGuardMiddleware(adminHost))
	adminUIGroup.Use(admin.AdminRateLimitMiddleware(admin.DefaultAdminRateLimitConfig))
	adminui.RegisterPublicRoutes(adminUIGroup, adminUIHandler)

	adminUIProtected := adminUIGroup.Group("")
	adminUIProtected.Use(adminAuthService.AttachSessionActorMiddleware())
	adminUIProtected.Use(adminAuthService.RequireSessionMiddleware("/admin/login"))
	adminUIProtected.Use(adminUIHandler.CSRFMiddleware())
	adminui.RegisterProtectedRoutes(adminUIProtected, adminUIHandler)

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

func isCleanupRetentionMode(args []string, mode string) bool {
	if strings.EqualFold(strings.TrimSpace(mode), "cleanup-retention") {
		return true
	}
	if len(args) < 2 {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(args[1]), "cleanup-retention")
}

type retentionCleanupCLIOptions struct {
	DryRun                    bool
	BatchSizeOverride         int
	IncludeAdminAudit         bool
	IncludeUserSecurityEvents bool
}

func runRetentionCleanupCommand(args []string) error {
	options, err := parseRetentionCleanupCLIOptions(args, os.Getenv)
	if err != nil {
		return err
	}

	pgURL := strings.TrimSpace(os.Getenv("POSTGRES_URL"))
	if pgURL == "" {
		return fmt.Errorf("POSTGRES_URL is required for cleanup-retention")
	}

	db, err := sql.Open("postgres", pgURL)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer db.Close()
	if err := db.Ping(); err != nil {
		return fmt.Errorf("ping db: %w", err)
	}

	cfg := maintenance.RetentionConfig{
		AdminAuditRetentionDays:         retentionDaysFromEnv("ADMIN_AUDIT_RETENTION_DAYS", maintenance.DefaultRetentionDays),
		UserSecurityEventsRetentionDays: retentionDaysFromEnv("USER_SECURITY_EVENTS_RETENTION_DAYS", maintenance.DefaultRetentionDays),
		DeleteBatchSize:                 retentionBatchSizeFromEnv("RETENTION_DELETE_BATCH_SIZE", maintenance.DefaultDeleteBatchSize),
		IncludeAdminAudit:               options.IncludeAdminAudit,
		IncludeUserSecurityEvents:       options.IncludeUserSecurityEvents,
		SelectionExplicit:               true,
	}
	if options.BatchSizeOverride != 0 {
		cfg.DeleteBatchSize = options.BatchSizeOverride
	}

	dbStore := store.New(db)
	result, runErr := maintenance.RunRetentionCleanup(context.Background(), dbStore, cfg, options.DryRun)
	if persistErr := recordRetentionMaintenanceRun(context.Background(), dbStore, result, runErr); persistErr != nil {
		log.Printf("retention.cleanup.persist.error err=%v", persistErr)
	}
	if runErr != nil {
		return runErr
	}

	for _, tableResult := range result.Results {
		cutoff := "-"
		if !tableResult.Cutoff.IsZero() {
			cutoff = tableResult.Cutoff.UTC().Format(time.RFC3339)
		}
		log.Printf(
			"retention.cleanup.summary table=%s retention_days=%d cutoff=%s eligible_count=%d deleted_count=%d batches=%d dry_run=%t skipped=%t",
			tableResult.Table,
			tableResult.RetentionDays,
			cutoff,
			tableResult.EligibleCount,
			tableResult.DeletedCount,
			tableResult.Batches,
			result.DryRun,
			tableResult.Skipped,
		)
	}
	log.Printf(
		"retention.cleanup.summary_total tables_processed=%d tables_skipped=%d eligible_total=%d deleted_total=%d dry_run=%t",
		result.TablesProcessed,
		result.TablesSkipped,
		result.TotalEligible,
		result.TotalDeleted,
		result.DryRun,
	)
	return nil
}

func parseRetentionCleanupCLIOptions(args []string, getenv func(string) string) (retentionCleanupCLIOptions, error) {
	if getenv == nil {
		getenv = os.Getenv
	}

	fs := flag.NewFlagSet("cleanup-retention", flag.ContinueOnError)
	dryRunFlag := fs.Bool("dry-run", false, "report eligible rows without deleting")
	batchSizeFlag := fs.Int("batch-size", 0, "delete batch size override")
	adminAuditOnlyFlag := fs.Bool("admin-audit-only", false, "process only admin_audit_log")
	userSecurityOnlyFlag := fs.Bool("user-security-only", false, "process only user_security_events")

	parsedArgs := args
	if len(parsedArgs) > 0 && strings.EqualFold(strings.TrimSpace(parsedArgs[0]), "cleanup-retention") {
		parsedArgs = parsedArgs[1:]
	}
	if err := fs.Parse(parsedArgs); err != nil {
		return retentionCleanupCLIOptions{}, err
	}

	includeAdminAudit := true
	includeUserSecurity := true
	if *adminAuditOnlyFlag && !*userSecurityOnlyFlag {
		includeUserSecurity = false
	}
	if *userSecurityOnlyFlag && !*adminAuditOnlyFlag {
		includeAdminAudit = false
	}

	return retentionCleanupCLIOptions{
		DryRun:                    *dryRunFlag || boolFromEnv(getenv("DRY_RUN")),
		BatchSizeOverride:         *batchSizeFlag,
		IncludeAdminAudit:         includeAdminAudit,
		IncludeUserSecurityEvents: includeUserSecurity,
	}, nil
}

func retentionDaysFromEnv(key string, defaultDays int) int {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return defaultDays
	}
	parsed, err := strconv.Atoi(raw)
	if err != nil {
		log.Printf("Invalid %s value %q; using default %d", key, raw, defaultDays)
		return defaultDays
	}
	if parsed <= 0 {
		return 0
	}
	return parsed
}

func retentionBatchSizeFromEnv(key string, defaultBatchSize int) int {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return defaultBatchSize
	}
	parsed, err := strconv.Atoi(raw)
	if err != nil {
		log.Printf("Invalid %s value %q; using default %d", key, raw, defaultBatchSize)
		return defaultBatchSize
	}
	if parsed <= 0 {
		return defaultBatchSize
	}
	return parsed
}

func boolFromEnv(raw string) bool {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return false
	}
	parsed, err := strconv.ParseBool(raw)
	return err == nil && parsed
}

func recordRetentionMaintenanceRun(ctx context.Context, dbStore *store.Store, result maintenance.RetentionRunResult, runErr error) error {
	if dbStore == nil {
		return nil
	}
	details := map[string]any{
		"dry_run":          result.DryRun,
		"batch_size":       result.BatchSize,
		"tables_processed": result.TablesProcessed,
		"tables_skipped":   result.TablesSkipped,
		"eligible_total":   result.TotalEligible,
		"deleted_total":    result.TotalDeleted,
	}
	tableResults := make([]map[string]any, 0, len(result.Results))
	for _, item := range result.Results {
		entry := map[string]any{
			"table":          item.Table,
			"retention_days": item.RetentionDays,
			"enabled":        item.Enabled,
			"skipped":        item.Skipped,
			"eligible_count": item.EligibleCount,
			"deleted_count":  item.DeletedCount,
			"batches":        item.Batches,
			"dry_run":        item.DryRun,
		}
		if !item.Cutoff.IsZero() {
			entry["cutoff"] = item.Cutoff.UTC().Format(time.RFC3339)
		}
		tableResults = append(tableResults, entry)
	}
	details["tables"] = tableResults
	if runErr != nil {
		details["error"] = runErr.Error()
	}

	detailsJSON, err := json.Marshal(details)
	if err != nil {
		return err
	}

	startedAt := result.StartedAt.UTC()
	if startedAt.IsZero() {
		startedAt = time.Now().UTC()
	}
	finishedAt := result.FinishedAt.UTC()
	if finishedAt.IsZero() {
		finishedAt = time.Now().UTC()
	}
	return dbStore.CreateMaintenanceRun(ctx, store.MaintenanceRun{
		JobName:     "cleanup-retention",
		StartedAt:   startedAt,
		FinishedAt:  finishedAt,
		Success:     runErr == nil,
		DetailsJSON: detailsJSON,
	})
}

func mailerConfiguredFromEnv() bool {
	host := strings.TrimSpace(os.Getenv("SMTP_HOST"))
	port := strings.TrimSpace(os.Getenv("SMTP_PORT"))
	from := strings.TrimSpace(os.Getenv("SMTP_FROM"))
	username := strings.TrimSpace(os.Getenv("SMTP_USERNAME"))
	password := strings.TrimSpace(os.Getenv("SMTP_PASSWORD"))
	if host == "" && port == "" && from == "" && username == "" && password == "" {
		return false
	}
	if host == "" || port == "" || from == "" {
		return false
	}
	if (username == "") != (password == "") {
		return false
	}
	return true
}

func smsConfiguredFromEnv() bool {
	clientID := strings.TrimSpace(os.Getenv("GOSMS_CLIENT_ID"))
	clientSecret := strings.TrimSpace(os.Getenv("GOSMS_CLIENT_SECRET"))
	channelID := strings.TrimSpace(os.Getenv("GOSMS_CHANNEL_ID"))
	return clientID != "" && clientSecret != "" && channelID != ""
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
