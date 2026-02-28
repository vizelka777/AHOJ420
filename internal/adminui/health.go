package adminui

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/houbamydar/AHOJ420/internal/store"
	"github.com/redis/go-redis/v9"
)

const (
	healthRecentFailuresDefaultLimit = 10
	healthRecentRunsScanLimit        = 25
)

type HealthStatus string

const (
	HealthStatusOK       HealthStatus = "ok"
	HealthStatusDegraded HealthStatus = "degraded"
	HealthStatusDown     HealthStatus = "down"
	HealthStatusDisabled HealthStatus = "disabled"
	HealthStatusUnknown  HealthStatus = "unknown"
)

type HealthCheckResult struct {
	Status    HealthStatus
	Message   string
	LatencyMS int64
	CheckedAt time.Time
}

type RetentionTableHealth struct {
	Table         string
	RetentionDays int
	Enabled       bool
}

type MaintenanceRunHealth struct {
	JobName         string
	StartedAt       time.Time
	FinishedAt      time.Time
	Success         bool
	DryRun          bool
	BatchSize       int
	TablesProcessed int
	TablesSkipped   int
	EligibleTotal   int64
	DeletedTotal    int64
	Error           string
}

type RetentionHealth struct {
	AdminAudit         RetentionTableHealth
	UserSecurityEvents RetentionTableHealth
	LastRun            *MaintenanceRunHealth
	LastSuccess        *MaintenanceRunHealth
	LastFailure        *MaintenanceRunHealth
}

type RecentFailureItem struct {
	Time    time.Time
	Source  string
	Event   string
	Message string
	Link    string
}

type SystemHealthSnapshot struct {
	GeneratedAt    time.Time
	Postgres       HealthCheckResult
	Redis          HealthCheckResult
	Mailer         HealthCheckResult
	SMS            HealthCheckResult
	Retention      RetentionHealth
	RecentFailures []RecentFailureItem
}

type SystemHealthProvider interface {
	GetSystemHealthSnapshot(ctx context.Context) (*SystemHealthSnapshot, error)
}

type retentionRunStore interface {
	ListMaintenanceRuns(ctx context.Context, opts store.MaintenanceRunListOptions) ([]store.MaintenanceRun, error)
}

type redisHealthClient interface {
	Ping(ctx context.Context) *redis.StatusCmd
}

type SystemHealthConfig struct {
	MailerConfigured                bool
	SMSConfigured                   bool
	AdminAuditRetentionDays         int
	UserSecurityEventsRetentionDays int
	RecentFailuresLimit             int
	ProbeTimeout                    time.Duration
	Now                             func() time.Time
}

type SystemHealthService struct {
	postgresProbe   func(ctx context.Context) error
	redisProbe      func(ctx context.Context) error
	maintenanceRuns retentionRunStore
	auditStore      AdminAuditStore
	cfg             SystemHealthConfig
}

func NewSystemHealthService(db *sql.DB, redisClient redisHealthClient, maintenanceStore retentionRunStore, auditStore AdminAuditStore, cfg SystemHealthConfig) *SystemHealthService {
	svc := &SystemHealthService{
		maintenanceRuns: maintenanceStore,
		auditStore:      auditStore,
		cfg:             normalizeSystemHealthConfig(cfg),
	}
	if db != nil {
		svc.postgresProbe = func(ctx context.Context) error {
			var ping int
			return db.QueryRowContext(ctx, `SELECT 1`).Scan(&ping)
		}
	}
	if redisClient != nil {
		svc.redisProbe = func(ctx context.Context) error {
			return redisClient.Ping(ctx).Err()
		}
	}
	return svc
}

func (s *SystemHealthService) GetSystemHealthSnapshot(ctx context.Context) (*SystemHealthSnapshot, error) {
	now := s.cfg.Now().UTC()
	snapshot := &SystemHealthSnapshot{GeneratedAt: now}

	snapshot.Postgres = runHealthProbe(ctx, s.cfg.ProbeTimeout, s.postgresProbe, "Postgres query ok")
	snapshot.Redis = runHealthProbe(ctx, s.cfg.ProbeTimeout, s.redisProbe, "Redis ping ok")
	snapshot.Mailer = deliveryHealthStatus(s.cfg.MailerConfigured, "Mailer configured")
	snapshot.SMS = deliveryHealthStatus(s.cfg.SMSConfigured, "SMS provider configured")
	snapshot.Retention = buildRetentionHealthDefaults(s.cfg)

	runs := make([]store.MaintenanceRun, 0)
	if s.maintenanceRuns != nil {
		items, err := s.maintenanceRuns.ListMaintenanceRuns(ctx, store.MaintenanceRunListOptions{
			JobName: "cleanup-retention",
			Limit:   healthRecentRunsScanLimit,
		})
		if err != nil {
			snapshot.Retention.LastFailure = &MaintenanceRunHealth{
				JobName:    "cleanup-retention",
				FinishedAt: now,
				Success:    false,
				Error:      "failed to load maintenance runs",
			}
		} else {
			runs = items
			snapshot.Retention.LastRun = firstMaintenanceRun(items)
			snapshot.Retention.LastSuccess = firstSuccessfulMaintenanceRun(items)
			snapshot.Retention.LastFailure = firstFailedMaintenanceRun(items)
		}
	}

	auditFailures := make([]RecentFailureItem, 0)
	if s.auditStore != nil {
		failed := false
		entries, err := s.auditStore.ListAdminAuditEntries(ctx, store.AdminAuditListOptions{
			Limit:   s.cfg.RecentFailuresLimit,
			Offset:  0,
			Success: &failed,
		})
		if err == nil {
			auditFailures = buildRecentAuditFailureItems(entries)
		}
	}

	maintenanceFailures := buildMaintenanceFailureItems(runs)
	snapshot.RecentFailures = mergeRecentFailures(auditFailures, maintenanceFailures, s.cfg.RecentFailuresLimit)

	return snapshot, nil
}

func normalizeSystemHealthConfig(cfg SystemHealthConfig) SystemHealthConfig {
	if cfg.RecentFailuresLimit <= 0 {
		cfg.RecentFailuresLimit = healthRecentFailuresDefaultLimit
	}
	if cfg.ProbeTimeout <= 0 {
		cfg.ProbeTimeout = 2 * time.Second
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return cfg
}

func runHealthProbe(ctx context.Context, timeout time.Duration, probe func(context.Context) error, okMessage string) HealthCheckResult {
	checkedAt := time.Now().UTC()
	if probe == nil {
		return HealthCheckResult{
			Status:    HealthStatusUnknown,
			Message:   "probe unavailable",
			CheckedAt: checkedAt,
		}
	}

	probeCtx := ctx
	cancel := func() {}
	if timeout > 0 {
		probeCtx, cancel = context.WithTimeout(ctx, timeout)
	}
	defer cancel()

	startedAt := time.Now()
	err := probe(probeCtx)
	latency := time.Since(startedAt).Milliseconds()
	if latency < 0 {
		latency = 0
	}
	if err != nil {
		return HealthCheckResult{
			Status:    HealthStatusDown,
			Message:   strings.TrimSpace(err.Error()),
			LatencyMS: latency,
			CheckedAt: checkedAt,
		}
	}
	return HealthCheckResult{
		Status:    HealthStatusOK,
		Message:   strings.TrimSpace(okMessage),
		LatencyMS: latency,
		CheckedAt: checkedAt,
	}
}

func deliveryHealthStatus(configured bool, message string) HealthCheckResult {
	checkedAt := time.Now().UTC()
	if !configured {
		return HealthCheckResult{
			Status:    HealthStatusDisabled,
			Message:   "not configured",
			CheckedAt: checkedAt,
		}
	}
	return HealthCheckResult{
		Status:    HealthStatusOK,
		Message:   strings.TrimSpace(message),
		CheckedAt: checkedAt,
	}
}

func buildRetentionHealthDefaults(cfg SystemHealthConfig) RetentionHealth {
	return RetentionHealth{
		AdminAudit: RetentionTableHealth{
			Table:         "admin_audit_log",
			RetentionDays: cfg.AdminAuditRetentionDays,
			Enabled:       cfg.AdminAuditRetentionDays > 0,
		},
		UserSecurityEvents: RetentionTableHealth{
			Table:         "user_security_events",
			RetentionDays: cfg.UserSecurityEventsRetentionDays,
			Enabled:       cfg.UserSecurityEventsRetentionDays > 0,
		},
	}
}

func decodeMaintenanceRun(raw store.MaintenanceRun) *MaintenanceRunHealth {
	item := &MaintenanceRunHealth{
		JobName:    strings.TrimSpace(raw.JobName),
		StartedAt:  raw.StartedAt.UTC(),
		FinishedAt: raw.FinishedAt.UTC(),
		Success:    raw.Success,
	}
	if len(raw.DetailsJSON) == 0 {
		return item
	}
	var details map[string]any
	if err := json.Unmarshal(raw.DetailsJSON, &details); err != nil {
		item.Error = "invalid details_json"
		return item
	}
	item.DryRun = anyBool(details["dry_run"])
	item.BatchSize = anyInt(details["batch_size"])
	item.TablesProcessed = anyInt(details["tables_processed"])
	item.TablesSkipped = anyInt(details["tables_skipped"])
	item.EligibleTotal = anyInt64(details["eligible_total"])
	item.DeletedTotal = anyInt64(details["deleted_total"])
	if msg := anyString(details["error"]); msg != "" {
		item.Error = msg
	}
	return item
}

func firstMaintenanceRun(runs []store.MaintenanceRun) *MaintenanceRunHealth {
	if len(runs) == 0 {
		return nil
	}
	return decodeMaintenanceRun(runs[0])
}

func firstSuccessfulMaintenanceRun(runs []store.MaintenanceRun) *MaintenanceRunHealth {
	for _, run := range runs {
		if !run.Success {
			continue
		}
		return decodeMaintenanceRun(run)
	}
	return nil
}

func firstFailedMaintenanceRun(runs []store.MaintenanceRun) *MaintenanceRunHealth {
	for _, run := range runs {
		if run.Success {
			continue
		}
		return decodeMaintenanceRun(run)
	}
	return nil
}

func buildRecentAuditFailureItems(entries []store.AdminAuditEntry) []RecentFailureItem {
	items := make([]RecentFailureItem, 0, len(entries))
	for _, entry := range entries {
		timestamp := entry.CreatedAt.UTC()
		message := "admin action failed"
		if parsed := parseFailureMessage(entry.DetailsJSON); parsed != "" {
			message = parsed
		}
		link := "/admin/audit?success=failure&action=" + url.QueryEscape(strings.TrimSpace(entry.Action))
		items = append(items, RecentFailureItem{
			Time:    timestamp,
			Source:  "admin_audit",
			Event:   strings.TrimSpace(entry.Action),
			Message: message,
			Link:    link,
		})
	}
	return items
}

func buildMaintenanceFailureItems(runs []store.MaintenanceRun) []RecentFailureItem {
	items := make([]RecentFailureItem, 0, len(runs))
	for _, run := range runs {
		if run.Success {
			continue
		}
		timestamp := run.FinishedAt.UTC()
		if timestamp.IsZero() {
			timestamp = run.CreatedAt.UTC()
		}
		decoded := decodeMaintenanceRun(run)
		message := "maintenance run failed"
		if decoded != nil && strings.TrimSpace(decoded.Error) != "" {
			message = strings.TrimSpace(decoded.Error)
		}
		items = append(items, RecentFailureItem{
			Time:    timestamp,
			Source:  "maintenance",
			Event:   strings.TrimSpace(run.JobName),
			Message: message,
		})
	}
	return items
}

func mergeRecentFailures(audit []RecentFailureItem, maintenance []RecentFailureItem, limit int) []RecentFailureItem {
	out := make([]RecentFailureItem, 0, len(audit)+len(maintenance))
	out = append(out, audit...)
	out = append(out, maintenance...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Time.Equal(out[j].Time) {
			return out[i].Event < out[j].Event
		}
		return out[i].Time.After(out[j].Time)
	})
	if limit <= 0 {
		limit = healthRecentFailuresDefaultLimit
	}
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

func parseFailureMessage(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return ""
	}
	for _, key := range []string{"error", "message", "reason", "phase"} {
		if value := anyString(decoded[key]); value != "" {
			return value
		}
	}
	return ""
}

func anyBool(value any) bool {
	switch typed := value.(type) {
	case bool:
		return typed
	case string:
		parsed := strings.TrimSpace(strings.ToLower(typed))
		return parsed == "1" || parsed == "true" || parsed == "yes" || parsed == "on"
	default:
		return false
	}
}

func anyInt(value any) int {
	switch typed := value.(type) {
	case int:
		return typed
	case int32:
		return int(typed)
	case int64:
		return int(typed)
	case float64:
		return int(typed)
	case json.Number:
		parsed, _ := typed.Int64()
		return int(parsed)
	case string:
		var parsed int
		_, _ = fmt.Sscanf(strings.TrimSpace(typed), "%d", &parsed)
		return parsed
	default:
		return 0
	}
}

func anyInt64(value any) int64 {
	switch typed := value.(type) {
	case int:
		return int64(typed)
	case int32:
		return int64(typed)
	case int64:
		return typed
	case float64:
		return int64(typed)
	case json.Number:
		parsed, _ := typed.Int64()
		return parsed
	case string:
		var parsed int64
		_, _ = fmt.Sscanf(strings.TrimSpace(typed), "%d", &parsed)
		return parsed
	default:
		return 0
	}
}

func healthStatusChipClass(status HealthStatus) string {
	switch status {
	case HealthStatusOK:
		return "ok"
	case HealthStatusDown:
		return "warn"
	case HealthStatusDegraded:
		return "degraded"
	case HealthStatusDisabled:
		return "disabled"
	default:
		return "unknown"
	}
}

func healthStatusLabel(status HealthStatus) string {
	switch status {
	case HealthStatusOK:
		return "ok"
	case HealthStatusDown:
		return "down"
	case HealthStatusDegraded:
		return "degraded"
	case HealthStatusDisabled:
		return "disabled"
	default:
		return "unknown"
	}
}
