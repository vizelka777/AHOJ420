package adminui

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/houbamydar/AHOJ420/internal/store"
)

func TestSystemHealthServiceDependencyStatusMapping(t *testing.T) {
	svc := &SystemHealthService{
		postgresProbe: func(ctx context.Context) error { return nil },
		redisProbe:    func(ctx context.Context) error { return errors.New("redis down") },
		cfg: normalizeSystemHealthConfig(SystemHealthConfig{
			MailerConfigured: true,
			SMSConfigured:    true,
		}),
	}

	snapshot, err := svc.GetSystemHealthSnapshot(context.Background())
	if err != nil {
		t.Fatalf("GetSystemHealthSnapshot failed: %v", err)
	}
	if snapshot.Postgres.Status != HealthStatusOK {
		t.Fatalf("expected postgres status ok, got %s", snapshot.Postgres.Status)
	}
	if snapshot.Redis.Status != HealthStatusDown {
		t.Fatalf("expected redis status down, got %s", snapshot.Redis.Status)
	}
}

func TestSystemHealthServiceDeliveryStatus(t *testing.T) {
	svc := &SystemHealthService{
		cfg: normalizeSystemHealthConfig(SystemHealthConfig{
			MailerConfigured: false,
			SMSConfigured:    true,
		}),
	}

	snapshot, err := svc.GetSystemHealthSnapshot(context.Background())
	if err != nil {
		t.Fatalf("GetSystemHealthSnapshot failed: %v", err)
	}
	if snapshot.Mailer.Status != HealthStatusDisabled {
		t.Fatalf("expected mailer disabled, got %s", snapshot.Mailer.Status)
	}
	if snapshot.SMS.Status != HealthStatusOK {
		t.Fatalf("expected sms ok, got %s", snapshot.SMS.Status)
	}
}

func TestSystemHealthServiceRecentFailuresAndRetentionInfo(t *testing.T) {
	now := time.Now().UTC()
	maintenanceStore := &fakeHealthRunStore{
		runs: []store.MaintenanceRun{
			{
				ID:          2,
				JobName:     "cleanup-retention",
				StartedAt:   now.Add(-2 * time.Hour),
				FinishedAt:  now.Add(-119 * time.Minute),
				Success:     false,
				DetailsJSON: json.RawMessage(`{"dry_run":false,"error":"db lock timeout"}`),
			},
			{
				ID:          1,
				JobName:     "cleanup-retention",
				StartedAt:   now.Add(-4 * time.Hour),
				FinishedAt:  now.Add(-239 * time.Minute),
				Success:     true,
				DetailsJSON: json.RawMessage(`{"dry_run":false,"deleted_total":42}`),
			},
		},
	}
	auditStore := &fakeHealthAuditStore{
		entries: []store.AdminAuditEntry{
			{
				ID:          10,
				CreatedAt:   now.Add(-30 * time.Minute),
				Action:      "admin.user.delete.failure",
				Success:     false,
				DetailsJSON: json.RawMessage(`{"error":"session_cleanup_failed"}`),
			},
		},
	}

	svc := &SystemHealthService{
		maintenanceRuns: maintenanceStore,
		auditStore:      auditStore,
		cfg: normalizeSystemHealthConfig(SystemHealthConfig{
			AdminAuditRetentionDays:         180,
			UserSecurityEventsRetentionDays: 90,
			RecentFailuresLimit:             10,
		}),
	}

	snapshot, err := svc.GetSystemHealthSnapshot(context.Background())
	if err != nil {
		t.Fatalf("GetSystemHealthSnapshot failed: %v", err)
	}
	if snapshot.Retention.LastRun == nil {
		t.Fatal("expected retention last run")
	}
	if snapshot.Retention.LastFailure == nil || snapshot.Retention.LastFailure.Error != "db lock timeout" {
		t.Fatalf("expected retention last failure with error, got %+v", snapshot.Retention.LastFailure)
	}
	if snapshot.Retention.LastSuccess == nil || snapshot.Retention.LastSuccess.DeletedTotal != 42 {
		t.Fatalf("expected retention last success deleted_total=42, got %+v", snapshot.Retention.LastSuccess)
	}
	if len(snapshot.RecentFailures) == 0 {
		t.Fatal("expected recent failures")
	}
}

type fakeHealthRunStore struct {
	runs []store.MaintenanceRun
}

func (f *fakeHealthRunStore) ListMaintenanceRuns(ctx context.Context, opts store.MaintenanceRunListOptions) ([]store.MaintenanceRun, error) {
	limit := opts.Limit
	if limit <= 0 || limit > len(f.runs) {
		limit = len(f.runs)
	}
	out := make([]store.MaintenanceRun, 0, limit)
	for i := 0; i < limit; i++ {
		out = append(out, f.runs[i])
	}
	return out, nil
}

type fakeHealthAuditStore struct {
	entries []store.AdminAuditEntry
}

func (f *fakeHealthAuditStore) CreateAdminAuditEntry(ctx context.Context, entry store.AdminAuditEntry) error {
	return nil
}

func (f *fakeHealthAuditStore) ListAdminAuditEntries(ctx context.Context, opts store.AdminAuditListOptions) ([]store.AdminAuditEntry, error) {
	out := make([]store.AdminAuditEntry, 0, len(f.entries))
	for _, entry := range f.entries {
		if opts.Success != nil && entry.Success != *opts.Success {
			continue
		}
		out = append(out, entry)
	}
	if opts.Limit > 0 && len(out) > opts.Limit {
		out = out[:opts.Limit]
	}
	return out, nil
}

func (f *fakeHealthAuditStore) CountAdminAuditFailuresSince(ctx context.Context, since time.Time) (int, error) {
	count := 0
	for _, entry := range f.entries {
		if !entry.Success && !entry.CreatedAt.Before(since) {
			count++
		}
	}
	return count, nil
}
