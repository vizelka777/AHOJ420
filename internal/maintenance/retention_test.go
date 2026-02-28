package maintenance

import (
	"bytes"
	"context"
	"errors"
	"log"
	"testing"
	"time"
)

func TestRunRetentionCleanupCountsOlderThanCutoff(t *testing.T) {
	now := time.Date(2026, time.February, 28, 12, 0, 0, 0, time.UTC)
	cutoff := now.AddDate(0, 0, -30)
	store := &fakeRetentionStore{
		adminRows: []time.Time{
			cutoff.Add(-time.Second),
			cutoff.Add(-2 * time.Hour),
			cutoff,
			cutoff.Add(time.Second),
		},
		userRows: []time.Time{
			cutoff.Add(-time.Minute),
			cutoff.Add(2 * time.Minute),
		},
	}

	result, err := RunRetentionCleanup(context.Background(), store, RetentionConfig{
		AdminAuditRetentionDays:         30,
		UserSecurityEventsRetentionDays: 30,
		Now:                             func() time.Time { return now },
	}, true)
	if err != nil {
		t.Fatalf("RunRetentionCleanup failed: %v", err)
	}

	adminResult := mustTableResult(t, result, "admin_audit_log")
	if adminResult.EligibleCount != 2 {
		t.Fatalf("admin eligible count=%d want 2", adminResult.EligibleCount)
	}
	userResult := mustTableResult(t, result, "user_security_events")
	if userResult.EligibleCount != 1 {
		t.Fatalf("user eligible count=%d want 1", userResult.EligibleCount)
	}
}

func TestRunRetentionCleanupDryRunDoesNotDelete(t *testing.T) {
	now := time.Date(2026, time.February, 28, 12, 0, 0, 0, time.UTC)
	store := &fakeRetentionStore{
		adminRows: seededRows(now, 5, 45),
		userRows:  seededRows(now, 4, 45),
	}
	adminBefore := len(store.adminRows)
	userBefore := len(store.userRows)

	result, err := RunRetentionCleanup(context.Background(), store, RetentionConfig{
		AdminAuditRetentionDays:         30,
		UserSecurityEventsRetentionDays: 30,
		DeleteBatchSize:                 2,
		Now:                             func() time.Time { return now },
	}, true)
	if err != nil {
		t.Fatalf("RunRetentionCleanup failed: %v", err)
	}

	if len(store.adminRows) != adminBefore || len(store.userRows) != userBefore {
		t.Fatalf("dry-run mutated rows: admin=%d/%d user=%d/%d", len(store.adminRows), adminBefore, len(store.userRows), userBefore)
	}
	for _, table := range result.Results {
		if table.DeletedCount != 0 || table.Batches != 0 {
			t.Fatalf("dry-run table %s deleted=%d batches=%d want 0/0", table.Table, table.DeletedCount, table.Batches)
		}
	}
}

func TestRunRetentionCleanupBatchedDelete(t *testing.T) {
	now := time.Date(2026, time.February, 28, 12, 0, 0, 0, time.UTC)
	store := &fakeRetentionStore{
		adminRows: append(seededRows(now, 5, 60), now.Add(-24*time.Hour)),
	}

	result, err := RunRetentionCleanup(context.Background(), store, RetentionConfig{
		AdminAuditRetentionDays:         30,
		UserSecurityEventsRetentionDays: 0,
		DeleteBatchSize:                 2,
		Now:                             func() time.Time { return now },
	}, false)
	if err != nil {
		t.Fatalf("RunRetentionCleanup failed: %v", err)
	}

	adminResult := mustTableResult(t, result, "admin_audit_log")
	if adminResult.DeletedCount != 5 {
		t.Fatalf("deleted=%d want 5", adminResult.DeletedCount)
	}
	if adminResult.Batches != 3 {
		t.Fatalf("batches=%d want 3", adminResult.Batches)
	}
	if len(store.adminRows) != 1 {
		t.Fatalf("remaining admin rows=%d want 1", len(store.adminRows))
	}
	for _, limit := range store.adminDeleteLimits {
		if limit != 2 {
			t.Fatalf("delete called with limit=%d want 2", limit)
		}
	}
}

func TestRunRetentionCleanupDisabledRetentionSkipsTable(t *testing.T) {
	now := time.Date(2026, time.February, 28, 12, 0, 0, 0, time.UTC)
	store := &fakeRetentionStore{
		adminRows: seededRows(now, 3, 90),
		userRows:  seededRows(now, 3, 90),
	}

	result, err := RunRetentionCleanup(context.Background(), store, RetentionConfig{
		AdminAuditRetentionDays:         0,
		UserSecurityEventsRetentionDays: -1,
		DeleteBatchSize:                 50,
		Now:                             func() time.Time { return now },
	}, false)
	if err != nil {
		t.Fatalf("RunRetentionCleanup failed: %v", err)
	}

	if len(store.adminDeleteLimits) != 0 || len(store.userDeleteLimits) != 0 {
		t.Fatalf("delete should not run for disabled retention")
	}
	for _, table := range result.Results {
		if table.Enabled {
			t.Fatalf("table %s expected disabled", table.Table)
		}
		if table.EligibleCount != 0 || table.DeletedCount != 0 {
			t.Fatalf("disabled table %s should have 0 counts got eligible=%d deleted=%d", table.Table, table.EligibleCount, table.DeletedCount)
		}
	}
}

func TestRunRetentionCleanupEmptyTable(t *testing.T) {
	now := time.Date(2026, time.February, 28, 12, 0, 0, 0, time.UTC)
	store := &fakeRetentionStore{}

	result, err := RunRetentionCleanup(context.Background(), store, RetentionConfig{
		AdminAuditRetentionDays:         30,
		UserSecurityEventsRetentionDays: 30,
		Now:                             func() time.Time { return now },
	}, false)
	if err != nil {
		t.Fatalf("RunRetentionCleanup failed: %v", err)
	}

	for _, table := range result.Results {
		if table.EligibleCount != 0 || table.DeletedCount != 0 || table.Batches != 0 {
			t.Fatalf("expected zero result for table %s got eligible=%d deleted=%d batches=%d", table.Table, table.EligibleCount, table.DeletedCount, table.Batches)
		}
	}
}

func TestRunRetentionCleanupCutoffBoundary(t *testing.T) {
	now := time.Date(2026, time.February, 28, 12, 0, 0, 0, time.UTC)
	cutoff := now.AddDate(0, 0, -30)
	store := &fakeRetentionStore{
		adminRows: []time.Time{
			cutoff.Add(-time.Nanosecond),
			cutoff,
			cutoff.Add(time.Nanosecond),
		},
	}

	result, err := RunRetentionCleanup(context.Background(), store, RetentionConfig{
		AdminAuditRetentionDays:         30,
		UserSecurityEventsRetentionDays: 0,
		DeleteBatchSize:                 10,
		Now:                             func() time.Time { return now },
	}, false)
	if err != nil {
		t.Fatalf("RunRetentionCleanup failed: %v", err)
	}

	adminResult := mustTableResult(t, result, "admin_audit_log")
	if adminResult.EligibleCount != 1 || adminResult.DeletedCount != 1 {
		t.Fatalf("cutoff boundary mismatch eligible=%d deleted=%d want 1/1", adminResult.EligibleCount, adminResult.DeletedCount)
	}
	if len(store.adminRows) != 2 {
		t.Fatalf("remaining rows=%d want 2", len(store.adminRows))
	}
	for _, ts := range store.adminRows {
		if ts.Before(cutoff) {
			t.Fatalf("found row older than cutoff after cleanup: %s", ts)
		}
	}
}

func TestRunRetentionCleanupCapsBatchSize(t *testing.T) {
	now := time.Date(2026, time.February, 28, 12, 0, 0, 0, time.UTC)
	store := &fakeRetentionStore{adminRows: seededRows(now, 3, 60)}

	_, err := RunRetentionCleanup(context.Background(), store, RetentionConfig{
		AdminAuditRetentionDays:         30,
		UserSecurityEventsRetentionDays: 0,
		DeleteBatchSize:                 MaxDeleteBatchSize + 1,
		Now:                             func() time.Time { return now },
	}, false)
	if err != nil {
		t.Fatalf("RunRetentionCleanup failed: %v", err)
	}
	for _, limit := range store.adminDeleteLimits {
		if limit != MaxDeleteBatchSize {
			t.Fatalf("limit=%d want %d", limit, MaxDeleteBatchSize)
		}
	}
}

func TestRunRetentionCleanupLogsLifecycle(t *testing.T) {
	now := time.Date(2026, time.February, 28, 12, 0, 0, 0, time.UTC)
	store := &fakeRetentionStore{adminRows: seededRows(now, 1, 90)}
	var logBuf bytes.Buffer
	logger := log.New(&logBuf, "", 0)

	_, err := RunRetentionCleanup(context.Background(), store, RetentionConfig{
		AdminAuditRetentionDays:         30,
		UserSecurityEventsRetentionDays: 0,
		DeleteBatchSize:                 1,
		Now:                             func() time.Time { return now },
		Logger:                          logger,
	}, false)
	if err != nil {
		t.Fatalf("RunRetentionCleanup failed: %v", err)
	}
	logs := logBuf.String()
	for _, marker := range []string{"retention.cleanup.start", "retention.cleanup.batch", "retention.cleanup.done"} {
		if !contains(logs, marker) {
			t.Fatalf("expected log marker %q in logs: %s", marker, logs)
		}
	}
}

func TestRunRetentionCleanupReturnsErrorOnStoreFailure(t *testing.T) {
	now := time.Date(2026, time.February, 28, 12, 0, 0, 0, time.UTC)
	store := &fakeRetentionStore{countAdminErr: errors.New("boom")}

	_, err := RunRetentionCleanup(context.Background(), store, RetentionConfig{
		AdminAuditRetentionDays:         30,
		UserSecurityEventsRetentionDays: 30,
		Now:                             func() time.Time { return now },
	}, false)
	if err == nil {
		t.Fatal("expected error")
	}
}

func mustTableResult(t *testing.T, result RetentionRunResult, table string) RetentionTableResult {
	t.Helper()
	for _, item := range result.Results {
		if item.Table == table {
			return item
		}
	}
	t.Fatalf("table result %q not found", table)
	return RetentionTableResult{}
}

func contains(haystack, needle string) bool {
	return bytes.Contains([]byte(haystack), []byte(needle))
}

func seededRows(now time.Time, count int, daysAgo int) []time.Time {
	rows := make([]time.Time, 0, count)
	for i := 0; i < count; i++ {
		rows = append(rows, now.AddDate(0, 0, -daysAgo).Add(-time.Duration(i)*time.Minute))
	}
	return rows
}

type fakeRetentionStore struct {
	adminRows []time.Time
	userRows  []time.Time

	adminDeleteLimits []int
	userDeleteLimits  []int

	countAdminErr error
}

func (f *fakeRetentionStore) CountAdminAuditEntriesOlderThan(ctx context.Context, cutoff time.Time) (int64, error) {
	if f.countAdminErr != nil {
		return 0, f.countAdminErr
	}
	return countOlderThan(f.adminRows, cutoff), nil
}

func (f *fakeRetentionStore) DeleteAdminAuditEntriesOlderThan(ctx context.Context, cutoff time.Time, limit int) (int64, error) {
	f.adminDeleteLimits = append(f.adminDeleteLimits, limit)
	deleted := int64(0)
	filtered := make([]time.Time, 0, len(f.adminRows))
	for _, ts := range f.adminRows {
		if ts.Before(cutoff) && deleted < int64(limit) {
			deleted++
			continue
		}
		filtered = append(filtered, ts)
	}
	f.adminRows = filtered
	return deleted, nil
}

func (f *fakeRetentionStore) CountUserSecurityEventsOlderThan(ctx context.Context, cutoff time.Time) (int64, error) {
	return countOlderThan(f.userRows, cutoff), nil
}

func (f *fakeRetentionStore) DeleteUserSecurityEventsOlderThan(ctx context.Context, cutoff time.Time, limit int) (int64, error) {
	f.userDeleteLimits = append(f.userDeleteLimits, limit)
	deleted := int64(0)
	filtered := make([]time.Time, 0, len(f.userRows))
	for _, ts := range f.userRows {
		if ts.Before(cutoff) && deleted < int64(limit) {
			deleted++
			continue
		}
		filtered = append(filtered, ts)
	}
	f.userRows = filtered
	return deleted, nil
}

func countOlderThan(rows []time.Time, cutoff time.Time) int64 {
	var count int64
	for _, ts := range rows {
		if ts.Before(cutoff) {
			count++
		}
	}
	return count
}
