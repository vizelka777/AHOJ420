package store

import (
	"context"
	"testing"
	"time"
)

func TestNormalizeRetentionDeleteBatch(t *testing.T) {
	tests := []struct {
		name string
		in   int
		want int
	}{
		{name: "default when non-positive", in: 0, want: 1000},
		{name: "default when negative", in: -10, want: 1000},
		{name: "keeps valid limit", in: 500, want: 500},
		{name: "caps too large", in: 12000, want: 10000},
	}

	for _, tc := range tests {
		if got := normalizeRetentionDeleteBatch(tc.in); got != tc.want {
			t.Fatalf("%s: normalizeRetentionDeleteBatch(%d)=%d want %d", tc.name, tc.in, got, tc.want)
		}
	}
}

func TestRetentionMethodsRequireCutoff(t *testing.T) {
	s := &Store{}
	ctx := context.Background()

	if _, err := s.CountAdminAuditEntriesOlderThan(ctx, time.Time{}); err == nil {
		t.Fatal("CountAdminAuditEntriesOlderThan expected error for zero cutoff")
	}
	if _, err := s.DeleteAdminAuditEntriesOlderThan(ctx, time.Time{}, 100); err == nil {
		t.Fatal("DeleteAdminAuditEntriesOlderThan expected error for zero cutoff")
	}
	if _, err := s.CountUserSecurityEventsOlderThan(ctx, time.Time{}); err == nil {
		t.Fatal("CountUserSecurityEventsOlderThan expected error for zero cutoff")
	}
	if _, err := s.DeleteUserSecurityEventsOlderThan(ctx, time.Time{}, 100); err == nil {
		t.Fatal("DeleteUserSecurityEventsOlderThan expected error for zero cutoff")
	}
}
