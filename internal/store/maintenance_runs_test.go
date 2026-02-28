package store

import (
	"encoding/json"
	"testing"
	"time"
)

func TestNormalizeMaintenanceRun(t *testing.T) {
	startedAt := time.Now().UTC().Add(-time.Minute)
	run, err := normalizeMaintenanceRun(MaintenanceRun{
		JobName:     " cleanup-retention ",
		StartedAt:   startedAt,
		FinishedAt:  startedAt.Add(time.Minute),
		Success:     true,
		DetailsJSON: json.RawMessage(`{"deleted":10}`),
	})
	if err != nil {
		t.Fatalf("normalizeMaintenanceRun failed: %v", err)
	}
	if run.JobName != "cleanup-retention" {
		t.Fatalf("unexpected job name: %q", run.JobName)
	}
	if string(run.DetailsJSON) != `{"deleted":10}` {
		t.Fatalf("unexpected details json: %s", string(run.DetailsJSON))
	}
}

func TestNormalizeMaintenanceRunRequiresJobName(t *testing.T) {
	if _, err := normalizeMaintenanceRun(MaintenanceRun{}); err == nil {
		t.Fatal("expected error for empty job name")
	}
}

func TestNormalizeMaintenanceRunRejectsInvalidJSON(t *testing.T) {
	if _, err := normalizeMaintenanceRun(MaintenanceRun{JobName: "cleanup-retention", DetailsJSON: json.RawMessage("{")}); err == nil {
		t.Fatal("expected invalid json error")
	}
}

func TestNormalizeMaintenanceRunFixesFinishedAt(t *testing.T) {
	startedAt := time.Now().UTC()
	run, err := normalizeMaintenanceRun(MaintenanceRun{
		JobName:    "cleanup-retention",
		StartedAt:  startedAt,
		FinishedAt: startedAt.Add(-time.Second),
	})
	if err != nil {
		t.Fatalf("normalizeMaintenanceRun failed: %v", err)
	}
	if !run.FinishedAt.Equal(startedAt) {
		t.Fatalf("expected finished_at normalized to started_at, got %s", run.FinishedAt)
	}
}
