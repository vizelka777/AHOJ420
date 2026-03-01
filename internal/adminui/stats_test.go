package adminui

import (
	"testing"
	"time"
)

func TestParseStatsRange(t *testing.T) {
	cases := []struct {
		name     string
		input    string
		expected StatsRange
	}{
		{name: "default empty", input: "", expected: StatsRange30d},
		{name: "default unknown", input: "365d", expected: StatsRange30d},
		{name: "7d", input: "7d", expected: StatsRange7d},
		{name: "90d", input: "90d", expected: StatsRange90d},
		{name: "30d explicit", input: "30d", expected: StatsRange30d},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ParseStatsRange(tc.input)
			if got != tc.expected {
				t.Fatalf("expected %s, got %s", tc.expected, got)
			}
		})
	}
}

func TestNewEmptyStatsSnapshotFillsFullRange(t *testing.T) {
	now := time.Date(2026, time.February, 5, 12, 30, 0, 0, time.UTC)
	snapshot := NewEmptyStatsSnapshot(StatsRange7d, now)

	if snapshot.Range != StatsRange7d {
		t.Fatalf("expected range 7d, got %s", snapshot.Range)
	}
	if snapshot.Days != 7 {
		t.Fatalf("expected 7 days, got %d", snapshot.Days)
	}
	if snapshot.StartDate != "2026-01-30" {
		t.Fatalf("expected start date 2026-01-30, got %s", snapshot.StartDate)
	}
	if snapshot.EndDate != "2026-02-05" {
		t.Fatalf("expected end date 2026-02-05, got %s", snapshot.EndDate)
	}
	if len(snapshot.LoginSeries) != 7 || len(snapshot.RecoverySeries) != 7 || len(snapshot.PasskeySeries) != 7 {
		t.Fatalf("expected full 7-day series, got login=%d recovery=%d passkey=%d", len(snapshot.LoginSeries), len(snapshot.RecoverySeries), len(snapshot.PasskeySeries))
	}
}

func TestStatsSeriesFillMissingDaysWithZeros(t *testing.T) {
	labels := []string{"2026-02-01", "2026-02-02", "2026-02-03"}

	login := buildStatsLoginSeries(labels, map[string]statsLoginCounts{
		"2026-02-01": {Success: 3, Failure: 1},
		"2026-02-03": {Success: 2, Failure: 0},
	})
	recovery := buildStatsRecoverySeries(labels, map[string]statsRecoveryCounts{
		"2026-02-01": {Requested: 1, Success: 1, Failure: 0},
		"2026-02-03": {Requested: 2, Success: 0, Failure: 1},
	})
	passkeys := buildStatsPasskeySeries(labels, map[string]statsPasskeyCounts{
		"2026-02-01": {Added: 2, Revoked: 1},
		"2026-02-03": {Added: 1, Revoked: 0},
	})

	if login[1].Date != "2026-02-02" || login[1].Success != 0 || login[1].Failure != 0 {
		t.Fatalf("expected zero-filled login day, got %+v", login[1])
	}
	if recovery[1].Date != "2026-02-02" || recovery[1].Requested != 0 || recovery[1].Success != 0 || recovery[1].Failure != 0 {
		t.Fatalf("expected zero-filled recovery day, got %+v", recovery[1])
	}
	if passkeys[1].Date != "2026-02-02" || passkeys[1].Added != 0 || passkeys[1].Revoked != 0 {
		t.Fatalf("expected zero-filled passkey day, got %+v", passkeys[1])
	}
}
