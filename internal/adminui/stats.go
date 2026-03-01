package adminui

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"
)

const (
	statsTopClientsLimit = 10
)

type StatsRange string

const (
	StatsRange7d  StatsRange = "7d"
	StatsRange30d StatsRange = "30d"
	StatsRange90d StatsRange = "90d"
)

type StatsSummary struct {
	NewUsers                int `json:"new_users"`
	LoginSuccesses          int `json:"login_successes"`
	LoginFailures           int `json:"login_failures"`
	RecoveryRequests        int `json:"recovery_requests"`
	RecoverySuccesses       int `json:"recovery_successes"`
	PasskeysAdded           int `json:"passkeys_added"`
	PasskeysRevoked         int `json:"passkeys_revoked"`
	ActiveOIDCClientsCount  int `json:"active_oidc_clients_count"`
	UniqueUsersWithActivity int `json:"unique_users_with_activity"`
}

type StatsTimeSeriesPoint struct {
	Date  string `json:"date"`
	Value int    `json:"value"`
}

type StatsLoginSeriesPoint struct {
	Date    string `json:"date"`
	Success int    `json:"success"`
	Failure int    `json:"failure"`
}

type StatsRecoverySeriesPoint struct {
	Date      string `json:"date"`
	Requested int    `json:"requested"`
	Success   int    `json:"success"`
	Failure   int    `json:"failure"`
}

type StatsPasskeySeriesPoint struct {
	Date    string `json:"date"`
	Added   int    `json:"added"`
	Revoked int    `json:"revoked"`
}

type StatsTopClientPoint struct {
	ClientID      string `json:"client_id"`
	ActivityCount int    `json:"activity_count"`
}

type StatsSnapshot struct {
	Range          StatsRange                 `json:"range"`
	Days           int                        `json:"days"`
	GeneratedAt    time.Time                  `json:"generated_at"`
	StartDate      string                     `json:"start_date"`
	EndDate        string                     `json:"end_date"`
	Summary        StatsSummary               `json:"summary"`
	LoginSeries    []StatsLoginSeriesPoint    `json:"login_series"`
	RecoverySeries []StatsRecoverySeriesPoint `json:"recovery_series"`
	NewUsersSeries []StatsTimeSeriesPoint     `json:"new_users_series"`
	PasskeySeries  []StatsPasskeySeriesPoint  `json:"passkey_series"`
	TopClients     []StatsTopClientPoint      `json:"top_clients"`
}

type StatsProvider interface {
	GetStatsSnapshot(ctx context.Context, statsRange StatsRange) (*StatsSnapshot, error)
}

type StatsService struct {
	db  *sql.DB
	now func() time.Time
}

func NewStatsService(db *sql.DB, now func() time.Time) *StatsService {
	if now == nil {
		now = time.Now
	}
	return &StatsService{
		db:  db,
		now: now,
	}
}

func ParseStatsRange(raw string) StatsRange {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case string(StatsRange7d):
		return StatsRange7d
	case string(StatsRange90d):
		return StatsRange90d
	default:
		return StatsRange30d
	}
}

func (r StatsRange) Days() int {
	switch ParseStatsRange(string(r)) {
	case StatsRange7d:
		return 7
	case StatsRange90d:
		return 90
	default:
		return 30
	}
}

func (r StatsRange) String() string {
	return string(ParseStatsRange(string(r)))
}

func NewEmptyStatsSnapshot(statsRange StatsRange, now time.Time) *StatsSnapshot {
	statsRange = ParseStatsRange(string(statsRange))
	days := statsRange.Days()
	startUTC, _ := statsWindowUTC(now, days)
	labels := statsDateLabelsUTC(startUTC, days)

	snapshot := &StatsSnapshot{
		Range:          statsRange,
		Days:           days,
		GeneratedAt:    now.UTC(),
		StartDate:      labels[0],
		EndDate:        labels[len(labels)-1],
		LoginSeries:    buildStatsLoginSeries(labels, map[string]statsLoginCounts{}),
		RecoverySeries: buildStatsRecoverySeries(labels, map[string]statsRecoveryCounts{}),
		NewUsersSeries: buildStatsTimeSeries(labels, map[string]int{}),
		PasskeySeries:  buildStatsPasskeySeries(labels, map[string]statsPasskeyCounts{}),
		TopClients:     []StatsTopClientPoint{},
	}
	return snapshot
}

func (s *StatsService) GetStatsSnapshot(ctx context.Context, statsRange StatsRange) (*StatsSnapshot, error) {
	statsRange = ParseStatsRange(string(statsRange))
	now := time.Now().UTC()
	if s != nil && s.now != nil {
		now = s.now().UTC()
	}
	if s == nil || s.db == nil {
		return NewEmptyStatsSnapshot(statsRange, now), nil
	}

	days := statsRange.Days()
	startUTC, endExclusiveUTC := statsWindowUTC(now, days)
	labels := statsDateLabelsUTC(startUTC, days)

	loginByDate := map[string]statsLoginCounts{}
	recoveryByDate := map[string]statsRecoveryCounts{}
	passkeyByDate := map[string]statsPasskeyCounts{}

	eventRows, err := s.db.QueryContext(ctx, `
		SELECT
			((created_at AT TIME ZONE 'UTC')::date)::text AS day,
			COUNT(*) FILTER (WHERE event_type = 'login_success')::bigint AS login_success,
			COUNT(*) FILTER (WHERE event_type = 'login_failure')::bigint AS login_failure,
			COUNT(*) FILTER (WHERE event_type = 'recovery_requested')::bigint AS recovery_requested,
			COUNT(*) FILTER (WHERE event_type = 'recovery_success')::bigint AS recovery_success,
			COUNT(*) FILTER (WHERE event_type = 'recovery_failure')::bigint AS recovery_failure,
			COUNT(*) FILTER (WHERE event_type = 'passkey_added')::bigint AS passkey_added,
			COUNT(*) FILTER (WHERE event_type = 'passkey_revoked')::bigint AS passkey_revoked
		FROM user_security_events
		WHERE created_at >= $1
		  AND created_at < $2
		  AND event_type IN (
			'login_success',
			'login_failure',
			'recovery_requested',
			'recovery_success',
			'recovery_failure',
			'passkey_added',
			'passkey_revoked'
		  )
		GROUP BY day
		ORDER BY day ASC
	`, startUTC, endExclusiveUTC)
	if err != nil {
		return nil, fmt.Errorf("query user security events stats: %w", err)
	}
	defer eventRows.Close()

	for eventRows.Next() {
		var (
			day               string
			loginSuccess      int
			loginFailure      int
			recoveryRequested int
			recoverySuccess   int
			recoveryFailure   int
			passkeyAdded      int
			passkeyRevoked    int
		)
		if err := eventRows.Scan(
			&day,
			&loginSuccess,
			&loginFailure,
			&recoveryRequested,
			&recoverySuccess,
			&recoveryFailure,
			&passkeyAdded,
			&passkeyRevoked,
		); err != nil {
			return nil, fmt.Errorf("scan user security events stats: %w", err)
		}
		key := strings.TrimSpace(day)
		if key == "" {
			continue
		}
		loginByDate[key] = statsLoginCounts{
			Success: loginSuccess,
			Failure: loginFailure,
		}
		recoveryByDate[key] = statsRecoveryCounts{
			Requested: recoveryRequested,
			Success:   recoverySuccess,
			Failure:   recoveryFailure,
		}
		passkeyByDate[key] = statsPasskeyCounts{
			Added:   passkeyAdded,
			Revoked: passkeyRevoked,
		}
	}
	if err := eventRows.Err(); err != nil {
		return nil, fmt.Errorf("iterate user security events stats: %w", err)
	}

	newUsersByDate := map[string]int{}
	userRows, err := s.db.QueryContext(ctx, `
		SELECT
			((created_at AT TIME ZONE 'UTC')::date)::text AS day,
			COUNT(*)::bigint AS users_count
		FROM users
		WHERE created_at >= $1
		  AND created_at < $2
		GROUP BY day
		ORDER BY day ASC
	`, startUTC, endExclusiveUTC)
	if err != nil {
		return nil, fmt.Errorf("query users stats: %w", err)
	}
	defer userRows.Close()

	for userRows.Next() {
		var day string
		var count int
		if err := userRows.Scan(&day, &count); err != nil {
			return nil, fmt.Errorf("scan users stats: %w", err)
		}
		key := strings.TrimSpace(day)
		if key == "" {
			continue
		}
		newUsersByDate[key] = count
	}
	if err := userRows.Err(); err != nil {
		return nil, fmt.Errorf("iterate users stats: %w", err)
	}

	topClientsRows, err := s.db.QueryContext(ctx, `
		SELECT client_id, COUNT(*)::bigint AS activity_count
		FROM user_oidc_clients
		WHERE last_seen_at >= $1
		  AND last_seen_at < $2
		GROUP BY client_id
		ORDER BY activity_count DESC, client_id ASC
		LIMIT $3
	`, startUTC, endExclusiveUTC, statsTopClientsLimit)
	if err != nil {
		return nil, fmt.Errorf("query top oidc clients stats: %w", err)
	}
	defer topClientsRows.Close()

	topClients := make([]StatsTopClientPoint, 0, statsTopClientsLimit)
	for topClientsRows.Next() {
		var clientID string
		var activityCount int
		if err := topClientsRows.Scan(&clientID, &activityCount); err != nil {
			return nil, fmt.Errorf("scan top oidc clients stats: %w", err)
		}
		clientID = strings.TrimSpace(clientID)
		if clientID == "" {
			continue
		}
		topClients = append(topClients, StatsTopClientPoint{
			ClientID:      clientID,
			ActivityCount: activityCount,
		})
	}
	if err := topClientsRows.Err(); err != nil {
		return nil, fmt.Errorf("iterate top oidc clients stats: %w", err)
	}

	activeOIDCClientsCount := 0
	if err := s.db.QueryRowContext(ctx, `
		SELECT COUNT(DISTINCT client_id)::bigint
		FROM user_oidc_clients
		WHERE last_seen_at >= $1
		  AND last_seen_at < $2
	`, startUTC, endExclusiveUTC).Scan(&activeOIDCClientsCount); err != nil {
		return nil, fmt.Errorf("count active oidc clients: %w", err)
	}

	uniqueUsersWithActivity := 0
	if err := s.db.QueryRowContext(ctx, `
		SELECT COUNT(DISTINCT user_id)::bigint
		FROM user_security_events
		WHERE created_at >= $1
		  AND created_at < $2
	`, startUTC, endExclusiveUTC).Scan(&uniqueUsersWithActivity); err != nil {
		return nil, fmt.Errorf("count users with activity: %w", err)
	}

	snapshot := &StatsSnapshot{
		Range:          statsRange,
		Days:           days,
		GeneratedAt:    now,
		StartDate:      labels[0],
		EndDate:        labels[len(labels)-1],
		LoginSeries:    buildStatsLoginSeries(labels, loginByDate),
		RecoverySeries: buildStatsRecoverySeries(labels, recoveryByDate),
		NewUsersSeries: buildStatsTimeSeries(labels, newUsersByDate),
		PasskeySeries:  buildStatsPasskeySeries(labels, passkeyByDate),
		TopClients:     topClients,
	}
	snapshot.Summary = buildStatsSummary(snapshot, activeOIDCClientsCount, uniqueUsersWithActivity)
	return snapshot, nil
}

type statsLoginCounts struct {
	Success int
	Failure int
}

type statsRecoveryCounts struct {
	Requested int
	Success   int
	Failure   int
}

type statsPasskeyCounts struct {
	Added   int
	Revoked int
}

func statsWindowUTC(now time.Time, days int) (time.Time, time.Time) {
	if days <= 0 {
		days = StatsRange30d.Days()
	}
	endExclusiveUTC := now.UTC().Truncate(24 * time.Hour).Add(24 * time.Hour)
	startUTC := endExclusiveUTC.AddDate(0, 0, -days)
	return startUTC, endExclusiveUTC
}

func statsDateLabelsUTC(startUTC time.Time, days int) []string {
	if days <= 0 {
		return []string{}
	}
	labels := make([]string, 0, days)
	day := startUTC.UTC().Truncate(24 * time.Hour)
	for idx := 0; idx < days; idx++ {
		labels = append(labels, day.Format("2006-01-02"))
		day = day.Add(24 * time.Hour)
	}
	return labels
}

func buildStatsTimeSeries(labels []string, valuesByDate map[string]int) []StatsTimeSeriesPoint {
	points := make([]StatsTimeSeriesPoint, 0, len(labels))
	for _, date := range labels {
		points = append(points, StatsTimeSeriesPoint{
			Date:  date,
			Value: valuesByDate[date],
		})
	}
	return points
}

func buildStatsLoginSeries(labels []string, valuesByDate map[string]statsLoginCounts) []StatsLoginSeriesPoint {
	points := make([]StatsLoginSeriesPoint, 0, len(labels))
	for _, date := range labels {
		values := valuesByDate[date]
		points = append(points, StatsLoginSeriesPoint{
			Date:    date,
			Success: values.Success,
			Failure: values.Failure,
		})
	}
	return points
}

func buildStatsRecoverySeries(labels []string, valuesByDate map[string]statsRecoveryCounts) []StatsRecoverySeriesPoint {
	points := make([]StatsRecoverySeriesPoint, 0, len(labels))
	for _, date := range labels {
		values := valuesByDate[date]
		points = append(points, StatsRecoverySeriesPoint{
			Date:      date,
			Requested: values.Requested,
			Success:   values.Success,
			Failure:   values.Failure,
		})
	}
	return points
}

func buildStatsPasskeySeries(labels []string, valuesByDate map[string]statsPasskeyCounts) []StatsPasskeySeriesPoint {
	points := make([]StatsPasskeySeriesPoint, 0, len(labels))
	for _, date := range labels {
		values := valuesByDate[date]
		points = append(points, StatsPasskeySeriesPoint{
			Date:    date,
			Added:   values.Added,
			Revoked: values.Revoked,
		})
	}
	return points
}

func buildStatsSummary(snapshot *StatsSnapshot, activeOIDCClientsCount int, uniqueUsersWithActivity int) StatsSummary {
	summary := StatsSummary{
		ActiveOIDCClientsCount:  activeOIDCClientsCount,
		UniqueUsersWithActivity: uniqueUsersWithActivity,
	}
	for _, point := range snapshot.NewUsersSeries {
		summary.NewUsers += point.Value
	}
	for _, point := range snapshot.LoginSeries {
		summary.LoginSuccesses += point.Success
		summary.LoginFailures += point.Failure
	}
	for _, point := range snapshot.RecoverySeries {
		summary.RecoveryRequests += point.Requested
		summary.RecoverySuccesses += point.Success
	}
	for _, point := range snapshot.PasskeySeries {
		summary.PasskeysAdded += point.Added
		summary.PasskeysRevoked += point.Revoked
	}
	return summary
}
