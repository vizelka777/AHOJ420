package store

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

const (
	defaultMaintenanceRunsLimit = 20
	maxMaintenanceRunsLimit     = 200
)

type MaintenanceRun struct {
	ID          int64
	JobName     string
	StartedAt   time.Time
	FinishedAt  time.Time
	Success     bool
	DetailsJSON json.RawMessage
	CreatedAt   time.Time
}

type MaintenanceRunListOptions struct {
	JobName string
	Success *bool
	Limit   int
}

func (s *Store) CreateMaintenanceRun(ctx context.Context, run MaintenanceRun) error {
	normalized, err := normalizeMaintenanceRun(run)
	if err != nil {
		return err
	}

	_, err = s.db.ExecContext(ctx, `
		INSERT INTO maintenance_runs (job_name, started_at, finished_at, success, details_json)
		VALUES ($1, $2, $3, $4, $5::jsonb)
	`,
		normalized.JobName,
		normalized.StartedAt.UTC(),
		normalized.FinishedAt.UTC(),
		normalized.Success,
		string(normalized.DetailsJSON),
	)
	return err
}

func (s *Store) ListMaintenanceRuns(ctx context.Context, opts MaintenanceRunListOptions) ([]MaintenanceRun, error) {
	limit := opts.Limit
	if limit <= 0 {
		limit = defaultMaintenanceRunsLimit
	}
	if limit > maxMaintenanceRunsLimit {
		limit = maxMaintenanceRunsLimit
	}
	jobName := strings.TrimSpace(opts.JobName)

	var successFilter any
	if opts.Success != nil {
		successFilter = *opts.Success
	}

	rows, err := s.db.QueryContext(ctx, `
		SELECT id, job_name, started_at, finished_at, success, details_json, created_at
		FROM maintenance_runs
		WHERE ($1 = '' OR job_name = $1)
		  AND ($2::boolean IS NULL OR success = $2)
		ORDER BY id DESC
		LIMIT $3
	`, jobName, successFilter, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]MaintenanceRun, 0, limit)
	for rows.Next() {
		var (
			item    MaintenanceRun
			details []byte
		)
		if err := rows.Scan(
			&item.ID,
			&item.JobName,
			&item.StartedAt,
			&item.FinishedAt,
			&item.Success,
			&details,
			&item.CreatedAt,
		); err != nil {
			return nil, err
		}
		item.JobName = strings.TrimSpace(item.JobName)
		item.DetailsJSON = append([]byte(nil), details...)
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func normalizeMaintenanceRun(run MaintenanceRun) (MaintenanceRun, error) {
	run.JobName = strings.TrimSpace(run.JobName)
	if run.JobName == "" {
		return MaintenanceRun{}, fmt.Errorf("maintenance run job_name is required")
	}
	if run.StartedAt.IsZero() {
		run.StartedAt = time.Now().UTC()
	}
	if run.FinishedAt.IsZero() {
		run.FinishedAt = run.StartedAt
	}
	if run.FinishedAt.UTC().Before(run.StartedAt.UTC()) {
		run.FinishedAt = run.StartedAt
	}

	if len(run.DetailsJSON) == 0 {
		run.DetailsJSON = json.RawMessage(`{}`)
		return run, nil
	}

	var decoded any
	if err := json.Unmarshal(run.DetailsJSON, &decoded); err != nil {
		return MaintenanceRun{}, fmt.Errorf("invalid maintenance details_json: %w", err)
	}
	encoded, err := json.Marshal(decoded)
	if err != nil {
		return MaintenanceRun{}, err
	}
	run.DetailsJSON = encoded
	return run, nil
}
