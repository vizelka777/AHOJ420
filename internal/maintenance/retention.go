package maintenance

import (
	"context"
	"log"
	"time"
)

const (
	DefaultRetentionDays   = 180
	DefaultDeleteBatchSize = 1000
	MaxDeleteBatchSize     = 10000
)

type RetentionStore interface {
	CountAdminAuditEntriesOlderThan(ctx context.Context, cutoff time.Time) (int64, error)
	DeleteAdminAuditEntriesOlderThan(ctx context.Context, cutoff time.Time, limit int) (int64, error)
	CountUserSecurityEventsOlderThan(ctx context.Context, cutoff time.Time) (int64, error)
	DeleteUserSecurityEventsOlderThan(ctx context.Context, cutoff time.Time, limit int) (int64, error)
}

type Logger interface {
	Printf(format string, v ...any)
}

type RetentionConfig struct {
	AdminAuditRetentionDays         int
	UserSecurityEventsRetentionDays int
	DeleteBatchSize                 int
	IncludeAdminAudit               bool
	IncludeUserSecurityEvents       bool
	SelectionExplicit               bool
	Logger                          Logger
	Now                             func() time.Time
}

type RetentionTableResult struct {
	Table         string
	RetentionDays int
	Enabled       bool
	Skipped       bool
	Cutoff        time.Time
	EligibleCount int64
	DeletedCount  int64
	Batches       int
	DryRun        bool
}

type RetentionRunResult struct {
	DryRun          bool
	BatchSize       int
	StartedAt       time.Time
	FinishedAt      time.Time
	TablesProcessed int
	TablesSkipped   int
	TotalEligible   int64
	TotalDeleted    int64
	Results         []RetentionTableResult
}

func RunRetentionCleanup(ctx context.Context, store RetentionStore, cfg RetentionConfig, dryRun bool) (RetentionRunResult, error) {
	cfg = normalizeRetentionConfig(cfg)
	now := cfg.Now().UTC()
	logger := cfg.Logger

	result := RetentionRunResult{
		DryRun:    dryRun,
		BatchSize: cfg.DeleteBatchSize,
		StartedAt: now,
		Results:   make([]RetentionTableResult, 0, 2),
	}

	logger.Printf(
		"retention.cleanup.start dry_run=%t batch_size=%d include_admin_audit=%t include_user_security_events=%t admin_audit_retention_days=%d user_security_events_retention_days=%d",
		dryRun,
		cfg.DeleteBatchSize,
		cfg.IncludeAdminAudit,
		cfg.IncludeUserSecurityEvents,
		cfg.AdminAuditRetentionDays,
		cfg.UserSecurityEventsRetentionDays,
	)

	if cfg.IncludeAdminAudit {
		adminResult, err := runTableCleanup(ctx, store.CountAdminAuditEntriesOlderThan, store.DeleteAdminAuditEntriesOlderThan, tableCleanupInput{
			Table:         "admin_audit_log",
			RetentionDays: cfg.AdminAuditRetentionDays,
			BatchSize:     cfg.DeleteBatchSize,
			DryRun:        dryRun,
			Now:           now,
			Logger:        logger,
		})
		result.Results = append(result.Results, adminResult)
		if err != nil {
			logger.Printf("retention.cleanup.error table=admin_audit_log err=%v", err)
			finalizeRetentionRunResult(&result, cfg.Now().UTC())
			return result, err
		}
	}

	if cfg.IncludeUserSecurityEvents {
		userResult, err := runTableCleanup(ctx, store.CountUserSecurityEventsOlderThan, store.DeleteUserSecurityEventsOlderThan, tableCleanupInput{
			Table:         "user_security_events",
			RetentionDays: cfg.UserSecurityEventsRetentionDays,
			BatchSize:     cfg.DeleteBatchSize,
			DryRun:        dryRun,
			Now:           now,
			Logger:        logger,
		})
		result.Results = append(result.Results, userResult)
		if err != nil {
			logger.Printf("retention.cleanup.error table=user_security_events err=%v", err)
			finalizeRetentionRunResult(&result, cfg.Now().UTC())
			return result, err
		}
	}

	finalizeRetentionRunResult(&result, cfg.Now().UTC())
	logger.Printf(
		"retention.cleanup.done dry_run=%t batch_size=%d tables_processed=%d tables_skipped=%d eligible_total=%d deleted_total=%d",
		dryRun,
		cfg.DeleteBatchSize,
		result.TablesProcessed,
		result.TablesSkipped,
		result.TotalEligible,
		result.TotalDeleted,
	)
	return result, nil
}

type tableCleanupInput struct {
	Table         string
	RetentionDays int
	BatchSize     int
	DryRun        bool
	Now           time.Time
	Logger        Logger
}

type countOlderThanFunc func(ctx context.Context, cutoff time.Time) (int64, error)
type deleteOlderThanFunc func(ctx context.Context, cutoff time.Time, limit int) (int64, error)

func runTableCleanup(ctx context.Context, countFn countOlderThanFunc, deleteFn deleteOlderThanFunc, in tableCleanupInput) (RetentionTableResult, error) {
	result := RetentionTableResult{
		Table:         in.Table,
		RetentionDays: in.RetentionDays,
		Enabled:       in.RetentionDays > 0,
		DryRun:        in.DryRun,
	}
	if in.RetentionDays <= 0 {
		result.Skipped = true
		in.Logger.Printf("retention.cleanup.done table=%s enabled=false skipped=true reason=retention_disabled", in.Table)
		return result, nil
	}

	cutoff := in.Now.UTC().AddDate(0, 0, -in.RetentionDays)
	result.Cutoff = cutoff

	eligibleCount, err := countFn(ctx, cutoff)
	if err != nil {
		return result, err
	}
	result.EligibleCount = eligibleCount

	in.Logger.Printf("retention.cleanup.start table=%s cutoff=%s dry_run=%t eligible=%d batch_size=%d", in.Table, cutoff.Format(time.RFC3339), in.DryRun, eligibleCount, in.BatchSize)

	if in.DryRun {
		in.Logger.Printf("retention.cleanup.done table=%s cutoff=%s dry_run=true skipped=false eligible=%d deleted=0 batches=0", in.Table, cutoff.Format(time.RFC3339), eligibleCount)
		return result, nil
	}

	for {
		deleted, err := deleteFn(ctx, cutoff, in.BatchSize)
		if err != nil {
			return result, err
		}
		if deleted <= 0 {
			break
		}
		result.Batches++
		result.DeletedCount += deleted
		in.Logger.Printf("retention.cleanup.batch table=%s cutoff=%s batch=%d deleted=%d deleted_total=%d", in.Table, cutoff.Format(time.RFC3339), result.Batches, deleted, result.DeletedCount)
	}

	in.Logger.Printf("retention.cleanup.done table=%s cutoff=%s dry_run=false skipped=false eligible=%d deleted=%d batches=%d", in.Table, cutoff.Format(time.RFC3339), result.EligibleCount, result.DeletedCount, result.Batches)
	return result, nil
}

func normalizeRetentionConfig(cfg RetentionConfig) RetentionConfig {
	if cfg.DeleteBatchSize <= 0 {
		cfg.DeleteBatchSize = DefaultDeleteBatchSize
	} else if cfg.DeleteBatchSize > MaxDeleteBatchSize {
		cfg.DeleteBatchSize = MaxDeleteBatchSize
	}
	if cfg.Logger == nil {
		cfg.Logger = log.Default()
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if !cfg.SelectionExplicit {
		cfg.IncludeAdminAudit = true
		cfg.IncludeUserSecurityEvents = true
	} else if !cfg.IncludeAdminAudit && !cfg.IncludeUserSecurityEvents {
		cfg.IncludeAdminAudit = true
		cfg.IncludeUserSecurityEvents = true
	}
	return cfg
}

func finalizeRetentionRunResult(result *RetentionRunResult, finishedAt time.Time) {
	result.FinishedAt = finishedAt
	result.TablesProcessed = len(result.Results)
	result.TablesSkipped = 0
	result.TotalEligible = 0
	result.TotalDeleted = 0
	for _, item := range result.Results {
		if item.Skipped {
			result.TablesSkipped++
		}
		result.TotalEligible += item.EligibleCount
		result.TotalDeleted += item.DeletedCount
	}
}
