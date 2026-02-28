package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
)

type UserBlockState struct {
	UserID               string
	IsBlocked            bool
	BlockedAt            *time.Time
	BlockedReason        string
	BlockedByAdminUserID string
}

func (s *Store) SetUserBlocked(ctx context.Context, userID string, blocked bool, reason string, blockedByAdminUserID string) error {
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return ErrUserNotFound
	}
	reason = strings.TrimSpace(reason)
	blockedByAdminUserID = strings.TrimSpace(blockedByAdminUserID)

	var (
		res sql.Result
		err error
	)
	if blocked {
		res, err = s.db.ExecContext(ctx, `
			UPDATE users
			SET
				is_blocked = true,
				blocked_at = NOW(),
				blocked_reason = $2,
				blocked_by_admin_user_id = NULLIF($3, '')::uuid
			WHERE id = $1::uuid
		`, userID, reason, blockedByAdminUserID)
	} else {
		res, err = s.db.ExecContext(ctx, `
			UPDATE users
			SET
				is_blocked = false,
				blocked_at = NULL,
				blocked_reason = '',
				blocked_by_admin_user_id = NULL
			WHERE id = $1::uuid
		`, userID)
	}
	if err != nil {
		return err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return ErrUserNotFound
	}
	return nil
}

func (s *Store) GetUserBlockState(ctx context.Context, userID string) (*UserBlockState, error) {
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return nil, ErrUserNotFound
	}

	var (
		state     UserBlockState
		blockedAt sql.NullTime
	)
	err := s.db.QueryRowContext(ctx, `
		SELECT
			u.id::text,
			COALESCE(u.is_blocked, false),
			u.blocked_at,
			COALESCE(u.blocked_reason, ''),
			COALESCE(u.blocked_by_admin_user_id::text, '')
		FROM users u
		WHERE u.id = $1::uuid
	`, userID).Scan(
		&state.UserID,
		&state.IsBlocked,
		&blockedAt,
		&state.BlockedReason,
		&state.BlockedByAdminUserID,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}
	state.UserID = strings.TrimSpace(state.UserID)
	state.BlockedReason = strings.TrimSpace(state.BlockedReason)
	state.BlockedByAdminUserID = strings.TrimSpace(state.BlockedByAdminUserID)
	if blockedAt.Valid {
		ts := blockedAt.Time.UTC()
		state.BlockedAt = &ts
	}
	return &state, nil
}

func (s *Store) IsUserBlocked(ctx context.Context, userID string) (bool, error) {
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return false, ErrUserNotFound
	}

	var blocked bool
	err := s.db.QueryRowContext(ctx, `
		SELECT COALESCE(is_blocked, false)
		FROM users
		WHERE id = $1::uuid
	`, userID).Scan(&blocked)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, ErrUserNotFound
		}
		return false, err
	}
	return blocked, nil
}
