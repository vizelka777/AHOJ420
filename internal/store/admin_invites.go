package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

var (
	ErrAdminInviteNotFound = errors.New("admin invite not found")
	ErrAdminInviteInactive = errors.New("admin invite is inactive")
)

type AdminInvite struct {
	ID                   int64
	TokenHash            string
	AdminUserID          string
	CreatedByAdminUserID string
	CreatedAt            time.Time
	ExpiresAt            time.Time
	UsedAt               *time.Time
	RevokedAt            *time.Time
	Note                 string
}

func (s *Store) CreateAdminInvite(ctx context.Context, adminUserID string, createdBy string, tokenHash string, expiresAt time.Time, note string) (*AdminInvite, error) {
	adminUserID = strings.TrimSpace(adminUserID)
	createdBy = strings.TrimSpace(createdBy)
	tokenHash = strings.TrimSpace(tokenHash)
	note = strings.TrimSpace(note)
	expiresAt = expiresAt.UTC()

	if adminUserID == "" {
		return nil, fmt.Errorf("admin user id is required")
	}
	if createdBy == "" {
		return nil, fmt.Errorf("created by admin user id is required")
	}
	if tokenHash == "" {
		return nil, fmt.Errorf("invite token hash is required")
	}
	if expiresAt.IsZero() {
		return nil, fmt.Errorf("invite expires_at is required")
	}

	var out AdminInvite
	var usedAt sql.NullTime
	var revokedAt sql.NullTime
	err := s.db.QueryRowContext(ctx, `
		INSERT INTO admin_invites (
			token_hash, admin_user_id, created_by_admin_user_id, expires_at, note
		)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id, token_hash, admin_user_id::text, created_by_admin_user_id::text, created_at, expires_at, used_at, revoked_at, note
	`, tokenHash, adminUserID, createdBy, expiresAt, note).Scan(
		&out.ID,
		&out.TokenHash,
		&out.AdminUserID,
		&out.CreatedByAdminUserID,
		&out.CreatedAt,
		&out.ExpiresAt,
		&usedAt,
		&revokedAt,
		&out.Note,
	)
	if err != nil {
		return nil, err
	}
	if usedAt.Valid {
		ts := usedAt.Time.UTC()
		out.UsedAt = &ts
	}
	if revokedAt.Valid {
		ts := revokedAt.Time.UTC()
		out.RevokedAt = &ts
	}
	return &out, nil
}

func (s *Store) GetActiveAdminInviteByTokenHash(ctx context.Context, tokenHash string) (*AdminInvite, error) {
	tokenHash = strings.TrimSpace(tokenHash)
	if tokenHash == "" {
		return nil, ErrAdminInviteNotFound
	}
	return s.getAdminInviteBy(ctx, `
		SELECT id, token_hash, admin_user_id::text, created_by_admin_user_id::text, created_at, expires_at, used_at, revoked_at, note
		FROM admin_invites
		WHERE token_hash = $1
		  AND used_at IS NULL
		  AND revoked_at IS NULL
		  AND expires_at > NOW()
		LIMIT 1
	`, tokenHash)
}

func (s *Store) GetAdminInviteByID(ctx context.Context, inviteID int64) (*AdminInvite, error) {
	if inviteID <= 0 {
		return nil, ErrAdminInviteNotFound
	}
	return s.getAdminInviteBy(ctx, `
		SELECT id, token_hash, admin_user_id::text, created_by_admin_user_id::text, created_at, expires_at, used_at, revoked_at, note
		FROM admin_invites
		WHERE id = $1
		LIMIT 1
	`, inviteID)
}

func (s *Store) MarkAdminInviteUsed(ctx context.Context, inviteID int64, usedAt time.Time) error {
	if inviteID <= 0 {
		return ErrAdminInviteNotFound
	}
	if usedAt.IsZero() {
		usedAt = time.Now().UTC()
	}

	res, err := s.db.ExecContext(ctx, `
		UPDATE admin_invites
		SET used_at = $2
		WHERE id = $1
		  AND used_at IS NULL
		  AND revoked_at IS NULL
		  AND expires_at > NOW()
	`, inviteID, usedAt.UTC())
	if err != nil {
		return err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if affected > 0 {
		return nil
	}

	existing, err := s.GetAdminInviteByID(ctx, inviteID)
	if err != nil {
		return err
	}
	if existing.UsedAt != nil || existing.RevokedAt != nil || !existing.ExpiresAt.After(time.Now().UTC()) {
		return ErrAdminInviteInactive
	}
	return ErrAdminInviteNotFound
}

func (s *Store) RevokeAdminInvite(ctx context.Context, inviteID int64) error {
	if inviteID <= 0 {
		return ErrAdminInviteNotFound
	}
	res, err := s.db.ExecContext(ctx, `
		UPDATE admin_invites
		SET revoked_at = NOW()
		WHERE id = $1
		  AND used_at IS NULL
		  AND revoked_at IS NULL
		  AND expires_at > NOW()
	`, inviteID)
	if err != nil {
		return err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if affected > 0 {
		return nil
	}

	existing, err := s.GetAdminInviteByID(ctx, inviteID)
	if err != nil {
		return err
	}
	if existing.UsedAt != nil || existing.RevokedAt != nil || !existing.ExpiresAt.After(time.Now().UTC()) {
		return ErrAdminInviteInactive
	}
	return ErrAdminInviteNotFound
}

func (s *Store) ListAdminInvites(ctx context.Context, adminUserID string) ([]AdminInvite, error) {
	adminUserID = strings.TrimSpace(adminUserID)
	if adminUserID == "" {
		return []AdminInvite{}, nil
	}

	rows, err := s.db.QueryContext(ctx, `
		SELECT id, token_hash, admin_user_id::text, created_by_admin_user_id::text, created_at, expires_at, used_at, revoked_at, note
		FROM admin_invites
		WHERE admin_user_id = $1
		ORDER BY created_at DESC, id DESC
	`, adminUserID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]AdminInvite, 0, 8)
	for rows.Next() {
		var (
			item      AdminInvite
			usedAt    sql.NullTime
			revokedAt sql.NullTime
		)
		if err := rows.Scan(
			&item.ID,
			&item.TokenHash,
			&item.AdminUserID,
			&item.CreatedByAdminUserID,
			&item.CreatedAt,
			&item.ExpiresAt,
			&usedAt,
			&revokedAt,
			&item.Note,
		); err != nil {
			return nil, err
		}
		if usedAt.Valid {
			ts := usedAt.Time.UTC()
			item.UsedAt = &ts
		}
		if revokedAt.Valid {
			ts := revokedAt.Time.UTC()
			item.RevokedAt = &ts
		}
		item.Note = strings.TrimSpace(item.Note)
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Store) CountActiveAdminInvitesForUser(ctx context.Context, adminUserID string) (int, error) {
	adminUserID = strings.TrimSpace(adminUserID)
	if adminUserID == "" {
		return 0, nil
	}
	var count int
	err := s.db.QueryRowContext(ctx, `
		SELECT COUNT(*)
		FROM admin_invites
		WHERE admin_user_id = $1
		  AND used_at IS NULL
		  AND revoked_at IS NULL
		  AND expires_at > NOW()
	`, adminUserID).Scan(&count)
	if err != nil {
		return 0, err
	}
	return count, nil
}

func (s *Store) getAdminInviteBy(ctx context.Context, query string, arg any) (*AdminInvite, error) {
	var (
		item      AdminInvite
		usedAt    sql.NullTime
		revokedAt sql.NullTime
	)
	err := s.db.QueryRowContext(ctx, query, arg).Scan(
		&item.ID,
		&item.TokenHash,
		&item.AdminUserID,
		&item.CreatedByAdminUserID,
		&item.CreatedAt,
		&item.ExpiresAt,
		&usedAt,
		&revokedAt,
		&item.Note,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrAdminInviteNotFound
		}
		return nil, err
	}
	if usedAt.Valid {
		ts := usedAt.Time.UTC()
		item.UsedAt = &ts
	}
	if revokedAt.Valid {
		ts := revokedAt.Time.UTC()
		item.RevokedAt = &ts
	}
	item.TokenHash = strings.TrimSpace(item.TokenHash)
	item.AdminUserID = strings.TrimSpace(item.AdminUserID)
	item.CreatedByAdminUserID = strings.TrimSpace(item.CreatedByAdminUserID)
	item.Note = strings.TrimSpace(item.Note)
	return &item, nil
}
