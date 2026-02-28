package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

const (
	UserSecurityCategoryAuth     = "auth"
	UserSecurityCategoryRecovery = "recovery"
	UserSecurityCategorySession  = "session"
	UserSecurityCategoryPasskey  = "passkey"
	UserSecurityCategoryAdmin    = "admin"
	UserSecurityCategoryAll      = "all"
)

const (
	UserSecurityEventLoginSuccess     = "login_success"
	UserSecurityEventLoginFailure     = "login_failure"
	UserSecurityEventRecoveryReq      = "recovery_requested"
	UserSecurityEventRecoverySuccess  = "recovery_success"
	UserSecurityEventRecoveryFailure  = "recovery_failure"
	UserSecurityEventSessionCreated   = "session_created"
	UserSecurityEventSessionRevoked   = "session_revoked"
	UserSecurityEventSessionLogoutAll = "session_logout_all"
	UserSecurityEventPasskeyAdded     = "passkey_added"
	UserSecurityEventPasskeyRevoked   = "passkey_revoked"
)

const (
	defaultUserSecurityEventsLimit = 20
	maxUserSecurityEventsLimit     = 100
)

type UserSecurityEvent struct {
	ID           int64
	UserID       string
	CreatedAt    time.Time
	EventType    string
	Category     string
	Success      *bool
	ActorType    string
	ActorID      string
	SessionID    string
	CredentialID string
	ClientID     string
	RemoteIP     string
	DetailsJSON  json.RawMessage
}

type UserSecurityEventFilter struct {
	Limit    int
	Offset   int
	Category string
}

func NormalizeUserSecurityCategory(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "":
		return ""
	case "sessions":
		return UserSecurityCategorySession
	case "passkeys":
		return UserSecurityCategoryPasskey
	case UserSecurityCategoryAuth,
		UserSecurityCategoryRecovery,
		UserSecurityCategorySession,
		UserSecurityCategoryPasskey,
		UserSecurityCategoryAdmin,
		UserSecurityCategoryAll:
		return strings.ToLower(strings.TrimSpace(raw))
	default:
		return strings.ToLower(strings.TrimSpace(raw))
	}
}

func NormalizeUserSecurityFilterCategory(raw string) string {
	category := NormalizeUserSecurityCategory(raw)
	switch category {
	case "", UserSecurityCategoryAll:
		return ""
	case UserSecurityCategoryAuth,
		UserSecurityCategoryRecovery,
		UserSecurityCategorySession,
		UserSecurityCategoryPasskey,
		UserSecurityCategoryAdmin:
		return category
	default:
		return ""
	}
}

func (s *Store) CreateUserSecurityEvent(ctx context.Context, entry UserSecurityEvent) error {
	normalized, err := normalizeUserSecurityEventEntry(entry)
	if err != nil {
		return err
	}

	var successValue any
	if normalized.Success != nil {
		successValue = *normalized.Success
	}

	_, err = s.db.ExecContext(ctx, `
		INSERT INTO user_security_events (
			user_id, event_type, category, success, actor_type, actor_id, session_id, credential_id, client_id, remote_ip, details_json
		)
		VALUES ($1::uuid, $2, $3, $4::boolean, $5, $6, $7, $8, $9, $10, $11::jsonb)
	`,
		normalized.UserID,
		normalized.EventType,
		normalized.Category,
		successValue,
		normalized.ActorType,
		normalized.ActorID,
		normalized.SessionID,
		normalized.CredentialID,
		normalized.ClientID,
		normalized.RemoteIP,
		string(normalized.DetailsJSON),
	)
	return err
}

func (s *Store) ListUserSecurityEvents(ctx context.Context, userID string, filter UserSecurityEventFilter) ([]UserSecurityEvent, error) {
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return []UserSecurityEvent{}, nil
	}

	limit := filter.Limit
	if limit <= 0 {
		limit = defaultUserSecurityEventsLimit
	}
	if limit > maxUserSecurityEventsLimit {
		limit = maxUserSecurityEventsLimit
	}
	offset := filter.Offset
	if offset < 0 {
		offset = 0
	}
	category := NormalizeUserSecurityFilterCategory(filter.Category)

	rows, err := s.db.QueryContext(ctx, `
		SELECT
			id, user_id::text, created_at, event_type, category, success, actor_type, actor_id, session_id, credential_id, client_id, remote_ip, details_json
		FROM user_security_events
		WHERE user_id = $1::uuid
		  AND ($2 = '' OR category = $2)
		ORDER BY id DESC
		LIMIT $3 OFFSET $4
	`, userID, category, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]UserSecurityEvent, 0, limit)
	for rows.Next() {
		var (
			item    UserSecurityEvent
			success sql.NullBool
			details []byte
		)
		if err := rows.Scan(
			&item.ID,
			&item.UserID,
			&item.CreatedAt,
			&item.EventType,
			&item.Category,
			&success,
			&item.ActorType,
			&item.ActorID,
			&item.SessionID,
			&item.CredentialID,
			&item.ClientID,
			&item.RemoteIP,
			&details,
		); err != nil {
			return nil, err
		}
		item.UserID = strings.TrimSpace(item.UserID)
		item.EventType = strings.TrimSpace(item.EventType)
		item.Category = NormalizeUserSecurityCategory(item.Category)
		item.ActorType = strings.TrimSpace(item.ActorType)
		item.ActorID = strings.TrimSpace(item.ActorID)
		item.SessionID = strings.TrimSpace(item.SessionID)
		item.CredentialID = strings.TrimSpace(item.CredentialID)
		item.ClientID = strings.TrimSpace(item.ClientID)
		item.RemoteIP = strings.TrimSpace(item.RemoteIP)
		item.DetailsJSON = append([]byte(nil), details...)
		if success.Valid {
			value := success.Bool
			item.Success = &value
		}
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Store) CountUserSecurityEventsOlderThan(ctx context.Context, cutoff time.Time) (int64, error) {
	if cutoff.IsZero() {
		return 0, fmt.Errorf("cutoff time is required")
	}

	var count int64
	err := s.db.QueryRowContext(ctx, `
		SELECT COUNT(*)
		FROM user_security_events
		WHERE created_at < $1
	`, cutoff.UTC()).Scan(&count)
	if err != nil {
		return 0, err
	}
	return count, nil
}

func (s *Store) DeleteUserSecurityEventsOlderThan(ctx context.Context, cutoff time.Time, limit int) (int64, error) {
	if cutoff.IsZero() {
		return 0, fmt.Errorf("cutoff time is required")
	}
	batchLimit := normalizeRetentionDeleteBatch(limit)

	res, err := s.db.ExecContext(ctx, `
		WITH to_delete AS (
			SELECT id
			FROM user_security_events
			WHERE created_at < $1
			ORDER BY id ASC
			LIMIT $2
		)
		DELETE FROM user_security_events target
		USING to_delete d
		WHERE target.id = d.id
	`, cutoff.UTC(), batchLimit)
	if err != nil {
		return 0, err
	}

	affected, err := res.RowsAffected()
	if err != nil {
		return 0, err
	}
	return affected, nil
}

func normalizeUserSecurityEventEntry(entry UserSecurityEvent) (UserSecurityEvent, error) {
	entry.UserID = strings.TrimSpace(entry.UserID)
	if entry.UserID == "" {
		return UserSecurityEvent{}, fmt.Errorf("user_id is required")
	}

	entry.EventType = strings.TrimSpace(strings.ToLower(entry.EventType))
	if entry.EventType == "" {
		return UserSecurityEvent{}, fmt.Errorf("event_type is required")
	}

	entry.Category = NormalizeUserSecurityCategory(entry.Category)
	if entry.Category == "" || entry.Category == UserSecurityCategoryAll {
		entry.Category = UserSecurityCategoryAuth
	}
	entry.ActorType = strings.TrimSpace(strings.ToLower(entry.ActorType))
	if entry.ActorType == "" {
		entry.ActorType = "user"
	}
	entry.ActorID = strings.TrimSpace(entry.ActorID)
	entry.SessionID = strings.TrimSpace(entry.SessionID)
	entry.CredentialID = strings.TrimSpace(entry.CredentialID)
	entry.ClientID = strings.TrimSpace(entry.ClientID)
	entry.RemoteIP = strings.TrimSpace(entry.RemoteIP)

	if len(entry.DetailsJSON) == 0 {
		entry.DetailsJSON = json.RawMessage(`{}`)
		return entry, nil
	}
	var decoded any
	if err := json.Unmarshal(entry.DetailsJSON, &decoded); err != nil {
		return UserSecurityEvent{}, fmt.Errorf("invalid details_json: %w", err)
	}
	sanitized := sanitizeUserSecurityDetails(decoded)
	encoded, err := json.Marshal(sanitized)
	if err != nil {
		return UserSecurityEvent{}, err
	}
	entry.DetailsJSON = encoded
	return entry, nil
}

func sanitizeUserSecurityDetails(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(typed))
		for key, item := range typed {
			normalized := strings.ToLower(strings.TrimSpace(key))
			if normalized == "" || isSensitiveUserSecurityField(normalized) {
				continue
			}
			out[key] = sanitizeUserSecurityDetails(item)
		}
		return out
	case []any:
		out := make([]any, 0, len(typed))
		for _, item := range typed {
			out = append(out, sanitizeUserSecurityDetails(item))
		}
		return out
	default:
		return value
	}
}

func isSensitiveUserSecurityField(key string) bool {
	return strings.Contains(key, "secret") ||
		strings.Contains(key, "authorization") ||
		strings.Contains(key, "password") ||
		strings.Contains(key, "token") ||
		strings.Contains(key, "challenge") ||
		strings.Contains(key, "assertion") ||
		strings.Contains(key, "attestation") ||
		strings.Contains(key, "public_key") ||
		strings.Contains(key, "publickey")
}
