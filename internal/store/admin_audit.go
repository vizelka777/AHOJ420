package store

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type AdminAuditEntry struct {
	ID           int64
	CreatedAt    time.Time
	Action       string
	Success      bool
	ActorType    string
	ActorID      string
	RemoteIP     string
	RequestID    string
	ResourceType string
	ResourceID   string
	DetailsJSON  json.RawMessage
}

type AdminAuditListOptions struct {
	Limit        int
	Offset       int
	Action       string
	Success      *bool
	Actor        string
	ResourceType string
	ResourceID   string
}

func (s *Store) CreateAdminAuditEntry(ctx context.Context, entry AdminAuditEntry) error {
	normalized, err := normalizeAdminAuditEntry(entry)
	if err != nil {
		return err
	}

	_, err = s.db.ExecContext(ctx, `
		INSERT INTO admin_audit_log (
			action, success, actor_type, actor_id, remote_ip, request_id, resource_type, resource_id, details_json
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb)
	`,
		normalized.Action,
		normalized.Success,
		normalized.ActorType,
		normalized.ActorID,
		normalized.RemoteIP,
		normalized.RequestID,
		normalized.ResourceType,
		normalized.ResourceID,
		string(normalized.DetailsJSON),
	)
	return err
}

func (s *Store) ListAdminAuditEntries(ctx context.Context, opts AdminAuditListOptions) ([]AdminAuditEntry, error) {
	limit := opts.Limit
	offset := opts.Offset
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}

	action := strings.TrimSpace(opts.Action)
	resourceType := strings.TrimSpace(opts.ResourceType)
	resourceID := strings.TrimSpace(opts.ResourceID)
	actor := strings.TrimSpace(opts.Actor)

	actionPattern := ""
	if action != "" {
		actionPattern = "%" + strings.ToLower(action) + "%"
	}
	resourceIDPattern := ""
	if resourceID != "" {
		resourceIDPattern = "%" + strings.ToLower(resourceID) + "%"
	}
	actorPattern := ""
	if actor != "" {
		actorPattern = "%" + strings.ToLower(actor) + "%"
	}
	var successFilter any
	if opts.Success != nil {
		successFilter = *opts.Success
	}

	rows, err := s.db.QueryContext(ctx, `
		SELECT id, created_at, action, success, actor_type, actor_id, remote_ip, request_id, resource_type, resource_id, details_json
		FROM admin_audit_log
		WHERE ($1 = '' OR lower(action) LIKE $1)
		  AND ($2 = '' OR resource_type = $2)
		  AND ($3 = '' OR lower(resource_id) LIKE $3)
		  AND ($4 = '' OR lower(actor_type || ':' || actor_id) LIKE $4 OR lower(actor_id) LIKE $4)
		  AND ($5::boolean IS NULL OR success = $5)
		ORDER BY id DESC
		LIMIT $6 OFFSET $7
	`, actionPattern, resourceType, resourceIDPattern, actorPattern, successFilter, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]AdminAuditEntry, 0, limit)
	for rows.Next() {
		var (
			item    AdminAuditEntry
			details []byte
		)
		if err := rows.Scan(
			&item.ID,
			&item.CreatedAt,
			&item.Action,
			&item.Success,
			&item.ActorType,
			&item.ActorID,
			&item.RemoteIP,
			&item.RequestID,
			&item.ResourceType,
			&item.ResourceID,
			&details,
		); err != nil {
			return nil, err
		}
		item.Action = strings.TrimSpace(item.Action)
		item.ActorType = strings.TrimSpace(item.ActorType)
		item.ActorID = strings.TrimSpace(item.ActorID)
		item.RemoteIP = strings.TrimSpace(item.RemoteIP)
		item.RequestID = strings.TrimSpace(item.RequestID)
		item.ResourceType = strings.TrimSpace(item.ResourceType)
		item.ResourceID = strings.TrimSpace(item.ResourceID)
		item.DetailsJSON = append([]byte(nil), details...)
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Store) CountAdminAuditFailuresSince(ctx context.Context, since time.Time) (int, error) {
	if since.IsZero() {
		since = time.Now().UTC().Add(-24 * time.Hour)
	}
	var count int
	err := s.db.QueryRowContext(ctx, `
		SELECT COUNT(*)
		FROM admin_audit_log
		WHERE success = false
		  AND created_at >= $1
	`, since.UTC()).Scan(&count)
	if err != nil {
		return 0, err
	}
	return count, nil
}

func normalizeAdminAuditEntry(entry AdminAuditEntry) (AdminAuditEntry, error) {
	entry.Action = strings.TrimSpace(entry.Action)
	if entry.Action == "" {
		return AdminAuditEntry{}, fmt.Errorf("audit action is required")
	}

	entry.ActorType = strings.TrimSpace(entry.ActorType)
	if entry.ActorType == "" {
		entry.ActorType = "token"
	}

	entry.ActorID = strings.TrimSpace(entry.ActorID)
	if entry.ActorID == "" {
		entry.ActorID = "admin_api_token"
	}

	entry.RemoteIP = strings.TrimSpace(entry.RemoteIP)
	entry.RequestID = strings.TrimSpace(entry.RequestID)
	entry.ResourceType = strings.TrimSpace(entry.ResourceType)
	entry.ResourceID = strings.TrimSpace(entry.ResourceID)

	if len(entry.DetailsJSON) == 0 {
		entry.DetailsJSON = json.RawMessage(`{}`)
		return entry, nil
	}

	var decoded any
	if err := json.Unmarshal(entry.DetailsJSON, &decoded); err != nil {
		return AdminAuditEntry{}, fmt.Errorf("invalid details_json: %w", err)
	}
	encoded, err := json.Marshal(decoded)
	if err != nil {
		return AdminAuditEntry{}, err
	}
	entry.DetailsJSON = encoded
	return entry, nil
}
