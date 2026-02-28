package store

import (
	"database/sql"
	"errors"
	"strings"
	"time"
)

var ErrUserNotFound = errors.New("user not found")

type AdminUserSupportListFilter struct {
	Query  string
	Limit  int
	Offset int
}

type AdminUserSupportListItem struct {
	ID                   string
	LoginID              string
	ProfileEmail         string
	Phone                string
	CreatedAt            time.Time
	ProfileEmailVerified bool
	PhoneVerified        bool
	PasskeyCount         int
	LinkedClientCount    int
}

type AdminUserProfile struct {
	ID                   string
	LoginID              string
	DisplayName          string
	ProfileEmail         string
	Phone                string
	ShareProfile         bool
	ProfileEmailVerified bool
	PhoneVerified        bool
	AvatarKey            string
	AvatarUpdatedAt      *time.Time
	AvatarMIME           string
	AvatarBytes          int64
	CreatedAt            time.Time
	ProfileCompletedAt   *time.Time
}

func (s *Store) ListUsersForAdmin(filter AdminUserSupportListFilter) ([]AdminUserSupportListItem, error) {
	limit := filter.Limit
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	offset := filter.Offset
	if offset < 0 {
		offset = 0
	}
	queryRaw := strings.TrimSpace(filter.Query)
	queryLike := "%" + strings.ToLower(queryRaw) + "%"

	rows, err := s.db.Query(`
		SELECT
			u.id::text,
			COALESCE(u.email, ''),
			COALESCE(u.profile_email, ''),
			COALESCE(u.phone, ''),
			u.created_at,
			COALESCE(u.email_verified, false),
			COALESCE(u.phone_verified, false),
			COALESCE(c.passkey_count, 0),
			COALESCE(cl.linked_client_count, 0)
		FROM users u
		LEFT JOIN (
			SELECT user_id, COUNT(*) AS passkey_count
			FROM credentials
			GROUP BY user_id
		) c ON c.user_id = u.id
		LEFT JOIN (
			SELECT user_id, COUNT(*) AS linked_client_count
			FROM user_oidc_clients
			GROUP BY user_id
		) cl ON cl.user_id = u.id
		WHERE (
			$1 = ''
			OR lower(u.id::text) LIKE $2
			OR lower(COALESCE(u.email, '')) LIKE $2
			OR lower(COALESCE(u.profile_email, '')) LIKE $2
			OR lower(COALESCE(u.phone, '')) LIKE $2
		)
		ORDER BY u.created_at DESC, u.id::text DESC
		LIMIT $3 OFFSET $4
	`, queryRaw, queryLike, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]AdminUserSupportListItem, 0, limit)
	for rows.Next() {
		var item AdminUserSupportListItem
		if err := rows.Scan(
			&item.ID,
			&item.LoginID,
			&item.ProfileEmail,
			&item.Phone,
			&item.CreatedAt,
			&item.ProfileEmailVerified,
			&item.PhoneVerified,
			&item.PasskeyCount,
			&item.LinkedClientCount,
		); err != nil {
			return nil, err
		}
		item.ID = strings.TrimSpace(item.ID)
		item.LoginID = strings.TrimSpace(item.LoginID)
		item.ProfileEmail = strings.TrimSpace(item.ProfileEmail)
		item.Phone = strings.TrimSpace(item.Phone)
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Store) GetUserProfileForAdmin(userID string) (*AdminUserProfile, error) {
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return nil, ErrUserNotFound
	}

	var item AdminUserProfile
	var avatarUpdatedAt sql.NullTime
	var profileCompletedAt sql.NullTime
	err := s.db.QueryRow(`
		SELECT
			u.id::text,
			COALESCE(u.email, ''),
			COALESCE(u.display_name, ''),
			COALESCE(u.profile_email, ''),
			COALESCE(u.phone, ''),
			COALESCE(u.share_profile, false),
			COALESCE(u.email_verified, false),
			COALESCE(u.phone_verified, false),
			COALESCE(u.avatar_key, ''),
			u.avatar_updated_at,
			COALESCE(u.avatar_mime, ''),
			COALESCE(u.avatar_bytes, 0),
			u.created_at,
			u.profile_completed_at
		FROM users u
		WHERE u.id = $1
	`, userID).Scan(
		&item.ID,
		&item.LoginID,
		&item.DisplayName,
		&item.ProfileEmail,
		&item.Phone,
		&item.ShareProfile,
		&item.ProfileEmailVerified,
		&item.PhoneVerified,
		&item.AvatarKey,
		&avatarUpdatedAt,
		&item.AvatarMIME,
		&item.AvatarBytes,
		&item.CreatedAt,
		&profileCompletedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}

	item.ID = strings.TrimSpace(item.ID)
	item.LoginID = strings.TrimSpace(item.LoginID)
	item.DisplayName = strings.TrimSpace(item.DisplayName)
	item.ProfileEmail = strings.TrimSpace(item.ProfileEmail)
	item.Phone = strings.TrimSpace(item.Phone)
	item.AvatarKey = strings.TrimSpace(item.AvatarKey)
	item.AvatarMIME = strings.TrimSpace(item.AvatarMIME)
	if avatarUpdatedAt.Valid {
		ts := avatarUpdatedAt.Time.UTC()
		item.AvatarUpdatedAt = &ts
	}
	if profileCompletedAt.Valid {
		ts := profileCompletedAt.Time.UTC()
		item.ProfileCompletedAt = &ts
	}
	return &item, nil
}
