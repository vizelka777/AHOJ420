package store

import (
	"strings"
	"time"
)

type UserOIDCClient struct {
	ClientID    string
	ClientHost  string
	FirstSeenAt time.Time
	LastSeenAt  time.Time
}

func (s *Store) UpsertUserOIDCClient(userID, clientID, clientHost string) error {
	userID = strings.TrimSpace(userID)
	clientID = strings.TrimSpace(clientID)
	clientHost = strings.TrimSpace(clientHost)
	if userID == "" || clientID == "" {
		return nil
	}

	_, err := s.db.Exec(`
		INSERT INTO user_oidc_clients (user_id, client_id, client_host, first_seen_at, last_seen_at)
		VALUES ($1, $2, NULLIF($3, ''), NOW(), NOW())
		ON CONFLICT (user_id, client_id)
		DO UPDATE SET
			client_host = COALESCE(NULLIF(EXCLUDED.client_host, ''), user_oidc_clients.client_host),
			last_seen_at = NOW()
	`, userID, clientID, clientHost)
	return err
}

func (s *Store) ListUserOIDCClients(userID string) ([]UserOIDCClient, error) {
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return []UserOIDCClient{}, nil
	}

	rows, err := s.db.Query(`
		SELECT client_id, COALESCE(client_host, ''), first_seen_at, last_seen_at
		FROM user_oidc_clients
		WHERE user_id = $1
		ORDER BY last_seen_at DESC, client_id ASC
	`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]UserOIDCClient, 0, 8)
	for rows.Next() {
		var item UserOIDCClient
		if err := rows.Scan(&item.ClientID, &item.ClientHost, &item.FirstSeenAt, &item.LastSeenAt); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}
