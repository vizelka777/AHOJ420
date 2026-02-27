package store

import (
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrOIDCClientNotFound       = errors.New("oidc client not found")
	ErrOIDCClientSecretNotFound = errors.New("oidc client secret not found")
)

type OIDCClient struct {
	ID            string
	Name          string
	Enabled       bool
	Confidential  bool
	RequirePKCE   bool
	AuthMethod    string
	GrantTypes    []string
	ResponseTypes []string
	Scopes        []string
	RedirectURIs  []string
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

type OIDCClientSecret struct {
	ID         int64
	ClientID   string
	SecretHash string
	Label      string
	CreatedAt  time.Time
	RevokedAt  *time.Time
}

type OIDCClientSecretInput struct {
	PlainSecret string
	Label       string
}

type OIDCClientBootstrapInput struct {
	ID            string
	Name          string
	Enabled       bool
	Confidential  bool
	RequirePKCE   bool
	AuthMethod    string
	GrantTypes    []string
	ResponseTypes []string
	Scopes        []string
	RedirectURIs  []string
	Secrets       []OIDCClientSecretInput
}

func (s *Store) ListOIDCClients() ([]OIDCClient, error) {
	return s.listOIDCClients(false)
}

func (s *Store) ListEnabledOIDCClients() ([]OIDCClient, error) {
	return s.listOIDCClients(true)
}

func (s *Store) listOIDCClients(enabledOnly bool) ([]OIDCClient, error) {
	baseQuery := `
		SELECT id, name, enabled, confidential, require_pkce, auth_method,
		       grant_types, response_types, scopes, created_at, updated_at
		FROM oidc_clients
	`
	if enabledOnly {
		baseQuery += " WHERE enabled = true"
	}
	baseQuery += " ORDER BY id ASC"

	rows, err := s.db.Query(baseQuery)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]OIDCClient, 0, 16)
	byID := make(map[string]int, 16)
	for rows.Next() {
		var (
			client        OIDCClient
			grantTypes    pq.StringArray
			responseTypes pq.StringArray
			scopes        pq.StringArray
		)
		if err := rows.Scan(
			&client.ID,
			&client.Name,
			&client.Enabled,
			&client.Confidential,
			&client.RequirePKCE,
			&client.AuthMethod,
			&grantTypes,
			&responseTypes,
			&scopes,
			&client.CreatedAt,
			&client.UpdatedAt,
		); err != nil {
			return nil, err
		}

		client.ID = strings.TrimSpace(client.ID)
		client.Name = strings.TrimSpace(client.Name)
		client.AuthMethod = strings.ToLower(strings.TrimSpace(client.AuthMethod))
		client.GrantTypes = append([]string(nil), []string(grantTypes)...)
		client.ResponseTypes = append([]string(nil), []string(responseTypes)...)
		client.Scopes = append([]string(nil), []string(scopes)...)
		client.RedirectURIs = []string{}

		byID[client.ID] = len(out)
		out = append(out, client)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return []OIDCClient{}, nil
	}

	redirects, err := s.listOIDCClientRedirectURIsByClientIDs(keysOIDCClientMap(byID))
	if err != nil {
		return nil, err
	}
	for clientID, uris := range redirects {
		idx, ok := byID[clientID]
		if !ok {
			continue
		}
		out[idx].RedirectURIs = append([]string(nil), uris...)
	}

	return out, nil
}

func (s *Store) GetOIDCClient(id string) (*OIDCClient, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return nil, ErrOIDCClientNotFound
	}

	var (
		client        OIDCClient
		grantTypes    pq.StringArray
		responseTypes pq.StringArray
		scopes        pq.StringArray
	)
	err := s.db.QueryRow(`
		SELECT id, name, enabled, confidential, require_pkce, auth_method,
		       grant_types, response_types, scopes, created_at, updated_at
		FROM oidc_clients
		WHERE id = $1
	`, id).Scan(
		&client.ID,
		&client.Name,
		&client.Enabled,
		&client.Confidential,
		&client.RequirePKCE,
		&client.AuthMethod,
		&grantTypes,
		&responseTypes,
		&scopes,
		&client.CreatedAt,
		&client.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrOIDCClientNotFound
		}
		return nil, err
	}

	client.ID = strings.TrimSpace(client.ID)
	client.Name = strings.TrimSpace(client.Name)
	client.AuthMethod = strings.ToLower(strings.TrimSpace(client.AuthMethod))
	client.GrantTypes = append([]string(nil), []string(grantTypes)...)
	client.ResponseTypes = append([]string(nil), []string(responseTypes)...)
	client.Scopes = append([]string(nil), []string(scopes)...)

	redirects, err := s.listOIDCClientRedirectURIsByClientIDs([]string{client.ID})
	if err != nil {
		return nil, err
	}
	client.RedirectURIs = append([]string(nil), redirects[client.ID]...)

	return &client, nil
}

func (s *Store) ListOIDCClientSecrets(clientID string) ([]OIDCClientSecret, error) {
	clientID = strings.TrimSpace(clientID)
	if clientID == "" {
		return []OIDCClientSecret{}, nil
	}

	rows, err := s.db.Query(`
		SELECT id, client_id, secret_hash, label, created_at, revoked_at
		FROM oidc_client_secrets
		WHERE client_id = $1
		ORDER BY created_at DESC, id DESC
	`, clientID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]OIDCClientSecret, 0, 4)
	for rows.Next() {
		var (
			item      OIDCClientSecret
			revokedAt sql.NullTime
		)
		if err := rows.Scan(
			&item.ID,
			&item.ClientID,
			&item.SecretHash,
			&item.Label,
			&item.CreatedAt,
			&revokedAt,
		); err != nil {
			return nil, err
		}

		item.ClientID = strings.TrimSpace(item.ClientID)
		item.SecretHash = strings.TrimSpace(item.SecretHash)
		item.Label = strings.TrimSpace(item.Label)
		if revokedAt.Valid {
			ts := revokedAt.Time.UTC()
			item.RevokedAt = &ts
		}
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return out, nil
}

func (s *Store) CreateOIDCClient(client OIDCClient, secrets []OIDCClientSecretInput) error {
	input := OIDCClientBootstrapInput{
		ID:            client.ID,
		Name:          client.Name,
		Enabled:       client.Enabled,
		Confidential:  client.Confidential,
		RequirePKCE:   client.RequirePKCE,
		AuthMethod:    client.AuthMethod,
		GrantTypes:    client.GrantTypes,
		ResponseTypes: client.ResponseTypes,
		Scopes:        client.Scopes,
		RedirectURIs:  client.RedirectURIs,
		Secrets:       secrets,
	}
	normalized, err := normalizeOIDCClientBootstrapInput(input)
	if err != nil {
		return err
	}

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	if err := insertOIDCClientTx(tx, normalized); err != nil {
		return err
	}

	return tx.Commit()
}

func (s *Store) UpdateOIDCClient(client OIDCClient) error {
	normalized, err := normalizeOIDCClientForUpdate(client)
	if err != nil {
		return err
	}

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	res, err := tx.Exec(`
		UPDATE oidc_clients
		SET
			name = $2,
			enabled = $3,
			confidential = $4,
			require_pkce = $5,
			auth_method = $6,
			grant_types = $7,
			response_types = $8,
			scopes = $9,
			updated_at = NOW()
		WHERE id = $1
	`,
		normalized.ID,
		normalized.Name,
		normalized.Enabled,
		normalized.Confidential,
		normalized.RequirePKCE,
		normalized.AuthMethod,
		pq.Array(normalized.GrantTypes),
		pq.Array(normalized.ResponseTypes),
		pq.Array(normalized.Scopes),
	)
	if err != nil {
		return err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return ErrOIDCClientNotFound
	}

	if !normalized.Confidential {
		if _, err := tx.Exec(`DELETE FROM oidc_client_secrets WHERE client_id = $1`, normalized.ID); err != nil {
			return err
		}
	} else {
		activeCount, err := countActiveOIDCClientSecretsTx(tx, normalized.ID)
		if err != nil {
			return err
		}
		if activeCount == 0 {
			return fmt.Errorf("confidential client requires at least one active secret")
		}
	}

	return tx.Commit()
}

func (s *Store) ReplaceOIDCClientRedirectURIs(clientID string, uris []string) error {
	clientID = strings.TrimSpace(clientID)
	if clientID == "" {
		return fmt.Errorf("client id is required")
	}
	normalizedURIs, err := normalizeRedirectURIs(uris)
	if err != nil {
		return err
	}
	if len(normalizedURIs) == 0 {
		return fmt.Errorf("at least one redirect_uri is required")
	}

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := lookupOIDCClientConfidentialTx(tx, clientID); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM oidc_client_redirect_uris WHERE client_id = $1`, clientID); err != nil {
		return err
	}
	for _, uri := range normalizedURIs {
		if _, err := tx.Exec(`
			INSERT INTO oidc_client_redirect_uris (client_id, redirect_uri)
			VALUES ($1, $2)
		`, clientID, uri); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(`UPDATE oidc_clients SET updated_at = NOW() WHERE id = $1`, clientID); err != nil {
		return err
	}

	return tx.Commit()
}

func (s *Store) AddOIDCClientSecret(clientID string, plainSecret string, label string) error {
	clientID = strings.TrimSpace(clientID)
	plainSecret = strings.TrimSpace(plainSecret)
	label = strings.TrimSpace(label)
	if clientID == "" {
		return fmt.Errorf("client id is required")
	}
	if plainSecret == "" {
		return fmt.Errorf("secret is required")
	}

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	confidential, err := lookupOIDCClientConfidentialTx(tx, clientID)
	if err != nil {
		return err
	}
	if !confidential {
		return fmt.Errorf("public client must not have secrets")
	}

	hashBytes, err := bcrypt.GenerateFromPassword(secretMaterialForBcrypt(plainSecret), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(`
		INSERT INTO oidc_client_secrets (client_id, secret_hash, label)
		VALUES ($1, $2, $3)
	`, clientID, string(hashBytes), label); err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE oidc_clients SET updated_at = NOW() WHERE id = $1`, clientID); err != nil {
		return err
	}

	return tx.Commit()
}

func (s *Store) RevokeOIDCClientSecret(clientID string, secretID int64) error {
	clientID = strings.TrimSpace(clientID)
	if clientID == "" {
		return fmt.Errorf("client id is required")
	}
	if secretID <= 0 {
		return fmt.Errorf("secret id is required")
	}

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	confidential, err := lookupOIDCClientConfidentialTx(tx, clientID)
	if err != nil {
		return err
	}
	if !confidential {
		return fmt.Errorf("public client has no secrets")
	}

	res, err := tx.Exec(`
		UPDATE oidc_client_secrets
		SET revoked_at = NOW()
		WHERE client_id = $1 AND id = $2 AND revoked_at IS NULL
	`, clientID, secretID)
	if err != nil {
		return err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return ErrOIDCClientSecretNotFound
	}

	activeCount, err := countActiveOIDCClientSecretsTx(tx, clientID)
	if err != nil {
		return err
	}
	if activeCount == 0 {
		return fmt.Errorf("confidential client must keep at least one active secret")
	}

	if _, err := tx.Exec(`UPDATE oidc_clients SET updated_at = NOW() WHERE id = $1`, clientID); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) BootstrapOIDCClients(clients []OIDCClientBootstrapInput) (int, error) {
	if len(clients) == 0 {
		return 0, fmt.Errorf("bootstrap clients are empty")
	}

	normalizedClients := make([]OIDCClientBootstrapInput, 0, len(clients))
	seenIDs := make(map[string]struct{}, len(clients))
	for _, client := range clients {
		normalized, err := normalizeOIDCClientBootstrapInput(client)
		if err != nil {
			return 0, err
		}
		if _, exists := seenIDs[normalized.ID]; exists {
			return 0, fmt.Errorf("duplicate client id %q", normalized.ID)
		}
		seenIDs[normalized.ID] = struct{}{}
		normalizedClients = append(normalizedClients, normalized)
	}

	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()

	var existing int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM oidc_clients`).Scan(&existing); err != nil {
		return 0, err
	}
	if existing > 0 {
		return 0, nil
	}

	for _, client := range normalizedClients {
		if err := insertOIDCClientTx(tx, client); err != nil {
			return 0, err
		}
	}

	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return len(normalizedClients), nil
}

func insertOIDCClientTx(tx *sql.Tx, client OIDCClientBootstrapInput) error {
	_, err := tx.Exec(`
		INSERT INTO oidc_clients (
			id, name, enabled, confidential, require_pkce, auth_method, grant_types, response_types, scopes
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`,
		client.ID,
		client.Name,
		client.Enabled,
		client.Confidential,
		client.RequirePKCE,
		client.AuthMethod,
		pq.Array(client.GrantTypes),
		pq.Array(client.ResponseTypes),
		pq.Array(client.Scopes),
	)
	if err != nil {
		return err
	}

	for _, uri := range client.RedirectURIs {
		if _, err := tx.Exec(`
			INSERT INTO oidc_client_redirect_uris (client_id, redirect_uri)
			VALUES ($1, $2)
		`, client.ID, uri); err != nil {
			return err
		}
	}

	if client.Confidential {
		for _, secret := range client.Secrets {
			hashBytes, err := bcrypt.GenerateFromPassword(secretMaterialForBcrypt(secret.PlainSecret), bcrypt.DefaultCost)
			if err != nil {
				return err
			}
			if _, err := tx.Exec(`
				INSERT INTO oidc_client_secrets (client_id, secret_hash, label)
				VALUES ($1, $2, $3)
			`, client.ID, string(hashBytes), secret.Label); err != nil {
				return err
			}
		}
	}

	return nil
}

func lookupOIDCClientConfidentialTx(tx *sql.Tx, clientID string) (bool, error) {
	var confidential bool
	err := tx.QueryRow(`SELECT confidential FROM oidc_clients WHERE id = $1`, clientID).Scan(&confidential)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, ErrOIDCClientNotFound
		}
		return false, err
	}
	return confidential, nil
}

func countActiveOIDCClientSecretsTx(tx *sql.Tx, clientID string) (int, error) {
	var count int
	if err := tx.QueryRow(`
		SELECT COUNT(*)
		FROM oidc_client_secrets
		WHERE client_id = $1 AND revoked_at IS NULL
	`, clientID).Scan(&count); err != nil {
		return 0, err
	}
	return count, nil
}

func (s *Store) listOIDCClientRedirectURIsByClientIDs(clientIDs []string) (map[string][]string, error) {
	out := make(map[string][]string, len(clientIDs))
	if len(clientIDs) == 0 {
		return out, nil
	}

	rows, err := s.db.Query(`
		SELECT client_id, redirect_uri
		FROM oidc_client_redirect_uris
		WHERE client_id = ANY($1)
		ORDER BY client_id ASC, redirect_uri ASC
	`, pq.Array(clientIDs))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var (
			clientID string
			uri      string
		)
		if err := rows.Scan(&clientID, &uri); err != nil {
			return nil, err
		}
		clientID = strings.TrimSpace(clientID)
		uri = strings.TrimSpace(uri)
		if clientID == "" || uri == "" {
			continue
		}
		out[clientID] = append(out[clientID], uri)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return out, nil
}

func keysOIDCClientMap(in map[string]int) []string {
	out := make([]string, 0, len(in))
	for key := range in {
		out = append(out, key)
	}
	return out
}

func normalizeOIDCClientBootstrapInput(input OIDCClientBootstrapInput) (OIDCClientBootstrapInput, error) {
	var err error
	input.ID = strings.TrimSpace(input.ID)
	if input.ID == "" {
		return OIDCClientBootstrapInput{}, fmt.Errorf("client id is required")
	}
	input.Name = strings.TrimSpace(input.Name)
	input.AuthMethod = strings.ToLower(strings.TrimSpace(input.AuthMethod))

	input.RedirectURIs, err = normalizeRedirectURIs(input.RedirectURIs)
	if err != nil {
		return OIDCClientBootstrapInput{}, err
	}
	if len(input.RedirectURIs) == 0 {
		return OIDCClientBootstrapInput{}, fmt.Errorf("client %q: at least one redirect_uri is required", input.ID)
	}

	input.GrantTypes = normalizeStringListLower(input.GrantTypes)
	if len(input.GrantTypes) == 0 {
		input.GrantTypes = []string{"authorization_code"}
	}
	input.ResponseTypes = normalizeStringListLower(input.ResponseTypes)
	if len(input.ResponseTypes) == 0 {
		input.ResponseTypes = []string{"code"}
	}
	input.Scopes = normalizeStringList(input.Scopes)
	if len(input.Scopes) == 0 {
		input.Scopes = []string{"openid", "profile", "email", "phone", "offline_access"}
	}
	if containsString(input.GrantTypes, "refresh_token") && !containsString(input.Scopes, "offline_access") {
		input.Scopes = append(input.Scopes, "offline_access")
	}

	switch input.AuthMethod {
	case "":
		if input.Confidential {
			input.AuthMethod = "basic"
		} else {
			input.AuthMethod = "none"
		}
	case "client_secret_basic":
		input.AuthMethod = "basic"
	case "client_secret_post":
		input.AuthMethod = "post"
	}
	if input.AuthMethod != "none" && input.AuthMethod != "basic" && input.AuthMethod != "post" {
		return OIDCClientBootstrapInput{}, fmt.Errorf("client %q: unsupported auth_method %q", input.ID, input.AuthMethod)
	}

	input.Secrets = normalizeOIDCClientSecrets(input.Secrets)
	if !input.Confidential {
		input.AuthMethod = "none"
		if len(input.Secrets) > 0 {
			return OIDCClientBootstrapInput{}, fmt.Errorf("client %q: public clients must not define secrets", input.ID)
		}
	}
	if input.Confidential && input.AuthMethod == "none" {
		return OIDCClientBootstrapInput{}, fmt.Errorf("client %q: confidential client cannot use auth_method none", input.ID)
	}
	if input.Confidential && len(input.Secrets) == 0 {
		return OIDCClientBootstrapInput{}, fmt.Errorf("client %q: confidential client requires at least one secret", input.ID)
	}

	return input, nil
}

func normalizeOIDCClientForUpdate(client OIDCClient) (OIDCClient, error) {
	client.ID = strings.TrimSpace(client.ID)
	if client.ID == "" {
		return OIDCClient{}, fmt.Errorf("client id is required")
	}
	client.Name = strings.TrimSpace(client.Name)
	client.AuthMethod = strings.ToLower(strings.TrimSpace(client.AuthMethod))

	client.GrantTypes = normalizeStringListLower(client.GrantTypes)
	if len(client.GrantTypes) == 0 {
		client.GrantTypes = []string{"authorization_code"}
	}
	client.ResponseTypes = normalizeStringListLower(client.ResponseTypes)
	if len(client.ResponseTypes) == 0 {
		client.ResponseTypes = []string{"code"}
	}
	client.Scopes = normalizeStringList(client.Scopes)
	if len(client.Scopes) == 0 {
		client.Scopes = []string{"openid", "profile", "email", "phone", "offline_access"}
	}
	if containsString(client.GrantTypes, "refresh_token") && !containsString(client.Scopes, "offline_access") {
		client.Scopes = append(client.Scopes, "offline_access")
	}

	switch client.AuthMethod {
	case "":
		if client.Confidential {
			client.AuthMethod = "basic"
		} else {
			client.AuthMethod = "none"
		}
	case "client_secret_basic":
		client.AuthMethod = "basic"
	case "client_secret_post":
		client.AuthMethod = "post"
	}
	if client.AuthMethod != "none" && client.AuthMethod != "basic" && client.AuthMethod != "post" {
		return OIDCClient{}, fmt.Errorf("unsupported auth_method %q", client.AuthMethod)
	}
	if !client.Confidential {
		client.AuthMethod = "none"
	}
	if client.Confidential && client.AuthMethod == "none" {
		return OIDCClient{}, fmt.Errorf("confidential client cannot use auth_method none")
	}

	return client, nil
}

func normalizeRedirectURIs(uris []string) ([]string, error) {
	out := make([]string, 0, len(uris))
	seen := make(map[string]struct{}, len(uris))
	for _, uri := range uris {
		trimmed := strings.TrimSpace(uri)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		out = append(out, trimmed)
	}
	return out, nil
}

func normalizeOIDCClientSecrets(secrets []OIDCClientSecretInput) []OIDCClientSecretInput {
	out := make([]OIDCClientSecretInput, 0, len(secrets))
	seen := make(map[string]struct{}, len(secrets))
	for _, secret := range secrets {
		plain := strings.TrimSpace(secret.PlainSecret)
		if plain == "" {
			continue
		}
		if _, exists := seen[plain]; exists {
			continue
		}
		seen[plain] = struct{}{}
		out = append(out, OIDCClientSecretInput{
			PlainSecret: plain,
			Label:       strings.TrimSpace(secret.Label),
		})
	}
	return out
}

func normalizeStringListLower(items []string) []string {
	out := make([]string, 0, len(items))
	seen := make(map[string]struct{}, len(items))
	for _, item := range items {
		trimmed := strings.ToLower(strings.TrimSpace(item))
		if trimmed == "" {
			continue
		}
		if _, exists := seen[trimmed]; exists {
			continue
		}
		seen[trimmed] = struct{}{}
		out = append(out, trimmed)
	}
	return out
}

func normalizeStringList(items []string) []string {
	out := make([]string, 0, len(items))
	seen := make(map[string]struct{}, len(items))
	for _, item := range items {
		trimmed := strings.TrimSpace(item)
		if trimmed == "" {
			continue
		}
		if _, exists := seen[trimmed]; exists {
			continue
		}
		seen[trimmed] = struct{}{}
		out = append(out, trimmed)
	}
	return out
}

func containsString(items []string, needle string) bool {
	needle = strings.TrimSpace(needle)
	for _, item := range items {
		if strings.TrimSpace(item) == needle {
			return true
		}
	}
	return false
}

func secretMaterialForBcrypt(plainSecret string) []byte {
	trimmed := strings.TrimSpace(plainSecret)
	if len(trimmed) <= 72 {
		return []byte(trimmed)
	}
	sum := sha256.Sum256([]byte(trimmed))
	encoded := base64.RawURLEncoding.EncodeToString(sum[:])
	return []byte("sha256:" + encoded)
}
