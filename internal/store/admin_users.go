package store

import (
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/lib/pq"
)

var (
	ErrAdminUserNotFound       = errors.New("admin user not found")
	ErrAdminCredentialNotFound = errors.New("admin credential not found")
	ErrAdminUserDisabled       = errors.New("admin user is disabled")
	ErrAdminCredentialLast     = errors.New("cannot delete last admin credential")
)

type AdminUser struct {
	ID          string
	Login       string
	DisplayName string
	Enabled     bool
	CreatedAt   time.Time
	UpdatedAt   time.Time
	Credentials []webauthn.Credential
}

type AdminCredentialInfo struct {
	ID           int64
	CredentialID string
	CreatedAt    time.Time
	LastUsedAt   *time.Time
	Transports   []string
}

func (u *AdminUser) WebAuthnID() []byte {
	return []byte(u.ID)
}

func (u *AdminUser) WebAuthnName() string {
	return u.Login
}

func (u *AdminUser) WebAuthnDisplayName() string {
	if strings.TrimSpace(u.DisplayName) != "" {
		return u.DisplayName
	}
	return u.Login
}

func (u *AdminUser) WebAuthnIcon() string {
	return ""
}

func (u *AdminUser) WebAuthnCredentials() []webauthn.Credential {
	return u.Credentials
}

func (s *Store) CountAdminUsers() (int, error) {
	var count int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM admin_users`).Scan(&count); err != nil {
		return 0, err
	}
	return count, nil
}

func (s *Store) CountAdminCredentials() (int, error) {
	var count int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM admin_credentials`).Scan(&count); err != nil {
		return 0, err
	}
	return count, nil
}

func (s *Store) CreateAdminUser(login string, displayName string) (*AdminUser, error) {
	login = normalizeAdminLogin(login)
	if login == "" {
		return nil, fmt.Errorf("admin login is required")
	}
	displayName = strings.TrimSpace(displayName)
	if displayName == "" {
		displayName = login
	}

	var out AdminUser
	err := s.db.QueryRow(`
		INSERT INTO admin_users (login, display_name)
		VALUES ($1, $2)
		RETURNING id::text, login, display_name, enabled, created_at, updated_at
	`, login, displayName).Scan(
		&out.ID,
		&out.Login,
		&out.DisplayName,
		&out.Enabled,
		&out.CreatedAt,
		&out.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	out.Credentials = []webauthn.Credential{}
	return &out, nil
}

func (s *Store) GetAdminUser(id string) (*AdminUser, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return nil, ErrAdminUserNotFound
	}

	var out AdminUser
	err := s.db.QueryRow(`
		SELECT id::text, login, display_name, enabled, created_at, updated_at
		FROM admin_users
		WHERE id = $1
	`, id).Scan(
		&out.ID,
		&out.Login,
		&out.DisplayName,
		&out.Enabled,
		&out.CreatedAt,
		&out.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrAdminUserNotFound
		}
		return nil, err
	}

	credentials, err := s.listAdminCredentials(out.ID)
	if err != nil {
		return nil, err
	}
	out.Credentials = credentials
	return &out, nil
}

func (s *Store) GetAdminUserByLogin(login string) (*AdminUser, error) {
	login = normalizeAdminLogin(login)
	if login == "" {
		return nil, ErrAdminUserNotFound
	}
	var id string
	err := s.db.QueryRow(`SELECT id::text FROM admin_users WHERE lower(trim(login)) = lower(trim($1))`, login).Scan(&id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrAdminUserNotFound
		}
		return nil, err
	}
	return s.GetAdminUser(id)
}

func (s *Store) GetAdminUserByCredentialID(credentialID []byte) (*AdminUser, error) {
	if len(credentialID) == 0 {
		return nil, ErrAdminUserNotFound
	}
	var id string
	err := s.db.QueryRow(`
		SELECT u.id::text
		FROM admin_users u
		JOIN admin_credentials c ON c.admin_user_id = u.id
		WHERE c.credential_id = $1
		LIMIT 1
	`, credentialID).Scan(&id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrAdminUserNotFound
		}
		return nil, err
	}
	return s.GetAdminUser(id)
}

func (s *Store) AddAdminCredential(adminUserID string, credential *webauthn.Credential) error {
	adminUserID = strings.TrimSpace(adminUserID)
	if adminUserID == "" {
		return fmt.Errorf("admin user id is required")
	}
	if credential == nil || len(credential.ID) == 0 || len(credential.PublicKey) == 0 {
		return fmt.Errorf("admin credential is required")
	}

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	var enabled bool
	if err := tx.QueryRow(`SELECT enabled FROM admin_users WHERE id = $1`, adminUserID).Scan(&enabled); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrAdminUserNotFound
		}
		return err
	}
	if !enabled {
		return ErrAdminUserDisabled
	}

	transports := make([]string, 0, len(credential.Transport))
	for _, transport := range credential.Transport {
		trimmed := strings.TrimSpace(string(transport))
		if trimmed == "" {
			continue
		}
		transports = append(transports, trimmed)
	}

	_, err = tx.Exec(`
		INSERT INTO admin_credentials (
			admin_user_id, credential_id, public_key, aaguid, sign_count, transports
		)
		VALUES ($1, $2, $3, $4, $5, $6)
	`, adminUserID, credential.ID, credential.PublicKey, credential.Authenticator.AAGUID, credential.Authenticator.SignCount, pq.Array(transports))
	if err != nil {
		return err
	}

	if _, err := tx.Exec(`UPDATE admin_users SET updated_at = NOW() WHERE id = $1`, adminUserID); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) UpdateAdminCredential(credential *webauthn.Credential) error {
	if credential == nil || len(credential.ID) == 0 {
		return fmt.Errorf("admin credential id is required")
	}

	res, err := s.db.Exec(`
		UPDATE admin_credentials
		SET sign_count = $2, last_used_at = NOW()
		WHERE credential_id = $1
	`, credential.ID, credential.Authenticator.SignCount)
	if err != nil {
		return err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return ErrAdminCredentialNotFound
	}
	return nil
}

func (s *Store) ListAdminCredentials(adminUserID string) ([]AdminCredentialInfo, error) {
	adminUserID = strings.TrimSpace(adminUserID)
	if adminUserID == "" {
		return nil, ErrAdminUserNotFound
	}

	rows, err := s.db.Query(`
		SELECT id, credential_id, created_at, last_used_at, transports
		FROM admin_credentials
		WHERE admin_user_id = $1
		ORDER BY created_at ASC, id ASC
	`, adminUserID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]AdminCredentialInfo, 0, 4)
	for rows.Next() {
		var (
			item         AdminCredentialInfo
			credentialID []byte
			lastUsedAt   sql.NullTime
			transports   pq.StringArray
		)
		if err := rows.Scan(&item.ID, &credentialID, &item.CreatedAt, &lastUsedAt, &transports); err != nil {
			return nil, err
		}
		item.CredentialID = encodeCredentialDisplayID(credentialID)
		if lastUsedAt.Valid {
			value := lastUsedAt.Time.UTC()
			item.LastUsedAt = &value
		}
		item.Transports = make([]string, 0, len(transports))
		for _, transport := range transports {
			trimmed := strings.TrimSpace(transport)
			if trimmed == "" {
				continue
			}
			item.Transports = append(item.Transports, trimmed)
		}
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Store) CountAdminCredentialsForUser(adminUserID string) (int, error) {
	adminUserID = strings.TrimSpace(adminUserID)
	if adminUserID == "" {
		return 0, ErrAdminUserNotFound
	}
	var count int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM admin_credentials WHERE admin_user_id = $1`, adminUserID).Scan(&count); err != nil {
		return 0, err
	}
	return count, nil
}

func (s *Store) DeleteAdminCredential(adminUserID string, credentialID int64) error {
	adminUserID = strings.TrimSpace(adminUserID)
	if adminUserID == "" {
		return ErrAdminUserNotFound
	}
	if credentialID <= 0 {
		return ErrAdminCredentialNotFound
	}

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	var exists bool
	if err := tx.QueryRow(`SELECT EXISTS (SELECT 1 FROM admin_users WHERE id = $1)`, adminUserID).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		return ErrAdminUserNotFound
	}

	var count int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM admin_credentials WHERE admin_user_id = $1`, adminUserID).Scan(&count); err != nil {
		return err
	}
	if count <= 1 {
		return ErrAdminCredentialLast
	}

	res, err := tx.Exec(`DELETE FROM admin_credentials WHERE id = $1 AND admin_user_id = $2`, credentialID, adminUserID)
	if err != nil {
		return err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return ErrAdminCredentialNotFound
	}

	if _, err := tx.Exec(`UPDATE admin_users SET updated_at = NOW() WHERE id = $1`, adminUserID); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) listAdminCredentials(adminUserID string) ([]webauthn.Credential, error) {
	rows, err := s.db.Query(`
		SELECT credential_id, public_key, aaguid, sign_count, transports
		FROM admin_credentials
		WHERE admin_user_id = $1
		ORDER BY created_at ASC, id ASC
	`, adminUserID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]webauthn.Credential, 0, 4)
	for rows.Next() {
		var (
			credentialID []byte
			publicKey    []byte
			aaguid       []byte
			signCount    int64
			transports   pq.StringArray
		)
		if err := rows.Scan(&credentialID, &publicKey, &aaguid, &signCount, &transports); err != nil {
			return nil, err
		}
		item := webauthn.Credential{
			ID:        credentialID,
			PublicKey: publicKey,
			Transport: make([]protocol.AuthenticatorTransport, 0, len(transports)),
			Authenticator: webauthn.Authenticator{
				AAGUID:    aaguid,
				SignCount: uint32(signCount),
			},
		}
		for _, transport := range transports {
			trimmed := strings.TrimSpace(transport)
			if trimmed == "" {
				continue
			}
			item.Transport = append(item.Transport, protocol.AuthenticatorTransport(trimmed))
		}
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func normalizeAdminLogin(login string) string {
	return strings.ToLower(strings.TrimSpace(login))
}

func encodeCredentialDisplayID(raw []byte) string {
	if len(raw) == 0 {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}
