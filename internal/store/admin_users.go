package store

import (
	"context"
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
	ErrAdminRoleInvalid        = errors.New("admin role is invalid")
)

const (
	AdminRoleOwner = "owner"
	AdminRoleAdmin = "admin"
)

type AdminUser struct {
	ID                string
	Login             string
	DisplayName       string
	Enabled           bool
	Role              string
	CreatedAt         time.Time
	UpdatedAt         time.Time
	CredentialCount   int
	ActiveInviteCount int
	Credentials       []webauthn.Credential
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

func (u *AdminUser) IsOwner() bool {
	return NormalizeAdminRole(u.Role) == AdminRoleOwner
}

func (s *Store) CountAdminUsers() (int, error) {
	var count int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM admin_users`).Scan(&count); err != nil {
		return 0, err
	}
	return count, nil
}

func (s *Store) CountEnabledAdminUsers() (int, error) {
	var count int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM admin_users WHERE enabled = true`).Scan(&count); err != nil {
		return 0, err
	}
	return count, nil
}

func (s *Store) CountEnabledAdminUsersByRole(role string) (int, error) {
	role = strings.TrimSpace(strings.ToLower(role))
	if !IsValidAdminRole(role) {
		return 0, ErrAdminRoleInvalid
	}
	var count int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM admin_users WHERE enabled = true AND role = $1`, role).Scan(&count); err != nil {
		return 0, err
	}
	return count, nil
}

func (s *Store) ListAdminUsers() ([]AdminUser, error) {
	rows, err := s.db.Query(`
		SELECT
			u.id::text,
			u.login,
			u.display_name,
			u.enabled,
			u.role,
			u.created_at,
			u.updated_at,
			COALESCE(c.credential_count, 0),
			COALESCE(i.active_invite_count, 0)
		FROM admin_users u
		LEFT JOIN (
			SELECT admin_user_id, COUNT(*) AS credential_count
			FROM admin_credentials
			GROUP BY admin_user_id
		) c ON c.admin_user_id = u.id
		LEFT JOIN (
			SELECT admin_user_id, COUNT(*) AS active_invite_count
			FROM admin_invites
			WHERE used_at IS NULL
			  AND revoked_at IS NULL
			  AND expires_at > NOW()
			GROUP BY admin_user_id
		) i ON i.admin_user_id = u.id
		ORDER BY u.created_at ASC, lower(u.login) ASC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]AdminUser, 0, 8)
	for rows.Next() {
		var item AdminUser
		if err := rows.Scan(
			&item.ID,
			&item.Login,
			&item.DisplayName,
			&item.Enabled,
			&item.Role,
			&item.CreatedAt,
			&item.UpdatedAt,
			&item.CredentialCount,
			&item.ActiveInviteCount,
		); err != nil {
			return nil, err
		}
		item.Login = normalizeAdminLogin(item.Login)
		item.DisplayName = strings.TrimSpace(item.DisplayName)
		item.Role = NormalizeAdminRole(item.Role)
		item.Credentials = []webauthn.Credential{}
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
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
		INSERT INTO admin_users (login, display_name, role)
		VALUES ($1, $2, $3)
		RETURNING id::text, login, display_name, enabled, role, created_at, updated_at
	`, login, displayName, AdminRoleAdmin).Scan(
		&out.ID,
		&out.Login,
		&out.DisplayName,
		&out.Enabled,
		&out.Role,
		&out.CreatedAt,
		&out.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	out.Role = NormalizeAdminRole(out.Role)
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
		SELECT id::text, login, display_name, enabled, role, created_at, updated_at
		FROM admin_users
		WHERE id = $1
	`, id).Scan(
		&out.ID,
		&out.Login,
		&out.DisplayName,
		&out.Enabled,
		&out.Role,
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
	out.Role = NormalizeAdminRole(out.Role)
	out.Credentials = credentials
	out.CredentialCount = len(credentials)
	activeInvites, err := s.CountActiveAdminInvitesForUser(context.Background(), out.ID)
	if err == nil {
		out.ActiveInviteCount = activeInvites
	}
	return &out, nil
}

func (s *Store) GetAdminUserByID(id string) (*AdminUser, error) {
	return s.GetAdminUser(id)
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

func (s *Store) SetAdminUserEnabled(id string, enabled bool) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return ErrAdminUserNotFound
	}
	res, err := s.db.Exec(`
		UPDATE admin_users
		SET enabled = $2, updated_at = NOW()
		WHERE id = $1
	`, id, enabled)
	if err != nil {
		return err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return ErrAdminUserNotFound
	}
	return nil
}

func (s *Store) SetAdminUserRole(id string, role string) error {
	id = strings.TrimSpace(id)
	role = strings.TrimSpace(strings.ToLower(role))
	if id == "" {
		return ErrAdminUserNotFound
	}
	if !IsValidAdminRole(role) {
		return ErrAdminRoleInvalid
	}
	res, err := s.db.Exec(`
		UPDATE admin_users
		SET role = $2, updated_at = NOW()
		WHERE id = $1
	`, id, role)
	if err != nil {
		return err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return ErrAdminUserNotFound
	}
	return nil
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

func NormalizeAdminRole(role string) string {
	role = strings.TrimSpace(strings.ToLower(role))
	switch role {
	case AdminRoleOwner:
		return AdminRoleOwner
	default:
		return AdminRoleAdmin
	}
}

func IsValidAdminRole(role string) bool {
	switch strings.TrimSpace(strings.ToLower(role)) {
	case AdminRoleOwner, AdminRoleAdmin:
		return true
	default:
		return false
	}
}

func encodeCredentialDisplayID(raw []byte) string {
	if len(raw) == 0 {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}
