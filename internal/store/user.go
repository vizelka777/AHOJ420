package store

import (
	"bytes"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/lib/pq"
)

type Store struct {
	db *sql.DB
}

var (
	ErrProfileEmailVerificationMismatch = errors.New("profile email mismatch or nothing to verify")
	ErrPhoneVerificationMismatch        = errors.New("phone mismatch or nothing to verify")
	ErrProfileEmailAlreadyUsed          = errors.New("profile email already used")
	ErrPhoneAlreadyUsed                 = errors.New("phone already used")
	ErrCredentialNotFound               = errors.New("credential not found")
	ErrCannotDeleteLastCredential       = errors.New("cannot delete last credential")
)

func New(db *sql.DB) *Store {
	return &Store{db: db}
}

type User struct {
	ID              string
	LoginID         string
	DisplayName     string
	ProfileEmail    string
	Phone           string
	ShareProfile    bool
	EmailVerified   bool
	PhoneVerified   bool
	AvatarKey       string
	AvatarUpdatedAt *time.Time
	AvatarMIME      string
	AvatarBytes     int64
	Credentials     []webauthn.Credential
}

type CredentialRecord struct {
	ID         []byte
	DeviceName string
	CreatedAt  time.Time
	LastUsedAt *time.Time
}

// WebAuthnUser interface implementation
func (u *User) WebAuthnID() []byte {
	return []byte(u.ID)
}

func (u *User) WebAuthnName() string {
	if u.DisplayName != "" {
		return u.DisplayName
	}
	return "Ahoj User"
}

func (u *User) WebAuthnDisplayName() string {
	if u.DisplayName != "" {
		return u.DisplayName
	}
	return "Ahoj User"
}

func (u *User) WebAuthnIcon() string {
	return ""
}

func (u *User) WebAuthnCredentials() []webauthn.Credential {
	return u.Credentials
}

func (s *Store) CreateUser(loginID string) (*User, error) {
	normalizedLoginID := strings.TrimSpace(loginID)
	displayName := defaultDisplayName(normalizedLoginID)

	var id string
	var finalDisplayName string
	err := s.db.QueryRow(`
		INSERT INTO users (email, display_name) VALUES ($1, $2)
		ON CONFLICT (email) DO UPDATE SET email = EXCLUDED.email
		RETURNING id::text, COALESCE(NULLIF(display_name, ''), $2)
	`, normalizedLoginID, displayName).Scan(&id, &finalDisplayName)
	if err != nil {
		return nil, fmt.Errorf("create user: %w", err)
	}

	return &User{ID: id, LoginID: normalizedLoginID, DisplayName: finalDisplayName}, nil
}

func (s *Store) CreateAnonymousUser() (*User, error) {
	loginID := "anon-" + uuid.NewString()
	return s.CreateUser(loginID)
}

func defaultDisplayName(loginID string) string {
	loginID = strings.TrimSpace(loginID)
	if strings.HasPrefix(loginID, "anon-") {
		trimmed := strings.TrimPrefix(loginID, "anon-")
		if len(trimmed) >= 8 {
			return "Ahoj User " + strings.ToUpper(trimmed[:8])
		}
		return "Ahoj User"
	}

	local := strings.Split(loginID, "@")[0]
	local = strings.TrimSpace(local)
	if local == "" {
		return "Ahoj User"
	}
	return local
}

func (s *Store) GetUser(id string) (*User, error) {
	// 1. Get User
	var user User
	err := s.db.QueryRow(`
		SELECT
			id::text,
			email,
			COALESCE(NULLIF(display_name, ''), 'Ahoj User'),
			COALESCE(profile_email, ''),
			COALESCE(phone, ''),
			COALESCE(share_profile, false),
			COALESCE(email_verified, false),
			COALESCE(phone_verified, false),
			COALESCE(avatar_key, ''),
			avatar_updated_at,
			COALESCE(avatar_mime, ''),
			COALESCE(avatar_bytes, 0)
		FROM users
		WHERE id = $1
	`, id).Scan(
		&user.ID,
		&user.LoginID,
		&user.DisplayName,
		&user.ProfileEmail,
		&user.Phone,
		&user.ShareProfile,
		&user.EmailVerified,
		&user.PhoneVerified,
		&user.AvatarKey,
		&user.AvatarUpdatedAt,
		&user.AvatarMIME,
		&user.AvatarBytes,
	)
	if err != nil {
		return nil, fmt.Errorf("get user: %w", err)
	}

	// 2. Get Credentials
	rows, err := s.db.Query(`SELECT id, public_key, sign_count FROM credentials WHERE user_id = $1`, id)
	if err != nil {
		return nil, fmt.Errorf("get creds: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var cred webauthn.Credential
		var credID, pubKey []byte
		var signCount int64

		if err := rows.Scan(&credID, &pubKey, &signCount); err != nil {
			return nil, err
		}

		cred.ID = credID
		cred.PublicKey = pubKey
		cred.Authenticator.SignCount = uint32(signCount)

		user.Credentials = append(user.Credentials, cred)
	}

	return &user, nil
}

func (s *Store) GetUserByLoginID(loginID string) (*User, error) {
	normalizedLoginID := strings.TrimSpace(loginID)
	var id string
	err := s.db.QueryRow(`SELECT id::text FROM users WHERE email = $1`, normalizedLoginID).Scan(&id)
	if err != nil {
		return nil, err
	}
	return s.GetUser(id)
}

func (s *Store) GetUserByProfileEmail(profileEmail string) (*User, error) {
	normalizedProfileEmail := strings.TrimSpace(profileEmail)
	var id string
	err := s.db.QueryRow(`
		SELECT id::text
		FROM users
		WHERE trim(COALESCE(profile_email, '')) <> ''
		  AND lower(trim(profile_email)) = lower(trim($1))
		  AND COALESCE(email_verified, false) = true
		ORDER BY created_at ASC
		LIMIT 1
	`, normalizedProfileEmail).Scan(&id)
	if err != nil {
		return nil, err
	}
	return s.GetUser(id)
}

func (s *Store) GetUserByVerifiedPhone(phone string) (*User, error) {
	normalizedPhone := strings.TrimSpace(phone)
	var id string
	err := s.db.QueryRow(`
		SELECT id::text
		FROM users
		WHERE trim(COALESCE(phone, '')) <> ''
		  AND trim(phone) = trim($1)
		  AND COALESCE(phone_verified, false) = true
		ORDER BY created_at ASC
		LIMIT 1
	`, normalizedPhone).Scan(&id)
	if err != nil {
		return nil, err
	}
	return s.GetUser(id)
}

func (s *Store) GetUserByCredentialID(credID []byte) (*User, error) {
	var userID string
	err := s.db.QueryRow(`
        SELECT user_id FROM credentials WHERE id = $1
    `, credID).Scan(&userID)
	if err != nil {
		return nil, err
	}
	return s.GetUser(userID)
}

func (s *Store) AddCredential(userID string, cred *webauthn.Credential) error {
	_, err := s.db.Exec(`
        INSERT INTO credentials (id, user_id, public_key, aaguid, sign_count, last_used_at)
        VALUES ($1, $2, $3, $4, $5, NOW())
    `, cred.ID, userID, cred.PublicKey, cred.Authenticator.AAGUID, cred.Authenticator.SignCount)

	return err
}

func (s *Store) DeleteCredentialsByUser(userID string) error {
	_, err := s.db.Exec(`DELETE FROM credentials WHERE user_id = $1`, userID)
	return err
}

func (s *Store) DeleteCredentialByUserAndID(userID string, credID []byte) error {
	if strings.TrimSpace(userID) == "" || len(credID) == 0 {
		return ErrCredentialNotFound
	}

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	rows, err := tx.Query(`SELECT id FROM credentials WHERE user_id = $1 FOR UPDATE`, userID)
	if err != nil {
		return err
	}

	count := 0
	found := false
	for rows.Next() {
		var id []byte
		if err := rows.Scan(&id); err != nil {
			_ = rows.Close()
			return err
		}
		count++
		if bytes.Equal(id, credID) {
			found = true
		}
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}

	if !found {
		return ErrCredentialNotFound
	}
	if count <= 1 {
		return ErrCannotDeleteLastCredential
	}

	res, err := tx.Exec(`DELETE FROM credentials WHERE user_id = $1 AND id = $2`, userID, credID)
	if err != nil {
		return err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return ErrCredentialNotFound
	}

	return tx.Commit()
}

func (s *Store) UpdateCredential(cred *webauthn.Credential) error {
	_, err := s.db.Exec(`
	        UPDATE credentials
	        SET sign_count = $1, last_used_at = NOW()
	        WHERE id = $2
	    `, cred.Authenticator.SignCount, cred.ID)
	return err
}

func (s *Store) ListCredentialRecords(userID string) ([]CredentialRecord, error) {
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return []CredentialRecord{}, nil
	}

	rows, err := s.db.Query(`
		SELECT id, COALESCE(device_name, ''), created_at, last_used_at
		FROM credentials
		WHERE user_id = $1
		ORDER BY COALESCE(last_used_at, created_at) DESC, created_at DESC
	`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]CredentialRecord, 0, 8)
	for rows.Next() {
		var item CredentialRecord
		var lastUsed sql.NullTime
		if err := rows.Scan(&item.ID, &item.DeviceName, &item.CreatedAt, &lastUsed); err != nil {
			return nil, err
		}
		if lastUsed.Valid {
			ts := lastUsed.Time
			item.LastUsedAt = &ts
		}
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Store) UpdateProfile(userID, displayName, profileEmail, phone string, shareProfile bool) error {
	if strings.TrimSpace(displayName) == "" {
		displayName = "Ahoj User"
	}
	_, err := s.db.Exec(`
		UPDATE users
		SET
			display_name = $1,
			profile_email = NULLIF($2, ''),
			phone = NULLIF($3, ''),
			share_profile = $4,
			email_verified = CASE
				WHEN NULLIF($2, '') IS DISTINCT FROM profile_email THEN false
				ELSE email_verified
			END,
			phone_verified = CASE
				WHEN NULLIF($3, '') IS DISTINCT FROM phone THEN false
				ELSE phone_verified
			END,
			profile_completed_at = NOW()
		WHERE id = $5
	`, strings.TrimSpace(displayName), strings.TrimSpace(profileEmail), strings.TrimSpace(phone), shareProfile, userID)
	if err != nil {
		var pqErr *pq.Error
		if errors.As(err, &pqErr) && pqErr.Code == "23505" {
			switch strings.TrimSpace(pqErr.Constraint) {
			case "users_profile_email_unique_idx":
				return ErrProfileEmailAlreadyUsed
			case "users_phone_unique_idx":
				return ErrPhoneAlreadyUsed
			}
		}
		return err
	}
	return nil
}

func (s *Store) DeleteUser(userID string) error {
	_, err := s.db.Exec(`DELETE FROM users WHERE id = $1`, userID)
	return err
}

func (s *Store) UpdateAvatar(userID, avatarKey, avatarMIME string, avatarBytes int64) error {
	_, err := s.db.Exec(`
		UPDATE users
		SET
			avatar_key = $1,
			avatar_updated_at = NOW(),
			avatar_mime = $2,
			avatar_bytes = $3
		WHERE id = $4
	`, strings.TrimSpace(avatarKey), strings.TrimSpace(avatarMIME), avatarBytes, userID)
	return err
}

func (s *Store) VerifyProfileEmail(userID, expectedEmail string) error {
	res, err := s.db.Exec(`
		UPDATE users
		SET
			email_verified = true
		WHERE id = $1
		  AND lower(trim(COALESCE(profile_email, ''))) = lower(trim($2))
	`, userID, strings.TrimSpace(expectedEmail))
	if err != nil {
		return err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return ErrProfileEmailVerificationMismatch
	}
	return nil
}

func (s *Store) VerifyPhone(userID, expectedPhone string) error {
	res, err := s.db.Exec(`
		UPDATE users
		SET
			phone_verified = true
		WHERE id = $1
		  AND trim(COALESCE(phone, '')) <> ''
		  AND trim(COALESCE(phone, '')) = trim($2)
	`, userID, strings.TrimSpace(expectedPhone))
	if err != nil {
		return err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return ErrPhoneVerificationMismatch
	}
	return nil
}
