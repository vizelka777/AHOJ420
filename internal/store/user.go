package store

import (
	"database/sql"
	"fmt"
	"strings"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
)

type Store struct {
	db *sql.DB
}

func New(db *sql.DB) *Store {
	return &Store{db: db}
}

type User struct {
	ID          string
	Email       string
	Credentials []webauthn.Credential
}

// WebAuthnUser interface implementation
func (u *User) WebAuthnID() []byte {
    return []byte(u.ID)
}

func (u *User) WebAuthnName() string {
    return u.Email
}

func (u *User) WebAuthnDisplayName() string {
    if strings.HasPrefix(u.Email, "anon-") && len(u.Email) > 13 {
        return u.Email[:13]
    }
    return u.Email
}

func (u *User) WebAuthnIcon() string {
    return ""
}

func (u *User) WebAuthnCredentials() []webauthn.Credential {
    return u.Credentials
}

func (s *Store) CreateUser(email string) (*User, error) {
    var id string
    err := s.db.QueryRow(`
        INSERT INTO users (email) VALUES ($1)
        ON CONFLICT (email) DO UPDATE SET email = EXCLUDED.email
        RETURNING id::text
    `, email).Scan(&id)
    if err != nil {
        return nil, fmt.Errorf("create user: %w", err)
    }

    return &User{ID: id, Email: email}, nil
}

func (s *Store) CreateAnonymousUser() (*User, error) {
	email := "anon-" + uuid.NewString()
	return s.CreateUser(email)
}

func (s *Store) GetUser(id string) (*User, error) {
    // 1. Get User
    var user User
    err := s.db.QueryRow(`SELECT id::text, email FROM users WHERE id = $1`, id).Scan(&user.ID, &user.Email)
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
        var signCount int64 // Use int64 for DB scan
        
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

func (s *Store) GetUserByEmail(email string) (*User, error) {
    var id string
    err := s.db.QueryRow(`SELECT id::text FROM users WHERE email = $1`, email).Scan(&id)
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

func (s *Store) UpdateCredential(cred *webauthn.Credential) error {
    _, err := s.db.Exec(`
        UPDATE credentials 
        SET sign_count = $1, last_used_at = NOW()
        WHERE id = $2
    `, cred.Authenticator.SignCount, cred.ID)
    return err
}
