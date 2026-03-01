package oidc

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	refreshTokenTTL                 = 14 * 24 * time.Hour
	refreshTokenReuseGracePeriod    = 30 * time.Second
	refreshTokenKeyPrefix           = "oidc:rt:"
	refreshTokenFamilyRevokedPrefix = "oidc:rt_family_revoked:"
)

var ErrRefreshTokenNotFound = errors.New("refresh token not found")

type RefreshTokenRecord struct {
	TokenID          string    `json:"token_id"`
	UserID           string    `json:"user_id,omitempty"`
	Subject          string    `json:"subject,omitempty"`
	ClientID         string    `json:"client_id"`
	Scopes           []string  `json:"scopes,omitempty"`
	Audience         []string  `json:"audience,omitempty"`
	AMR              []string  `json:"amr,omitempty"`
	AuthTime         time.Time `json:"auth_time"`
	IssuedAt         time.Time `json:"issued_at"`
	ExpiresAt        time.Time `json:"expires_at"`
	ParentTokenID    string    `json:"parent_token_id,omitempty"`
	FamilyID         string    `json:"family_id,omitempty"`
	RotatedToTokenID string    `json:"rotated_to_token_id,omitempty"`
	RevokedAt        time.Time `json:"revoked_at,omitempty"`
	UsedAt           time.Time `json:"used_at,omitempty"`
	ReuseDetectedAt  time.Time `json:"reuse_detected_at,omitempty"`
}

func (r *RefreshTokenRecord) GetAMR() []string {
	return append([]string(nil), r.AMR...)
}

func (r *RefreshTokenRecord) GetAudience() []string {
	return append([]string(nil), r.Audience...)
}

func (r *RefreshTokenRecord) GetAuthTime() time.Time {
	return r.AuthTime
}

func (r *RefreshTokenRecord) GetClientID() string {
	return r.ClientID
}

func (r *RefreshTokenRecord) GetScopes() []string {
	return append([]string(nil), r.Scopes...)
}

func (r *RefreshTokenRecord) GetSubject() string {
	if r.Subject != "" {
		return r.Subject
	}
	return r.UserID
}

func (r *RefreshTokenRecord) SetCurrentScopes(scopes []string) {
	r.Scopes = append([]string(nil), scopes...)
}

func refreshTokenKey(tokenID string) string {
	return refreshTokenKeyPrefix + tokenID
}

func refreshTokenFamilyRevokedKey(familyID string) string {
	return refreshTokenFamilyRevokedPrefix + familyID
}

func generateOpaqueTokenID(prefix string) (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	opaque := base64.RawURLEncoding.EncodeToString(raw)
	return prefix + opaque, nil
}

func generateAccessTokenID() (string, error) {
	return generateOpaqueTokenID("at_")
}

func generateRefreshTokenID() (string, error) {
	return generateOpaqueTokenID("rt_")
}

func (s *MemStorage) revokeRefreshTokenFamily(ctx context.Context, familyID string, until time.Time) error {
	if familyID == "" {
		return fmt.Errorf("family id is required")
	}

	ttl := refreshTokenTTL
	if !until.IsZero() {
		candidate := time.Until(until.UTC())
		if candidate > ttl {
			ttl = candidate
		}
	}
	if ttl <= 0 {
		ttl = refreshTokenTTL
	}

	return s.redis.Set(ctx, refreshTokenFamilyRevokedKey(familyID), "1", ttl).Err()
}

func (s *MemStorage) isRefreshTokenFamilyRevoked(ctx context.Context, familyID string) (bool, error) {
	if familyID == "" {
		return false, fmt.Errorf("family id is required")
	}
	exists, err := s.redis.Exists(ctx, refreshTokenFamilyRevokedKey(familyID)).Result()
	if err != nil {
		return false, err
	}
	return exists > 0, nil
}

func (s *MemStorage) saveRefreshToken(ctx context.Context, rec *RefreshTokenRecord) error {
	if rec == nil {
		return fmt.Errorf("refresh token record is nil")
	}
	if rec.TokenID == "" {
		return fmt.Errorf("token id is required")
	}
	if rec.ClientID == "" {
		return fmt.Errorf("client id is required")
	}

	normalized := *rec
	normalized.AuthTime = normalized.AuthTime.UTC()
	if normalized.IssuedAt.IsZero() {
		normalized.IssuedAt = time.Now().UTC()
	} else {
		normalized.IssuedAt = normalized.IssuedAt.UTC()
	}
	if normalized.ExpiresAt.IsZero() {
		normalized.ExpiresAt = normalized.IssuedAt.Add(refreshTokenTTL)
	} else {
		normalized.ExpiresAt = normalized.ExpiresAt.UTC()
	}
	normalized.Scopes = append([]string(nil), normalized.Scopes...)
	normalized.Audience = append([]string(nil), normalized.Audience...)
	normalized.AMR = append([]string(nil), normalized.AMR...)
	if !normalized.RevokedAt.IsZero() {
		normalized.RevokedAt = normalized.RevokedAt.UTC()
	}
	if !normalized.UsedAt.IsZero() {
		normalized.UsedAt = normalized.UsedAt.UTC()
	}
	if !normalized.ReuseDetectedAt.IsZero() {
		normalized.ReuseDetectedAt = normalized.ReuseDetectedAt.UTC()
	}

	ttl := time.Until(normalized.ExpiresAt)
	if ttl <= 0 {
		return fmt.Errorf("refresh token already expired")
	}

	payload, err := json.Marshal(&normalized)
	if err != nil {
		return err
	}
	return s.redis.Set(ctx, refreshTokenKey(normalized.TokenID), payload, ttl).Err()
}

func (s *MemStorage) getRefreshToken(ctx context.Context, tokenID string) (*RefreshTokenRecord, error) {
	if tokenID == "" {
		return nil, fmt.Errorf("token id is required")
	}

	payload, err := s.redis.Get(ctx, refreshTokenKey(tokenID)).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, ErrRefreshTokenNotFound
		}
		return nil, err
	}

	var rec RefreshTokenRecord
	if err := json.Unmarshal(payload, &rec); err != nil {
		return nil, err
	}
	rec.AuthTime = rec.AuthTime.UTC()
	rec.IssuedAt = rec.IssuedAt.UTC()
	rec.ExpiresAt = rec.ExpiresAt.UTC()
	if !rec.RevokedAt.IsZero() {
		rec.RevokedAt = rec.RevokedAt.UTC()
	}
	if !rec.UsedAt.IsZero() {
		rec.UsedAt = rec.UsedAt.UTC()
	}
	if !rec.ReuseDetectedAt.IsZero() {
		rec.ReuseDetectedAt = rec.ReuseDetectedAt.UTC()
	}
	return &rec, nil
}

func (s *MemStorage) deleteRefreshToken(ctx context.Context, tokenID string) error {
	if tokenID == "" {
		return fmt.Errorf("token id is required")
	}
	return s.redis.Del(ctx, refreshTokenKey(tokenID)).Err()
}
