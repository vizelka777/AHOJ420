package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/redis/go-redis/v9"

	"github.com/houbamydar/AHOJ420/internal/store"
)

const (
	profilePhoneVerifyTokenPrefix   = "auth:profile_phone_verify:"
	profilePhoneVerifyRatePrefix    = "auth:profile_phone_verify_rate:"
	profilePhoneVerifyTokenTTL      = 10 * time.Minute
	profilePhoneVerifyRateTTL       = 60 * time.Second
	profilePhoneVerifyMaxAttempts   = 5
	profilePhoneVerifyCodeLen       = 6
	profilePhoneVerifyMessagePrefix = "Ahoj420 verification code: "
)

type profilePhoneVerifyToken struct {
	UserID          string    `json:"user_id"`
	Phone           string    `json:"phone"`
	CodeHash        string    `json:"code_hash"`
	AttemptsLeft    int       `json:"attempts_left"`
	IssuedAt        time.Time `json:"issued_at"`
	LastAttemptedAt time.Time `json:"last_attempted_at,omitempty"`
}

type profilePhoneVerifyPayload struct {
	Code string `json:"code"`
}

func profilePhoneVerifyTokenKey(userID string) string {
	return profilePhoneVerifyTokenPrefix + userID
}

func profilePhoneVerifyRateKey(userID string) string {
	return profilePhoneVerifyRatePrefix + userID
}

func hashPhoneVerifyCode(code string) string {
	sum := sha256.Sum256([]byte(code))
	return hex.EncodeToString(sum[:])
}

func generatePhoneVerifyCode() (string, error) {
	buf := make([]byte, 4)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	n := binary.BigEndian.Uint32(buf)
	code := int(n%900000) + 100000
	return fmt.Sprintf("%06d", code), nil
}

func isNumericCode(code string) bool {
	if len(code) != profilePhoneVerifyCodeLen {
		return false
	}
	for _, ch := range code {
		if ch < '0' || ch > '9' {
			return false
		}
	}
	return true
}

func (s *Service) logProfilePhoneVerifyCode(phone, code string) {
	if s.devMode {
		log.Printf("PHONE VERIFY CODE for %s: %s", phone, code)
		return
	}
	log.Printf("Phone verification code generated for %s", phone)
}

func (s *Service) sendProfilePhoneVerifyCode(c echo.Context, phone, code string) error {
	if s.smsSender == nil {
		if s.devMode {
			s.logProfilePhoneVerifyCode(phone, code)
			return nil
		}
		return fmt.Errorf("sms sender is not configured")
	}
	message := profilePhoneVerifyMessagePrefix + code
	if err := s.smsSender.SendSMS(c.Request().Context(), phone, message); err != nil {
		return err
	}
	s.logProfilePhoneVerifyCode(phone, code)
	return nil
}

func (s *Service) RequestProfilePhoneVerify(c echo.Context) error {
	userID, ok := s.SessionUserID(c)
	if !ok {
		return c.JSON(http.StatusUnauthorized, map[string]any{"message": "not authenticated"})
	}

	ctx := c.Request().Context()
	rateKey := profilePhoneVerifyRateKey(userID)
	okRate, err := s.redis.SetNX(ctx, rateKey, "1", profilePhoneVerifyRateTTL).Result()
	if err != nil {
		return c.String(http.StatusInternalServerError, "Internal error")
	}
	if !okRate {
		return c.String(http.StatusTooManyRequests, "Try again later")
	}

	user, err := s.store.GetUser(userID)
	if err != nil {
		return c.String(http.StatusInternalServerError, "Failed to load user")
	}

	phone, err := normalizePhone(user.Phone)
	if err != nil {
		_ = s.redis.Del(ctx, rateKey).Err()
		return c.String(http.StatusBadRequest, err.Error())
	}
	if phone == "" {
		_ = s.redis.Del(ctx, rateKey).Err()
		return c.String(http.StatusBadRequest, "No profile phone to verify")
	}

	code, err := generatePhoneVerifyCode()
	if err != nil {
		_ = s.redis.Del(ctx, rateKey).Err()
		return c.String(http.StatusInternalServerError, "Internal error")
	}

	token := profilePhoneVerifyToken{
		UserID:       userID,
		Phone:        phone,
		CodeHash:     hashPhoneVerifyCode(code),
		AttemptsLeft: profilePhoneVerifyMaxAttempts,
		IssuedAt:     time.Now().UTC(),
	}
	payload, err := json.Marshal(token)
	if err != nil {
		_ = s.redis.Del(ctx, rateKey).Err()
		return c.String(http.StatusInternalServerError, "Internal error")
	}
	tokenKey := profilePhoneVerifyTokenKey(userID)
	if err := s.redis.Set(ctx, tokenKey, payload, profilePhoneVerifyTokenTTL).Err(); err != nil {
		_ = s.redis.Del(ctx, rateKey).Err()
		return c.String(http.StatusInternalServerError, "Internal error")
	}

	if err := s.sendProfilePhoneVerifyCode(c, phone, code); err != nil {
		_ = s.redis.Del(ctx, tokenKey).Err()
		_ = s.redis.Del(ctx, rateKey).Err()
		log.Printf("Phone verify code send failed for %s: %v", phone, err)
		return c.String(http.StatusInternalServerError, "Failed to send verification code")
	}

	return c.JSON(http.StatusOK, map[string]string{"message": "Verification code sent"})
}

func (s *Service) VerifyProfilePhone(c echo.Context) error {
	userID, ok := s.SessionUserID(c)
	if !ok {
		return c.JSON(http.StatusUnauthorized, map[string]any{"message": "not authenticated"})
	}

	var body profilePhoneVerifyPayload
	_ = c.Bind(&body)
	code := strings.TrimSpace(body.Code)
	if code == "" {
		code = strings.TrimSpace(c.FormValue("code"))
	}
	if !isNumericCode(code) {
		return c.String(http.StatusBadRequest, "Invalid verification code")
	}

	ctx := c.Request().Context()
	tokenKey := profilePhoneVerifyTokenKey(userID)
	payload, err := s.redis.Get(ctx, tokenKey).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return c.String(http.StatusBadRequest, "Verification code expired or missing")
		}
		return c.String(http.StatusInternalServerError, "Internal error")
	}

	var token profilePhoneVerifyToken
	if err := json.Unmarshal(payload, &token); err != nil {
		_ = s.redis.Del(ctx, tokenKey).Err()
		return c.String(http.StatusBadRequest, "Invalid verification payload")
	}
	if strings.TrimSpace(token.UserID) == "" || strings.TrimSpace(token.Phone) == "" || strings.TrimSpace(token.CodeHash) == "" {
		_ = s.redis.Del(ctx, tokenKey).Err()
		return c.String(http.StatusBadRequest, "Invalid verification payload")
	}

	user, err := s.store.GetUser(userID)
	if err != nil {
		return c.String(http.StatusInternalServerError, "Failed to load user")
	}
	currentPhone, err := normalizePhone(user.Phone)
	if err != nil || currentPhone == "" {
		_ = s.redis.Del(ctx, tokenKey).Err()
		return c.String(http.StatusBadRequest, "Profile phone changed")
	}
	if currentPhone != token.Phone {
		_ = s.redis.Del(ctx, tokenKey).Err()
		return c.String(http.StatusConflict, "Profile phone changed, request a new code")
	}

	inputHash := hashPhoneVerifyCode(code)
	match := subtle.ConstantTimeCompare([]byte(inputHash), []byte(token.CodeHash)) == 1
	if !match {
		token.AttemptsLeft--
		token.LastAttemptedAt = time.Now().UTC()
		if token.AttemptsLeft <= 0 {
			_ = s.redis.Del(ctx, tokenKey).Err()
			return c.String(http.StatusBadRequest, "Verification code invalid")
		}
		ttl, ttlErr := s.redis.TTL(ctx, tokenKey).Result()
		if ttlErr != nil || ttl <= 0 {
			ttl = profilePhoneVerifyTokenTTL
		}
		updated, _ := json.Marshal(token)
		_ = s.redis.Set(ctx, tokenKey, updated, ttl).Err()
		return c.String(http.StatusBadRequest, "Verification code invalid")
	}

	if err := s.store.VerifyPhone(userID, token.Phone); err != nil {
		if errors.Is(err, store.ErrPhoneVerificationMismatch) {
			return c.String(http.StatusConflict, "Profile phone changed, request a new code")
		}
		return c.String(http.StatusInternalServerError, "Internal error")
	}

	_ = s.redis.Del(ctx, tokenKey).Err()
	return c.JSON(http.StatusOK, map[string]string{"message": "Phone confirmed"})
}
