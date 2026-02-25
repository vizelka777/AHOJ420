package auth

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/redis/go-redis/v9"

	"github.com/houbamydar/AHOJ420/internal/store"
)

const (
	profileEmailVerifyTokenTTL = 1 * time.Hour
	profileEmailVerifyRateTTL  = 60 * time.Second
)

var profileEmailRandReader io.Reader = rand.Reader

type profileEmailVerifyToken struct {
	UserID   string    `json:"user_id"`
	Email    string    `json:"email"`
	Purpose  string    `json:"purpose"`
	IssuedAt time.Time `json:"issued_at"`
}

func profileEmailVerifyTokenKey(token string) string {
	return "auth:profile_email_verify:" + token
}

func profileEmailVerifyRateKey(userID string) string {
	return "auth:profile_email_verify_rate:" + userID
}

func generateProfileEmailVerifyToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := io.ReadFull(profileEmailRandReader, buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func (s *Service) RequestProfileEmailVerify(c echo.Context) error {
	userID, ok := s.SessionUserID(c)
	if !ok {
		return c.JSON(http.StatusUnauthorized, map[string]any{"message": "not authenticated"})
	}

	user, err := s.store.GetUser(userID)
	if err != nil {
		return c.String(http.StatusInternalServerError, "User not found")
	}

	email, err := normalizeEmail(user.ProfileEmail)
	if err != nil {
		return c.String(http.StatusBadRequest, err.Error())
	}
	if email == "" {
		return c.String(http.StatusBadRequest, "No profile email to verify")
	}

	ctx := c.Request().Context()
	okRate, err := s.redis.SetNX(ctx, profileEmailVerifyRateKey(userID), "1", profileEmailVerifyRateTTL).Result()
	if err != nil {
		return c.String(http.StatusInternalServerError, "Internal error")
	}
	if !okRate {
		return c.String(http.StatusTooManyRequests, "Try again later")
	}

	token, err := generateProfileEmailVerifyToken()
	if err != nil {
		log.Printf("Profile email verify token generation failed: %v", err)
		return c.String(http.StatusInternalServerError, "Internal error")
	}

	payload := profileEmailVerifyToken{
		UserID:   userID,
		Email:    email,
		Purpose:  "profile_email_verify",
		IssuedAt: time.Now().UTC(),
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return c.String(http.StatusInternalServerError, "Internal error")
	}

	tokenKey := profileEmailVerifyTokenKey(token)
	if err := s.redis.Set(ctx, tokenKey, payloadJSON, profileEmailVerifyTokenTTL).Err(); err != nil {
		return c.String(http.StatusInternalServerError, "Internal error")
	}

	link := fmt.Sprintf("%s/auth/profile/email/verify?token=%s", recoveryBaseURL(), token)
	if err := s.sendProfileEmailVerifyLink(email, link); err != nil {
		_ = s.redis.Del(ctx, tokenKey).Err()
		log.Printf("Profile email verify send failed for %s: %v", email, err)
		return c.String(http.StatusInternalServerError, "Internal error")
	}

	return c.JSON(http.StatusOK, map[string]string{"message": "Verification email sent"})
}

func (s *Service) VerifyProfileEmail(c echo.Context) error {
	token := strings.TrimSpace(c.QueryParam("token"))
	if token == "" {
		return c.String(http.StatusBadRequest, "Token required")
	}

	raw, err := redisGetDel(c.Request().Context(), s.redis, profileEmailVerifyTokenKey(token))
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return c.String(http.StatusBadRequest, "Invalid or expired token")
		}
		return c.String(http.StatusInternalServerError, "Internal error")
	}

	var payload profileEmailVerifyToken
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		return c.String(http.StatusBadRequest, "Invalid token payload")
	}
	if payload.Purpose != "profile_email_verify" || strings.TrimSpace(payload.UserID) == "" {
		return c.String(http.StatusBadRequest, "Invalid token payload")
	}
	email, err := normalizeEmail(payload.Email)
	if err != nil || email == "" {
		return c.String(http.StatusBadRequest, "Invalid token payload")
	}

	if err := s.store.VerifyProfileEmail(payload.UserID, email); err != nil {
		if errors.Is(err, store.ErrProfileEmailVerificationMismatch) {
			return c.String(http.StatusBadRequest, "Email verification is no longer valid")
		}
		return c.String(http.StatusInternalServerError, "Internal error")
	}

	return c.String(http.StatusOK, "Email confirmed")
}

func (s *Service) logProfileEmailVerifyLink(email, link string) {
	if s.devMode {
		log.Println("==================================================")
		log.Printf("PROFILE EMAIL VERIFY LINK for %s: %s", email, link)
		log.Println("==================================================")
		return
	}
	log.Printf("Profile email verification link generated for email: %s", email)
}

func (s *Service) sendProfileEmailVerifyLink(email, link string) error {
	if s.mailer != nil {
		subject := "Ahoj420 email confirmation"
		body := "Confirm your profile email by opening this link:\n\n" + link + "\n\nIf you did not request this, ignore this email."
		if err := s.mailer.Send(email, subject, body); err != nil {
			return err
		}
	}
	s.logProfileEmailVerifyLink(email, link)
	return nil
}
