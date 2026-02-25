package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/redis/go-redis/v9"
)

var recoveryRandReader io.Reader = rand.Reader

func (s *Service) RequestRecovery(c echo.Context) error {
	rawEmail := strings.TrimSpace(c.FormValue("email"))
	rawPhone := strings.TrimSpace(c.FormValue("phone"))
	if rawEmail == "" && rawPhone == "" {
		return c.String(http.StatusBadRequest, "Email or phone required")
	}
	if rawEmail != "" && rawPhone != "" {
		return c.String(http.StatusBadRequest, "Provide either email or phone")
	}

	if rawEmail != "" {
		email, err := normalizeEmail(rawEmail)
		if err != nil {
			return c.String(http.StatusBadRequest, err.Error())
		}

		user, err := s.store.GetUserByProfileEmail(email)
		if err != nil || user == nil {
			log.Printf("Recovery requested for non-existent email: %s", email)
			return c.JSON(http.StatusOK, map[string]string{"message": "If this account exists, a recovery message has been sent."})
		}

		magicLink, tokenKey, err := s.createRecoveryToken(c, user.ID)
		if err != nil {
			return c.String(http.StatusInternalServerError, "Internal error")
		}

		if err := s.sendRecoveryLink(email, magicLink); err != nil {
			_ = s.redis.Del(c.Request().Context(), tokenKey).Err()
			log.Printf("Recovery mail send failed for %s: %v", email, err)
			return c.String(http.StatusInternalServerError, "Internal error")
		}

		return c.JSON(http.StatusOK, map[string]string{"message": "If this account exists, a recovery message has been sent."})
	}

	phone, err := normalizePhone(rawPhone)
	if err != nil {
		return c.String(http.StatusBadRequest, err.Error())
	}
	user, err := s.store.GetUserByVerifiedPhone(phone)
	if err != nil || user == nil {
		log.Printf("Recovery requested for non-existent or unverified phone: %s", phone)
		return c.JSON(http.StatusOK, map[string]string{"message": "If this account exists, a recovery message has been sent."})
	}

	magicLink, tokenKey, err := s.createRecoveryToken(c, user.ID)
	if err != nil {
		return c.String(http.StatusInternalServerError, "Internal error")
	}
	if err := s.sendRecoverySMS(c.Request().Context(), phone, magicLink); err != nil {
		_ = s.redis.Del(c.Request().Context(), tokenKey).Err()
		log.Printf("Recovery SMS send failed for %s: %v", phone, err)
		return c.String(http.StatusInternalServerError, "Internal error")
	}

	return c.JSON(http.StatusOK, map[string]string{"message": "If this account exists, a recovery message has been sent."})
}

func (s *Service) createRecoveryToken(c echo.Context, userID string) (magicLink string, tokenKey string, err error) {
	token, err := generateRecoveryToken()
	if err != nil {
		log.Printf("Recovery token generation failed: %v", err)
		return "", "", err
	}

	// 3. Store in Redis (15 min)
	// Key: recovery_token:<token> -> userID
	tokenKey = "recovery_token:" + token
	err = s.redis.Set(c.Request().Context(), tokenKey, userID, 15*time.Minute).Err()
	if err != nil {
		return "", "", err
	}

	// 4. Send recovery link
	base := recoveryBaseURL()
	magicLink = fmt.Sprintf("%s/auth/recovery/verify?token=%s", base, token)
	return magicLink, tokenKey, nil
}

func generateRecoveryToken() (string, error) {
	tokenBytes := make([]byte, 32)
	if _, err := io.ReadFull(recoveryRandReader, tokenBytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(tokenBytes), nil
}

func (s *Service) logRecoveryLink(email, magicLink string) {
	if s.devMode {
		log.Println("==================================================")
		log.Printf("MAGIC LINK for %s: %s", email, magicLink)
		log.Println("==================================================")
		return
	}
	log.Printf("Recovery link generated for email: %s", email)
}

func (s *Service) logRecoverySMS(phone, magicLink string) {
	if s.devMode {
		log.Println("==================================================")
		log.Printf("RECOVERY SMS for %s: %s", phone, magicLink)
		log.Println("==================================================")
		return
	}
	log.Printf("Recovery SMS generated for phone: %s", phone)
}

func recoveryBaseURL() string {
	base := strings.TrimSpace(os.Getenv("AHOJ_BASE_URL"))
	if base == "" {
		base = strings.TrimSpace(os.Getenv("RP_ORIGIN"))
	}
	if base == "" {
		base = "https://ahoj420.eu"
	}
	return strings.TrimRight(base, "/")
}

func (s *Service) sendRecoveryLink(email, magicLink string) error {
	if s.mailer != nil {
		subject := "Ahoj420 recovery link"
		body := "Use this link to access recovery mode:\n\n" + magicLink + "\n\nIf you did not request this, you can ignore this email."
		if err := s.mailer.Send(email, subject, body); err != nil {
			return err
		}
	}
	s.logRecoveryLink(email, magicLink)
	return nil
}

func (s *Service) sendRecoverySMS(ctx context.Context, phone, magicLink string) error {
	if s.smsSender == nil {
		if s.devMode {
			s.logRecoverySMS(phone, magicLink)
			return nil
		}
		return fmt.Errorf("sms sender is not configured")
	}
	message := "Ahoj420 recovery link: " + magicLink
	if err := s.smsSender.SendSMS(ctx, phone, message); err != nil {
		return err
	}
	s.logRecoverySMS(phone, magicLink)
	return nil
}

func (s *Service) VerifyRecovery(c echo.Context) error {
	token := c.QueryParam("token")
	if token == "" {
		return c.String(http.StatusBadRequest, "Token required")
	}

	ctx := c.Request().Context()
	userID, err := redisGetDel(ctx, s.redis, "recovery_token:"+token)
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return c.String(http.StatusForbidden, "Invalid or expired link")
		}
		return c.String(http.StatusInternalServerError, "Internal error")
	}
	if userID == "" {
		return c.String(http.StatusForbidden, "Invalid or expired link")
	}

	sessionID, err := s.setUserSessionWithID(c, userID)
	if err != nil {
		return c.String(http.StatusInternalServerError, "Internal error")
	}
	if err := s.redis.Set(ctx, "recovery:"+sessionID, "1", 15*time.Minute).Err(); err != nil {
		return c.String(http.StatusInternalServerError, "Internal error")
	}

	return c.Redirect(http.StatusTemporaryRedirect, "/?mode=recovery")
}

func redisGetDel(ctx context.Context, rdb *redis.Client, key string) (string, error) {
	value, err := rdb.Do(ctx, "GETDEL", key).Text()
	if err == nil {
		return value, nil
	}
	if errors.Is(err, redis.Nil) {
		return "", redis.Nil
	}
	if !isUnknownRedisCommand(err) {
		return "", err
	}

	res, evalErr := rdb.Eval(
		ctx,
		`local v = redis.call("GET", KEYS[1]); if v then redis.call("DEL", KEYS[1]); end; return v`,
		[]string{key},
	).Result()
	if evalErr != nil {
		if errors.Is(evalErr, redis.Nil) {
			return "", redis.Nil
		}
		return "", evalErr
	}
	if res == nil {
		return "", redis.Nil
	}
	str, ok := res.(string)
	if !ok {
		return "", fmt.Errorf("unexpected redis result type %T", res)
	}
	return str, nil
}

func isUnknownRedisCommand(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "unknown command") || strings.Contains(msg, "unsupported command")
}
