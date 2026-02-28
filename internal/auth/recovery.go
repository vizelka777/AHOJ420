package auth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/houbamydar/AHOJ420/internal/store"
	"github.com/labstack/echo/v4"
	"github.com/redis/go-redis/v9"
)

var recoveryRandReader io.Reader = rand.Reader

const (
	recoveryGenericMessage       = "If this account exists, a recovery message has been sent."
	recoveryCodeInvalidMessage   = "Recovery code invalid or expired"
	recoveryTokenTTL             = 15 * time.Minute
	recoveryPhoneCodePrefix      = "auth:recovery_phone_code:"
	recoveryPhoneRatePrefix      = "auth:recovery_phone_rate:"
	recoveryPhoneCodeTTL         = 10 * time.Minute
	recoveryPhoneRateTTL         = 60 * time.Second
	recoveryPhoneCodeMaxAttempts = 5
	recoverySMSCodePrefix        = "Ahoj420 recovery code: "
)

type recoveryPhoneCodeToken struct {
	UserID          string    `json:"user_id"`
	Phone           string    `json:"phone"`
	CodeHash        string    `json:"code_hash"`
	AttemptsLeft    int       `json:"attempts_left"`
	IssuedAt        time.Time `json:"issued_at"`
	LastAttemptedAt time.Time `json:"last_attempted_at,omitempty"`
}

type recoveryCodePayload struct {
	Phone string `json:"phone"`
	Code  string `json:"code"`
}

func recoveryPhoneCodeKey(phone string) string {
	return recoveryPhoneCodePrefix + phone
}

func recoveryPhoneRateKey(phone string) string {
	return recoveryPhoneRatePrefix + phone
}

func (s *Service) RequestRecovery(c echo.Context) error {
	ctx := c.Request().Context()
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
			log.Printf("Recovery requested for non-existent or unverified email: %s", email)
			return c.JSON(http.StatusOK, map[string]string{"message": recoveryGenericMessage})
		}
		if err := s.ensureUserNotBlocked(ctx, user.ID); err != nil {
			if errors.Is(err, errUserBlocked) {
				s.writeUserSecurityEventFromRequest(c, store.UserSecurityEvent{
					UserID:      user.ID,
					EventType:   store.UserSecurityEventRecoveryFailure,
					Category:    store.UserSecurityCategoryRecovery,
					Success:     boolPointer(false),
					ActorType:   "user",
					ActorID:     user.ID,
					DetailsJSON: userSecurityDetailsJSON(map[string]any{"channel": "email", "reason": "user_blocked"}),
				})
				return c.String(http.StatusForbidden, "User account is blocked")
			}
			return c.String(http.StatusInternalServerError, "Internal error")
		}

		magicLink, tokenKey, err := s.createRecoveryToken(ctx, user.ID)
		if err != nil {
			s.writeUserSecurityEventFromRequest(c, store.UserSecurityEvent{
				UserID:      user.ID,
				EventType:   store.UserSecurityEventRecoveryFailure,
				Category:    store.UserSecurityCategoryRecovery,
				Success:     boolPointer(false),
				ActorType:   "user",
				ActorID:     user.ID,
				DetailsJSON: userSecurityDetailsJSON(map[string]any{"channel": "email", "reason": "token_create_failed"}),
			})
			return c.String(http.StatusInternalServerError, "Internal error")
		}

		if err := s.sendRecoveryLink(email, magicLink); err != nil {
			_ = s.redis.Del(ctx, tokenKey).Err()
			s.writeUserSecurityEventFromRequest(c, store.UserSecurityEvent{
				UserID:      user.ID,
				EventType:   store.UserSecurityEventRecoveryFailure,
				Category:    store.UserSecurityCategoryRecovery,
				Success:     boolPointer(false),
				ActorType:   "user",
				ActorID:     user.ID,
				DetailsJSON: userSecurityDetailsJSON(map[string]any{"channel": "email", "reason": "delivery_failed"}),
			})
			log.Printf("Recovery mail send failed for %s: %v", email, err)
			return c.String(http.StatusInternalServerError, "Internal error")
		}
		s.writeUserSecurityEventFromRequest(c, store.UserSecurityEvent{
			UserID:      user.ID,
			EventType:   store.UserSecurityEventRecoveryReq,
			Category:    store.UserSecurityCategoryRecovery,
			Success:     boolPointer(true),
			ActorType:   "user",
			ActorID:     user.ID,
			DetailsJSON: userSecurityDetailsJSON(map[string]any{"channel": "email"}),
		})

		return c.JSON(http.StatusOK, map[string]string{"message": recoveryGenericMessage})
	}

	phone, err := normalizePhone(rawPhone)
	if err != nil {
		return c.String(http.StatusBadRequest, err.Error())
	}

	okRate, err := s.redis.SetNX(ctx, recoveryPhoneRateKey(phone), "1", recoveryPhoneRateTTL).Result()
	if err != nil {
		return c.String(http.StatusInternalServerError, "Internal error")
	}
	if !okRate {
		return c.String(http.StatusTooManyRequests, "Try again later")
	}

	user, err := s.store.GetUserByVerifiedPhone(phone)
	if err != nil || user == nil {
		log.Printf("Recovery requested for non-existent or unverified phone: %s", phone)
		return c.JSON(http.StatusOK, map[string]string{"message": recoveryGenericMessage})
	}
	if err := s.ensureUserNotBlocked(ctx, user.ID); err != nil {
		if errors.Is(err, errUserBlocked) {
			s.writeUserSecurityEventFromRequest(c, store.UserSecurityEvent{
				UserID:      user.ID,
				EventType:   store.UserSecurityEventRecoveryFailure,
				Category:    store.UserSecurityCategoryRecovery,
				Success:     boolPointer(false),
				ActorType:   "user",
				ActorID:     user.ID,
				DetailsJSON: userSecurityDetailsJSON(map[string]any{"channel": "phone", "reason": "user_blocked"}),
			})
			return c.String(http.StatusForbidden, "User account is blocked")
		}
		return c.String(http.StatusInternalServerError, "Internal error")
	}

	code, err := generatePhoneVerifyCode()
	if err != nil {
		return c.String(http.StatusInternalServerError, "Internal error")
	}

	token := recoveryPhoneCodeToken{
		UserID:       user.ID,
		Phone:        phone,
		CodeHash:     hashPhoneVerifyCode(code),
		AttemptsLeft: recoveryPhoneCodeMaxAttempts,
		IssuedAt:     time.Now().UTC(),
	}
	tokenPayload, err := json.Marshal(token)
	if err != nil {
		return c.String(http.StatusInternalServerError, "Internal error")
	}

	codeKey := recoveryPhoneCodeKey(phone)
	if err := s.redis.Set(ctx, codeKey, tokenPayload, recoveryPhoneCodeTTL).Err(); err != nil {
		s.writeUserSecurityEventFromRequest(c, store.UserSecurityEvent{
			UserID:      user.ID,
			EventType:   store.UserSecurityEventRecoveryFailure,
			Category:    store.UserSecurityCategoryRecovery,
			Success:     boolPointer(false),
			ActorType:   "user",
			ActorID:     user.ID,
			DetailsJSON: userSecurityDetailsJSON(map[string]any{"channel": "phone", "reason": "token_store_failed"}),
		})
		return c.String(http.StatusInternalServerError, "Internal error")
	}

	if err := s.sendRecoverySMSCode(ctx, phone, code); err != nil {
		_ = s.redis.Del(ctx, codeKey).Err()
		s.writeUserSecurityEventFromRequest(c, store.UserSecurityEvent{
			UserID:      user.ID,
			EventType:   store.UserSecurityEventRecoveryFailure,
			Category:    store.UserSecurityCategoryRecovery,
			Success:     boolPointer(false),
			ActorType:   "user",
			ActorID:     user.ID,
			DetailsJSON: userSecurityDetailsJSON(map[string]any{"channel": "phone", "reason": "delivery_failed"}),
		})
		log.Printf("Recovery SMS code send failed for %s: %v", phone, err)
		return c.String(http.StatusInternalServerError, "Internal error")
	}
	s.writeUserSecurityEventFromRequest(c, store.UserSecurityEvent{
		UserID:      user.ID,
		EventType:   store.UserSecurityEventRecoveryReq,
		Category:    store.UserSecurityCategoryRecovery,
		Success:     boolPointer(true),
		ActorType:   "user",
		ActorID:     user.ID,
		DetailsJSON: userSecurityDetailsJSON(map[string]any{"channel": "phone"}),
	})

	return c.JSON(http.StatusOK, map[string]string{"message": recoveryGenericMessage})
}

func (s *Service) createRecoveryToken(ctx context.Context, userID string) (magicLink string, tokenKey string, err error) {
	token, err := generateRecoveryToken()
	if err != nil {
		log.Printf("Recovery token generation failed: %v", err)
		return "", "", err
	}

	tokenKey = "recovery_token:" + token
	err = s.redis.Set(ctx, tokenKey, userID, recoveryTokenTTL).Err()
	if err != nil {
		return "", "", err
	}

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

func (s *Service) logRecoverySMSCode(phone, code string) {
	if s.devMode {
		log.Println("==================================================")
		log.Printf("RECOVERY SMS CODE for %s: %s", phone, code)
		log.Println("==================================================")
		return
	}
	log.Printf("Recovery SMS code generated for phone: %s", phone)
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

func (s *Service) sendRecoverySMSCode(ctx context.Context, phone, code string) error {
	if s.smsSender == nil {
		if s.devMode {
			s.logRecoverySMSCode(phone, code)
			return nil
		}
		return fmt.Errorf("sms sender is not configured")
	}
	message := recoverySMSCodePrefix + code
	if err := s.smsSender.SendSMS(ctx, phone, message); err != nil {
		return err
	}
	s.logRecoverySMSCode(phone, code)
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
	if err := s.ensureUserNotBlocked(ctx, userID); err != nil {
		if errors.Is(err, errUserBlocked) {
			s.writeUserSecurityEventFromRequest(c, store.UserSecurityEvent{
				UserID:      userID,
				EventType:   store.UserSecurityEventRecoveryFailure,
				Category:    store.UserSecurityCategoryRecovery,
				Success:     boolPointer(false),
				ActorType:   "user",
				ActorID:     userID,
				DetailsJSON: userSecurityDetailsJSON(map[string]any{"channel": "email", "reason": "user_blocked"}),
			})
			return c.String(http.StatusForbidden, "User account is blocked")
		}
		return c.String(http.StatusInternalServerError, "Internal error")
	}

	if err := s.startRecoveryMode(c, userID); err != nil {
		s.writeUserSecurityEventFromRequest(c, store.UserSecurityEvent{
			UserID:      userID,
			EventType:   store.UserSecurityEventRecoveryFailure,
			Category:    store.UserSecurityCategoryRecovery,
			Success:     boolPointer(false),
			ActorType:   "user",
			ActorID:     userID,
			DetailsJSON: userSecurityDetailsJSON(map[string]any{"channel": "email", "reason": "start_recovery_mode_failed"}),
		})
		return c.String(http.StatusInternalServerError, "Internal error")
	}
	s.writeUserSecurityEventFromRequest(c, store.UserSecurityEvent{
		UserID:      userID,
		EventType:   store.UserSecurityEventRecoverySuccess,
		Category:    store.UserSecurityCategoryRecovery,
		Success:     boolPointer(true),
		ActorType:   "user",
		ActorID:     userID,
		DetailsJSON: userSecurityDetailsJSON(map[string]any{"channel": "email"}),
	})
	return c.Redirect(http.StatusTemporaryRedirect, "/?mode=recovery")
}

func (s *Service) VerifyRecoveryCode(c echo.Context) error {
	var body recoveryCodePayload
	_ = c.Bind(&body)

	phoneRaw := strings.TrimSpace(body.Phone)
	if phoneRaw == "" {
		phoneRaw = strings.TrimSpace(c.FormValue("phone"))
	}
	code := strings.TrimSpace(body.Code)
	if code == "" {
		code = strings.TrimSpace(c.FormValue("code"))
	}

	phone, err := normalizePhone(phoneRaw)
	if err != nil {
		return c.String(http.StatusBadRequest, err.Error())
	}
	if !isNumericCode(code) {
		return c.String(http.StatusBadRequest, "Invalid recovery code")
	}

	ctx := c.Request().Context()
	codeKey := recoveryPhoneCodeKey(phone)
	payload, err := s.redis.Get(ctx, codeKey).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return c.String(http.StatusBadRequest, recoveryCodeInvalidMessage)
		}
		return c.String(http.StatusInternalServerError, "Internal error")
	}

	var token recoveryPhoneCodeToken
	if err := json.Unmarshal(payload, &token); err != nil {
		_ = s.redis.Del(ctx, codeKey).Err()
		return c.String(http.StatusBadRequest, recoveryCodeInvalidMessage)
	}
	if strings.TrimSpace(token.UserID) == "" || strings.TrimSpace(token.Phone) == "" || strings.TrimSpace(token.CodeHash) == "" {
		_ = s.redis.Del(ctx, codeKey).Err()
		return c.String(http.StatusBadRequest, recoveryCodeInvalidMessage)
	}
	if token.Phone != phone {
		_ = s.redis.Del(ctx, codeKey).Err()
		return c.String(http.StatusBadRequest, recoveryCodeInvalidMessage)
	}
	if err := s.ensureUserNotBlocked(ctx, token.UserID); err != nil {
		_ = s.redis.Del(ctx, codeKey).Err()
		if errors.Is(err, errUserBlocked) {
			s.writeUserSecurityEventFromRequest(c, store.UserSecurityEvent{
				UserID:      strings.TrimSpace(token.UserID),
				EventType:   store.UserSecurityEventRecoveryFailure,
				Category:    store.UserSecurityCategoryRecovery,
				Success:     boolPointer(false),
				ActorType:   "user",
				ActorID:     strings.TrimSpace(token.UserID),
				DetailsJSON: userSecurityDetailsJSON(map[string]any{"channel": "phone", "reason": "user_blocked"}),
			})
			return c.String(http.StatusForbidden, "User account is blocked")
		}
		return c.String(http.StatusInternalServerError, "Internal error")
	}

	inputHash := hashPhoneVerifyCode(code)
	match := subtle.ConstantTimeCompare([]byte(inputHash), []byte(token.CodeHash)) == 1
	if !match {
		s.writeUserSecurityEventFromRequest(c, store.UserSecurityEvent{
			UserID:      strings.TrimSpace(token.UserID),
			EventType:   store.UserSecurityEventRecoveryFailure,
			Category:    store.UserSecurityCategoryRecovery,
			Success:     boolPointer(false),
			ActorType:   "user",
			ActorID:     strings.TrimSpace(token.UserID),
			DetailsJSON: userSecurityDetailsJSON(map[string]any{"channel": "phone", "reason": "invalid_code"}),
		})
		_, decErr := decrementTokenAttemptsAtomic(ctx, s.redis, codeKey, recoveryPhoneCodeTTL, time.Now())
		if decErr != nil {
			if errors.Is(decErr, errVerifyTokenMissing) || errors.Is(decErr, errVerifyAttemptsExhausted) {
				return c.String(http.StatusBadRequest, recoveryCodeInvalidMessage)
			}
			if errors.Is(decErr, errVerifyTokenInvalid) {
				_ = s.redis.Del(ctx, codeKey).Err()
				return c.String(http.StatusBadRequest, recoveryCodeInvalidMessage)
			}
			return c.String(http.StatusInternalServerError, "Internal error")
		}
		return c.String(http.StatusBadRequest, recoveryCodeInvalidMessage)
	}

	_ = s.redis.Del(ctx, codeKey).Err()
	if err := s.startRecoveryMode(c, token.UserID); err != nil {
		s.writeUserSecurityEventFromRequest(c, store.UserSecurityEvent{
			UserID:      strings.TrimSpace(token.UserID),
			EventType:   store.UserSecurityEventRecoveryFailure,
			Category:    store.UserSecurityCategoryRecovery,
			Success:     boolPointer(false),
			ActorType:   "user",
			ActorID:     strings.TrimSpace(token.UserID),
			DetailsJSON: userSecurityDetailsJSON(map[string]any{"channel": "phone", "reason": "start_recovery_mode_failed"}),
		})
		return c.String(http.StatusInternalServerError, "Internal error")
	}
	s.writeUserSecurityEventFromRequest(c, store.UserSecurityEvent{
		UserID:      strings.TrimSpace(token.UserID),
		EventType:   store.UserSecurityEventRecoverySuccess,
		Category:    store.UserSecurityCategoryRecovery,
		Success:     boolPointer(true),
		ActorType:   "user",
		ActorID:     strings.TrimSpace(token.UserID),
		DetailsJSON: userSecurityDetailsJSON(map[string]any{"channel": "phone"}),
	})
	return c.JSON(http.StatusOK, map[string]string{
		"message":  "Recovery verified",
		"redirect": "/?mode=recovery",
	})
}

func (s *Service) startRecoveryMode(c echo.Context, userID string) error {
	ctx := c.Request().Context()
	if err := s.ensureUserNotBlocked(ctx, userID); err != nil {
		return err
	}
	sessionID, err := s.setUserSessionWithID(c, userID)
	if err != nil {
		return err
	}
	return s.redis.Set(ctx, "recovery:"+sessionID, "1", recoveryTokenTTL).Err()
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
