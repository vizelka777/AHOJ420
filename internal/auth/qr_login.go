package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/redis/go-redis/v9"
)

const (
	qrLoginPrefix       = "auth:qr_login:"
	qrLoginPending      = "pending"
	qrLoginApprovedTTL  = 1 * time.Minute
	qrLoginPendingTTL   = 2 * time.Minute
	qrLoginTokenBytes   = 32
	qrLoginWatchRetries = 16
)

var (
	errQRLoginTokenExpired    = errors.New("qr login token expired")
	errQRLoginTokenInvalid    = errors.New("qr login token invalid")
	errQRLoginTokenNotPending = errors.New("qr login token not pending")
	errQRLoginStillPending    = errors.New("qr login still pending")
)

type qrApprovePayload struct {
	Token string `json:"token"`
}

func qrLoginRedisKey(token string) string {
	return qrLoginPrefix + token
}

func qrLoginURL(token string) string {
	return fmt.Sprintf("%s/qr-login?token=%s", recoveryBaseURL(), token)
}

func generateQRLoginToken() (string, error) {
	buf := make([]byte, qrLoginTokenBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func normalizeQRLoginToken(raw string) (string, error) {
	token := strings.TrimSpace(raw)
	if token == "" {
		return "", fmt.Errorf("token is required")
	}
	if len(token) != qrLoginTokenBytes*2 {
		return "", fmt.Errorf("invalid token")
	}
	if _, err := hex.DecodeString(token); err != nil {
		return "", fmt.Errorf("invalid token")
	}
	return strings.ToLower(token), nil
}

func (s *Service) GenerateQRLogin(c echo.Context) error {
	ctx := c.Request().Context()

	for i := 0; i < 4; i++ {
		token, err := generateQRLoginToken()
		if err != nil {
			return c.String(http.StatusInternalServerError, "Internal error")
		}

		ok, err := s.redis.SetNX(ctx, qrLoginRedisKey(token), qrLoginPending, qrLoginPendingTTL).Result()
		if err != nil {
			return c.String(http.StatusInternalServerError, "Internal error")
		}
		if !ok {
			continue
		}

		return c.JSON(http.StatusOK, map[string]string{
			"token":  token,
			"qr_url": qrLoginURL(token),
		})
	}

	return c.String(http.StatusInternalServerError, "Failed to generate qr token")
}

func (s *Service) ApproveQRLogin(c echo.Context) error {
	userID, ok := s.SessionUserID(c)
	if !ok {
		return c.JSON(http.StatusUnauthorized, map[string]any{"message": "not authenticated"})
	}

	var body qrApprovePayload
	_ = c.Bind(&body)
	tokenRaw := strings.TrimSpace(body.Token)
	if tokenRaw == "" {
		tokenRaw = strings.TrimSpace(c.FormValue("token"))
	}
	token, err := normalizeQRLoginToken(tokenRaw)
	if err != nil {
		return c.String(http.StatusBadRequest, err.Error())
	}

	if err := s.approveQRLoginToken(c.Request().Context(), token, userID); err != nil {
		if errors.Is(err, errQRLoginTokenExpired) {
			return c.String(http.StatusBadRequest, "Token expired")
		}
		if errors.Is(err, errQRLoginTokenNotPending) {
			return c.String(http.StatusConflict, "Token already approved")
		}
		if errors.Is(err, errQRLoginTokenInvalid) {
			return c.String(http.StatusBadRequest, "Invalid token status")
		}
		return c.String(http.StatusInternalServerError, "Internal error")
	}

	return c.JSON(http.StatusOK, map[string]string{"message": "approved"})
}

func (s *Service) approveQRLoginToken(ctx context.Context, token, userID string) error {
	key := qrLoginRedisKey(token)
	approvedValue := "approved:" + userID

	for i := 0; i < qrLoginWatchRetries; i++ {
		err := s.redis.Watch(ctx, func(tx *redis.Tx) error {
			current, err := tx.Get(ctx, key).Result()
			if err != nil {
				if errors.Is(err, redis.Nil) {
					return errQRLoginTokenExpired
				}
				return err
			}
			switch current {
			case qrLoginPending:
				_, err = tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
					pipe.Set(ctx, key, approvedValue, qrLoginApprovedTTL)
					return nil
				})
				return err
			case approvedValue:
				return nil
			default:
				if strings.HasPrefix(current, "approved:") {
					return errQRLoginTokenNotPending
				}
				return errQRLoginTokenInvalid
			}
		}, key)
		if err == nil {
			return nil
		}
		if errors.Is(err, redis.TxFailedErr) {
			continue
		}
		return err
	}

	return fmt.Errorf("failed to approve qr token atomically")
}

func (s *Service) QRLoginStatus(c echo.Context) error {
	token, err := normalizeQRLoginToken(c.QueryParam("token"))
	if err != nil {
		return c.String(http.StatusBadRequest, err.Error())
	}
	authReqID := strings.TrimSpace(c.QueryParam("auth_request_id"))

	status, userID, err := s.getQRLoginStatus(c.Request().Context(), token)
	if err != nil {
		return c.String(http.StatusInternalServerError, "Internal error")
	}

	switch status {
	case "pending":
		return c.JSON(http.StatusOK, map[string]string{"status": "pending"})
	case "expired":
		return c.JSON(http.StatusOK, map[string]string{"status": "expired"})
	case "approved":
		if _, err := s.setUserSessionWithID(c, userID); err != nil {
			return c.String(http.StatusInternalServerError, "Internal error")
		}

		redirect := "/"
		if authReqID != "" {
			if err := s.provider.SetAuthRequestDone(authReqID, userID); err != nil {
				return c.String(http.StatusBadRequest, "OIDC auth request invalid")
			}
			redirect = "/authorize/callback?id=" + authReqID
		}

		return c.JSON(http.StatusOK, map[string]string{
			"status":   "approved",
			"redirect": redirect,
		})
	default:
		return c.String(http.StatusInternalServerError, "Internal error")
	}
}

func (s *Service) getQRLoginStatus(ctx context.Context, token string) (status string, userID string, err error) {
	key := qrLoginRedisKey(token)

	for i := 0; i < qrLoginWatchRetries; i++ {
		status = ""
		userID = ""

		err = s.redis.Watch(ctx, func(tx *redis.Tx) error {
			current, err := tx.Get(ctx, key).Result()
			if err != nil {
				if errors.Is(err, redis.Nil) {
					status = "expired"
					return errQRLoginTokenExpired
				}
				return err
			}

			if current == qrLoginPending {
				status = "pending"
				return errQRLoginStillPending
			}

			if !strings.HasPrefix(current, "approved:") {
				_, delErr := tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
					pipe.Del(ctx, key)
					return nil
				})
				if delErr != nil {
					return delErr
				}
				status = "expired"
				return errQRLoginTokenInvalid
			}

			approvedUserID := strings.TrimSpace(strings.TrimPrefix(current, "approved:"))
			if approvedUserID == "" {
				_, delErr := tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
					pipe.Del(ctx, key)
					return nil
				})
				if delErr != nil {
					return delErr
				}
				status = "expired"
				return errQRLoginTokenInvalid
			}

			_, err = tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
				pipe.Del(ctx, key)
				return nil
			})
			if err != nil {
				return err
			}

			status = "approved"
			userID = approvedUserID
			return nil
		}, key)

		if err == nil {
			return status, userID, nil
		}
		if errors.Is(err, errQRLoginStillPending) || errors.Is(err, errQRLoginTokenExpired) || errors.Is(err, errQRLoginTokenInvalid) {
			return status, userID, nil
		}
		if errors.Is(err, redis.TxFailedErr) {
			continue
		}
		return "", "", err
	}

	return "", "", fmt.Errorf("failed to resolve qr login status atomically")
}
