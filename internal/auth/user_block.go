package auth

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/houbamydar/AHOJ420/internal/store"
	"github.com/labstack/echo/v4"
)

var errUserBlocked = errors.New("user is blocked")

func (s *Service) isUserBlocked(ctx context.Context, userID string) (bool, error) {
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return false, store.ErrUserNotFound
	}
	if s.userBlockedChecker != nil {
		return s.userBlockedChecker(ctx, userID)
	}
	if s.store == nil {
		return false, nil
	}
	return s.store.IsUserBlocked(ctx, userID)
}

func (s *Service) ensureUserNotBlocked(ctx context.Context, userID string) error {
	blocked, err := s.isUserBlocked(ctx, userID)
	if err != nil {
		return err
	}
	if blocked {
		return errUserBlocked
	}
	return nil
}

func clearUserSessionCookie(c echo.Context) {
	c.SetCookie(&http.Cookie{
		Name:     "user_session",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}
