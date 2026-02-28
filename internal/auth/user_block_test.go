package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/labstack/echo/v4"
)

func TestSessionUserIDBlockedUserInvalidatesSession(t *testing.T) {
	s, ctx := newSessionServiceForTest(t)
	s.userBlockedChecker = func(_ context.Context, userID string) (bool, error) {
		return userID == "blocked-user", nil
	}

	putSessionArtifacts(t, s, ctx, "blocked-user", "sess-blocked", "device-1", "", 100, true, true)

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/auth/session", nil)
	req.AddCookie(&http.Cookie{Name: "user_session", Value: "sess-blocked", Path: "/"})
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	if _, ok := s.SessionUserID(c); ok {
		t.Fatal("expected blocked session to be rejected")
	}

	assertKeyMissing(t, s, ctx, "sess:sess-blocked")
	assertKeyMissing(t, s, ctx, "recovery:sess-blocked")
	assertKeyMissing(t, s, ctx, deviceSessionMetaKey("sess-blocked"))
	assertZSetMissingMember(t, s, ctx, deviceSessionListKey("blocked-user"), "sess-blocked")
	assertZSetMissingMember(t, s, ctx, deviceSessionAllKey("blocked-user"), "sess-blocked")

	cleared := false
	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == "user_session" && cookie.MaxAge < 0 {
			cleared = true
			break
		}
	}
	if !cleared {
		t.Fatal("expected user_session cookie to be cleared for blocked user")
	}
}

func TestSetUserSessionWithCredentialIDBlocked(t *testing.T) {
	s, ctx := newSessionServiceForTest(t)
	s.userBlockedChecker = func(_ context.Context, userID string) (bool, error) {
		return userID == "blocked-user", nil
	}

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	if _, err := s.setUserSessionWithCredentialID(c, "blocked-user", "cred-1"); err != errUserBlocked {
		t.Fatalf("expected errUserBlocked, got %v", err)
	}

	keys, err := s.redis.Keys(ctx, "sess:*").Result()
	if err != nil {
		t.Fatalf("list sess keys failed: %v", err)
	}
	if len(keys) != 0 {
		t.Fatalf("expected no sessions to be created, got %v", keys)
	}
}

func TestStartRecoveryModeBlocked(t *testing.T) {
	s, ctx := newSessionServiceForTest(t)
	s.userBlockedChecker = func(_ context.Context, userID string) (bool, error) {
		return userID == "blocked-user", nil
	}

	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/auth/recovery/verify", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	if err := s.startRecoveryMode(c, "blocked-user"); err != errUserBlocked {
		t.Fatalf("expected errUserBlocked, got %v", err)
	}

	keys, err := s.redis.Keys(ctx, "sess:*").Result()
	if err != nil {
		t.Fatalf("list sess keys failed: %v", err)
	}
	if len(keys) != 0 {
		t.Fatalf("expected no user sessions to be created, got %v", keys)
	}
}

func TestSessionUserIDAllowsActiveUser(t *testing.T) {
	s, _ := newSessionServiceForTest(t)
	s.userBlockedChecker = func(_ context.Context, userID string) (bool, error) {
		return false, nil
	}
	if err := s.redis.Set(context.Background(), "sess:sess-active", "active-user", time.Hour).Err(); err != nil {
		t.Fatalf("set active session failed: %v", err)
	}

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/auth/session", nil)
	req.AddCookie(&http.Cookie{Name: "user_session", Value: "sess-active", Path: "/"})
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	userID, ok := s.SessionUserID(c)
	if !ok {
		t.Fatal("expected active session to pass")
	}
	if userID != "active-user" {
		t.Fatalf("expected active-user, got %q", userID)
	}
}
