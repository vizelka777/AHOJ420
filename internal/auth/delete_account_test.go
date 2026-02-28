package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/redis/go-redis/v9"
)

func hasClearedUserSessionCookie(rec *httptest.ResponseRecorder) bool {
	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == "user_session" && cookie.MaxAge < 0 {
			return true
		}
	}
	return false
}

func countKeysByPattern(t *testing.T, s *Service, ctx context.Context, pattern string) int {
	t.Helper()
	keys, err := s.redis.Keys(ctx, pattern).Result()
	if err != nil {
		t.Fatalf("keys %s failed: %v", pattern, err)
	}
	return len(keys)
}

func allowDeleteAccountForSession(t *testing.T, s *Service, ctx context.Context, sessionID string) {
	t.Helper()
	if err := s.redis.Set(ctx, deleteAccountReauthConfirmedKey(sessionID), "1", deleteAccountReauthConfirmTTL).Err(); err != nil {
		t.Fatalf("set delete-account confirmation marker failed: %v", err)
	}
}

func TestDeleteAccountClearsAllUserSessionsAndArtifacts(t *testing.T) {
	s, ctx := newSessionServiceForTest(t)
	const userID = "user-delete-1"

	deletedUserID := ""
	s.deleteUserFunc = func(gotUserID string) error {
		deletedUserID = strings.TrimSpace(gotUserID)
		return nil
	}

	putSessionArtifacts(t, s, ctx, userID, "sess-a", "dev-a", encodeCredentialID([]byte{1, 2, 3}), 100, true, true)
	putSessionArtifacts(t, s, ctx, userID, "sess-b", "dev-b", encodeCredentialID([]byte{4, 5, 6}), 101, true, true)
	if err := s.redis.Del(ctx, "recovery:sess-a").Err(); err != nil {
		t.Fatalf("clear current recovery marker: %v", err)
	}
	if err := s.redis.Set(ctx, deviceSessionDeviceKey(userID, "dev-orphan"), "orphan", deviceSessionHistoryTTL).Err(); err != nil {
		t.Fatalf("set orphan device mapping: %v", err)
	}

	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/auth/delete-account", nil)
	req.AddCookie(&http.Cookie{Name: "user_session", Value: "sess-a", Path: "/"})
	req.AddCookie(&http.Cookie{Name: deviceCookieName, Value: "dev-a", Path: "/"})
	allowDeleteAccountForSession(t, s, ctx, "sess-a")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	if err := s.DeleteAccount(c); err != nil {
		t.Fatalf("DeleteAccount returned error: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	if deletedUserID != userID {
		t.Fatalf("expected delete user %q, got %q", userID, deletedUserID)
	}

	for _, sessionID := range []string{"sess-a", "sess-b"} {
		assertKeyMissing(t, s, ctx, "sess:"+sessionID)
		assertKeyMissing(t, s, ctx, "recovery:"+sessionID)
		assertKeyMissing(t, s, ctx, deviceSessionMetaKey(sessionID))
	}
	if countKeysByPattern(t, s, ctx, deviceSessionDevicePrefix+userID+":*") != 0 {
		t.Fatalf("expected no sessdev mappings for user %s", userID)
	}
	if exists, err := s.redis.Exists(ctx, deviceSessionListKey(userID), deviceSessionAllKey(userID)).Result(); err != nil {
		t.Fatalf("exists for user indexes failed: %v", err)
	} else if exists != 0 {
		t.Fatalf("expected no session index keys for user %s", userID)
	}
	if !hasClearedUserSessionCookie(rec) {
		t.Fatalf("expected current user_session cookie to be cleared")
	}

	// stale cookie from another device must no longer authenticate
	reqStale := httptest.NewRequest(http.MethodGet, "/auth/session", nil)
	reqStale.AddCookie(&http.Cookie{Name: "user_session", Value: "sess-b", Path: "/"})
	recStale := httptest.NewRecorder()
	cStale := e.NewContext(reqStale, recStale)
	if _, ok := s.SessionUserID(cStale); ok {
		t.Fatal("expected stale session to be invalid after account deletion")
	}
}

func TestDeleteAccountDoesNotCleanupRedisWhenDBDeleteFails(t *testing.T) {
	s, ctx := newSessionServiceForTest(t)
	const userID = "user-delete-2"

	s.deleteUserFunc = func(string) error {
		return errors.New("db delete failed")
	}
	revokeCalled := false
	s.revokeAllSessions = func(context.Context, string) error {
		revokeCalled = true
		return nil
	}

	putSessionArtifacts(t, s, ctx, userID, "sess-a", "dev-a", encodeCredentialID([]byte{7, 8, 9}), 100, true, true)
	putSessionArtifacts(t, s, ctx, userID, "sess-b", "dev-b", encodeCredentialID([]byte{10, 11, 12}), 101, true, true)
	if err := s.redis.Del(ctx, "recovery:sess-a").Err(); err != nil {
		t.Fatalf("clear current recovery marker: %v", err)
	}

	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/auth/delete-account", nil)
	req.AddCookie(&http.Cookie{Name: "user_session", Value: "sess-a", Path: "/"})
	req.AddCookie(&http.Cookie{Name: deviceCookieName, Value: "dev-a", Path: "/"})
	allowDeleteAccountForSession(t, s, ctx, "sess-a")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	if err := s.DeleteAccount(c); err != nil {
		t.Fatalf("DeleteAccount returned error: %v", err)
	}
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 on DB delete failure, got %d body=%s", rec.Code, rec.Body.String())
	}
	if revokeCalled {
		t.Fatal("expected revoke-all cleanup to not run when DB delete fails")
	}
	for _, sessionID := range []string{"sess-a", "sess-b"} {
		if _, err := s.redis.Get(ctx, "sess:"+sessionID).Result(); err != nil {
			t.Fatalf("expected session key %s to remain, err=%v", sessionID, err)
		}
	}
}

func TestRevokeAllUserSessionsCleansMetadataTails(t *testing.T) {
	s, ctx := newSessionServiceForTest(t)
	const userID = "user-delete-3"

	putSessionArtifacts(t, s, ctx, userID, "sess-a", "dev-a", encodeCredentialID([]byte{1, 1, 1}), 100, true, true)
	if err := s.redis.Set(ctx, "sess:sess-b", userID, time.Hour).Err(); err != nil {
		t.Fatalf("set sess-b owner failed: %v", err)
	}
	if err := s.redis.Set(ctx, "recovery:sess-b", "1", time.Hour).Err(); err != nil {
		t.Fatalf("set recovery sess-b failed: %v", err)
	}
	meta := deviceSessionMeta{
		SessionID:    "sess-b",
		UserID:       userID,
		DeviceID:     "dev-b",
		CredentialID: encodeCredentialID([]byte{2, 2, 2}),
		CreatedAtUTC: 101,
		LastSeenUTC:  102,
	}
	metaPayload, err := json.Marshal(meta)
	if err != nil {
		t.Fatalf("marshal sess-b meta failed: %v", err)
	}
	if err := s.redis.Set(ctx, deviceSessionMetaKey("sess-b"), metaPayload, time.Hour).Err(); err != nil {
		t.Fatalf("set sess-b meta failed: %v", err)
	}
	if err := s.redis.ZAdd(ctx, deviceSessionListKey(userID), redis.Z{Score: 101, Member: "sess-b"}).Err(); err != nil {
		t.Fatalf("zadd sess-b list failed: %v", err)
	}
	if err := s.redis.ZAdd(ctx, deviceSessionAllKey(userID), redis.Z{Score: 101, Member: "sess-b"}).Err(); err != nil {
		t.Fatalf("zadd sess-b all failed: %v", err)
	}
	if err := s.redis.Set(ctx, deviceSessionDeviceKey(userID, "dev-b"), "sess-b", time.Hour).Err(); err != nil {
		t.Fatalf("set dev-b mapping failed: %v", err)
	}

	// orphan metadata tails
	orphan := deviceSessionMeta{
		SessionID:    "sess-orphan",
		UserID:       userID,
		DeviceID:     "dev-orphan",
		CredentialID: "",
		CreatedAtUTC: 103,
		LastSeenUTC:  104,
	}
	orphanPayload, err := json.Marshal(orphan)
	if err != nil {
		t.Fatalf("marshal orphan meta failed: %v", err)
	}
	if err := s.redis.Set(ctx, deviceSessionMetaKey("sess-orphan"), orphanPayload, time.Hour).Err(); err != nil {
		t.Fatalf("set orphan meta failed: %v", err)
	}
	if err := s.redis.ZAdd(ctx, deviceSessionListKey(userID), redis.Z{Score: 103, Member: "sess-orphan"}).Err(); err != nil {
		t.Fatalf("zadd orphan list failed: %v", err)
	}
	if err := s.redis.ZAdd(ctx, deviceSessionAllKey(userID), redis.Z{Score: 103, Member: "sess-orphan"}).Err(); err != nil {
		t.Fatalf("zadd orphan all failed: %v", err)
	}
	if err := s.redis.Set(ctx, deviceSessionDeviceKey(userID, "dev-orphan"), "sess-orphan", time.Hour).Err(); err != nil {
		t.Fatalf("set orphan mapping failed: %v", err)
	}

	if err := s.RevokeAllUserSessions(ctx, userID); err != nil {
		t.Fatalf("RevokeAllUserSessions failed: %v", err)
	}

	for _, sessionID := range []string{"sess-a", "sess-b", "sess-orphan"} {
		assertKeyMissing(t, s, ctx, "sess:"+sessionID)
		assertKeyMissing(t, s, ctx, "recovery:"+sessionID)
		assertKeyMissing(t, s, ctx, deviceSessionMetaKey(sessionID))
	}
	if exists, err := s.redis.Exists(ctx, deviceSessionListKey(userID), deviceSessionAllKey(userID)).Result(); err != nil {
		t.Fatalf("exists for user indexes failed: %v", err)
	} else if exists != 0 {
		t.Fatalf("expected no session index keys for user %s", userID)
	}
	if countKeysByPattern(t, s, ctx, deviceSessionDevicePrefix+userID+":*") != 0 {
		t.Fatalf("expected no sessdev mappings for user %s", userID)
	}
}

func TestDeleteAccountSurfacesCleanupFailureAfterDBDelete(t *testing.T) {
	s, ctx := newSessionServiceForTest(t)
	const userID = "user-delete-4"

	dbDeleteCalled := false
	s.deleteUserFunc = func(string) error {
		dbDeleteCalled = true
		return nil
	}
	s.revokeAllSessions = func(context.Context, string) error {
		return errors.New("redis cleanup failed")
	}

	putSessionArtifacts(t, s, ctx, userID, "sess-a", "dev-a", encodeCredentialID([]byte{1, 9, 9}), 100, true, true)
	if err := s.redis.Del(ctx, "recovery:sess-a").Err(); err != nil {
		t.Fatalf("clear current recovery marker: %v", err)
	}

	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/auth/delete-account", nil)
	req.AddCookie(&http.Cookie{Name: "user_session", Value: "sess-a", Path: "/"})
	req.AddCookie(&http.Cookie{Name: deviceCookieName, Value: "dev-a", Path: "/"})
	allowDeleteAccountForSession(t, s, ctx, "sess-a")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	if err := s.DeleteAccount(c); err != nil {
		t.Fatalf("DeleteAccount returned error: %v", err)
	}
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 when cleanup fails after delete, got %d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(strings.ToLower(rec.Body.String()), "account deleted but session cleanup failed") {
		t.Fatalf("expected explicit cleanup failure message, got %s", rec.Body.String())
	}
	if !dbDeleteCalled {
		t.Fatal("expected DB delete to be attempted")
	}
	if !hasClearedUserSessionCookie(rec) {
		t.Fatal("expected current session cookie to be cleared even on cleanup failure")
	}
}

func TestDeleteAccountRequiresPasskeyConfirmation(t *testing.T) {
	s, ctx := newSessionServiceForTest(t)
	const userID = "user-delete-5"

	deleteCalled := false
	s.deleteUserFunc = func(string) error {
		deleteCalled = true
		return nil
	}
	cleanupCalled := false
	s.revokeAllSessions = func(context.Context, string) error {
		cleanupCalled = true
		return nil
	}

	putSessionArtifacts(t, s, ctx, userID, "sess-a", "dev-a", encodeCredentialID([]byte{3, 3, 3}), 100, true, true)
	if err := s.redis.Del(ctx, "recovery:sess-a").Err(); err != nil {
		t.Fatalf("clear current recovery marker: %v", err)
	}

	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/auth/delete-account", nil)
	req.AddCookie(&http.Cookie{Name: "user_session", Value: "sess-a", Path: "/"})
	req.AddCookie(&http.Cookie{Name: deviceCookieName, Value: "dev-a", Path: "/"})
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	if err := s.DeleteAccount(c); err != nil {
		t.Fatalf("DeleteAccount returned error: %v", err)
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 when passkey confirmation is missing, got %d body=%s", rec.Code, rec.Body.String())
	}
	if deleteCalled {
		t.Fatal("expected DB delete to be blocked without passkey confirmation")
	}
	if cleanupCalled {
		t.Fatal("expected cleanup to be blocked without passkey confirmation")
	}
}
