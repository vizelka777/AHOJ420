package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/labstack/echo/v4"
	"github.com/redis/go-redis/v9"
)

func newSessionServiceForTest(t *testing.T) (*Service, context.Context) {
	t.Helper()

	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() {
		_ = rdb.Close()
		mr.Close()
	})
	return &Service{redis: rdb}, context.Background()
}

func putSessionArtifacts(
	t *testing.T,
	s *Service,
	ctx context.Context,
	userID, sessionID, deviceID, credentialID string,
	score int64,
	visible bool,
	inAll bool,
) deviceSessionMeta {
	t.Helper()

	meta := deviceSessionMeta{
		SessionID:    sessionID,
		UserID:       userID,
		DeviceID:     deviceID,
		CredentialID: credentialID,
		UserAgent:    "GoTestAgent",
		IP:           "203.0.113.10",
		CreatedAtUTC: score,
		LastSeenUTC:  score + 1,
	}
	payload, err := json.Marshal(meta)
	if err != nil {
		t.Fatalf("marshal meta: %v", err)
	}
	if err := s.redis.Set(ctx, "sess:"+sessionID, userID, time.Hour).Err(); err != nil {
		t.Fatalf("set sess key: %v", err)
	}
	if err := s.redis.Set(ctx, "recovery:"+sessionID, "1", time.Hour).Err(); err != nil {
		t.Fatalf("set recovery key: %v", err)
	}
	if err := s.redis.Set(ctx, deviceSessionMetaKey(sessionID), payload, deviceSessionHistoryTTL).Err(); err != nil {
		t.Fatalf("set meta key: %v", err)
	}
	if visible {
		if err := s.redis.ZAdd(ctx, deviceSessionListKey(userID), redis.Z{Score: float64(score), Member: sessionID}).Err(); err != nil {
			t.Fatalf("zadd list: %v", err)
		}
	}
	if inAll {
		if err := s.redis.ZAdd(ctx, deviceSessionAllKey(userID), redis.Z{Score: float64(score), Member: sessionID}).Err(); err != nil {
			t.Fatalf("zadd all: %v", err)
		}
	}
	if deviceID != "" {
		if err := s.redis.Set(ctx, deviceSessionDeviceKey(userID, deviceID), sessionID, deviceSessionHistoryTTL).Err(); err != nil {
			t.Fatalf("set device mapping: %v", err)
		}
	}
	return meta
}

func assertKeyMissing(t *testing.T, s *Service, ctx context.Context, key string) {
	t.Helper()
	_, err := s.redis.Get(ctx, key).Result()
	if !errors.Is(err, redis.Nil) {
		t.Fatalf("expected key %q to be missing, got err=%v", key, err)
	}
}

func assertZSetMissingMember(t *testing.T, s *Service, ctx context.Context, key, member string) {
	t.Helper()
	_, err := s.redis.ZScore(ctx, key, member).Result()
	if !errors.Is(err, redis.Nil) {
		t.Fatalf("expected member %q to be missing in %q, got err=%v", member, key, err)
	}
}

func TestTouchDeviceSessionReplacesPreviousSessionCompletely(t *testing.T) {
	s, ctx := newSessionServiceForTest(t)

	userID := "user-1"
	deviceID := "device-1"
	credentialID := encodeCredentialID([]byte{1, 2, 3, 4})

	putSessionArtifacts(t, s, ctx, userID, "S1", deviceID, credentialID, 100, true, true)
	if err := s.redis.Set(ctx, "sess:S2", userID, time.Hour).Err(); err != nil {
		t.Fatalf("set S2 session key: %v", err)
	}

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "198.51.100.5:32123"
	req.Header.Set("User-Agent", "Mozilla/5.0 Test")
	req.AddCookie(&http.Cookie{Name: deviceCookieName, Value: deviceID})
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	if err := s.touchDeviceSession(c, "S2", userID, credentialID); err != nil {
		t.Fatalf("touchDeviceSession failed: %v", err)
	}

	assertKeyMissing(t, s, ctx, "sess:S1")
	assertKeyMissing(t, s, ctx, "recovery:S1")
	assertKeyMissing(t, s, ctx, deviceSessionMetaKey("S1"))
	assertZSetMissingMember(t, s, ctx, deviceSessionListKey(userID), "S1")
	assertZSetMissingMember(t, s, ctx, deviceSessionAllKey(userID), "S1")

	mapped, err := s.redis.Get(ctx, deviceSessionDeviceKey(userID, deviceID)).Result()
	if err != nil {
		t.Fatalf("read device mapping: %v", err)
	}
	if mapped != "S2" {
		t.Fatalf("expected device mapping to point to S2, got %q", mapped)
	}

	if _, err := s.redis.ZScore(ctx, deviceSessionListKey(userID), "S2").Result(); err != nil {
		t.Fatalf("expected S2 in visible list: %v", err)
	}
	if _, err := s.redis.ZScore(ctx, deviceSessionAllKey(userID), "S2").Result(); err != nil {
		t.Fatalf("expected S2 in full list: %v", err)
	}

	payload, err := s.redis.Get(ctx, deviceSessionMetaKey("S2")).Bytes()
	if err != nil {
		t.Fatalf("read S2 meta: %v", err)
	}
	meta, err := decodeSessionMeta(payload)
	if err != nil {
		t.Fatalf("decode S2 meta: %v", err)
	}
	if meta.CreatedAtUTC != 100 {
		t.Fatalf("expected created_at to be preserved from S1, got %d", meta.CreatedAtUTC)
	}
	if meta.CredentialID != credentialID {
		t.Fatalf("expected credential %q, got %q", credentialID, meta.CredentialID)
	}
}

func TestRevokeSessionsForCredentialRemovesHiddenOrphanFromFullIndex(t *testing.T) {
	s, ctx := newSessionServiceForTest(t)

	userID := "user-1"
	deviceID := "device-2"
	targetCred := []byte{9, 8, 7}
	encodedCred := encodeCredentialID(targetCred)

	putSessionArtifacts(t, s, ctx, userID, "S1", deviceID, encodedCred, 200, false, true)

	removedCurrent, err := s.revokeSessionsForCredential(ctx, userID, targetCred, "")
	if err != nil {
		t.Fatalf("revokeSessionsForCredential failed: %v", err)
	}
	if removedCurrent {
		t.Fatal("expected removedCurrent=false")
	}

	assertKeyMissing(t, s, ctx, "sess:S1")
	assertKeyMissing(t, s, ctx, "recovery:S1")
	assertKeyMissing(t, s, ctx, deviceSessionMetaKey("S1"))
	assertZSetMissingMember(t, s, ctx, deviceSessionListKey(userID), "S1")
	assertZSetMissingMember(t, s, ctx, deviceSessionAllKey(userID), "S1")
	assertKeyMissing(t, s, ctx, deviceSessionDeviceKey(userID, deviceID))
}

func TestRevokeSessionsForCredentialRemovesLegacyHiddenSessionOutsideIndexes(t *testing.T) {
	s, ctx := newSessionServiceForTest(t)

	userID := "user-1"
	deviceID := "device-legacy"
	targetCred := []byte{7, 7, 7}
	encodedCred := encodeCredentialID(targetCred)

	putSessionArtifacts(t, s, ctx, userID, "Slegacy", deviceID, encodedCred, 210, false, false)

	removedCurrent, err := s.revokeSessionsForCredential(ctx, userID, targetCred, "")
	if err != nil {
		t.Fatalf("revokeSessionsForCredential failed: %v", err)
	}
	if removedCurrent {
		t.Fatal("expected removedCurrent=false")
	}

	assertKeyMissing(t, s, ctx, "sess:Slegacy")
	assertKeyMissing(t, s, ctx, "recovery:Slegacy")
	assertKeyMissing(t, s, ctx, deviceSessionMetaKey("Slegacy"))
	assertZSetMissingMember(t, s, ctx, deviceSessionListKey(userID), "Slegacy")
	assertZSetMissingMember(t, s, ctx, deviceSessionAllKey(userID), "Slegacy")
	assertKeyMissing(t, s, ctx, deviceSessionDeviceKey(userID, deviceID))
}

func TestRevokeSessionsForCredentialRemovesAllMatchingSessions(t *testing.T) {
	s, ctx := newSessionServiceForTest(t)

	userID := "user-1"
	targetCred := []byte{1, 1, 1}
	targetEncoded := encodeCredentialID(targetCred)
	otherCred := encodeCredentialID([]byte{2, 2, 2})

	putSessionArtifacts(t, s, ctx, userID, "S1", "dev-1", targetEncoded, 100, true, true)
	putSessionArtifacts(t, s, ctx, userID, "S2", "dev-2", targetEncoded, 101, false, true)
	putSessionArtifacts(t, s, ctx, userID, "S3", "dev-3", otherCred, 102, true, true)

	removedCurrent, err := s.revokeSessionsForCredential(ctx, userID, targetCred, "S2")
	if err != nil {
		t.Fatalf("revokeSessionsForCredential failed: %v", err)
	}
	if !removedCurrent {
		t.Fatal("expected removedCurrent=true for S2")
	}

	for _, sessionID := range []string{"S1", "S2"} {
		assertKeyMissing(t, s, ctx, "sess:"+sessionID)
		assertKeyMissing(t, s, ctx, "recovery:"+sessionID)
		assertKeyMissing(t, s, ctx, deviceSessionMetaKey(sessionID))
		assertZSetMissingMember(t, s, ctx, deviceSessionListKey(userID), sessionID)
		assertZSetMissingMember(t, s, ctx, deviceSessionAllKey(userID), sessionID)
	}

	if _, err := s.redis.Get(ctx, "sess:S3").Result(); err != nil {
		t.Fatalf("expected S3 to remain active: %v", err)
	}
	if _, err := s.redis.Get(ctx, "recovery:S3").Result(); err != nil {
		t.Fatalf("expected S3 recovery marker to remain: %v", err)
	}
	if _, err := s.redis.Get(ctx, deviceSessionMetaKey("S3")).Result(); err != nil {
		t.Fatalf("expected S3 meta to remain: %v", err)
	}
	if _, err := s.redis.ZScore(ctx, deviceSessionListKey(userID), "S3").Result(); err != nil {
		t.Fatalf("expected S3 in visible list: %v", err)
	}
	if _, err := s.redis.ZScore(ctx, deviceSessionAllKey(userID), "S3").Result(); err != nil {
		t.Fatalf("expected S3 in full list: %v", err)
	}
	mapped, err := s.redis.Get(ctx, deviceSessionDeviceKey(userID, "dev-3")).Result()
	if err != nil {
		t.Fatalf("expected S3 device mapping to remain: %v", err)
	}
	if mapped != "S3" {
		t.Fatalf("expected S3 mapping, got %q", mapped)
	}
}

func TestCleanupSessionArtifactsDoesNotDeleteNewDeviceMapping(t *testing.T) {
	s, ctx := newSessionServiceForTest(t)

	userID := "user-1"
	deviceID := "device-9"
	putSessionArtifacts(t, s, ctx, userID, "S1", deviceID, encodeCredentialID([]byte{4, 4, 4}), 50, true, true)
	if err := s.redis.Set(ctx, deviceSessionDeviceKey(userID, deviceID), "S2", deviceSessionHistoryTTL).Err(); err != nil {
		t.Fatalf("set new mapping: %v", err)
	}

	meta := &deviceSessionMeta{
		UserID:   userID,
		DeviceID: deviceID,
	}
	if err := s.cleanupSessionArtifacts(ctx, userID, "S1", meta); err != nil {
		t.Fatalf("cleanupSessionArtifacts failed: %v", err)
	}

	assertKeyMissing(t, s, ctx, "sess:S1")
	assertKeyMissing(t, s, ctx, "recovery:S1")
	assertKeyMissing(t, s, ctx, deviceSessionMetaKey("S1"))
	assertZSetMissingMember(t, s, ctx, deviceSessionListKey(userID), "S1")
	assertZSetMissingMember(t, s, ctx, deviceSessionAllKey(userID), "S1")

	mapped, err := s.redis.Get(ctx, deviceSessionDeviceKey(userID, deviceID)).Result()
	if err != nil {
		t.Fatalf("read mapping after cleanup: %v", err)
	}
	if mapped != "S2" {
		t.Fatalf("expected mapping to remain on new session S2, got %q", mapped)
	}
}
