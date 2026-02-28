package auth

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/houbamydar/AHOJ420/internal/store"
	"github.com/labstack/echo/v4"
	"github.com/redis/go-redis/v9"
)

const (
	deviceSessionMetaPrefix   = "sessmeta:"
	deviceSessionListPrefix   = "sesslist:"
	deviceSessionAllPrefix    = "sessall:"
	deviceSessionDevicePrefix = "sessdev:"
	deviceSessionHistoryTTL   = 90 * 24 * time.Hour
	deviceSessionListLimit    = 50
	deviceCookieName          = "device_id"
	deviceCookieMaxAgeSec     = 365 * 24 * 60 * 60
)

var (
	errDeviceNotFound            = errors.New("device not found")
	errCannotDeleteLastDevice    = errors.New("cannot delete last device")
	errDeviceSessionAccessDenied = errors.New("forbidden")
)

type deviceSessionMeta struct {
	SessionID    string `json:"session_id"`
	UserID       string `json:"user_id"`
	DeviceID     string `json:"device_id"`
	CredentialID string `json:"credential_id"`
	UserAgent    string `json:"user_agent"`
	IP           string `json:"ip"`
	CreatedAtUTC int64  `json:"created_at_utc"`
	LastSeenUTC  int64  `json:"last_seen_utc"`
}

type deviceSessionDTO struct {
	SessionID  string `json:"session_id"`
	Device     string `json:"device"`
	UserAgent  string `json:"user_agent,omitempty"`
	IP         string `json:"ip,omitempty"`
	CreatedAt  string `json:"created_at,omitempty"`
	LastSeenAt string `json:"last_seen_at,omitempty"`
	Active     bool   `json:"active"`
	Current    bool   `json:"current"`
}

type deviceLogoutPayload struct {
	SessionID string `json:"session_id"`
}

type deviceRemovePayload struct {
	SessionID string `json:"session_id"`
}

func deviceSessionMetaKey(sessionID string) string {
	return deviceSessionMetaPrefix + sessionID
}

func deviceSessionListKey(userID string) string {
	return deviceSessionListPrefix + userID
}

func deviceSessionAllKey(userID string) string {
	return deviceSessionAllPrefix + userID
}

func deviceSessionDeviceKey(userID, deviceID string) string {
	return deviceSessionDevicePrefix + userID + ":" + deviceID
}

func (s *Service) ensureDeviceID(c echo.Context) (string, error) {
	if cookie, err := c.Cookie(deviceCookieName); err == nil {
		if deviceID, normalizeErr := normalizeDeviceSessionID(cookie.Value); normalizeErr == nil {
			return deviceID, nil
		}
	}

	deviceID, err := newSessionID()
	if err != nil {
		return "", err
	}
	c.SetCookie(&http.Cookie{
		Name:     deviceCookieName,
		Value:    deviceID,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   deviceCookieMaxAgeSec,
	})
	return deviceID, nil
}

func encodeCredentialID(raw []byte) string {
	if len(raw) == 0 {
		return ""
	}
	return hex.EncodeToString(raw)
}

func decodeCredentialID(encoded string) ([]byte, error) {
	normalized := strings.TrimSpace(encoded)
	if normalized == "" {
		return nil, errors.New("credential_id is empty")
	}
	if raw, err := hex.DecodeString(normalized); err == nil {
		return raw, nil
	}
	return base64.RawURLEncoding.DecodeString(normalized)
}

func credentialIDMatches(rawMeta string, target []byte) bool {
	if len(target) == 0 {
		return false
	}
	decoded, err := decodeCredentialID(rawMeta)
	if err != nil {
		return false
	}
	return bytes.Equal(decoded, target)
}

func decodeSessionMeta(payload []byte) (*deviceSessionMeta, error) {
	var meta deviceSessionMeta
	if err := json.Unmarshal(payload, &meta); err != nil {
		return nil, err
	}
	return &meta, nil
}

func (s *Service) deleteDeviceMappingIfMatches(ctx context.Context, userID, deviceID, sessionID string) error {
	userID = strings.TrimSpace(userID)
	deviceID = strings.TrimSpace(deviceID)
	sessionID = strings.TrimSpace(sessionID)
	if userID == "" || deviceID == "" || sessionID == "" {
		return nil
	}

	mapKey := deviceSessionDeviceKey(userID, deviceID)
	for attempts := 0; attempts < 5; attempts++ {
		err := s.redis.Watch(ctx, func(tx *redis.Tx) error {
			mappedSessionID, err := tx.Get(ctx, mapKey).Result()
			if errors.Is(err, redis.Nil) {
				return nil
			}
			if err != nil {
				return err
			}
			if strings.TrimSpace(mappedSessionID) != sessionID {
				return nil
			}
			_, txErr := tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
				pipe.Del(ctx, mapKey)
				return nil
			})
			return txErr
		}, mapKey)
		if err == nil {
			return nil
		}
		if errors.Is(err, redis.TxFailedErr) {
			continue
		}
		return err
	}
	return redis.TxFailedErr
}

func enqueueSessionCleanupArtifacts(ctx context.Context, pipe redis.Pipeliner, userID, sessionID string) {
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return
	}
	pipe.Del(ctx, "sess:"+sessionID)
	pipe.Del(ctx, "recovery:"+sessionID)
	pipe.Del(ctx, deviceSessionMetaKey(sessionID))

	userID = strings.TrimSpace(userID)
	if userID == "" {
		return
	}
	pipe.ZRem(ctx, deviceSessionListKey(userID), sessionID)
	pipe.ZRem(ctx, deviceSessionAllKey(userID), sessionID)
}

func (s *Service) cleanupSessionArtifacts(ctx context.Context, userID, sessionID string, meta *deviceSessionMeta) error {
	userID = strings.TrimSpace(userID)
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return nil
	}

	deviceID := ""
	if meta != nil {
		if userID == "" {
			userID = strings.TrimSpace(meta.UserID)
		}
		deviceID = strings.TrimSpace(meta.DeviceID)
	}
	if userID == "" || deviceID == "" {
		payload, err := s.redis.Get(ctx, deviceSessionMetaKey(sessionID)).Bytes()
		if err == nil {
			if loadedMeta, decodeErr := decodeSessionMeta(payload); decodeErr == nil {
				if userID == "" {
					userID = strings.TrimSpace(loadedMeta.UserID)
				}
				if deviceID == "" {
					deviceID = strings.TrimSpace(loadedMeta.DeviceID)
				}
			}
		} else if !errors.Is(err, redis.Nil) {
			return err
		}
	}

	pipe := s.redis.TxPipeline()
	enqueueSessionCleanupArtifacts(ctx, pipe, userID, sessionID)
	if _, err := pipe.Exec(ctx); err != nil && !errors.Is(err, redis.Nil) {
		return err
	}

	return s.deleteDeviceMappingIfMatches(ctx, userID, deviceID, sessionID)
}

func (s *Service) listOwnedSessionIDs(ctx context.Context, userID string) ([]string, error) {
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return nil, nil
	}

	out := make([]string, 0, 16)
	var cursor uint64
	for {
		keys, nextCursor, err := s.redis.Scan(ctx, cursor, "sess:*", 128).Result()
		if err != nil {
			return nil, err
		}
		cursor = nextCursor
		if len(keys) == 0 {
			if cursor == 0 {
				break
			}
			continue
		}

		pipe := s.redis.Pipeline()
		ownerCmd := make(map[string]*redis.StringCmd, len(keys))
		for _, key := range keys {
			ownerCmd[key] = pipe.Get(ctx, key)
		}
		if _, err := pipe.Exec(ctx); err != nil && !errors.Is(err, redis.Nil) {
			return nil, err
		}

		for _, key := range keys {
			owner, ownerErr := ownerCmd[key].Result()
			if errors.Is(ownerErr, redis.Nil) {
				continue
			}
			if ownerErr != nil {
				return nil, ownerErr
			}
			if strings.TrimSpace(owner) != userID {
				continue
			}
			sessionID := strings.TrimSpace(strings.TrimPrefix(key, "sess:"))
			if sessionID == "" {
				continue
			}
			out = append(out, sessionID)
		}

		if cursor == 0 {
			break
		}
	}

	return out, nil
}

func addSessionID(sessionIDs map[string]struct{}, value string) {
	value = strings.TrimSpace(value)
	if value == "" {
		return
	}
	sessionIDs[value] = struct{}{}
}

func (s *Service) listIndexedSessionIDs(ctx context.Context, key string) ([]string, error) {
	items, err := s.redis.ZRange(ctx, strings.TrimSpace(key), 0, -1).Result()
	if err != nil && !errors.Is(err, redis.Nil) {
		return nil, err
	}
	if len(items) == 0 {
		return []string{}, nil
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		normalized := strings.TrimSpace(item)
		if normalized == "" {
			continue
		}
		out = append(out, normalized)
	}
	return out, nil
}

func (s *Service) listSessionIDsFromMeta(ctx context.Context, userID string) ([]string, error) {
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return []string{}, nil
	}

	out := make([]string, 0, 16)
	var cursor uint64
	for {
		keys, nextCursor, err := s.redis.Scan(ctx, cursor, deviceSessionMetaPrefix+"*", 128).Result()
		if err != nil {
			return nil, err
		}
		cursor = nextCursor
		if len(keys) == 0 {
			if cursor == 0 {
				break
			}
			continue
		}

		pipe := s.redis.Pipeline()
		metaCmd := make(map[string]*redis.StringCmd, len(keys))
		for _, key := range keys {
			metaCmd[key] = pipe.Get(ctx, key)
		}
		if _, err := pipe.Exec(ctx); err != nil && !errors.Is(err, redis.Nil) {
			return nil, err
		}

		for _, key := range keys {
			payload, err := metaCmd[key].Bytes()
			if errors.Is(err, redis.Nil) {
				continue
			}
			if err != nil {
				return nil, err
			}
			meta, err := decodeSessionMeta(payload)
			if err != nil {
				continue
			}
			if strings.TrimSpace(meta.UserID) != userID {
				continue
			}

			sessionID := strings.TrimSpace(meta.SessionID)
			if sessionID == "" {
				sessionID = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(key), deviceSessionMetaPrefix))
			}
			if sessionID == "" {
				continue
			}
			out = append(out, sessionID)
		}

		if cursor == 0 {
			break
		}
	}

	return out, nil
}

func (s *Service) listAllUserSessionIDs(ctx context.Context, userID string) ([]string, error) {
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return []string{}, nil
	}

	sessionSet := make(map[string]struct{}, 32)

	indexedList, err := s.listIndexedSessionIDs(ctx, deviceSessionListKey(userID))
	if err != nil {
		return nil, err
	}
	for _, item := range indexedList {
		addSessionID(sessionSet, item)
	}

	indexedAll, err := s.listIndexedSessionIDs(ctx, deviceSessionAllKey(userID))
	if err != nil {
		return nil, err
	}
	for _, item := range indexedAll {
		addSessionID(sessionSet, item)
	}

	owned, err := s.listOwnedSessionIDs(ctx, userID)
	if err != nil {
		return nil, err
	}
	for _, item := range owned {
		addSessionID(sessionSet, item)
	}

	metaOwned, err := s.listSessionIDsFromMeta(ctx, userID)
	if err != nil {
		return nil, err
	}
	for _, item := range metaOwned {
		addSessionID(sessionSet, item)
	}

	out := make([]string, 0, len(sessionSet))
	for sessionID := range sessionSet {
		out = append(out, sessionID)
	}
	sort.Strings(out)
	return out, nil
}

func (s *Service) cleanupUserDeviceMappings(ctx context.Context, userID string) error {
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return nil
	}

	var cursor uint64
	for {
		keys, nextCursor, err := s.redis.Scan(ctx, cursor, deviceSessionDevicePrefix+userID+":*", 128).Result()
		if err != nil {
			return err
		}
		cursor = nextCursor
		if len(keys) > 0 {
			if err := s.redis.Del(ctx, keys...).Err(); err != nil && !errors.Is(err, redis.Nil) {
				return err
			}
		}
		if cursor == 0 {
			break
		}
	}
	return nil
}

func (s *Service) RevokeAllUserSessions(ctx context.Context, userID string) error {
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return errors.New("user id is required")
	}

	sessionIDs, err := s.listAllUserSessionIDs(ctx, userID)
	if err != nil {
		return err
	}

	var (
		firstErr error
		errCount int
	)
	recordError := func(err error) {
		if err == nil {
			return
		}
		errCount++
		if firstErr == nil {
			firstErr = err
		}
	}

	for _, sessionID := range sessionIDs {
		sessionID = strings.TrimSpace(sessionID)
		if sessionID == "" {
			continue
		}

		var meta *deviceSessionMeta
		if payload, err := s.redis.Get(ctx, deviceSessionMetaKey(sessionID)).Bytes(); err == nil {
			if decoded, decodeErr := decodeSessionMeta(payload); decodeErr == nil {
				meta = decoded
			}
		} else if !errors.Is(err, redis.Nil) {
			recordError(err)
		}

		recordError(s.cleanupSessionArtifacts(ctx, userID, sessionID, meta))
	}

	if err := s.redis.Del(ctx, deviceSessionListKey(userID), deviceSessionAllKey(userID)).Err(); err != nil && !errors.Is(err, redis.Nil) {
		recordError(err)
	}
	recordError(s.cleanupUserDeviceMappings(ctx, userID))

	if errCount > 0 {
		return fmt.Errorf("user session cleanup failed (%d errors): %w", errCount, firstErr)
	}
	return nil
}

func (s *Service) revokeSessionsForCredential(ctx context.Context, userID string, credentialID []byte, currentSessionID string) (bool, error) {
	userID = strings.TrimSpace(userID)
	currentSessionID = strings.TrimSpace(currentSessionID)
	if userID == "" || len(credentialID) == 0 {
		return false, nil
	}
	credentialDisplayID := encodeCredentialID(credentialID)

	allKey := deviceSessionAllKey(userID)
	sessionIDs, err := s.redis.ZRange(ctx, allKey, 0, -1).Result()
	if err != nil && !errors.Is(err, redis.Nil) {
		return false, err
	}
	backfillIDs := make([]string, 0, 8)

	// Legacy fallback: visible list might still have entries that were never backfilled to full index.
	listSessionIDs, listErr := s.redis.ZRange(ctx, deviceSessionListKey(userID), 0, -1).Result()
	if listErr != nil && !errors.Is(listErr, redis.Nil) {
		return false, listErr
	}
	sessionSeen := make(map[string]struct{}, len(sessionIDs)+len(listSessionIDs))
	for _, sessionID := range sessionIDs {
		sessionSeen[sessionID] = struct{}{}
	}
	for _, sessionID := range listSessionIDs {
		if _, exists := sessionSeen[sessionID]; exists {
			continue
		}
		sessionIDs = append(sessionIDs, sessionID)
		sessionSeen[sessionID] = struct{}{}
		backfillIDs = append(backfillIDs, sessionID)
	}

	legacySessionIDs, legacyErr := s.listOwnedSessionIDs(ctx, userID)
	if legacyErr != nil {
		return false, legacyErr
	}
	for _, sessionID := range legacySessionIDs {
		if _, exists := sessionSeen[sessionID]; exists {
			continue
		}
		sessionIDs = append(sessionIDs, sessionID)
		sessionSeen[sessionID] = struct{}{}
		backfillIDs = append(backfillIDs, sessionID)
	}
	if len(sessionIDs) == 0 {
		return false, nil
	}
	if len(backfillIDs) > 0 {
		nowScore := float64(time.Now().UTC().Unix())
		backfillPipe := s.redis.TxPipeline()
		for _, sessionID := range backfillIDs {
			backfillPipe.ZAdd(ctx, allKey, redis.Z{
				Score:  nowScore,
				Member: sessionID,
			})
		}
		backfillPipe.Expire(ctx, allKey, deviceSessionHistoryTTL)
		if _, err := backfillPipe.Exec(ctx); err != nil && !errors.Is(err, redis.Nil) {
			return false, err
		}
	}

	pipe := s.redis.Pipeline()
	metaCmd := make(map[string]*redis.StringCmd, len(sessionIDs))
	for _, sessionID := range sessionIDs {
		metaCmd[sessionID] = pipe.Get(ctx, deviceSessionMetaKey(sessionID))
	}
	_, err = pipe.Exec(ctx)
	if err != nil && !errors.Is(err, redis.Nil) {
		return false, err
	}

	removedCurrent := false
	for _, sessionID := range sessionIDs {
		rawMeta, metaErr := metaCmd[sessionID].Bytes()
		var meta *deviceSessionMeta
		staleEntry := false

		switch {
		case metaErr == nil:
			decodedMeta, decodeErr := decodeSessionMeta(rawMeta)
			if decodeErr != nil {
				staleEntry = true
				break
			}
			if strings.TrimSpace(decodedMeta.UserID) != userID {
				staleEntry = true
				break
			}
			meta = decodedMeta
		case errors.Is(metaErr, redis.Nil):
			staleEntry = true
		default:
			return false, metaErr
		}

		if !staleEntry && (meta == nil || !credentialIDMatches(meta.CredentialID, credentialID)) {
			continue
		}
		if cleanupErr := s.cleanupSessionArtifacts(ctx, userID, sessionID, meta); cleanupErr != nil {
			return false, cleanupErr
		}
		s.writeUserSecurityEvent(ctx, store.UserSecurityEvent{
			UserID:       userID,
			EventType:    store.UserSecurityEventSessionRevoked,
			Category:     store.UserSecurityCategorySession,
			Success:      boolPointer(true),
			ActorType:    "user",
			ActorID:      userID,
			SessionID:    sessionID,
			CredentialID: credentialDisplayID,
			DetailsJSON:  userSecurityDetailsJSON(map[string]any{"reason": "passkey_revoked"}),
		})
		if sessionID == currentSessionID {
			removedCurrent = true
		}
	}

	return removedCurrent, nil
}

func requestIP(c echo.Context) string {
	if ip := strings.TrimSpace(c.RealIP()); ip != "" {
		return ip
	}
	host, _, err := net.SplitHostPort(strings.TrimSpace(c.Request().RemoteAddr))
	if err == nil {
		return strings.TrimSpace(host)
	}
	return strings.TrimSpace(c.Request().RemoteAddr)
}

func sessionDeviceLabel(userAgent string) string {
	ua := strings.ToLower(strings.TrimSpace(userAgent))
	if ua == "" {
		return "Unknown device"
	}

	browser := "Browser"
	switch {
	case strings.Contains(ua, "edg/"):
		browser = "Edge"
	case strings.Contains(ua, "opr/") || strings.Contains(ua, "opera"):
		browser = "Opera"
	case strings.Contains(ua, "firefox/"):
		browser = "Firefox"
	case strings.Contains(ua, "chrome/"):
		browser = "Chrome"
	case strings.Contains(ua, "safari/"):
		browser = "Safari"
	}

	os := "Unknown OS"
	switch {
	case strings.Contains(ua, "windows"):
		os = "Windows"
	case strings.Contains(ua, "android"):
		os = "Android"
	case strings.Contains(ua, "iphone") || strings.Contains(ua, "ipad") || strings.Contains(ua, "ios"):
		os = "iOS"
	case strings.Contains(ua, "mac os x") || strings.Contains(ua, "macintosh"):
		os = "macOS"
	case strings.Contains(ua, "linux"):
		os = "Linux"
	}

	if browser == "Browser" && os == "Unknown OS" {
		return "Unknown device"
	}
	if os == "Unknown OS" {
		return browser
	}
	return browser + " on " + os
}

func formatUnixUTC(ts int64) string {
	if ts <= 0 {
		return ""
	}
	return time.Unix(ts, 0).UTC().Format(time.RFC3339)
}

func (s *Service) touchDeviceSession(c echo.Context, sessionID, userID, credentialID string) error {
	sessionID = strings.TrimSpace(sessionID)
	userID = strings.TrimSpace(userID)
	credentialID = strings.TrimSpace(credentialID)
	if sessionID == "" || userID == "" {
		return nil
	}

	ctx := c.Request().Context()
	now := time.Now().UTC().Unix()
	deviceID, err := s.ensureDeviceID(c)
	if err != nil {
		return err
	}
	deviceMapKey := deviceSessionDeviceKey(userID, deviceID)

	prevSessionID := ""
	if cached, mapErr := s.redis.Get(ctx, deviceMapKey).Result(); mapErr == nil {
		prevSessionID = strings.TrimSpace(cached)
	} else if !errors.Is(mapErr, redis.Nil) {
		return mapErr
	}
	if prevSessionID == sessionID {
		prevSessionID = ""
	}

	meta := deviceSessionMeta{
		SessionID: sessionID,
		UserID:    userID,
		DeviceID:  deviceID,
	}
	if payload, err := s.redis.Get(ctx, deviceSessionMetaKey(sessionID)).Bytes(); err == nil {
		_ = json.Unmarshal(payload, &meta)
	} else if !errors.Is(err, redis.Nil) {
		return err
	}

	meta.SessionID = sessionID
	meta.UserID = userID
	meta.DeviceID = deviceID
	if credentialID != "" {
		meta.CredentialID = credentialID
	}
	var prevMeta *deviceSessionMeta
	if prevSessionID != "" {
		if prevPayload, prevErr := s.redis.Get(ctx, deviceSessionMetaKey(prevSessionID)).Bytes(); prevErr == nil {
			decodedPrevMeta, decodeErr := decodeSessionMeta(prevPayload)
			if decodeErr == nil {
				prevMeta = decodedPrevMeta
				if meta.CreatedAtUTC <= 0 && decodedPrevMeta.CreatedAtUTC > 0 {
					meta.CreatedAtUTC = decodedPrevMeta.CreatedAtUTC
				}
			}
		} else if !errors.Is(prevErr, redis.Nil) {
			return prevErr
		}
		if prevMeta == nil {
			prevMeta = &deviceSessionMeta{
				UserID:   userID,
				DeviceID: deviceID,
			}
		}
		if cleanupErr := s.cleanupSessionArtifacts(ctx, userID, prevSessionID, prevMeta); cleanupErr != nil {
			return cleanupErr
		}
	}
	userAgent := strings.TrimSpace(c.Request().UserAgent())
	if len(userAgent) > 512 {
		userAgent = userAgent[:512]
	}
	meta.UserAgent = userAgent
	meta.IP = requestIP(c)
	if meta.CreatedAtUTC <= 0 {
		meta.CreatedAtUTC = now
	}
	meta.LastSeenUTC = now

	payload, err := json.Marshal(meta)
	if err != nil {
		return err
	}

	listKey := deviceSessionListKey(userID)
	allKey := deviceSessionAllKey(userID)
	pipe := s.redis.TxPipeline()
	pipe.Set(ctx, deviceSessionMetaKey(sessionID), payload, deviceSessionHistoryTTL)
	pipe.ZAdd(ctx, listKey, redis.Z{
		Score:  float64(now),
		Member: sessionID,
	})
	pipe.Expire(ctx, listKey, deviceSessionHistoryTTL)
	pipe.ZAdd(ctx, allKey, redis.Z{
		Score:  float64(now),
		Member: sessionID,
	})
	pipe.Expire(ctx, allKey, deviceSessionHistoryTTL)
	pipe.Set(ctx, deviceMapKey, sessionID, deviceSessionHistoryTTL)
	_, err = pipe.Exec(ctx)
	if err != nil && !errors.Is(err, redis.Nil) {
		return err
	}
	return nil
}

func (s *Service) ListDeviceSessions(c echo.Context) error {
	userID, ok := s.SessionUserID(c)
	if !ok {
		return c.JSON(http.StatusUnauthorized, map[string]any{"message": "not authenticated"})
	}
	currentSessionID, _ := s.sessionID(c)
	ctx := c.Request().Context()
	listKey := deviceSessionListKey(userID)

	sessionIDs, err := s.redis.ZRevRange(ctx, listKey, 0, deviceSessionListLimit-1).Result()
	if err != nil && !errors.Is(err, redis.Nil) {
		return c.String(http.StatusInternalServerError, "Internal error")
	}
	if len(sessionIDs) == 0 {
		return c.JSON(http.StatusOK, map[string]any{"devices": []deviceSessionDTO{}})
	}

	pipe := s.redis.Pipeline()
	metaCmd := make(map[string]*redis.StringCmd, len(sessionIDs))
	activeCmd := make(map[string]*redis.IntCmd, len(sessionIDs))
	for _, sessionID := range sessionIDs {
		metaCmd[sessionID] = pipe.Get(ctx, deviceSessionMetaKey(sessionID))
		activeCmd[sessionID] = pipe.Exists(ctx, "sess:"+sessionID)
	}
	_, err = pipe.Exec(ctx)
	if err != nil && !errors.Is(err, redis.Nil) {
		return c.String(http.StatusInternalServerError, "Internal error")
	}

	devices := make([]deviceSessionDTO, 0, len(sessionIDs))
	seenDevice := make(map[string]struct{}, len(sessionIDs))
	staleSessionIDs := make([]string, 0, len(sessionIDs))
	for _, sessionID := range sessionIDs {
		rawMeta, metaErr := metaCmd[sessionID].Bytes()
		if metaErr != nil {
			staleSessionIDs = append(staleSessionIDs, sessionID)
			continue
		}

		var meta deviceSessionMeta
		if err := json.Unmarshal(rawMeta, &meta); err != nil {
			staleSessionIDs = append(staleSessionIDs, sessionID)
			continue
		}
		if strings.TrimSpace(meta.UserID) != userID {
			staleSessionIDs = append(staleSessionIDs, sessionID)
			continue
		}
		deviceKey := strings.TrimSpace(meta.DeviceID)
		if deviceKey == "" {
			deviceKey = "legacy:" + strings.TrimSpace(meta.UserAgent) + "|" + strings.TrimSpace(meta.IP)
		}
		if _, exists := seenDevice[deviceKey]; exists {
			staleSessionIDs = append(staleSessionIDs, sessionID)
			continue
		}
		seenDevice[deviceKey] = struct{}{}

		devices = append(devices, deviceSessionDTO{
			SessionID:  sessionID,
			Device:     sessionDeviceLabel(meta.UserAgent),
			UserAgent:  meta.UserAgent,
			IP:         meta.IP,
			CreatedAt:  formatUnixUTC(meta.CreatedAtUTC),
			LastSeenAt: formatUnixUTC(meta.LastSeenUTC),
			Active:     activeCmd[sessionID].Val() > 0,
			Current:    sessionID == currentSessionID,
		})
	}
	if len(staleSessionIDs) > 0 {
		for _, staleSessionID := range staleSessionIDs {
			_ = s.cleanupSessionArtifacts(ctx, userID, staleSessionID, nil)
		}
	}

	return c.JSON(http.StatusOK, map[string]any{"devices": devices})
}

func normalizeDeviceSessionID(raw string) (string, error) {
	sessionID := strings.TrimSpace(raw)
	if sessionID == "" {
		return "", errors.New("session_id is required")
	}
	if len(sessionID) > 128 {
		return "", errors.New("invalid session_id")
	}
	for _, r := range sessionID {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			continue
		}
		return "", errors.New("invalid session_id")
	}
	return sessionID, nil
}

func (s *Service) LogoutDeviceSession(c echo.Context) error {
	userID, ok := s.SessionUserID(c)
	if !ok {
		return c.JSON(http.StatusUnauthorized, map[string]any{"message": "not authenticated"})
	}

	var body deviceLogoutPayload
	_ = c.Bind(&body)
	sessionID, err := normalizeDeviceSessionID(body.SessionID)
	if err != nil {
		sessionID, err = normalizeDeviceSessionID(c.FormValue("session_id"))
		if err != nil {
			return c.String(http.StatusBadRequest, err.Error())
		}
	}

	ctx := c.Request().Context()
	var targetMeta *deviceSessionMeta
	metaPayload, err := s.redis.Get(ctx, deviceSessionMetaKey(sessionID)).Bytes()
	if err == nil {
		if decodedMeta, decodeErr := decodeSessionMeta(metaPayload); decodeErr == nil {
			targetMeta = decodedMeta
			if strings.TrimSpace(decodedMeta.UserID) != "" && strings.TrimSpace(decodedMeta.UserID) != userID {
				return c.String(http.StatusForbidden, "forbidden")
			}
		}
	} else if !errors.Is(err, redis.Nil) {
		return c.String(http.StatusInternalServerError, "Internal error")
	}

	if ownerID, ownerErr := s.redis.Get(ctx, "sess:"+sessionID).Result(); ownerErr == nil && strings.TrimSpace(ownerID) != userID {
		return c.String(http.StatusForbidden, "forbidden")
	} else if ownerErr != nil && !errors.Is(ownerErr, redis.Nil) {
		return c.String(http.StatusInternalServerError, "Internal error")
	}

	if err := s.cleanupSessionArtifacts(ctx, userID, sessionID, targetMeta); err != nil {
		return c.String(http.StatusInternalServerError, "Internal error")
	}

	currentSessionID, _ := s.sessionID(c)
	currentLoggedOut := sessionID == currentSessionID
	if currentLoggedOut {
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
	s.writeUserSecurityEventFromRequest(c, store.UserSecurityEvent{
		UserID:      userID,
		EventType:   store.UserSecurityEventSessionRevoked,
		Category:    store.UserSecurityCategorySession,
		Success:     boolPointer(true),
		ActorType:   "user",
		ActorID:     userID,
		SessionID:   sessionID,
		DetailsJSON: userSecurityDetailsJSON(map[string]any{"reason": "logout_device", "current_logged_out": currentLoggedOut}),
	})

	return c.JSON(http.StatusOK, map[string]any{
		"status":             "ok",
		"current_logged_out": currentLoggedOut,
	})
}

func (s *Service) RemoveDeviceSession(c echo.Context) error {
	userID, ok := s.SessionUserID(c)
	if !ok {
		return c.JSON(http.StatusUnauthorized, map[string]any{"message": "not authenticated"})
	}

	var body deviceRemovePayload
	_ = c.Bind(&body)
	sessionID, err := normalizeDeviceSessionID(body.SessionID)
	if err != nil {
		sessionID, err = normalizeDeviceSessionID(c.FormValue("session_id"))
		if err != nil {
			return c.String(http.StatusBadRequest, err.Error())
		}
	}

	ctx := c.Request().Context()
	currentSessionID, _ := s.sessionID(c)
	removedCurrent := false
	targetDeviceID := ""

	for attempts := 0; attempts < 5; attempts++ {
		err = s.redis.Watch(ctx, func(tx *redis.Tx) error {
			listKey := deviceSessionListKey(userID)
			targetDeviceID = ""

			if _, scoreErr := tx.ZScore(ctx, listKey, sessionID).Result(); scoreErr != nil {
				if errors.Is(scoreErr, redis.Nil) {
					return errDeviceNotFound
				}
				return scoreErr
			}

			total, totalErr := tx.ZCard(ctx, listKey).Result()
			if totalErr != nil && !errors.Is(totalErr, redis.Nil) {
				return totalErr
			}
			if total <= 1 {
				return errCannotDeleteLastDevice
			}

			metaPayload, metaErr := tx.Get(ctx, deviceSessionMetaKey(sessionID)).Bytes()
			if metaErr == nil {
				var meta deviceSessionMeta
				if json.Unmarshal(metaPayload, &meta) == nil {
					metaUserID := strings.TrimSpace(meta.UserID)
					if metaUserID != "" && metaUserID != userID {
						return errDeviceSessionAccessDenied
					}
					targetDeviceID = strings.TrimSpace(meta.DeviceID)
				}
			} else if !errors.Is(metaErr, redis.Nil) {
				return metaErr
			}

			if ownerID, ownerErr := tx.Get(ctx, "sess:"+sessionID).Result(); ownerErr == nil && strings.TrimSpace(ownerID) != userID {
				return errDeviceSessionAccessDenied
			} else if ownerErr != nil && !errors.Is(ownerErr, redis.Nil) {
				return ownerErr
			}

			_, txErr := tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
				enqueueSessionCleanupArtifacts(ctx, pipe, userID, sessionID)
				return nil
			})
			if txErr != nil && !errors.Is(txErr, redis.Nil) {
				return txErr
			}

			return nil
		}, deviceSessionListKey(userID), deviceSessionMetaKey(sessionID), "sess:"+sessionID)

		if err == nil {
			removedCurrent = sessionID == currentSessionID
			break
		}
		if errors.Is(err, redis.TxFailedErr) {
			continue
		}
		if errors.Is(err, errCannotDeleteLastDevice) {
			return c.String(http.StatusConflict, "Нельзя удалить последнее устройство. Если хотите уйти полностью, удалите аккаунт.")
		}
		if errors.Is(err, errDeviceNotFound) {
			return c.String(http.StatusNotFound, "Устройство не найдено")
		}
		if errors.Is(err, errDeviceSessionAccessDenied) {
			return c.String(http.StatusForbidden, "forbidden")
		}
		return c.String(http.StatusInternalServerError, "Internal error")
	}
	if errors.Is(err, redis.TxFailedErr) {
		return c.String(http.StatusConflict, "Try again")
	}
	if mapErr := s.deleteDeviceMappingIfMatches(ctx, userID, targetDeviceID, sessionID); mapErr != nil {
		return c.String(http.StatusInternalServerError, "Internal error")
	}

	if removedCurrent {
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
	s.writeUserSecurityEventFromRequest(c, store.UserSecurityEvent{
		UserID:      userID,
		EventType:   store.UserSecurityEventSessionRevoked,
		Category:    store.UserSecurityCategorySession,
		Success:     boolPointer(true),
		ActorType:   "user",
		ActorID:     userID,
		SessionID:   sessionID,
		DetailsJSON: userSecurityDetailsJSON(map[string]any{"reason": "remove_device", "current_removed": removedCurrent}),
	})

	return c.JSON(http.StatusOK, map[string]any{
		"status":             "removed",
		"current_removed":    removedCurrent,
		"credential_revoked": false,
	})
}
