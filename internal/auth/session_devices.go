package auth

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/redis/go-redis/v9"
)

const (
	deviceSessionMetaPrefix = "sessmeta:"
	deviceSessionListPrefix = "sesslist:"
	deviceSessionDevicePrefix = "sessdev:"
	deviceSessionHistoryTTL = 90 * 24 * time.Hour
	deviceSessionListLimit  = 50
	deviceCookieName        = "device_id"
	deviceCookieMaxAgeSec   = 365 * 24 * 60 * 60
)

var (
	errDeviceNotFound             = errors.New("device not found")
	errCannotDeleteLastDevice     = errors.New("cannot delete last device")
	errDeviceSessionAccessDenied  = errors.New("forbidden")
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

func (s *Service) revokeSessionsForCredential(ctx context.Context, userID string, credentialID []byte, currentSessionID string) (bool, error) {
	userID = strings.TrimSpace(userID)
	currentSessionID = strings.TrimSpace(currentSessionID)
	if userID == "" || len(credentialID) == 0 {
		return false, nil
	}

	listKey := deviceSessionListKey(userID)
	sessionIDs, err := s.redis.ZRange(ctx, listKey, 0, -1).Result()
	if err != nil && !errors.Is(err, redis.Nil) {
		return false, err
	}
	if len(sessionIDs) == 0 {
		return false, nil
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
	type cleanupTarget struct {
		sessionID string
		deviceID  string
	}
	targets := make([]cleanupTarget, 0, len(sessionIDs))
	for _, sessionID := range sessionIDs {
		rawMeta, metaErr := metaCmd[sessionID].Bytes()
		if metaErr != nil {
			continue
		}
		var meta deviceSessionMeta
		if json.Unmarshal(rawMeta, &meta) != nil {
			continue
		}
		if strings.TrimSpace(meta.UserID) != userID {
			continue
		}
		if !credentialIDMatches(meta.CredentialID, credentialID) {
			continue
		}
		targets = append(targets, cleanupTarget{
			sessionID: sessionID,
			deviceID:  strings.TrimSpace(meta.DeviceID),
		})
		if sessionID == currentSessionID {
			removedCurrent = true
		}
	}
	if len(targets) == 0 {
		return false, nil
	}

	cleanPipe := s.redis.TxPipeline()
	for _, t := range targets {
		cleanPipe.Del(ctx, "sess:"+t.sessionID)
		cleanPipe.Del(ctx, "recovery:"+t.sessionID)
		cleanPipe.Del(ctx, deviceSessionMetaKey(t.sessionID))
		cleanPipe.ZRem(ctx, listKey, t.sessionID)
		if t.deviceID != "" {
			cleanPipe.Del(ctx, deviceSessionDeviceKey(userID, t.deviceID))
		}
	}
	if _, err := cleanPipe.Exec(ctx); err != nil && !errors.Is(err, redis.Nil) {
		return false, err
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
	if meta.CreatedAtUTC <= 0 && prevSessionID != "" {
		if prevPayload, prevErr := s.redis.Get(ctx, deviceSessionMetaKey(prevSessionID)).Bytes(); prevErr == nil {
			var prevMeta deviceSessionMeta
			if json.Unmarshal(prevPayload, &prevMeta) == nil && prevMeta.CreatedAtUTC > 0 {
				meta.CreatedAtUTC = prevMeta.CreatedAtUTC
			}
		} else if !errors.Is(prevErr, redis.Nil) {
			return prevErr
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
	pipe := s.redis.TxPipeline()
	if prevSessionID != "" {
		pipe.Del(ctx, deviceSessionMetaKey(prevSessionID))
		pipe.ZRem(ctx, listKey, prevSessionID)
	}
	pipe.Set(ctx, deviceSessionMetaKey(sessionID), payload, deviceSessionHistoryTTL)
	pipe.ZAdd(ctx, listKey, redis.Z{
		Score:  float64(now),
		Member: sessionID,
	})
	pipe.Expire(ctx, listKey, deviceSessionHistoryTTL)
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
		cleanPipe := s.redis.Pipeline()
		for _, staleSessionID := range staleSessionIDs {
			cleanPipe.ZRem(ctx, listKey, staleSessionID)
			cleanPipe.Del(ctx, deviceSessionMetaKey(staleSessionID))
		}
		_, _ = cleanPipe.Exec(ctx)
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
	metaPayload, err := s.redis.Get(ctx, deviceSessionMetaKey(sessionID)).Bytes()
	if err == nil {
		var meta deviceSessionMeta
		if json.Unmarshal(metaPayload, &meta) == nil {
			if strings.TrimSpace(meta.UserID) != "" && strings.TrimSpace(meta.UserID) != userID {
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

	pipe := s.redis.TxPipeline()
	pipe.Del(ctx, "sess:"+sessionID)
	pipe.Del(ctx, "recovery:"+sessionID)
	if _, err := pipe.Exec(ctx); err != nil && !errors.Is(err, redis.Nil) {
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
				pipe.Del(ctx, "sess:"+sessionID)
				pipe.Del(ctx, "recovery:"+sessionID)
				pipe.Del(ctx, deviceSessionMetaKey(sessionID))
				pipe.ZRem(ctx, listKey, sessionID)
				if targetDeviceID != "" {
					pipe.Del(ctx, deviceSessionDeviceKey(userID, targetDeviceID))
				}
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

	return c.JSON(http.StatusOK, map[string]any{
		"status":             "removed",
		"current_removed":    removedCurrent,
		"credential_revoked": false,
	})
}
