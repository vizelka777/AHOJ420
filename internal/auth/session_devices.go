package auth

import (
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
	deviceSessionHistoryTTL = 90 * 24 * time.Hour
	deviceSessionListLimit  = 50
)

type deviceSessionMeta struct {
	SessionID    string `json:"session_id"`
	UserID       string `json:"user_id"`
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

func deviceSessionMetaKey(sessionID string) string {
	return deviceSessionMetaPrefix + sessionID
}

func deviceSessionListKey(userID string) string {
	return deviceSessionListPrefix + userID
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

func (s *Service) touchDeviceSession(c echo.Context, sessionID, userID string) error {
	sessionID = strings.TrimSpace(sessionID)
	userID = strings.TrimSpace(userID)
	if sessionID == "" || userID == "" {
		return nil
	}

	ctx := c.Request().Context()
	now := time.Now().UTC().Unix()

	meta := deviceSessionMeta{
		SessionID: sessionID,
		UserID:    userID,
	}
	if payload, err := s.redis.Get(ctx, deviceSessionMetaKey(sessionID)).Bytes(); err == nil {
		_ = json.Unmarshal(payload, &meta)
	} else if !errors.Is(err, redis.Nil) {
		return err
	}

	meta.SessionID = sessionID
	meta.UserID = userID
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

	pipe := s.redis.TxPipeline()
	pipe.Set(ctx, deviceSessionMetaKey(sessionID), payload, deviceSessionHistoryTTL)
	pipe.ZAdd(ctx, deviceSessionListKey(userID), redis.Z{
		Score:  float64(now),
		Member: sessionID,
	})
	pipe.Expire(ctx, deviceSessionListKey(userID), deviceSessionHistoryTTL)
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

	sessionIDs, err := s.redis.ZRevRange(ctx, deviceSessionListKey(userID), 0, deviceSessionListLimit-1).Result()
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
	for _, sessionID := range sessionIDs {
		rawMeta, metaErr := metaCmd[sessionID].Bytes()
		if metaErr != nil {
			continue
		}

		var meta deviceSessionMeta
		if err := json.Unmarshal(rawMeta, &meta); err != nil {
			continue
		}
		if strings.TrimSpace(meta.UserID) != userID {
			continue
		}

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
