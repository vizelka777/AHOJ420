package auth

import (
	"context"
	"encoding/json"
	"log"
	"strings"

	"github.com/houbamydar/AHOJ420/internal/store"
	"github.com/labstack/echo/v4"
)

func boolPointer(value bool) *bool {
	item := value
	return &item
}

func userSecurityDetailsJSON(details map[string]any) json.RawMessage {
	if len(details) == 0 {
		return json.RawMessage(`{}`)
	}
	encoded, err := json.Marshal(details)
	if err != nil {
		return json.RawMessage(`{}`)
	}
	return encoded
}

func (s *Service) writeUserSecurityEvent(ctx context.Context, entry store.UserSecurityEvent) {
	if s == nil || s.userSecurityEvents == nil {
		return
	}
	if strings.TrimSpace(entry.UserID) == "" || strings.TrimSpace(entry.EventType) == "" {
		return
	}
	if err := s.userSecurityEvents.CreateUserSecurityEvent(ctx, entry); err != nil {
		log.Printf("user security event write failed user_id=%s event_type=%s error=%v", strings.TrimSpace(entry.UserID), strings.TrimSpace(entry.EventType), err)
	}
}

func (s *Service) writeUserSecurityEventFromRequest(c echo.Context, entry store.UserSecurityEvent) {
	if c == nil {
		s.writeUserSecurityEvent(context.Background(), entry)
		return
	}
	if strings.TrimSpace(entry.RemoteIP) == "" {
		entry.RemoteIP = requestIP(c)
	}
	s.writeUserSecurityEvent(c.Request().Context(), entry)
}
