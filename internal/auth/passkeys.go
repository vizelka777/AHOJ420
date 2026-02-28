package auth

import (
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/houbamydar/AHOJ420/internal/store"
	"github.com/labstack/echo/v4"
)

type passkeyDTO struct {
	CredentialID string `json:"credential_id"`
	Label        string `json:"label"`
	CreatedAt    string `json:"created_at,omitempty"`
	LastUsedAt   string `json:"last_used_at,omitempty"`
}

type passkeyDeletePayload struct {
	CredentialID string `json:"credential_id"`
}

func passkeyLabel(deviceName, credentialHex string) string {
	name := strings.TrimSpace(deviceName)
	if name != "" {
		return name
	}
	short := strings.TrimSpace(credentialHex)
	if len(short) > 8 {
		short = short[:8]
	}
	if short == "" {
		return "Passkey"
	}
	return "Passkey " + short
}

func (s *Service) ListPasskeys(c echo.Context) error {
	userID, ok := s.SessionUserID(c)
	if !ok {
		return c.JSON(http.StatusUnauthorized, map[string]any{"message": "not authenticated"})
	}

	rows, err := s.store.ListCredentialRecords(userID)
	if err != nil {
		return c.String(http.StatusInternalServerError, "Internal error")
	}

	out := make([]passkeyDTO, 0, len(rows))
	for _, row := range rows {
		credentialHex := hex.EncodeToString(row.ID)
		item := passkeyDTO{
			CredentialID: credentialHex,
			Label:        passkeyLabel(row.DeviceName, credentialHex),
			CreatedAt:    row.CreatedAt.UTC().Format(time.RFC3339),
		}
		if row.LastUsedAt != nil {
			item.LastUsedAt = row.LastUsedAt.UTC().Format(time.RFC3339)
		}
		out = append(out, item)
	}

	return c.JSON(http.StatusOK, map[string]any{"passkeys": out})
}

func (s *Service) DeletePasskey(c echo.Context) error {
	userID, ok := s.SessionUserID(c)
	if !ok {
		return c.JSON(http.StatusUnauthorized, map[string]any{"message": "not authenticated"})
	}
	userID = strings.TrimSpace(userID)
	credentialHex := ""

	recordFailure := func(reason string) {
		s.writeUserSecurityEventFromRequest(c, store.UserSecurityEvent{
			UserID:       userID,
			EventType:    store.UserSecurityEventPasskeyRevoked,
			Category:     store.UserSecurityCategoryPasskey,
			Success:      boolPointer(false),
			ActorType:    "user",
			ActorID:      userID,
			CredentialID: credentialHex,
			DetailsJSON:  userSecurityDetailsJSON(map[string]any{"reason": strings.TrimSpace(reason)}),
		})
	}

	var body passkeyDeletePayload
	_ = c.Bind(&body)
	credentialHex = strings.TrimSpace(body.CredentialID)
	if credentialHex == "" {
		credentialHex = strings.TrimSpace(c.FormValue("credential_id"))
	}
	if credentialHex == "" {
		recordFailure("missing_credential_id")
		return c.String(http.StatusBadRequest, "credential_id is required")
	}
	if len(credentialHex) > 1024 {
		recordFailure("credential_id_too_long")
		return c.String(http.StatusBadRequest, "invalid credential_id")
	}

	credID, err := hex.DecodeString(credentialHex)
	if err != nil || len(credID) == 0 {
		recordFailure("credential_id_decode_failed")
		return c.String(http.StatusBadRequest, "invalid credential_id")
	}

	if err := s.store.DeleteCredentialByUserAndID(userID, credID); err != nil {
		if errors.Is(err, store.ErrCredentialNotFound) {
			recordFailure("credential_not_found")
			return c.String(http.StatusNotFound, "Passkey not found")
		}
		if errors.Is(err, store.ErrCannotDeleteLastCredential) {
			recordFailure("last_credential_blocked")
			return c.String(http.StatusConflict, "Нельзя удалить последний passkey. Используйте восстановление или удаление аккаунта.")
		}
		recordFailure("credential_delete_failed")
		return c.String(http.StatusInternalServerError, "Internal error")
	}

	currentSessionID, _ := s.sessionID(c)
	currentLoggedOut, err := s.revokeSessionsForCredential(c.Request().Context(), userID, credID, currentSessionID)
	if err != nil {
		return c.String(http.StatusInternalServerError, "Internal error")
	}

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
		UserID:       userID,
		EventType:    store.UserSecurityEventPasskeyRevoked,
		Category:     store.UserSecurityCategoryPasskey,
		Success:      boolPointer(true),
		ActorType:    "user",
		ActorID:      userID,
		CredentialID: credentialHex,
		SessionID:    currentSessionID,
		DetailsJSON:  userSecurityDetailsJSON(map[string]any{"current_logged_out": currentLoggedOut}),
	})

	return c.JSON(http.StatusOK, map[string]any{
		"status":             "deleted",
		"current_logged_out": currentLoggedOut,
	})
}
