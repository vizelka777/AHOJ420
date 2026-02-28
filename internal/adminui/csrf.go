package adminui

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"log"
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"
)

const (
	adminCSRFCookieName = "admin_csrf"
	adminCSRFFieldName  = "csrf_token"
	adminCSRFTokenBytes = 32
	adminCSRFContextKey = "admin_ui_csrf_token"
)

func (h *Handler) CSRFMiddleware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			expectedToken, err := h.ensureCSRFToken(c)
			if err != nil {
				log.Printf("admin ui csrf token init failed error=%v", err)
				return c.String(http.StatusInternalServerError, "failed to initialize csrf token")
			}

			if requiresCSRFValidation(c.Request().Method) {
				providedToken := strings.TrimSpace(c.FormValue(adminCSRFFieldName))
				if !csrfTokensMatch(expectedToken, providedToken) {
					return c.String(http.StatusForbidden, "invalid csrf token")
				}
			}

			return next(c)
		}
	}
}

func (h *Handler) csrfToken(c echo.Context) string {
	if token, ok := c.Get(adminCSRFContextKey).(string); ok && isValidCSRFToken(token) {
		return token
	}

	token := readCSRFCookieToken(c)
	if token != "" {
		c.Set(adminCSRFContextKey, token)
	}
	return token
}

func (h *Handler) ensureCSRFToken(c echo.Context) (string, error) {
	if token := h.csrfToken(c); token != "" {
		return token, nil
	}

	token, err := newCSRFToken()
	if err != nil {
		return "", err
	}
	h.setCSRFCookie(c, token)
	c.Set(adminCSRFContextKey, token)
	return token, nil
}

func (h *Handler) setCSRFCookie(c echo.Context, token string) {
	c.SetCookie(&http.Cookie{
		Name:     adminCSRFCookieName,
		Value:    token,
		Path:     "/admin",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})
}

func (h *Handler) clearCSRFCookie(c echo.Context) {
	c.SetCookie(&http.Cookie{
		Name:     adminCSRFCookieName,
		Value:    "",
		Path:     "/admin",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})
	c.Set(adminCSRFContextKey, "")
}

func readCSRFCookieToken(c echo.Context) string {
	cookie, err := c.Cookie(adminCSRFCookieName)
	if err != nil {
		return ""
	}
	token := strings.TrimSpace(cookie.Value)
	if !isValidCSRFToken(token) {
		return ""
	}
	return token
}

func newCSRFToken() (string, error) {
	raw := make([]byte, adminCSRFTokenBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func isValidCSRFToken(token string) bool {
	token = strings.TrimSpace(token)
	if token == "" {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return false
	}
	return len(raw) == adminCSRFTokenBytes
}

func csrfTokensMatch(expected string, provided string) bool {
	if !isValidCSRFToken(expected) || !isValidCSRFToken(provided) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(expected), []byte(provided)) == 1
}

func requiresCSRFValidation(method string) bool {
	switch strings.ToUpper(strings.TrimSpace(method)) {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
		return false
	default:
		return true
	}
}
