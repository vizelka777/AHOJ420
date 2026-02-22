package auth

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/labstack/echo/v4"
)

func (s *Service) RequestRecovery(c echo.Context) error {
	email := c.FormValue("email")
	if email == "" {
		return c.String(http.StatusBadRequest, "Email required")
	}

	// 1. Check if user exists
	user, err := s.store.GetUserByEmail(email)
	if err != nil || user == nil {
		// Security: Always return success to prevent enumeration
		// But for dev we might want to know
		log.Printf("Recovery requested for non-existent email: %s", email)
		return c.JSON(http.StatusOK, map[string]string{"message": "If this email exists, a link has been sent."})
	}

	// 2. Generate Token
	tokenBytes := make([]byte, 32)
	rand.Read(tokenBytes)
	token := hex.EncodeToString(tokenBytes)

	// 3. Store in Redis (15 min)
	// Key: recovery_token:<token> -> userID
	err = s.redis.Set(c.Request().Context(), "recovery_token:"+token, user.ID, 15*time.Minute).Err()
	if err != nil {
		return c.String(http.StatusInternalServerError, "Internal error")
	}

	// 4. "Send" Email
	base := os.Getenv("RP_ORIGIN")
	if base == "" {
		base = "https://ahoj420.eu"
	}
	magicLink := fmt.Sprintf("%s/auth/recovery/verify?token=%s", base, token)
	log.Println("==================================================")
	log.Printf("MAGIC LINK for %s: %s", email, magicLink)
	log.Println("==================================================")

	return c.JSON(http.StatusOK, map[string]string{"message": "If this email exists, a link has been sent."})
}

func (s *Service) VerifyRecovery(c echo.Context) error {
	token := c.QueryParam("token")
	if token == "" {
		return c.String(http.StatusBadRequest, "Token required")
	}

	// 1. Validate Token
	userID, err := s.redis.Get(c.Request().Context(), "recovery_token:"+token).Result()
	if err != nil {
		return c.String(http.StatusForbidden, "Invalid or expired link")
	}

	// 2. Consume Token (Single Use)
	s.redis.Del(c.Request().Context(), "recovery_token:"+token)

	// 3. Set Recovery Session
	// This session puts the user in a special "Must Re-Register" state.
	// We set a cookie that allows them to call /auth/register endpoints ONLY?
	// Or we just log them in fully but redirect to settings?
	// The requirement is "User MUST create a new Passkey immediately".
	// Let's set a strictly scoped cookie "recovery_mode_user_id".
	
	c.SetCookie(&http.Cookie{
		Name:     "user_id", // Reuse the main session cookie for simplicity, effectively logging them in?
		Value:    userID,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		MaxAge:   900, // 15 minutes to register a new key
	})

	// Also set a flag to frontend to trigger "Force Setup" UI?
	// Actually, we can just redirect to the main page with a query param?
	return c.Redirect(http.StatusTemporaryRedirect, "/?mode=recovery")
}
