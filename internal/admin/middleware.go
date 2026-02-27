package admin

import (
	"crypto/subtle"
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"
)

const bearerPrefix = "Bearer "

func AdminAPIMiddleware(token string) echo.MiddlewareFunc {
	configuredToken := strings.TrimSpace(token)

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			if configuredToken == "" {
				return c.JSON(http.StatusServiceUnavailable, map[string]string{
					"message": "admin api disabled: ADMIN_API_TOKEN is not set",
				})
			}

			authHeader := strings.TrimSpace(c.Request().Header.Get(echo.HeaderAuthorization))
			if !strings.HasPrefix(authHeader, bearerPrefix) {
				return c.JSON(http.StatusUnauthorized, map[string]string{"message": "unauthorized"})
			}

			provided := strings.TrimSpace(strings.TrimPrefix(authHeader, bearerPrefix))
			if provided == "" {
				return c.JSON(http.StatusUnauthorized, map[string]string{"message": "unauthorized"})
			}

			if subtle.ConstantTimeCompare([]byte(provided), []byte(configuredToken)) != 1 {
				return c.JSON(http.StatusUnauthorized, map[string]string{"message": "unauthorized"})
			}

			return next(c)
		}
	}
}
