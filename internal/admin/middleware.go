package admin

import (
	"crypto/subtle"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"golang.org/x/time/rate"
)

const bearerPrefix = "Bearer "
const requestIDContextKey = "admin_request_id"

type AdminRateLimitConfig struct {
	Rate      rate.Limit
	Burst     int
	ExpiresIn time.Duration
}

var DefaultAdminRateLimitConfig = AdminRateLimitConfig{
	Rate:      rate.Limit(1),
	Burst:     10,
	ExpiresIn: 5 * time.Minute,
}

func AdminRequestIDMiddleware() echo.MiddlewareFunc {
	return middleware.RequestIDWithConfig(middleware.RequestIDConfig{
		RequestIDHandler: func(c echo.Context, requestID string) {
			c.Set(requestIDContextKey, requestID)
		},
	})
}

func AdminHostGuardMiddleware(allowedHost string) echo.MiddlewareFunc {
	configuredHost := normalizeHost(allowedHost)
	disabledMessage := disabledAdminHostMessage(configuredHost)

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			if disabledMessage != "" {
				return c.JSON(http.StatusServiceUnavailable, map[string]string{
					"message": disabledMessage,
				})
			}

			if normalizeHost(c.Request().Host) != configuredHost {
				return c.NoContent(http.StatusNotFound)
			}

			return next(c)
		}
	}
}

func AdminRequireActorMiddleware(token string, tokenEnabled bool) echo.MiddlewareFunc {
	configuredToken := strings.TrimSpace(token)

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			if actorType, actorID := AdminActorFromContext(c); actorType != "" && actorID != "" {
				return next(c)
			}

			if !tokenEnabled {
				return c.JSON(http.StatusUnauthorized, map[string]string{"message": "unauthorized"})
			}
			if configuredToken == "" {
				return c.JSON(http.StatusServiceUnavailable, map[string]string{
					"message": "admin api token fallback enabled but ADMIN_API_TOKEN is not set",
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
			SetAdminActor(c, "token", "admin_api_token")
			return next(c)
		}
	}
}

// AdminAPIMiddleware is kept as compatibility wrapper for legacy token-only setup.
func AdminAPIMiddleware(token string, allowedHost string) echo.MiddlewareFunc {
	hostMW := AdminHostGuardMiddleware(allowedHost)
	authMW := AdminRequireActorMiddleware(token, true)
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return hostMW(authMW(next))
	}
}

func AdminRateLimitMiddleware(config AdminRateLimitConfig) echo.MiddlewareFunc {
	if config.Rate <= 0 {
		config.Rate = DefaultAdminRateLimitConfig.Rate
	}
	if config.Burst <= 0 {
		config.Burst = DefaultAdminRateLimitConfig.Burst
	}
	if config.ExpiresIn <= 0 {
		config.ExpiresIn = DefaultAdminRateLimitConfig.ExpiresIn
	}

	store := middleware.NewRateLimiterMemoryStoreWithConfig(middleware.RateLimiterMemoryStoreConfig{
		Rate:      config.Rate,
		Burst:     config.Burst,
		ExpiresIn: config.ExpiresIn,
	})

	return middleware.RateLimiterWithConfig(middleware.RateLimiterConfig{
		Store: store,
		IdentifierExtractor: func(c echo.Context) (string, error) {
			ip := strings.TrimSpace(c.RealIP())
			if ip == "" {
				ip = "unknown"
			}
			return ip, nil
		},
		ErrorHandler: func(c echo.Context, err error) error {
			return c.JSON(http.StatusForbidden, map[string]string{"message": "forbidden"})
		},
		DenyHandler: func(c echo.Context, identifier string, err error) error {
			return c.JSON(http.StatusTooManyRequests, map[string]string{"message": "rate limit exceeded"})
		},
	})
}

func requestIDFromContext(c echo.Context) string {
	if value, ok := c.Get(requestIDContextKey).(string); ok {
		trimmed := strings.TrimSpace(value)
		if trimmed != "" {
			return trimmed
		}
	}
	if requestID := strings.TrimSpace(c.Response().Header().Get(echo.HeaderXRequestID)); requestID != "" {
		return requestID
	}
	return strings.TrimSpace(c.Request().Header.Get(echo.HeaderXRequestID))
}

func disabledAdminHostMessage(host string) string {
	if strings.TrimSpace(host) == "" {
		return "admin api disabled: ADMIN_API_HOST is not set"
	}
	return ""
}

func normalizeHost(raw string) string {
	host := strings.ToLower(strings.TrimSpace(raw))
	if host == "" {
		return ""
	}
	if strings.HasPrefix(host, "http://") {
		host = strings.TrimPrefix(host, "http://")
	}
	if strings.HasPrefix(host, "https://") {
		host = strings.TrimPrefix(host, "https://")
	}
	host = strings.TrimSuffix(host, "/")

	if parsedHost, _, err := net.SplitHostPort(host); err == nil {
		host = parsedHost
	} else if strings.Count(host, ":") == 1 && !strings.HasPrefix(host, "[") {
		if shortHost, _, ok := strings.Cut(host, ":"); ok {
			host = shortHost
		}
	}

	return strings.Trim(strings.TrimSpace(host), "[]")
}
