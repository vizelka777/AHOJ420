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

func AdminAPIMiddleware(token string, allowedHost string) echo.MiddlewareFunc {
	configuredToken := strings.TrimSpace(token)
	configuredHost := normalizeHost(allowedHost)
	disabledMessage := disabledAdminMessage(configuredToken, configuredHost)

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

func disabledAdminMessage(token string, host string) string {
	missing := make([]string, 0, 2)
	if strings.TrimSpace(token) == "" {
		missing = append(missing, "ADMIN_API_TOKEN")
	}
	if strings.TrimSpace(host) == "" {
		missing = append(missing, "ADMIN_API_HOST")
	}
	if len(missing) == 0 {
		return ""
	}
	return "admin api disabled: " + strings.Join(missing, " and ") + " is not set"
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
