package admin

import (
	"strings"

	"github.com/labstack/echo/v4"
)

const (
	adminActorTypeContextKey = "admin_actor_type"
	adminActorIDContextKey   = "admin_actor_id"
	adminActorRoleContextKey = "admin_actor_role"
)

func SetAdminActor(c echo.Context, actorType string, actorID string) {
	c.Set(adminActorTypeContextKey, strings.TrimSpace(actorType))
	c.Set(adminActorIDContextKey, strings.TrimSpace(actorID))
}

func SetAdminActorRole(c echo.Context, role string) {
	c.Set(adminActorRoleContextKey, strings.TrimSpace(strings.ToLower(role)))
}

func AdminActorFromContext(c echo.Context) (actorType string, actorID string) {
	if rawType, ok := c.Get(adminActorTypeContextKey).(string); ok {
		actorType = strings.TrimSpace(rawType)
	}
	if rawID, ok := c.Get(adminActorIDContextKey).(string); ok {
		actorID = strings.TrimSpace(rawID)
	}
	return actorType, actorID
}

func AdminActorRoleFromContext(c echo.Context) string {
	if rawRole, ok := c.Get(adminActorRoleContextKey).(string); ok {
		return strings.TrimSpace(strings.ToLower(rawRole))
	}
	return ""
}
