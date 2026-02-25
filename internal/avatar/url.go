package avatar

import (
	"fmt"
	"strings"
	"time"
)

func BuildPublicURL(base, key string, updatedAt *time.Time) string {
	base = strings.TrimSpace(base)
	key = strings.TrimSpace(key)
	if base == "" || key == "" {
		return ""
	}
	if !strings.HasSuffix(base, "/") {
		base += "/"
	}
	url := base + key
	if updatedAt != nil && !updatedAt.IsZero() {
		url = fmt.Sprintf("%s?v=%d", url, updatedAt.UTC().Unix())
	}
	return url
}
