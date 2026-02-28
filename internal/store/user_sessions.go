package store

import "time"

type UserSessionInfo struct {
	SessionID  string
	CreatedAt  time.Time
	LastSeenAt time.Time
	ExpiresAt  time.Time
	RemoteIP   string
	UserAgent  string
}
