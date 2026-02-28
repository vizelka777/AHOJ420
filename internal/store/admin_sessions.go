package store

import "time"

type AdminSessionInfo struct {
	SessionID  string
	CreatedAt  time.Time
	LastSeenAt time.Time
	ExpiresAt  time.Time
	RemoteIP   string
	UserAgent  string
	Current    bool
}
