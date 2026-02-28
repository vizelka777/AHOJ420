package store

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestNormalizeUserSecurityEventEntrySanitizesSensitiveDetails(t *testing.T) {
	success := true
	normalized, err := normalizeUserSecurityEventEntry(UserSecurityEvent{
		UserID:    "user-1",
		EventType: UserSecurityEventLoginFailure,
		Category:  UserSecurityCategoryAuth,
		Success:   &success,
		DetailsJSON: json.RawMessage(`{
			"reason":"assertion_failed",
			"token":"leaked-token",
			"secret":"leaked-secret",
			"authorization":"Bearer leaked",
			"challenge":"raw-challenge",
			"nested":{"password":"pw","ok":"visible"}
		}`),
	})
	if err != nil {
		t.Fatalf("normalizeUserSecurityEventEntry failed: %v", err)
	}
	encoded := string(normalized.DetailsJSON)
	for _, forbidden := range []string{"leaked-token", "leaked-secret", "Bearer leaked", "raw-challenge", `"password"`} {
		if strings.Contains(encoded, forbidden) {
			t.Fatalf("sensitive value leaked into details_json: %s", encoded)
		}
	}
	if !strings.Contains(encoded, `"reason":"assertion_failed"`) {
		t.Fatalf("expected non-sensitive detail to remain visible: %s", encoded)
	}
	if !strings.Contains(encoded, `"ok":"visible"`) {
		t.Fatalf("expected nested non-sensitive detail to remain visible: %s", encoded)
	}
}

func TestNormalizeUserSecurityFilterCategory(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{in: "", want: ""},
		{in: "all", want: ""},
		{in: "auth", want: UserSecurityCategoryAuth},
		{in: "recovery", want: UserSecurityCategoryRecovery},
		{in: "session", want: UserSecurityCategorySession},
		{in: "sessions", want: UserSecurityCategorySession},
		{in: "passkey", want: UserSecurityCategoryPasskey},
		{in: "passkeys", want: UserSecurityCategoryPasskey},
		{in: "admin", want: UserSecurityCategoryAdmin},
		{in: "unknown", want: ""},
	}

	for _, tc := range tests {
		if got := NormalizeUserSecurityFilterCategory(tc.in); got != tc.want {
			t.Fatalf("NormalizeUserSecurityFilterCategory(%q)=%q want %q", tc.in, got, tc.want)
		}
	}
}
