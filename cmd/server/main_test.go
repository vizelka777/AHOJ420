package main

import "testing"

func TestIsSafeReturnTo(t *testing.T) {
	tests := []struct {
		name string
		in   string
		ok   bool
	}{
		{name: "valid callback", in: "/authorize/callback?id=auth_123", ok: true},
		{name: "valid callback path", in: "/authorize/callback", ok: true},
		{name: "empty", in: "", ok: false},
		{name: "absolute url", in: "https://evil.test/pwn", ok: false},
		{name: "scheme-like", in: "javascript:alert(1)", ok: false},
		{name: "double slash", in: "//evil.test", ok: false},
		{name: "other path", in: "/profile", ok: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isSafeReturnTo(tc.in); got != tc.ok {
				t.Fatalf("isSafeReturnTo(%q) = %v, want %v", tc.in, got, tc.ok)
			}
		})
	}
}

func TestIsSafeAuthRequestID(t *testing.T) {
	tests := []struct {
		id string
		ok bool
	}{
		{id: "auth_abc-123_X", ok: true},
		{id: "auth_123", ok: true},
		{id: "", ok: false},
		{id: "auth_", ok: false},
		{id: "auth_../../etc", ok: false},
		{id: "other_123", ok: false},
	}

	for _, tc := range tests {
		if got := isSafeAuthRequestID(tc.id); got != tc.ok {
			t.Fatalf("isSafeAuthRequestID(%q) = %v, want %v", tc.id, got, tc.ok)
		}
	}
}
