package main

import (
	"os"
	"strings"
	"testing"
)

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

func TestParseRetentionCleanupCLIOptionsDefaultsToBothTables(t *testing.T) {
	options, err := parseRetentionCleanupCLIOptions([]string{"cleanup-retention"}, func(key string) string {
		return ""
	})
	if err != nil {
		t.Fatalf("parseRetentionCleanupCLIOptions failed: %v", err)
	}
	if !options.IncludeAdminAudit || !options.IncludeUserSecurityEvents {
		t.Fatalf("default selection should include both tables: %+v", options)
	}
	if options.DryRun {
		t.Fatalf("dry-run should be false by default")
	}
}

func TestParseRetentionCleanupCLIOptionsAdminAuditOnly(t *testing.T) {
	options, err := parseRetentionCleanupCLIOptions([]string{"cleanup-retention", "--admin-audit-only"}, func(key string) string {
		return ""
	})
	if err != nil {
		t.Fatalf("parseRetentionCleanupCLIOptions failed: %v", err)
	}
	if !options.IncludeAdminAudit || options.IncludeUserSecurityEvents {
		t.Fatalf("admin-only selection mismatch: %+v", options)
	}
}

func TestParseRetentionCleanupCLIOptionsUserSecurityOnlyWithDryRunEnv(t *testing.T) {
	options, err := parseRetentionCleanupCLIOptions([]string{"cleanup-retention", "--user-security-only"}, func(key string) string {
		if key == "DRY_RUN" {
			return "1"
		}
		return ""
	})
	if err != nil {
		t.Fatalf("parseRetentionCleanupCLIOptions failed: %v", err)
	}
	if options.IncludeAdminAudit || !options.IncludeUserSecurityEvents {
		t.Fatalf("user-security-only selection mismatch: %+v", options)
	}
	if !options.DryRun {
		t.Fatalf("expected dry-run from DRY_RUN env")
	}
}

func TestParseRetentionCleanupCLIOptionsBothFlagsMeansBothTables(t *testing.T) {
	options, err := parseRetentionCleanupCLIOptions([]string{"cleanup-retention", "--admin-audit-only", "--user-security-only"}, func(key string) string {
		return ""
	})
	if err != nil {
		t.Fatalf("parseRetentionCleanupCLIOptions failed: %v", err)
	}
	if !options.IncludeAdminAudit || !options.IncludeUserSecurityEvents {
		t.Fatalf("both flags should mean both tables: %+v", options)
	}
}

func TestCleanupCommandPathNoSchemaInitReference(t *testing.T) {
	data, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	source := string(data)

	fnStart := strings.Index(source, "func runRetentionCleanupCommand(args []string) error {")
	if fnStart < 0 {
		t.Fatalf("runRetentionCleanupCommand function not found")
	}
	rest := source[fnStart:]
	nextFn := strings.Index(rest, "\nfunc ")
	fnSource := rest
	if nextFn > 0 {
		fnSource = rest[:nextFn]
	}

	if strings.Contains(fnSource, "schema.sql") {
		t.Fatalf("cleanup command should not reference schema.sql")
	}
	if strings.Contains(fnSource, "Schema init error") {
		t.Fatalf("cleanup command should not execute schema init")
	}
}
