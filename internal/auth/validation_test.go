package auth

import "testing"

func TestNormalizeProfilePayload(t *testing.T) {
	in := profilePayload{
		DisplayName: " Alice_1 ",
		Email:       "  Alice@Example.com ",
		Phone:       " +420777123456 ",
	}
	out, err := normalizeProfilePayload(in)
	if err != nil {
		t.Fatalf("normalizeProfilePayload failed: %v", err)
	}
	if out.DisplayName != "Alice_1" {
		t.Fatalf("unexpected display_name: %q", out.DisplayName)
	}
	if out.Email != "alice@example.com" {
		t.Fatalf("unexpected email: %q", out.Email)
	}
	if out.Phone != "+420777123456" {
		t.Fatalf("unexpected phone: %q", out.Phone)
	}
}

func TestNormalizeProfilePayloadRejectsInvalidPhone(t *testing.T) {
	_, err := normalizeProfilePayload(profilePayload{
		DisplayName: "Alice",
		Email:       "alice@example.com",
		Phone:       "777123456",
	})
	if err == nil {
		t.Fatal("expected validation error for non-E.164 phone")
	}
}

func TestNormalizeEmailRejectsInvalid(t *testing.T) {
	if _, err := normalizeEmail("not-an-email"); err == nil {
		t.Fatal("expected invalid email error")
	}
}
