package auth

import (
	"fmt"
	"regexp"
	"strings"
)

const (
	maxDisplayNameLen = 80
	maxEmailLen       = 254
	maxPhoneLen       = 32
)

var (
	emailPattern       = regexp.MustCompile(`^[^\s@]+@[^\s@]+\.[^\s@]+$`)
	phoneE164Pattern   = regexp.MustCompile(`^\+[1-9][0-9]{6,14}$`)
	displayNamePattern = regexp.MustCompile(`^[\p{L}\p{N} .,_'\-]+$`)
)

func normalizeEmail(raw string) (string, error) {
	email := strings.ToLower(strings.TrimSpace(raw))
	if email == "" {
		return "", nil
	}
	if len(email) > maxEmailLen {
		return "", fmt.Errorf("email too long")
	}
	if !emailPattern.MatchString(email) {
		return "", fmt.Errorf("invalid email format")
	}
	return email, nil
}

func normalizePhone(raw string) (string, error) {
	phone := strings.TrimSpace(raw)
	if phone == "" {
		return "", nil
	}
	if len(phone) > maxPhoneLen {
		return "", fmt.Errorf("phone too long")
	}
	if !phoneE164Pattern.MatchString(phone) {
		return "", fmt.Errorf("phone must be E.164 format, e.g. +420777123456")
	}
	return phone, nil
}

func normalizeDisplayName(raw string) (string, error) {
	name := strings.TrimSpace(raw)
	if name == "" {
		return "", nil
	}
	if len(name) > maxDisplayNameLen {
		return "", fmt.Errorf("display name too long")
	}
	if !displayNamePattern.MatchString(name) {
		return "", fmt.Errorf("display name contains unsupported characters")
	}
	return name, nil
}

func normalizeProfilePayload(payload profilePayload) (profilePayload, error) {
	name, err := normalizeDisplayName(payload.DisplayName)
	if err != nil {
		return profilePayload{}, err
	}
	email, err := normalizeEmail(payload.Email)
	if err != nil {
		return profilePayload{}, err
	}
	phone, err := normalizePhone(payload.Phone)
	if err != nil {
		return profilePayload{}, err
	}

	payload.DisplayName = name
	payload.Email = email
	payload.Phone = phone
	return payload, nil
}
