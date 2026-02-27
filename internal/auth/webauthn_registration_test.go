package auth

import (
	"errors"
	"testing"

	"github.com/houbamydar/AHOJ420/internal/store"
)

func TestSelectRegistrationUserWithSessionUsesExistingUser(t *testing.T) {
	expected := &store.User{ID: "user-1"}
	getCalls := 0
	anonCalls := 0

	got, err := selectRegistrationUser(
		"user-1",
		true,
		func(userID string) (*store.User, error) {
			getCalls++
			if userID != "user-1" {
				t.Fatalf("unexpected user id: %q", userID)
			}
			return expected, nil
		},
		func() (*store.User, error) {
			anonCalls++
			return &store.User{ID: "anon-unexpected"}, nil
		},
	)
	if err != nil {
		t.Fatalf("selectRegistrationUser returned error: %v", err)
	}
	if got != expected {
		t.Fatalf("expected pointer %p, got %p", expected, got)
	}
	if getCalls != 1 {
		t.Fatalf("expected getUser to be called once, got %d", getCalls)
	}
	if anonCalls != 0 {
		t.Fatalf("expected createAnonymous to not be called, got %d", anonCalls)
	}
}

func TestSelectRegistrationUserWithoutSessionCreatesAnonymous(t *testing.T) {
	expected := &store.User{ID: "anon-1"}
	getCalls := 0
	anonCalls := 0

	got, err := selectRegistrationUser(
		"test@example.com",
		false,
		func(string) (*store.User, error) {
			getCalls++
			return &store.User{ID: "user-unexpected"}, nil
		},
		func() (*store.User, error) {
			anonCalls++
			return expected, nil
		},
	)
	if err != nil {
		t.Fatalf("selectRegistrationUser returned error: %v", err)
	}
	if got != expected {
		t.Fatalf("expected pointer %p, got %p", expected, got)
	}
	if getCalls != 0 {
		t.Fatalf("expected getUser to not be called, got %d", getCalls)
	}
	if anonCalls != 1 {
		t.Fatalf("expected createAnonymous to be called once, got %d", anonCalls)
	}
}

func TestSelectRegistrationUserPropagatesErrors(t *testing.T) {
	t.Run("get user error", func(t *testing.T) {
		wantErr := errors.New("get user failed")
		_, err := selectRegistrationUser(
			"user-1",
			true,
			func(string) (*store.User, error) { return nil, wantErr },
			func() (*store.User, error) { return &store.User{ID: "anon"}, nil },
		)
		if !errors.Is(err, wantErr) {
			t.Fatalf("expected error %v, got %v", wantErr, err)
		}
	})

	t.Run("create anonymous error", func(t *testing.T) {
		wantErr := errors.New("create anonymous failed")
		_, err := selectRegistrationUser(
			"",
			false,
			func(string) (*store.User, error) { return &store.User{ID: "user"}, nil },
			func() (*store.User, error) { return nil, wantErr },
		)
		if !errors.Is(err, wantErr) {
			t.Fatalf("expected error %v, got %v", wantErr, err)
		}
	})
}
