package oidc

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/houbamydar/AHOJ420/internal/store"
	"github.com/redis/go-redis/v9"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

func TestCreateAuthRequestRequiresPKCE(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	storage := &MemStorage{
		redis: rdb,
		clients: map[string]*StaticClient{
			"client2": {
				id:          "client2",
				requirePKCE: true,
			},
		},
	}

	_, err := storage.CreateAuthRequest(context.Background(), &oidc.AuthRequest{
		ClientID:     "client2",
		RedirectURI:  "https://houbamzdar.cz/callback2.html",
		ResponseType: oidc.ResponseTypeCode,
		Scopes:       []string{oidc.ScopeOpenID},
	}, "client2")
	if err == nil {
		t.Fatal("expected error when PKCE is missing")
	}
}

func TestAuthRequestStoredInRedisAcrossStorageInstances(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	clients := map[string]*StaticClient{
		"client2": {
			id:          "client2",
			requirePKCE: true,
		},
	}

	st1 := &MemStorage{redis: rdb, clients: clients}
	req, err := st1.CreateAuthRequest(context.Background(), &oidc.AuthRequest{
		ClientID:            "client2",
		RedirectURI:         "https://houbamzdar.cz/callback2.html",
		ResponseType:        oidc.ResponseTypeCode,
		Scopes:              []string{oidc.ScopeOpenID},
		CodeChallenge:       "challenge",
		CodeChallengeMethod: oidc.CodeChallengeMethodS256,
	}, "client2")
	if err != nil {
		t.Fatalf("CreateAuthRequest failed: %v", err)
	}

	st2 := &MemStorage{redis: rdb, clients: clients}
	read, err := st2.AuthRequestByID(context.Background(), req.GetID())
	if err != nil {
		t.Fatalf("AuthRequestByID failed after new storage instance: %v", err)
	}

	if read.GetID() != req.GetID() {
		t.Fatalf("unexpected id: got %s want %s", read.GetID(), req.GetID())
	}
}

func TestAuthCodeSingleUse(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	clients := map[string]*StaticClient{
		"client2": {
			id:          "client2",
			requirePKCE: true,
		},
	}

	st := &MemStorage{redis: rdb, clients: clients}
	req, err := st.CreateAuthRequest(context.Background(), &oidc.AuthRequest{
		ClientID:            "client2",
		RedirectURI:         "https://houbamzdar.cz/callback2.html",
		ResponseType:        oidc.ResponseTypeCode,
		Scopes:              []string{oidc.ScopeOpenID},
		CodeChallenge:       "challenge",
		CodeChallengeMethod: oidc.CodeChallengeMethodS256,
	}, "client2")
	if err != nil {
		t.Fatalf("CreateAuthRequest failed: %v", err)
	}

	if err := st.SaveAuthCode(context.Background(), req.GetID(), "code123"); err != nil {
		t.Fatalf("SaveAuthCode failed: %v", err)
	}

	first, err := st.AuthRequestByCode(context.Background(), "code123")
	if err != nil {
		t.Fatalf("first AuthRequestByCode should succeed: %v", err)
	}
	if first.GetID() != req.GetID() {
		t.Fatalf("unexpected auth request id: got %s want %s", first.GetID(), req.GetID())
	}

	if _, err := st.AuthRequestByCode(context.Background(), "code123"); err == nil {
		t.Fatal("second AuthRequestByCode should fail for single-use code")
	}
}

func TestUserinfoClaimsByScopes(t *testing.T) {
	st := &MemStorage{
		avatarBase: "https://avatar.ahoj420.eu/",
		userStore: &UserStore{
			get: func(userID string) (*store.User, error) {
				now := time.Unix(1700000000, 0).UTC()
				return &store.User{
					ID:              userID,
					LoginID:         "anon-alice",
					ProfileEmail:    "alice@example.com",
					DisplayName:     "alice",
					Phone:           "+420777123456",
					EmailVerified:   true,
					PhoneVerified:   false,
					AvatarKey:       "avatars/u-1.webp",
					AvatarUpdatedAt: &now,
				}, nil
			},
		},
	}

	userinfo := &oidc.UserInfo{}
	scopes := []string{oidc.ScopeOpenID, oidc.ScopeProfile, oidc.ScopeEmail, oidc.ScopePhone}
	if err := st.SetUserinfoFromScopes(context.Background(), userinfo, "u-1", "client2", scopes); err != nil {
		t.Fatalf("SetUserinfoFromScopes failed: %v", err)
	}

	if userinfo.Subject != "u-1" {
		t.Fatalf("unexpected sub: %s", userinfo.Subject)
	}
	if userinfo.Name != "alice" || userinfo.PreferredUsername != "alice" {
		t.Fatalf("unexpected profile claims: name=%q preferred=%q", userinfo.Name, userinfo.PreferredUsername)
	}
	if userinfo.Email != "alice@example.com" || !bool(userinfo.EmailVerified) {
		t.Fatalf("unexpected email claims: %+v", userinfo)
	}
	if userinfo.PhoneNumber != "+420777123456" || bool(userinfo.PhoneNumberVerified) {
		t.Fatalf("unexpected phone claims: %+v", userinfo)
	}
	if userinfo.Picture == "" {
		t.Fatalf("missing picture in userinfo: %+v", userinfo)
	}

	privateClaims, err := st.GetPrivateClaimsFromScopes(context.Background(), "u-1", "client2", scopes)
	if err != nil {
		t.Fatalf("GetPrivateClaimsFromScopes failed: %v", err)
	}
	if privateClaims["preferred_username"] != "alice" {
		t.Fatalf("missing preferred_username claim")
	}
	if privateClaims["email"] != "alice@example.com" {
		t.Fatalf("missing email claim")
	}
	if privateClaims["phone_number"] != "+420777123456" {
		t.Fatalf("missing phone_number claim")
	}
	if privateClaims["picture"] == "" {
		t.Fatalf("missing picture claim")
	}
}

func TestPictureClaimAbsentWhenAvatarMissing(t *testing.T) {
	st := &MemStorage{
		avatarBase: "https://avatar.ahoj420.eu/",
		userStore: &UserStore{
			get: func(userID string) (*store.User, error) {
				return &store.User{
					ID:          userID,
					LoginID:     "bob@example.com",
					DisplayName: "bob",
				}, nil
			},
		},
	}

	userinfo := &oidc.UserInfo{}
	if err := st.SetUserinfoFromScopes(context.Background(), userinfo, "u-2", "client2", []string{oidc.ScopeProfile}); err != nil {
		t.Fatalf("SetUserinfoFromScopes failed: %v", err)
	}
	if userinfo.Picture != "" {
		t.Fatalf("picture must be absent, got %q", userinfo.Picture)
	}

	privateClaims, err := st.GetPrivateClaimsFromScopes(context.Background(), "u-2", "client2", []string{oidc.ScopeProfile})
	if err != nil {
		t.Fatalf("GetPrivateClaimsFromScopes failed: %v", err)
	}
	if _, ok := privateClaims["picture"]; ok {
		t.Fatalf("picture claim must be absent: %+v", privateClaims)
	}
}
