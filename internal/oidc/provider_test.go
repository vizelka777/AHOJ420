package oidc

import (
	"context"
	"testing"

	"github.com/alicebob/miniredis/v2"
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
