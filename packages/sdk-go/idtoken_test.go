package auth4

import (
	"context"
	"errors"
	"testing"
)

func TestValidIDToken(t *testing.T) {
	key := testKeys(t)[0]
	client := newTestClient(t, newFakeIssuer(publicJWK("k1", key)), newClock(), nil)
	token := sign(key, map[string]any{"alg": "RS256", "typ": "JWT", "kid": "k1"}, idClaims())

	verified, err := client.ValidateIDToken(context.Background(), token, testAudience, "nonce-0123456789abcdef")
	if err != nil {
		t.Fatalf("ValidateIDToken: %v", err)
	}
	if verified.Subject != "usr_player0000000001" || verified.Audience != testAudience ||
		verified.Email != "player@example.test" || verified.EmailVerified == nil || !*verified.EmailVerified ||
		verified.AuthTime.Unix() != testEpoch-10 || verified.Nonce != "nonce-0123456789abcdef" {
		t.Fatalf("unexpected claims: %+v", verified)
	}
	if _, err := client.ValidateIDToken(context.Background(), token, testAudience, ""); err != nil {
		t.Fatalf("without a nonce check: %v", err)
	}
}

func TestRejectedIDTokens(t *testing.T) {
	key := testKeys(t)[0]
	idHeader := map[string]any{"alg": "RS256", "typ": "JWT", "kid": "k1"}
	client := newTestClient(t, newFakeIssuer(publicJWK("k1", key)), newClock(), nil)
	cases := map[string]struct {
		token string
		nonce string
	}{
		"access token":                   {sign(key, accessHeader("k1"), accessClaims()), ""},
		"access typ on id claims":        {sign(key, accessHeader("k1"), idClaims()), ""},
		"wrong nonce":                    {sign(key, idHeader, idClaims()), "nonce-other-0123456789"},
		"missing nonce":                  {sign(key, idHeader, with(idClaims(), map[string]any{"nonce": nil})), "nonce-0123456789abcdef"},
		"short nonce":                    {sign(key, idHeader, with(idClaims(), map[string]any{"nonce": "short"})), ""},
		"other client":                   {sign(key, idHeader, with(idClaims(), map[string]any{"aud": "cli_webclient00000002"})), ""},
		"email_verified without email":   {sign(key, idHeader, with(idClaims(), map[string]any{"email": nil})), ""},
		"access claims in an id token":   {sign(key, idHeader, with(idClaims(), map[string]any{"scope": "openid"})), ""},
		"missing auth_time":              {sign(key, idHeader, with(idClaims(), map[string]any{"auth_time": nil})), ""},
		"lifetime over five minutes":     {sign(key, idHeader, with(idClaims(), map[string]any{"exp": testEpoch + 600})), ""},
		"invalid email":                  {sign(key, idHeader, with(idClaims(), map[string]any{"email": "not an email"})), ""},
		"non-boolean email_verified":     {sign(key, idHeader, with(idClaims(), map[string]any{"email_verified": "yes"})), ""},
		"id token for another use":       {sign(key, idHeader, with(idClaims(), map[string]any{"token_use": "access"})), ""},
		"id token with guest claim":      {sign(key, idHeader, with(idClaims(), map[string]any{"auth4_guest": true})), ""},
		"id token signed by another key": {sign(testKeys(t)[1], idHeader, idClaims()), ""},
	}
	for name, item := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := client.ValidateIDToken(context.Background(), item.token, testAudience, item.nonce)
			if !errors.Is(err, ErrInvalidToken) {
				t.Fatalf("expected invalid_token, got %v", err)
			}
		})
	}

	// And the access path refuses a valid ID token.
	if _, err := client.ValidateAccessToken(context.Background(), sign(key, idHeader, idClaims())); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("access path accepted an ID token: %v", err)
	}
	if _, err := client.ValidateIDToken(context.Background(), sign(key, idHeader, idClaims()), "not-a-client", ""); err == nil {
		t.Fatal("expected an argument error for a malformed client ID")
	}
}
