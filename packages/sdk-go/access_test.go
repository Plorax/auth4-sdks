package auth4

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestValidAccessTokenExposesClaims(t *testing.T) {
	key := testKeys(t)[0]
	client := newTestClient(t, newFakeIssuer(publicJWK("k1", key)), newClock(), nil)
	token := sign(key, accessHeader("k1"), with(accessClaims(), map[string]any{
		"auth4_guest": true,
		"auth4_roles": []string{"moderator", "tester"},
		"auth4_meta":  map[string]any{"level": 7, "region": "eu", "beta": false, "note": nil},
	}))

	verified, err := client.ValidateAccessToken(context.Background(), token)
	if err != nil {
		t.Fatalf("ValidateAccessToken: %v", err)
	}
	if verified.Subject != "usr_player0000000001" || verified.TenantID != testTenant ||
		verified.Issuer != testIssuer || verified.Audience != testAudience ||
		verified.ClientID != testAudience || verified.SessionID != "ses_session000000001" ||
		verified.TokenID != "jti_token0000000000001" {
		t.Fatalf("unexpected claims: %+v", verified)
	}
	if !verified.ExpiresAt.Equal(time.Unix(testEpoch+300, 0)) || !verified.IssuedAt.Equal(time.Unix(testEpoch, 0)) ||
		!verified.NotBefore.IsZero() {
		t.Fatalf("unexpected times: %+v", verified)
	}
	if !verified.HasScope("profile") || verified.HasScope("email") || len(verified.Scopes) != 2 {
		t.Fatalf("unexpected scopes: %v", verified.Scopes)
	}
	if !verified.IsGuest {
		t.Fatal("expected a guest")
	}
	if !verified.HasRole("moderator") || verified.HasRole("Moderator") || !verified.HasAnyRole("admin", "tester") ||
		verified.HasAnyRole() || verified.HasAnyRole("admin") {
		t.Fatalf("unexpected roles: %v", verified.Roles)
	}
	if verified.Metadata["level"] != float64(7) || verified.Metadata["region"] != "eu" ||
		verified.Metadata["beta"] != false || verified.Metadata["note"] != nil || len(verified.Metadata) != 4 {
		t.Fatalf("unexpected metadata: %v", verified.Metadata)
	}
}

func TestAbsentCustomClaimsMeanNoneAndNotGuest(t *testing.T) {
	key := testKeys(t)[0]
	client := newTestClient(t, newFakeIssuer(publicJWK("k1", key)), newClock(), nil)
	verified, err := client.ValidateAccessToken(context.Background(),
		sign(key, accessHeader("k1"), with(accessClaims(), map[string]any{"sid": nil})))
	if err != nil {
		t.Fatalf("ValidateAccessToken: %v", err)
	}
	if verified.IsGuest || verified.Roles == nil || len(verified.Roles) != 0 ||
		verified.Metadata == nil || len(verified.Metadata) != 0 || verified.SessionID != "" {
		t.Fatalf("unexpected defaults: %+v", verified)
	}
}

// AUTH4D-324: projects can opt in to the player's Name#1234 in access tokens.
func TestPlayerNameClaim(t *testing.T) {
	key := testKeys(t)[0]
	for name, value := range map[string]any{"tag": "Ace#0427", "no discriminator": "Ace", "number": 7} {
		t.Run(name, func(t *testing.T) {
			client := newTestClient(t, newFakeIssuer(publicJWK("k1", key)), newClock(), nil)
			_, err := client.ValidateAccessToken(context.Background(),
				sign(key, accessHeader("k1"), with(accessClaims(), map[string]any{"name": value})))
			if name == "tag" && err != nil {
				t.Fatalf("ValidateAccessToken: %v", err)
			}
			if name != "tag" {
				expectCode(t, err, CodeInvalidToken)
			}
		})
	}
}

func TestRejectedAccessTokens(t *testing.T) {
	keys := testKeys(t)
	base := accessClaims()
	cases := map[string]string{
		"expired": sign(keys[0], accessHeader("k1"), with(base, map[string]any{"exp": testEpoch, "iat": testEpoch - 300})),
		"not yet valid": sign(keys[0], accessHeader("k1"),
			with(base, map[string]any{"nbf": testEpoch + 60})),
		"other audience":      sign(keys[0], accessHeader("k1"), with(base, map[string]any{"aud": "cli_webclient00000002"})),
		"audience array":      sign(keys[0], accessHeader("k1"), with(base, map[string]any{"aud": []string{testAudience}})),
		"management audience": sign(keys[0], accessHeader("k1"), with(base, map[string]any{"aud": managementAudience})),
		"other tenant": sign(keys[0], accessHeader("k1"), with(base, map[string]any{
			"tenant_id": "ten_qrstuvwxyzabcdef", "iss": "https://auth.example.test/t/ten_qrstuvwxyzabcdef",
		})),
		"other issuer":            sign(keys[0], accessHeader("k1"), with(base, map[string]any{"iss": "https://evil.example.test/t/" + testTenant})),
		"tenant claim mismatch":   sign(keys[0], accessHeader("k1"), with(base, map[string]any{"tenant_id": "ten_qrstuvwxyzabcdef"})),
		"id token use":            sign(keys[0], accessHeader("k1"), with(base, map[string]any{"token_use": "id"})),
		"unknown claim":           sign(keys[0], accessHeader("k1"), with(base, map[string]any{"role": "admin"})),
		"missing scope":           sign(keys[0], accessHeader("k1"), with(base, map[string]any{"scope": nil})),
		"duplicate scope":         sign(keys[0], accessHeader("k1"), with(base, map[string]any{"scope": "openid openid"})),
		"bad subject":             sign(keys[0], accessHeader("k1"), with(base, map[string]any{"sub": "player"})),
		"bad session":             sign(keys[0], accessHeader("k1"), with(base, map[string]any{"sid": "session"})),
		"lifetime over 5 minutes": sign(keys[0], accessHeader("k1"), with(base, map[string]any{"exp": testEpoch + 301})),
		"exp before iat":          sign(keys[0], accessHeader("k1"), with(base, map[string]any{"iat": testEpoch + 300})),
		"fractional exp":          sign(keys[0], accessHeader("k1"), with(base, map[string]any{"exp": float64(testEpoch) + 299.5})),
		"string exp":              sign(keys[0], accessHeader("k1"), with(base, map[string]any{"exp": "1800000300"})),
		"non-boolean guest":       sign(keys[0], accessHeader("k1"), with(base, map[string]any{"auth4_guest": "true"})),
		"duplicate roles":         sign(keys[0], accessHeader("k1"), with(base, map[string]any{"auth4_roles": []string{"a", "a"}})),
		"empty roles":             sign(keys[0], accessHeader("k1"), with(base, map[string]any{"auth4_roles": []string{}})),
		"uppercase role":          sign(keys[0], accessHeader("k1"), with(base, map[string]any{"auth4_roles": []string{"Admin"}})),
		"too many roles": sign(keys[0], accessHeader("k1"), with(base, map[string]any{"auth4_roles": func() []string {
			roles := make([]string, 21)
			for i := range roles {
				roles[i] = "role" + string(rune('a'+i))
			}
			return roles
		}()})),
		"nested metadata":       sign(keys[0], accessHeader("k1"), with(base, map[string]any{"auth4_meta": map[string]any{"x": map[string]any{"y": 1}}})),
		"metadata array":        sign(keys[0], accessHeader("k1"), with(base, map[string]any{"auth4_meta": map[string]any{"x": []int{1}}})),
		"empty metadata":        sign(keys[0], accessHeader("k1"), with(base, map[string]any{"auth4_meta": map[string]any{}})),
		"reserved metadata key": sign(keys[0], accessHeader("k1"), with(base, map[string]any{"auth4_meta": map[string]any{"email": "x"}})),
		"long metadata string":  sign(keys[0], accessHeader("k1"), with(base, map[string]any{"auth4_meta": map[string]any{"x": strings.Repeat("a", 257)}})),
		"metadata over 2048 bytes": sign(keys[0], accessHeader("k1"), with(base, map[string]any{"auth4_meta": func() map[string]any {
			metadata := map[string]any{}
			for i := 0; i < 9; i++ {
				metadata["k"+string(rune('a'+i))] = strings.Repeat("v", 250)
			}
			return metadata
		}()})),
		"signed by another key": sign(keys[1], accessHeader("k1"), base),
		"typ JWT":               sign(keys[0], map[string]any{"alg": "RS256", "typ": "JWT", "kid": "k1"}, base),
		"no typ":                sign(keys[0], map[string]any{"alg": "RS256", "kid": "k1"}, base),
		"alg PS256":             sign(keys[0], map[string]any{"alg": "PS256", "typ": "at+jwt", "kid": "k1"}, base),
		"jku header":            sign(keys[0], map[string]any{"alg": "RS256", "typ": "at+jwt", "kid": "k1", "jku": "https://evil.example.test/jwks"}, base),
		"crit header":           sign(keys[0], map[string]any{"alg": "RS256", "typ": "at+jwt", "kid": "k1", "crit": []string{"exp"}}, base),
		"duplicate claim": signRaw(keys[0], mustJSON(accessHeader("k1")),
			strings.Replace(mustJSON(base), `"sub":"usr_player0000000001"`, `"sub":"usr_player0000000001","sub":"usr_player0000000002"`, 1)),
		"duplicate header": signRaw(keys[0], `{"alg":"RS256","typ":"at+jwt","kid":"k1","kid":"k2"}`, mustJSON(base)),
		"alg none": func() string {
			parts := strings.Split(sign(keys[0], map[string]any{"alg": "none", "typ": "at+jwt", "kid": "k1"}, base), ".")
			return parts[0] + "." + parts[1] + "."
		}(),
		"tampered payload": func() string {
			parts := strings.Split(sign(keys[0], accessHeader("k1"), base), ".")
			return parts[0] + "." + b64([]byte(mustJSON(with(base, map[string]any{"sub": "usr_player0000000002"})))) + "." + parts[2]
		}(),
		"padded base64":  sign(keys[0], accessHeader("k1"), base) + "=",
		"two segments":   "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0",
		"empty":          "",
		"too long":       strings.Repeat("a", maxTokenLength+1),
		"not base64":     "%%%.%%%.%%%",
		"payload array":  signRaw(keys[0], mustJSON(accessHeader("k1")), "[1]"),
		"trailing bytes": signRaw(keys[0], mustJSON(accessHeader("k1")), mustJSON(base)+"{}"),
	}
	for name, token := range cases {
		t.Run(name, func(t *testing.T) {
			client := newTestClient(t, newFakeIssuer(publicJWK("k1", keys[0])), newClock(), nil)
			_, err := client.ValidateAccessToken(context.Background(), token)
			expectCode(t, err, CodeInvalidToken)
			if !errors.Is(err, ErrInvalidToken) || IsOutage(err) {
				t.Fatalf("expected a non-outage invalid_token, got %v", err)
			}
		})
	}
}

func TestClockTolerance(t *testing.T) {
	key := testKeys(t)[0]
	expired := sign(key, accessHeader("k1"), with(accessClaims(), map[string]any{"exp": testEpoch, "iat": testEpoch - 300}))
	early := sign(key, accessHeader("k1"), with(accessClaims(), map[string]any{"nbf": testEpoch + 30}))
	strict := newTestClient(t, newFakeIssuer(publicJWK("k1", key)), newClock(), nil)
	lenient := newTestClient(t, newFakeIssuer(publicJWK("k1", key)), newClock(), func(o *Options) { o.ClockTolerance = 60 * time.Second })
	for _, token := range []string{expired, early} {
		if _, err := strict.ValidateAccessToken(context.Background(), token); err == nil {
			t.Fatal("strict client accepted a token outside its time window")
		}
		if _, err := lenient.ValidateAccessToken(context.Background(), token); err != nil {
			t.Fatalf("lenient client: %v", err)
		}
	}
}

func TestAuthorizationHeader(t *testing.T) {
	key := testKeys(t)[0]
	client := newTestClient(t, newFakeIssuer(publicJWK("k1", key)), newClock(), nil)
	token := sign(key, accessHeader("k1"), accessClaims())
	for _, header := range []string{"Bearer " + token, "bearer " + token, "BEARER " + token} {
		if _, err := client.ValidateAuthorizationHeader(context.Background(), header); err != nil {
			t.Fatalf("%q: %v", header[:8], err)
		}
	}
	for _, header := range []string{"", "Bearer", "Bearer  " + token, "Basic " + token, "Bearer " + token + " x", "Bearer a,b", token, "Bearer " + token + "\n"} {
		if _, err := client.ValidateAuthorizationHeader(context.Background(), header); !errors.Is(err, ErrInvalidToken) {
			t.Fatalf("header %q: expected invalid_token, got %v", header, err)
		}
	}
	if value, ok := ParseBearerToken("Bearer abc.def.ghi"); !ok || value != "abc.def.ghi" {
		t.Fatalf("ParseBearerToken: %q %t", value, ok)
	}
}
