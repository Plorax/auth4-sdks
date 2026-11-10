package auth4

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

func activeAnswer() string {
	return mustJSON(map[string]any{
		"active": true, "sub": "usr_player0000000001", "client_id": testAudience,
		"jti": "jti_token0000000000001", "tenant_id": testTenant, "token_type": "Bearer",
	})
}

func introspectingClient(t *testing.T, issuer *fakeIssuer, clock *testClock, change func(*IntrospectionOptions)) *Client {
	t.Helper()
	return newTestClient(t, issuer, clock, func(o *Options) {
		o.Introspection = &IntrospectionOptions{ClientID: testServer, ClientSecret: testSecret}
		if change != nil {
			change(o.Introspection)
		}
	})
}

func TestIntrospectionRequestAndCache(t *testing.T) {
	key := testKeys(t)[0]
	issuer := newFakeIssuer(publicJWK("k1", key))
	token := sign(key, accessHeader("k1"), accessClaims())
	issuer.introspect = func(r *http.Request, form string) (int, string) {
		if r.Method != http.MethodPost || r.URL.String() != "https://auth.example.test/oauth/introspect?tenant_id="+testTenant {
			t.Errorf("unexpected request %s %s", r.Method, r.URL)
		}
		user, password, ok := r.BasicAuth()
		if !ok || user != testServer || password != testSecret {
			t.Errorf("unexpected credentials")
		}
		if r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
			t.Errorf("unexpected content type %q", r.Header.Get("Content-Type"))
		}
		values, _ := url.ParseQuery(form)
		if values.Get("token") != token || len(values) != 1 {
			t.Errorf("unexpected form")
		}
		return http.StatusOK, activeAnswer()
	}
	clock := newClock()
	client := introspectingClient(t, issuer, clock, nil)
	if client.IntrospectionURL() != "https://auth.example.test/oauth/introspect?tenant_id="+testTenant {
		t.Fatalf("IntrospectionURL: %s", client.IntrospectionURL())
	}

	for i := 0; i < 3; i++ {
		if _, err := client.ValidateAccessToken(context.Background(), token); err != nil {
			t.Fatalf("active token: %v", err)
		}
	}
	if calls := issuer.introCalls.Load(); calls != 1 {
		t.Fatalf("expected the active answer to be reused, got %d calls", calls)
	}
	clock.Advance(5 * time.Second)
	if _, err := client.ValidateAccessToken(context.Background(), token); err != nil {
		t.Fatalf("after the cache TTL: %v", err)
	}
	if calls := issuer.introCalls.Load(); calls != 2 {
		t.Fatalf("expected a new check after 5 s, got %d calls", calls)
	}
}

func TestIntrospectionInactiveIsRememberedUntilExpiry(t *testing.T) {
	key := testKeys(t)[0]
	issuer := newFakeIssuer(publicJWK("k1", key))
	issuer.introspect = func(*http.Request, string) (int, string) { return http.StatusOK, `{"active":false}` }
	clock := newClock()
	client := introspectingClient(t, issuer, clock, nil)
	token := sign(key, accessHeader("k1"), accessClaims())
	for i := 0; i < 2; i++ {
		_, err := client.ValidateAccessToken(context.Background(), token)
		expectCode(t, err, CodeInvalidToken)
		clock.Advance(time.Minute)
	}
	if calls := issuer.introCalls.Load(); calls != 1 {
		t.Fatalf("expected the inactive answer to be remembered, got %d calls", calls)
	}
}

func TestIntrospectionFailsClosed(t *testing.T) {
	key := testKeys(t)[0]
	cases := map[string]struct {
		status int
		body   string
		code   ErrorCode
	}{
		"unavailable":          {http.StatusServiceUnavailable, `{"error":"temporarily_unavailable"}`, CodeIntrospectionUnavailable},
		"rate limited":         {http.StatusTooManyRequests, `{"error":"slow_down"}`, CodeIntrospectionUnavailable},
		"not json":             {http.StatusOK, `active`, CodeIntrospectionUnavailable},
		"no active member":     {http.StatusOK, `{"sub":"usr_player0000000001"}`, CodeIntrospectionUnavailable},
		"string active":        {http.StatusOK, `{"active":"true"}`, CodeIntrospectionUnavailable},
		"other subject":        {http.StatusOK, strings.Replace(activeAnswer(), "usr_player0000000001", "usr_player0000000002", 1), CodeInvalidToken},
		"other token":          {http.StatusOK, strings.Replace(activeAnswer(), "jti_token0000000000001", "jti_token0000000000009", 1), CodeInvalidToken},
		"other tenant":         {http.StatusOK, strings.Replace(activeAnswer(), testTenant, "ten_qrstuvwxyzabcdef", 1), CodeInvalidToken},
		"non-string client_id": {http.StatusOK, strings.Replace(activeAnswer(), `"client_id":"`+testAudience+`"`, `"client_id":1`, 1), CodeInvalidToken},
	}
	for name, item := range cases {
		t.Run(name, func(t *testing.T) {
			issuer := newFakeIssuer(publicJWK("k1", key))
			issuer.introspect = func(*http.Request, string) (int, string) { return item.status, item.body }
			client := introspectingClient(t, issuer, newClock(), nil)
			_, err := client.ValidateAccessToken(context.Background(), sign(key, accessHeader("k1"), accessClaims()))
			expectCode(t, err, item.code)
		})
	}
}

func TestIntrospectionOnlyAfterLocalVerification(t *testing.T) {
	keys := testKeys(t)
	issuer := newFakeIssuer(publicJWK("k1", keys[0]))
	issuer.introspect = func(*http.Request, string) (int, string) { return http.StatusOK, activeAnswer() }
	client := introspectingClient(t, issuer, newClock(), nil)
	_, err := client.ValidateAccessToken(context.Background(), sign(keys[1], accessHeader("k1"), accessClaims()))
	expectCode(t, err, CodeInvalidToken)
	if calls := issuer.introCalls.Load(); calls != 0 {
		t.Fatalf("a forged token reached the introspection endpoint (%d calls)", calls)
	}
}

func TestIntrospectionDisableCache(t *testing.T) {
	key := testKeys(t)[0]
	issuer := newFakeIssuer(publicJWK("k1", key))
	issuer.introspect = func(*http.Request, string) (int, string) { return http.StatusOK, activeAnswer() }
	client := introspectingClient(t, issuer, newClock(), func(o *IntrospectionOptions) { o.DisableCache = true })
	token := sign(key, accessHeader("k1"), accessClaims())
	for i := 0; i < 3; i++ {
		if _, err := client.ValidateAccessToken(context.Background(), token); err != nil {
			t.Fatalf("ValidateAccessToken: %v", err)
		}
	}
	if calls := issuer.introCalls.Load(); calls != 3 || client.introspector.cacheLen() != 0 {
		t.Fatalf("expected every request checked, got %d calls", calls)
	}
}

func TestIntrospectionSecretStaysPrivate(t *testing.T) {
	issuer := newFakeIssuer()
	options := IntrospectionOptions{ClientID: testServer, ClientSecret: testSecret}
	client := introspectingClient(t, issuer, newClock(), nil)
	encoded := base64.StdEncoding.EncodeToString([]byte(testServer + ":" + testSecret))
	jsonOptions, _ := json.Marshal(options)
	jsonPointer, _ := json.Marshal(&options)
	for _, text := range []string{
		fmt.Sprint(options), fmt.Sprintf("%+v", options), fmt.Sprintf("%#v", options), fmt.Sprintf("%v", &options),
		fmt.Sprint(client), fmt.Sprintf("%+v", client), fmt.Sprintf("%#v", client),
		string(jsonOptions), string(jsonPointer),
	} {
		if strings.Contains(text, testSecret) || strings.Contains(text, encoded) {
			t.Fatalf("secret leaked in %q", text)
		}
	}
	if !strings.Contains(fmt.Sprint(options), testServer) {
		t.Fatal("expected the client ID in the string form")
	}
}

func TestIntrospectionOptionsAreChecked(t *testing.T) {
	for name, options := range map[string]IntrospectionOptions{
		"bad client ID":  {ClientID: "server", ClientSecret: testSecret},
		"short secret":   {ClientID: testServer, ClientSecret: "short"},
		"long cache":     {ClientID: testServer, ClientSecret: testSecret, CacheTTL: 61 * time.Second},
		"negative cache": {ClientID: testServer, ClientSecret: testSecret, CacheTTL: -time.Second},
		"long timeout":   {ClientID: testServer, ClientSecret: testSecret, Timeout: 11 * time.Second},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := New(Options{TenantID: testTenant, Issuer: testIssuer, Audience: testAudience, Introspection: &options})
			if err == nil {
				t.Fatal("expected an error")
			}
			if strings.Contains(err.Error(), testSecret) {
				t.Fatal("the error includes the secret")
			}
		})
	}
}
