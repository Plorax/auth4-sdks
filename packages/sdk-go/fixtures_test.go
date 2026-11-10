package auth4

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Local fixtures only: keys are generated in memory and every request is answered by fakeIssuer,
// so no test reaches a live endpoint.

const (
	testTenant   = "ten_abcdefghijklmnop"
	testIssuer   = "https://auth.example.test/t/ten_abcdefghijklmnop"
	testAudience = "cli_gameclient000001"
	testServer   = "cli_serverclient00001"
	testSecret   = "server-secret-0123456789abcdefghijklmnop"
	testJWKSURL  = testIssuer + "/.well-known/jwks.json"
	testEpoch    = int64(1_800_000_000)
)

var (
	keyOnce sync.Once
	keys    [2]*rsa.PrivateKey
)

func testKeys(t *testing.T) [2]*rsa.PrivateKey {
	t.Helper()
	keyOnce.Do(func() {
		for i := range keys {
			key, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				panic(err)
			}
			keys[i] = key
		}
	})
	return keys
}

func b64(data []byte) string { return base64.RawURLEncoding.EncodeToString(data) }

func publicJWK(kid string, key *rsa.PrivateKey) map[string]any {
	return map[string]any{
		"kty": "RSA", "kid": kid, "use": "sig", "alg": "RS256",
		"n": b64(key.N.Bytes()), "e": b64(big.NewInt(int64(key.E)).Bytes()),
	}
}

// sign builds a compact JWS from raw JSON header and payload text, so tests can send duplicate
// members and other shapes a map can't express.
func signRaw(key *rsa.PrivateKey, header, payload string) string {
	input := b64([]byte(header)) + "." + b64([]byte(payload))
	digest := sha256.Sum256([]byte(input))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		panic(err)
	}
	return input + "." + b64(signature)
}

func mustJSON(value any) string {
	data, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return string(data)
}

func accessHeader(kid string) map[string]any {
	return map[string]any{"alg": "RS256", "typ": "at+jwt", "kid": kid}
}

func accessClaims() map[string]any {
	return map[string]any{
		"iss": testIssuer, "sub": "usr_player0000000001", "aud": testAudience,
		"exp": testEpoch + 300, "iat": testEpoch, "jti": "jti_token0000000000001",
		"tenant_id": testTenant, "token_use": "access", "client_id": testAudience,
		"scope": "openid profile", "sid": "ses_session000000001",
	}
}

func idClaims() map[string]any {
	return map[string]any{
		"iss": testIssuer, "sub": "usr_player0000000001", "aud": testAudience,
		"exp": testEpoch + 300, "iat": testEpoch, "jti": "jti_token0000000000002",
		"tenant_id": testTenant, "token_use": "id", "auth_time": testEpoch - 10,
		"nonce": "nonce-0123456789abcdef", "email": "player@example.test", "email_verified": true,
	}
}

func sign(key *rsa.PrivateKey, header, claims map[string]any) string {
	return signRaw(key, mustJSON(header), mustJSON(claims))
}

func with(claims map[string]any, changes map[string]any) map[string]any {
	copied := make(map[string]any, len(claims))
	for name, value := range claims {
		copied[name] = value
	}
	for name, value := range changes {
		if value == nil {
			delete(copied, name)
		} else {
			copied[name] = value
		}
	}
	return copied
}

// fakeIssuer is an http.RoundTripper standing in for the auth origin.
type fakeIssuer struct {
	mu            sync.Mutex
	jwks          map[string]any
	jwksStatus    int
	jwksDelay     time.Duration
	discovery     map[string]any
	introspect    func(r *http.Request, form string) (int, string)
	jwksCalls     atomic.Int32
	introCalls    atomic.Int32
	discoverCalls atomic.Int32
	urls          []string
}

func newFakeIssuer(jwks ...map[string]any) *fakeIssuer {
	keys := make([]any, len(jwks))
	for i, key := range jwks {
		keys[i] = key
	}
	return &fakeIssuer{jwks: map[string]any{"keys": keys}, jwksStatus: http.StatusOK}
}

func (f *fakeIssuer) setKeys(jwks ...map[string]any) {
	keys := make([]any, len(jwks))
	for i, key := range jwks {
		keys[i] = key
	}
	f.mu.Lock()
	f.jwks = map[string]any{"keys": keys}
	f.mu.Unlock()
}

func (f *fakeIssuer) RoundTrip(r *http.Request) (*http.Response, error) {
	f.mu.Lock()
	f.urls = append(f.urls, r.URL.String())
	jwks, status, delay := f.jwks, f.jwksStatus, f.jwksDelay
	f.mu.Unlock()
	switch {
	case r.URL.String() == testJWKSURL:
		f.jwksCalls.Add(1)
		if delay > 0 {
			select {
			case <-time.After(delay):
			case <-r.Context().Done():
				return nil, r.Context().Err()
			}
		}
		return respond(status, mustJSON(jwks), nil), nil
	case r.URL.String() == testIssuer+"/.well-known/openid-configuration":
		f.discoverCalls.Add(1)
		return respond(http.StatusOK, mustJSON(f.discovery), nil), nil
	case strings.HasPrefix(r.URL.String(), "https://auth.example.test/oauth/introspect"):
		f.introCalls.Add(1)
		body, _ := io.ReadAll(r.Body)
		code, text := f.introspect(r, string(body))
		return respond(code, text, nil), nil
	}
	return respond(http.StatusNotFound, `{"error":"not_found"}`, nil), nil
}

func respond(status int, body string, header http.Header) *http.Response {
	if header == nil {
		header = http.Header{}
	}
	header.Set("Content-Type", "application/json")
	return &http.Response{
		StatusCode:    status,
		Header:        header,
		Body:          io.NopCloser(bytes.NewBufferString(body)),
		ContentLength: int64(len(body)),
	}
}

// testClock is a settable clock for cache and expiry tests.
type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func newClock() *testClock { return &testClock{now: time.Unix(testEpoch, 0)} }

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

func newTestClient(t *testing.T, issuer *fakeIssuer, clock *testClock, change func(*Options)) *Client {
	t.Helper()
	options := Options{
		TenantID:   testTenant,
		Issuer:     testIssuer,
		Audience:   testAudience,
		HTTPClient: &http.Client{Transport: issuer},
		Now:        clock.Now,
	}
	if change != nil {
		change(&options)
	}
	client, err := New(options)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return client
}

func expectCode(t *testing.T, err error, code ErrorCode) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected %s, got success", code)
	}
	tokenError, ok := err.(*TokenError)
	if !ok {
		t.Fatalf("expected *TokenError %s, got %T %v", code, err, err)
	}
	if tokenError.Code != code {
		t.Fatalf("expected %s, got %s (%v)", code, tokenError.Code, err)
	}
}
