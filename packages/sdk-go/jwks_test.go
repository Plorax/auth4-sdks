package auth4

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestKeysAreCachedAndShared(t *testing.T) {
	key := testKeys(t)[0]
	issuer := newFakeIssuer(publicJWK("k1", key))
	issuer.jwksDelay = 50 * time.Millisecond
	client := newTestClient(t, issuer, newClock(), nil)
	token := sign(key, accessHeader("k1"), accessClaims())

	var wg sync.WaitGroup
	errs := make(chan error, 20)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := client.ValidateAccessToken(context.Background(), token)
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent validation: %v", err)
		}
	}
	if calls := issuer.jwksCalls.Load(); calls != 1 {
		t.Fatalf("expected one shared JWKS fetch, got %d", calls)
	}
	for _, url := range issuer.urls {
		if url != testJWKSURL {
			t.Fatalf("unexpected request to %s", url)
		}
	}
}

func TestKeyRotationAndExpiry(t *testing.T) {
	keys := testKeys(t)
	issuer := newFakeIssuer(publicJWK("k1", keys[0]))
	clock := newClock()
	client := newTestClient(t, issuer, clock, nil)
	ctx := context.Background()

	if _, err := client.ValidateAccessToken(ctx, sign(keys[0], accessHeader("k1"), accessClaims())); err != nil {
		t.Fatalf("first key: %v", err)
	}
	// The issuer rotates to k2; the first token with the new kid triggers one refresh.
	issuer.setKeys(publicJWK("k1", keys[0]), publicJWK("k2", keys[1]))
	if _, err := client.ValidateAccessToken(ctx, sign(keys[1], accessHeader("k2"), accessClaims())); err != nil {
		t.Fatalf("rotated key: %v", err)
	}
	if calls := issuer.jwksCalls.Load(); calls != 2 {
		t.Fatalf("expected a refresh for the unknown kid, got %d fetches", calls)
	}

	// Another unknown kid within the cooldown is refused without a fetch.
	_, err := client.ValidateAccessToken(ctx, sign(keys[1], accessHeader("k3"), accessClaims()))
	expectCode(t, err, CodeJWKSRefreshLimited)
	if !IsOutage(err) || !errors.Is(err, ErrJWKSRefreshLimited) {
		t.Fatalf("expected an outage, got %v", err)
	}
	if calls := issuer.jwksCalls.Load(); calls != 2 {
		t.Fatalf("cooldown did not hold: %d fetches", calls)
	}

	// After the cooldown, an unknown kid the issuer doesn't publish is an invalid token.
	clock.Advance(31 * time.Second)
	_, err = client.ValidateAccessToken(ctx, sign(keys[1], accessHeader("k3"), with(accessClaims(), map[string]any{
		"iat": testEpoch + 31, "exp": testEpoch + 331,
	})))
	expectCode(t, err, CodeInvalidToken)

	// Known keys keep working without fetches until the cache expires.
	clock.Advance(4 * time.Minute)
	fresh := with(accessClaims(), map[string]any{"iat": clock.Now().Unix(), "exp": clock.Now().Unix() + 300})
	if _, err := client.ValidateAccessToken(ctx, sign(keys[0], accessHeader("k1"), fresh)); err != nil {
		t.Fatalf("cached key: %v", err)
	}
	if calls := issuer.jwksCalls.Load(); calls != 3 {
		t.Fatalf("expected no fetch before expiry, got %d", calls)
	}
	// A removed key stops working once the cache expires.
	issuer.setKeys(publicJWK("k2", keys[1]))
	clock.Advance(2 * time.Minute)
	fresh = with(accessClaims(), map[string]any{"iat": clock.Now().Unix(), "exp": clock.Now().Unix() + 300})
	_, err = client.ValidateAccessToken(ctx, sign(keys[0], accessHeader("k1"), fresh))
	expectCode(t, err, CodeInvalidToken)
}

func TestUnavailableKeysFailAsOutage(t *testing.T) {
	key := testKeys(t)[0]
	token := sign(key, accessHeader("k1"), accessClaims())
	for name, change := range map[string]func(*fakeIssuer){
		"server error": func(f *fakeIssuer) { f.jwksStatus = http.StatusInternalServerError },
		"redirect":     func(f *fakeIssuer) { f.jwksStatus = http.StatusFound },
		"no keys":      func(f *fakeIssuer) { f.setKeys() },
		"private key only": func(f *fakeIssuer) {
			jwk := publicJWK("k1", key)
			jwk["d"] = "AQAB"
			f.setKeys(jwk)
		},
		"wrong use": func(f *fakeIssuer) {
			jwk := publicJWK("k1", key)
			jwk["use"] = "enc"
			f.setKeys(jwk)
		},
		"short key": func(f *fakeIssuer) {
			jwk := publicJWK("k1", key)
			jwk["n"] = b64(key.N.Bytes()[:128])
			f.setKeys(jwk)
		},
		"duplicate kid": func(f *fakeIssuer) { f.setKeys(publicJWK("k1", key), publicJWK("k1", key)) },
		"too many keys": func(f *fakeIssuer) {
			many := make([]map[string]any, 65)
			for i := range many {
				many[i] = publicJWK("k"+strings.Repeat("x", i+1), key)
			}
			f.setKeys(many...)
		},
		"oversized": func(f *fakeIssuer) {
			jwk := publicJWK("k1", key)
			jwk["x-padding"] = strings.Repeat("a", maxResponseBytes)
			f.setKeys(jwk)
		},
	} {
		t.Run(name, func(t *testing.T) {
			issuer := newFakeIssuer(publicJWK("k1", key))
			change(issuer)
			client := newTestClient(t, issuer, newClock(), nil)
			_, err := client.ValidateAccessToken(context.Background(), token)
			expectCode(t, err, CodeJWKSUnavailable)
			if !IsOutage(err) {
				t.Fatal("expected an outage")
			}
		})
	}
}

func TestFetchTimeoutAndCallerCancellation(t *testing.T) {
	key := testKeys(t)[0]
	issuer := newFakeIssuer(publicJWK("k1", key))
	issuer.jwksDelay = time.Second
	client := newTestClient(t, issuer, newClock(), func(o *Options) { o.JWKSFetchTimeout = 20 * time.Millisecond })
	_, err := client.ValidateAccessToken(context.Background(), sign(key, accessHeader("k1"), accessClaims()))
	expectCode(t, err, CodeJWKSUnavailable)

	issuer.jwksDelay = 200 * time.Millisecond
	slow := newTestClient(t, issuer, newClock(), nil)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	_, err = slow.ValidateAccessToken(ctx, sign(key, accessHeader("k1"), accessClaims()))
	expectCode(t, err, CodeJWKSUnavailable)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected the caller's deadline as the cause, got %v", err)
	}
	// The shared fetch carries on for later callers.
	time.Sleep(300 * time.Millisecond)
	if _, err := slow.ValidateAccessToken(context.Background(), sign(key, accessHeader("k1"), accessClaims())); err != nil {
		t.Fatalf("after the shared fetch finished: %v", err)
	}
}
