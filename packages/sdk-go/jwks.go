package auth4

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"sync"
	"time"
)

const (
	maxResponseBytes = 256 * 1024
	maxJWKSKeys      = 64
	minRSAKeyBytes   = 256
)

var privateRSAParameters = []string{"d", "p", "q", "dp", "dq", "qi", "oth"}

// jwksCache holds signing keys from the configured issuer's JWKS for the cache TTL. An unknown kid
// triggers one refresh per cooldown, so key rotation needs no restart. Concurrent callers share
// one in-flight fetch.
type jwksCache struct {
	httpClient *http.Client
	url        string
	ttl        time.Duration
	cooldown   time.Duration
	timeout    time.Duration
	now        func() time.Time

	mu                    sync.Mutex
	keys                  map[string]*rsa.PublicKey
	expiresAt             time.Time
	inFlight              *jwksFetch
	lastFetchAttempt      time.Time
	lastUnknownKidRefresh time.Time
}

type jwksFetch struct {
	done chan struct{}
	err  error
}

// key returns the key for kid, or nil when the issuer doesn't publish it.
func (c *jwksCache) key(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	c.mu.Lock()
	now := c.now()
	var fetch *jwksFetch
	var err error
	if c.keys != nil && c.expiresAt.After(now) {
		if existing := c.keys[kid]; existing != nil {
			c.mu.Unlock()
			return existing, nil
		}
		fetch, err = c.refreshLocked(true, now)
	} else {
		fetch, err = c.refreshLocked(false, now)
	}
	c.mu.Unlock()
	if err != nil {
		return nil, err
	}

	select {
	case <-fetch.done:
	case <-ctx.Done():
		return nil, &TokenError{Code: CodeJWKSUnavailable, Message: "The request ended before signing keys were fetched.", Err: ctx.Err()}
	}
	if fetch.err != nil {
		return nil, fetch.err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.keys[kid], nil
}

func (c *jwksCache) refreshLocked(unknownKid bool, now time.Time) (*jwksFetch, error) {
	if c.inFlight != nil {
		return c.inFlight, nil
	}
	if unknownKid {
		if !c.lastUnknownKidRefresh.IsZero() && now.Sub(c.lastUnknownKidRefresh) < c.cooldown {
			return nil, refreshLimited()
		}
		c.lastUnknownKidRefresh = now
	} else if !c.lastFetchAttempt.IsZero() && now.Sub(c.lastFetchAttempt) < c.cooldown {
		return nil, refreshLimited()
	}
	c.lastFetchAttempt = now

	fetch := &jwksFetch{done: make(chan struct{})}
	c.inFlight = fetch
	go func() {
		// Detached from any one caller, so a cancelled request can't fail the others waiting on it.
		ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
		defer cancel()
		keys, err := c.fetch(ctx)
		c.mu.Lock()
		if err == nil {
			c.keys = keys
			c.expiresAt = c.now().Add(c.ttl)
		}
		c.inFlight = nil
		c.mu.Unlock()
		fetch.err = err
		close(fetch.done)
	}()
	return fetch, nil
}

func refreshLimited() *TokenError {
	return &TokenError{Code: CodeJWKSRefreshLimited, Message: "A signing-key refresh was recently attempted."}
}

func (c *jwksCache) fetch(ctx context.Context) (map[string]*rsa.PublicKey, error) {
	keys, err := c.fetchKeys(ctx)
	if err != nil {
		return nil, &TokenError{
			Code:    CodeJWKSUnavailable,
			Message: "Signing keys could not be refreshed from the configured issuer.",
			Err:     err,
		}
	}
	return keys, nil
}

func (c *jwksCache) fetchKeys(ctx context.Context) (map[string]*rsa.PublicKey, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/jwk-set+json, application/json")
	body, err := fetchJSONObject(c.httpClient, request, "the JWKS endpoint")
	if err != nil {
		return nil, err
	}
	var candidates []json.RawMessage
	if raw, ok := body["keys"]; !ok || !isJSONArray(raw) || json.Unmarshal(raw, &candidates) != nil ||
		len(candidates) > maxJWKSKeys {
		return nil, errors.New("JWKS response has an invalid or oversized key set")
	}

	keys := make(map[string]*rsa.PublicKey)
	for _, candidate := range candidates {
		kid, key, ok, err := importPublicRS256JWK(candidate)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		if _, duplicate := keys[kid]; duplicate {
			return nil, errors.New("JWKS contains duplicate key IDs")
		}
		keys[kid] = key
	}
	if len(keys) == 0 {
		return nil, errors.New("JWKS contains no usable RS256 public keys")
	}
	return keys, nil
}

// importPublicRS256JWK skips keys that aren't public RS256 signing keys (ok false) and fails on a
// usable-looking key that is malformed or shorter than 2048 bits.
func importPublicRS256JWK(raw json.RawMessage) (kid string, key *rsa.PublicKey, ok bool, err error) {
	members, decodeErr := decodeObject(raw)
	if decodeErr != nil {
		return "", nil, false, nil
	}
	text := func(name string) (string, bool) {
		value, present := members[name]
		if !present {
			return "", false
		}
		return jsonString(value)
	}
	if kty, _ := text("kty"); kty != "RSA" {
		return "", nil, false, nil
	}
	kid, hasKid := text("kid")
	n, hasN := text("n")
	e, hasE := text("e")
	if !hasKid || len(kid) < 1 || len(kid) > 128 || !hasN || !hasE {
		return "", nil, false, nil
	}
	if _, present := members["alg"]; present {
		if alg, _ := text("alg"); alg != "RS256" {
			return "", nil, false, nil
		}
	}
	if _, present := members["use"]; present {
		if use, _ := text("use"); use != "sig" {
			return "", nil, false, nil
		}
	}
	if rawOps, present := members["key_ops"]; present {
		var ops []any
		if !isJSONArray(rawOps) || json.Unmarshal(rawOps, &ops) != nil || !containsString(ops, "verify") {
			return "", nil, false, nil
		}
	}
	for _, parameter := range privateRSAParameters {
		if _, present := members[parameter]; present {
			return "", nil, false, nil
		}
	}

	modulus, err := base64.RawURLEncoding.Strict().DecodeString(n)
	if err != nil {
		return "", nil, false, errors.New("JWKS key is not valid base64url")
	}
	exponent, err := base64.RawURLEncoding.Strict().DecodeString(e)
	if err != nil || len(exponent) == 0 || len(exponent) > 4 {
		return "", nil, false, errors.New("JWKS key has an invalid exponent")
	}
	modulusValue := new(big.Int).SetBytes(modulus)
	// RS256 keys must be at least 2048 bits, as jose enforces for the TypeScript SDK.
	if (modulusValue.BitLen()+7)/8 < minRSAKeyBytes {
		return "", nil, false, errors.New("JWKS key is shorter than 2048 bits")
	}
	exponentValue := new(big.Int).SetBytes(exponent)
	if !exponentValue.IsInt64() || exponentValue.Int64() < 3 || exponentValue.Int64() > 1<<31-1 ||
		exponentValue.Bit(0) == 0 {
		return "", nil, false, errors.New("JWKS key has an invalid exponent")
	}
	return kid, &rsa.PublicKey{N: modulusValue, E: int(exponentValue.Int64())}, true, nil
}

func containsString(values []any, want string) bool {
	for _, value := range values {
		if text, ok := value.(string); ok && text == want {
			return true
		}
	}
	return false
}

// fetchJSONObject sends request without following redirects and reads a JSON object of at most
// 256 KiB from a 2xx response.
func fetchJSONObject(client *http.Client, request *http.Request, what string) (map[string]json.RawMessage, error) {
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return nil, fmt.Errorf("%s returned HTTP %d", what, response.StatusCode)
	}
	if response.ContentLength > maxResponseBytes {
		return nil, fmt.Errorf("%s response exceeded its size limit", what)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxResponseBytes {
		return nil, fmt.Errorf("%s response exceeded its size limit", what)
	}
	members, err := decodeObject(body)
	if err != nil {
		return nil, fmt.Errorf("%s returned a non-object body", what)
	}
	return members, nil
}

// noRedirects copies client so that it returns redirects instead of following them; a redirect
// then fails as a non-2xx answer.
func noRedirects(client *http.Client) *http.Client {
	if client == nil {
		client = &http.Client{}
	}
	copied := *client
	copied.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &copied
}
