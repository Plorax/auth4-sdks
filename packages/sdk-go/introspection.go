package auth4

import (
	"container/list"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const maxIntrospectionCacheEntries = 10_000

// IntrospectionOptions turns on introspect mode (AUTH4D-155) with a confidential server client's
// credentials. Its String, GoString and MarshalJSON leave the secret out.
type IntrospectionOptions struct {
	// ClientID is the server client's ID, cli_….
	ClientID string
	// ClientSecret belongs in a secret store. The SDK never logs, prints or serializes it.
	ClientSecret string
	// CacheTTL is how long an active answer is reused for the same token. Default 5 seconds; at
	// most 60 seconds.
	CacheTTL time.Duration
	// DisableCache checks every request with the issuer, ignoring CacheTTL.
	DisableCache bool
	// Timeout for one introspection request. Default 3 seconds; 10 ms to 10 seconds.
	Timeout time.Duration
}

func (o IntrospectionOptions) String() string {
	return fmt.Sprintf("auth4.IntrospectionOptions{ClientID: %q}", o.ClientID)
}

func (o IntrospectionOptions) GoString() string { return o.String() }

// MarshalJSON writes everything except ClientSecret.
func (o IntrospectionOptions) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf(`{"ClientID":%q,"CacheTTL":%d,"DisableCache":%t,"Timeout":%d}`,
		o.ClientID, int64(o.CacheTTL), o.DisableCache, int64(o.Timeout))), nil
}

// introspector asks the tenant's RFC 7662 endpoint, after offline verification, whether the token's
// session is still live. Unreachable or unexpected answers fail closed. Mirrors
// @auth4/sdk-server's assertActive.
type introspector struct {
	httpClient    *http.Client
	url           string
	authorization string
	tenantID      string
	cacheTTL      time.Duration
	timeout       time.Duration
	now           func() time.Time

	mu       sync.Mutex
	cache    map[string]*list.Element
	order    *list.List
	inFlight map[string]*introspection
}

type cacheEntry struct {
	key       string
	active    bool
	expiresAt time.Time
}

type introspection struct {
	done   chan struct{}
	answer introspectionAnswer
	err    error
}

type introspectionAnswer struct {
	active    *bool
	subject   string
	clientID  string
	tokenID   string
	tenantID  string
	malformed bool
}

func newIntrospector(httpClient *http.Client, issuer, tenantID string, options IntrospectionOptions, now func() time.Time) (*introspector, error) {
	if !clientIDPattern.MatchString(options.ClientID) {
		return nil, errors.New("auth4: Introspection.ClientID must be a server client ID (cli_…)")
	}
	if len(options.ClientSecret) < 32 || len(options.ClientSecret) > 512 {
		return nil, errors.New("auth4: Introspection.ClientSecret must be the server client's secret")
	}
	cacheTTL, err := bounded("Introspection.CacheTTL", options.CacheTTL, 5*time.Second, 0, time.Minute)
	if err != nil {
		return nil, err
	}
	if options.DisableCache {
		cacheTTL = 0
	}
	timeout, err := bounded("Introspection.Timeout", options.Timeout, 3*time.Second, 10*time.Millisecond, 10*time.Second)
	if err != nil {
		return nil, err
	}
	issuerURL, err := url.Parse(issuer)
	if err != nil {
		return nil, err
	}
	// Like the JWKS URL, the endpoint comes only from the configured issuer, never from a token.
	endpoint := issuerURL.Scheme + "://" + issuerURL.Host + "/oauth/introspect?tenant_id=" + url.QueryEscape(tenantID)
	// RFC 6749 section 2.3.1: form-encode each part before Basic encoding.
	credentials := formEncode(options.ClientID) + ":" + formEncode(options.ClientSecret)
	return &introspector{
		httpClient:    httpClient,
		url:           endpoint,
		authorization: "Basic " + base64.StdEncoding.EncodeToString([]byte(credentials)),
		tenantID:      tenantID,
		cacheTTL:      cacheTTL,
		timeout:       timeout,
		now:           now,
		cache:         make(map[string]*list.Element),
		order:         list.New(),
		inFlight:      make(map[string]*introspection),
	}, nil
}

// formEncode percent-encodes like encodeURIComponent; the server percent-decodes both parts.
func formEncode(value string) string {
	return strings.ReplaceAll(url.QueryEscape(value), "+", "%20")
}

func (i *introspector) assertActive(ctx context.Context, token string, claims *AccessToken) error {
	digest := sha256.Sum256([]byte(token))
	key := hex.EncodeToString(digest[:])
	now := i.now()

	i.mu.Lock()
	if element, ok := i.cache[key]; ok {
		entry := element.Value.(*cacheEntry)
		if entry.expiresAt.After(now) {
			i.mu.Unlock()
			if !entry.active {
				return invalidToken(nil)
			}
			return nil
		}
		i.order.Remove(element)
		delete(i.cache, key)
	}
	pending, ok := i.inFlight[key]
	if !ok {
		pending = &introspection{done: make(chan struct{})}
		i.inFlight[key] = pending
		go func() {
			// Detached from any one caller, so a cancelled request can't fail the others waiting on it.
			requestCtx, cancel := context.WithTimeout(context.Background(), i.timeout)
			defer cancel()
			pending.answer, pending.err = i.introspect(requestCtx, token)
			i.mu.Lock()
			delete(i.inFlight, key)
			i.mu.Unlock()
			close(pending.done)
		}()
	}
	i.mu.Unlock()

	select {
	case <-pending.done:
	case <-ctx.Done():
		return &TokenError{Code: CodeIntrospectionUnavailable, Message: "The request ended before the session was checked.", Err: ctx.Err()}
	}
	if pending.err != nil {
		return &TokenError{
			Code:    CodeIntrospectionUnavailable,
			Message: "The token's session could not be checked with the configured issuer.",
			Err:     pending.err,
		}
	}
	answer := pending.answer
	if answer.active == nil {
		return &TokenError{Code: CodeIntrospectionUnavailable, Message: "The introspection response was not understood."}
	}
	active := *answer.active
	if active && (answer.malformed ||
		answer.subject != claims.Subject ||
		answer.clientID != claims.ClientID ||
		answer.tokenID != claims.TokenID ||
		answer.tenantID != i.tenantID) {
		return invalidToken(nil)
	}
	// A revoked session never comes back, so an inactive answer is kept until the token expires.
	expiresAt := claims.ExpiresAt
	if active {
		if until := now.Add(i.cacheTTL); until.Before(expiresAt) {
			expiresAt = until
		}
	}
	if expiresAt.After(now) && (i.cacheTTL > 0 || !active) {
		i.remember(key, active, expiresAt)
	}
	if !active {
		return invalidToken(nil)
	}
	return nil
}

func (i *introspector) remember(key string, active bool, expiresAt time.Time) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if element, ok := i.cache[key]; ok {
		i.order.Remove(element)
		delete(i.cache, key)
	}
	if len(i.cache) >= maxIntrospectionCacheEntries {
		if oldest := i.order.Front(); oldest != nil {
			i.order.Remove(oldest)
			delete(i.cache, oldest.Value.(*cacheEntry).key)
		}
	}
	i.cache[key] = i.order.PushBack(&cacheEntry{key: key, active: active, expiresAt: expiresAt})
}

func (i *introspector) cacheLen() int {
	i.mu.Lock()
	defer i.mu.Unlock()
	return len(i.cache)
}

func (i *introspector) introspect(ctx context.Context, token string) (introspectionAnswer, error) {
	form := url.Values{"token": {token}}.Encode()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, i.url, strings.NewReader(form))
	if err != nil {
		return introspectionAnswer{}, err
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Authorization", i.authorization)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	body, err := fetchJSONObject(i.httpClient, request, "the introspection endpoint")
	if err != nil {
		return introspectionAnswer{}, err
	}
	var answer introspectionAnswer
	if raw, ok := body["active"]; ok {
		if active, ok := jsonBool(raw); ok {
			answer.active = &active
		}
	}
	text := func(name string) string {
		raw, ok := body[name]
		if !ok {
			return ""
		}
		value, ok := jsonString(raw)
		if !ok {
			answer.malformed = true
		}
		return value
	}
	answer.subject = text("sub")
	answer.clientID = text("client_id")
	answer.tokenID = text("jti")
	answer.tenantID = text("tenant_id")
	return answer, nil
}
