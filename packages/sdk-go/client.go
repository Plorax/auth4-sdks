// Package auth4 verifies auth4.dev access tokens in Go game backends and APIs. It matches
// @auth4/sdk-server: the same checks, error codes and opt-in introspect mode, plus net/http
// middleware. The guide is https://auth4.dev/docs/go/.
package auth4

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"time"
)

// Options configure one tenant and one resource audience.
type Options struct {
	// TenantID is the project ID, ten_….
	TenantID string
	// Issuer is the trusted, configured tenant issuer, {AUTH_ORIGIN}/t/{tenantId}. Leave it empty
	// and set AuthOrigin instead to have it derived.
	Issuer string
	// AuthOrigin is the auth origin, for example https://auth.auth4.dev. Used when Issuer is empty.
	AuthOrigin string
	// Audience is the API audience this server accepts: the client ID of the application calling it.
	Audience string
	// HTTPClient is used for the JWKS, discovery and introspection requests, which only ever go to
	// URLs derived from the configured issuer. Redirects are never followed. Default: a new client.
	HTTPClient *http.Client
	// JWKSCacheTTL is how long a fetched key set is trusted. Default 5 minutes; 10 seconds to 1 hour.
	JWKSCacheTTL time.Duration
	// JWKSRefreshCooldown is the minimum gap between key refreshes. Default 30 seconds; 1 second to
	// 10 minutes.
	JWKSRefreshCooldown time.Duration
	// JWKSFetchTimeout limits one key-set or discovery request. Default 3 seconds; 10 ms to 10 seconds.
	JWKSFetchTimeout time.Duration
	// ClockTolerance is the allowed clock drift for exp and nbf, in whole seconds. Default zero; at
	// most 60 seconds.
	ClockTolerance time.Duration
	// Now is an injectable clock, primarily for deterministic tests.
	Now func() time.Time
	// Introspection opts in to a live revocation check (AUTH4D-155). After local verification
	// succeeds, the token is also sent to the tenant's introspection endpoint, so a revoked session
	// is refused within IntrospectionOptions.CacheTTL instead of up to five minutes later. Off when nil.
	Introspection *IntrospectionOptions
}

// Client verifies auth4.dev access tokens for one configured tenant and audience. Signing keys are
// fetched only from the URL derived from the configured issuer. Create one Client per audience and
// reuse it, so its key cache is shared across requests. It is safe for concurrent use.
type Client struct {
	tenantID       string
	issuer         string
	audience       string
	jwksURL        string
	httpClient     *http.Client
	fetchTimeout   time.Duration
	clockTolerance int64
	now            func() time.Time
	jwks           *jwksCache
	introspector   *introspector
}

var bearerPattern = regexp.MustCompile(`^(?i:bearer) ([^\s,]+)$`)

// New validates options and creates the client. It makes no network calls.
func New(options Options) (*Client, error) {
	if !tenantIDPattern.MatchString(options.TenantID) {
		return nil, errors.New("auth4: TenantID must be a project ID (ten_…)")
	}
	client := &Client{tenantID: options.TenantID}
	var err error
	switch {
	case options.Issuer != "":
		client.issuer, err = validateIssuer(options.TenantID, options.Issuer)
	case options.AuthOrigin != "":
		client.issuer, err = issuerFromOrigin(options.TenantID, options.AuthOrigin)
	default:
		err = errors.New("auth4: set Issuer or AuthOrigin")
	}
	if err != nil {
		return nil, err
	}
	if len(options.Audience) < 1 || len(options.Audience) > 255 {
		return nil, errors.New("auth4: Audience must be 1 to 255 characters")
	}
	if options.Audience == managementAudience {
		return nil, errors.New("auth4: customer server clients cannot use the management audience")
	}
	client.audience = options.Audience
	// No token-supplied issuer, jku or x5u value is ever used to build this URL.
	client.jwksURL = client.issuer + "/.well-known/jwks.json"

	cacheTTL, err := bounded("JWKSCacheTTL", options.JWKSCacheTTL, 5*time.Minute, 10*time.Second, time.Hour)
	if err != nil {
		return nil, err
	}
	cooldown, err := bounded("JWKSRefreshCooldown", options.JWKSRefreshCooldown, 30*time.Second, time.Second, 10*time.Minute)
	if err != nil {
		return nil, err
	}
	client.fetchTimeout, err = bounded("JWKSFetchTimeout", options.JWKSFetchTimeout, 3*time.Second, 10*time.Millisecond, 10*time.Second)
	if err != nil {
		return nil, err
	}
	tolerance, err := bounded("ClockTolerance", options.ClockTolerance, 0, 0, time.Minute)
	if err != nil {
		return nil, err
	}
	if tolerance%time.Second != 0 {
		return nil, errors.New("auth4: ClockTolerance must be whole seconds")
	}
	client.clockTolerance = int64(tolerance / time.Second)
	client.now = options.Now
	if client.now == nil {
		client.now = time.Now
	}
	client.httpClient = noRedirects(options.HTTPClient)
	client.jwks = &jwksCache{
		httpClient: client.httpClient,
		url:        client.jwksURL,
		ttl:        cacheTTL,
		cooldown:   cooldown,
		timeout:    client.fetchTimeout,
		now:        client.now,
	}
	if options.Introspection != nil {
		client.introspector, err = newIntrospector(client.httpClient, client.issuer, client.tenantID, *options.Introspection, client.now)
		if err != nil {
			return nil, err
		}
	}
	return client, nil
}

// bounded applies a default to a zero duration and checks the result is within [minimum, maximum].
func bounded(name string, value, fallback, minimum, maximum time.Duration) (time.Duration, error) {
	if value == 0 {
		value = fallback
	}
	if value < minimum || value > maximum {
		return 0, fmt.Errorf("auth4: %s must be from %s to %s", name, minimum, maximum)
	}
	return value, nil
}

// TenantID is the configured project ID.
func (c *Client) TenantID() string { return c.tenantID }

// Issuer is the configured issuer, {AUTH_ORIGIN}/t/{tenantId}.
func (c *Client) Issuer() string { return c.issuer }

// Audience is the configured audience.
func (c *Client) Audience() string { return c.audience }

// JWKSURL is {issuer}/.well-known/jwks.json.
func (c *Client) JWKSURL() string { return c.jwksURL }

// IntrospectionURL is the endpoint introspect mode calls, derived from the configured issuer. It is
// empty when introspect mode is off.
func (c *Client) IntrospectionURL() string {
	if c.introspector == nil {
		return ""
	}
	return c.introspector.url
}

// String names the issuer and audience only, so printing a Client never prints credentials.
func (c *Client) String() string {
	return fmt.Sprintf("auth4.Client{Issuer: %q, Audience: %q, Introspection: %t}", c.issuer, c.audience, c.introspector != nil)
}

// GoString is the same as String, for %#v.
func (c *Client) GoString() string { return c.String() }

// IssuerFor returns the issuer for a project on an auth origin, for example
// https://auth.auth4.dev/t/ten_….
func IssuerFor(authOrigin, tenantID string) (string, error) {
	if !tenantIDPattern.MatchString(tenantID) {
		return "", errors.New("auth4: tenantID must be a project ID (ten_…)")
	}
	return issuerFromOrigin(tenantID, authOrigin)
}

// ParseBearerToken reads a single RFC 6750 Bearer credential from an Authorization header value.
// It does not validate the token.
func ParseBearerToken(header string) (string, bool) {
	if len(header) > maxTokenLength+16 {
		return "", false
	}
	match := bearerPattern.FindStringSubmatch(header)
	if match == nil {
		return "", false
	}
	return match[1], true
}

// Discover fetches {issuer}/.well-known/openid-configuration and checks that it names the
// configured issuer, the derived JWKS URL and RS256 (and, in introspect mode, the introspection
// endpoint). Verification never depends on it, so call it at startup to catch a wrong project ID
// or auth origin early.
func (c *Client) Discover(ctx context.Context) (*Discovery, error) {
	requestCtx, cancel := context.WithTimeout(ctx, c.fetchTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(requestCtx, http.MethodGet, c.issuer+"/.well-known/openid-configuration", nil)
	if err != nil {
		return nil, &DiscoveryError{Message: "The discovery request could not be built.", Err: err}
	}
	request.Header.Set("Accept", "application/json")
	body, err := fetchJSONObject(c.httpClient, request, "the discovery endpoint")
	if err != nil {
		return nil, &DiscoveryError{Message: "The issuer's discovery document could not be fetched.", Err: err}
	}
	text := func(name string) string {
		value, _ := jsonString(body[name])
		return value
	}
	if text("issuer") != c.issuer {
		return nil, &DiscoveryError{Message: "The discovery document names a different issuer."}
	}
	if text("jwks_uri") != c.jwksURL {
		return nil, &DiscoveryError{Message: "The discovery document names a different JWKS URL."}
	}
	var algorithms []any
	if raw := body["id_token_signing_alg_values_supported"]; !isJSONArray(raw) ||
		json.Unmarshal(raw, &algorithms) != nil || !containsString(algorithms, "RS256") {
		return nil, &DiscoveryError{Message: "The issuer does not advertise RS256."}
	}
	introspection := text("introspection_endpoint")
	if c.introspector != nil && introspection != c.introspector.url {
		return nil, &DiscoveryError{Message: "The issuer does not advertise the introspection endpoint introspect mode uses."}
	}
	return &Discovery{
		Issuer:                c.issuer,
		JWKSURI:               c.jwksURL,
		TokenEndpoint:         text("token_endpoint"),
		UserInfoEndpoint:      text("userinfo_endpoint"),
		IntrospectionEndpoint: introspection,
	}, nil
}

// ValidateAccessToken verifies an access token: the RS256 signature with a key from the issuer,
// typ at+jwt, iss, aud, exp, nbf, tenant_id and the claim contract. In introspect mode it also
// checks the session. Errors are *TokenError.
func (c *Client) ValidateAccessToken(ctx context.Context, token string) (*AccessToken, error) {
	payload, err := c.verifySignature(ctx, token, accessKind)
	if err != nil {
		return nil, err
	}
	verified, ok := c.readAccessClaims(payload)
	if !ok {
		return nil, invalidToken(nil)
	}
	if c.introspector != nil {
		if err := c.introspector.assertActive(ctx, token, verified); err != nil {
			return nil, err
		}
	}
	return verified, nil
}

// ValidateAuthorizationHeader verifies an Authorization header value and rejects absent or
// malformed Bearer credentials.
func (c *Client) ValidateAuthorizationHeader(ctx context.Context, header string) (*AccessToken, error) {
	token, ok := ParseBearerToken(header)
	if !ok {
		return nil, invalidToken(nil)
	}
	return c.ValidateAccessToken(ctx, token)
}

// ValidateIDToken verifies an ID token for clientID. ID tokens have typ JWT and token_use id, so
// neither validation method accepts the other kind of token. Pass the nonce your authorization
// request sent as expectedNonce, or "" to skip that check. Never use an ID token to authorize an
// API call.
func (c *Client) ValidateIDToken(ctx context.Context, idToken, clientID, expectedNonce string) (*IDToken, error) {
	if !clientIDPattern.MatchString(clientID) {
		return nil, errors.New("auth4: clientID must be an application client ID (cli_…)")
	}
	payload, err := c.verifySignature(ctx, idToken, idKind)
	if err != nil {
		return nil, err
	}
	verified, ok := c.readIDClaims(payload, clientID)
	if !ok {
		return nil, invalidToken(nil)
	}
	if expectedNonce != "" &&
		(verified.Nonce == "" || subtle.ConstantTimeCompare([]byte(verified.Nonce), []byte(expectedNonce)) != 1) {
		return nil, invalidToken(nil)
	}
	return verified, nil
}

func (c *Client) verifySignature(ctx context.Context, token string, kind tokenKind) ([]byte, error) {
	jwt, err := parseJWT(token)
	if err != nil {
		return nil, invalidToken(nil)
	}
	kid, ok := jwt.checkHeader(kind)
	if !ok {
		return nil, invalidToken(nil)
	}
	key, err := c.jwks.key(ctx, kid)
	if err != nil {
		return nil, err
	}
	if key == nil || !jwt.verify(key) {
		return nil, invalidToken(nil)
	}
	return jwt.payload, nil
}

type commonClaims struct {
	subject   string
	tokenID   string
	issuedAt  int64
	expiresAt int64
	notBefore int64
}

// readCommon checks the registered claims both token kinds share.
func (c *Client) readCommon(claims map[string]json.RawMessage, allowed map[string]bool, tokenUse string, maxLifetime int64) (commonClaims, bool) {
	var common commonClaims
	for name := range claims {
		// Unknown claims fail, like the strict contract schemas. decodeObject already refused
		// duplicates.
		if !allowed[name] {
			return common, false
		}
	}
	text := func(name string) (string, bool) {
		raw, ok := claims[name]
		if !ok {
			return "", false
		}
		return jsonString(raw)
	}
	integer := func(name string) (int64, bool) {
		raw, ok := claims[name]
		if !ok {
			return 0, false
		}
		return jsonPositiveInt(raw)
	}
	if iss, ok := text("iss"); !ok || iss != c.issuer {
		return common, false
	}
	var ok bool
	if common.subject, ok = text("sub"); !ok || !userIDPattern.MatchString(common.subject) {
		return common, false
	}
	if common.tokenID, ok = text("jti"); !ok || !tokenIDPattern.MatchString(common.tokenID) {
		return common, false
	}
	if tenantID, ok := text("tenant_id"); !ok || tenantID != c.tenantID {
		return common, false
	}
	if use, ok := text("token_use"); !ok || use != tokenUse {
		return common, false
	}
	if common.expiresAt, ok = integer("exp"); !ok {
		return common, false
	}
	if common.issuedAt, ok = integer("iat"); !ok {
		return common, false
	}
	if _, present := claims["nbf"]; present {
		if common.notBefore, ok = integer("nbf"); !ok {
			return common, false
		}
	}
	if common.expiresAt <= common.issuedAt || common.expiresAt-common.issuedAt > maxLifetime {
		return common, false
	}

	// Same comparisons as jose: whole seconds, with the configured tolerance.
	now := c.now().Unix()
	if common.expiresAt <= now-c.clockTolerance {
		return common, false
	}
	if common.notBefore != 0 && common.notBefore > now+c.clockTolerance {
		return common, false
	}
	return common, true
}

func (c *Client) readAccessClaims(payload []byte) (*AccessToken, bool) {
	claims, err := decodeObject(payload)
	if err != nil {
		return nil, false
	}
	common, ok := c.readCommon(claims, accessTokenClaims, "access", accessTokenLifetimeSeconds)
	if !ok {
		return nil, false
	}
	// aud is a single string in the contract; an array is refused.
	aud, ok := jsonString(claims["aud"])
	if !ok || aud != c.audience || aud == managementAudience {
		return nil, false
	}
	clientID, ok := jsonString(claims["client_id"])
	if !ok || !clientIDPattern.MatchString(clientID) {
		return nil, false
	}
	scope, ok := jsonString(claims["scope"])
	if !ok || !isScopeList(scope) {
		return nil, false
	}
	token := &AccessToken{
		Subject:   common.subject,
		TenantID:  c.tenantID,
		Issuer:    c.issuer,
		Audience:  aud,
		ClientID:  clientID,
		Scope:     scope,
		Scopes:    splitScopes(scope),
		TokenID:   common.tokenID,
		IssuedAt:  time.Unix(common.issuedAt, 0).UTC(),
		ExpiresAt: time.Unix(common.expiresAt, 0).UTC(),
		Roles:     []string{},
		Metadata:  map[string]any{},
	}
	if common.notBefore != 0 {
		token.NotBefore = time.Unix(common.notBefore, 0).UTC()
	}
	if raw, present := claims["sid"]; present {
		if token.SessionID, ok = jsonString(raw); !ok || !sessionIDPattern.MatchString(token.SessionID) {
			return nil, false
		}
	}
	// A non-boolean auth4_guest and malformed auth4_roles or auth4_meta make the token invalid;
	// absent claims mean not a guest, no roles and no metadata.
	if raw, present := claims[guestClaim]; present {
		if token.IsGuest, ok = jsonBool(raw); !ok {
			return nil, false
		}
	}
	if raw, present := claims[rolesClaim]; present {
		if token.Roles, ok = readRoles(raw); !ok {
			return nil, false
		}
	}
	if raw, present := claims[metadataClaim]; present {
		if token.Metadata, ok = readMetadata(raw); !ok {
			return nil, false
		}
	}
	if !idpIsValid(claims) || !playerNameIsValid(claims) {
		return nil, false
	}
	return token, true
}

// playerNameIsValid accepts an absent name or Name#1234 (AUTH4D-324).
func playerNameIsValid(claims map[string]json.RawMessage) bool {
	raw, present := claims["name"]
	if !present {
		return true
	}
	name, ok := jsonString(raw)
	return ok && playerNamePattern.MatchString(name)
}

func (c *Client) readIDClaims(payload []byte, clientID string) (*IDToken, bool) {
	claims, err := decodeObject(payload)
	if err != nil {
		return nil, false
	}
	common, ok := c.readCommon(claims, idTokenClaims, "id", idTokenLifetimeSeconds)
	if !ok {
		return nil, false
	}
	aud, ok := jsonString(claims["aud"])
	if !ok || aud != clientID {
		return nil, false
	}
	authTime, ok := jsonPositiveInt(claims["auth_time"])
	if !ok {
		return nil, false
	}
	token := &IDToken{
		Subject:   common.subject,
		TenantID:  c.tenantID,
		Issuer:    c.issuer,
		Audience:  aud,
		TokenID:   common.tokenID,
		IssuedAt:  time.Unix(common.issuedAt, 0).UTC(),
		ExpiresAt: time.Unix(common.expiresAt, 0).UTC(),
		AuthTime:  time.Unix(authTime, 0).UTC(),
	}
	if raw, present := claims["nonce"]; present {
		if token.Nonce, ok = jsonString(raw); !ok || utf16Length(token.Nonce) < 16 || utf16Length(token.Nonce) > 512 {
			return nil, false
		}
	}
	if raw, present := claims["email"]; present {
		if token.Email, ok = jsonString(raw); !ok || !isEmailAddress(token.Email) {
			return nil, false
		}
	}
	if raw, present := claims["email_verified"]; present {
		verified, ok := jsonBool(raw)
		if !ok {
			return nil, false
		}
		token.EmailVerified = &verified
	}
	if token.EmailVerified != nil && *token.EmailVerified && token.Email == "" {
		return nil, false
	}
	if !idpIsValid(claims) {
		return nil, false
	}
	return token, true
}

// idpIsValid accepts an absent idp (AUTH4D-258) or any well-formed method name, so later methods
// stay readable.
func idpIsValid(claims map[string]json.RawMessage) bool {
	raw, present := claims["idp"]
	if !present {
		return true
	}
	idp, ok := jsonString(raw)
	return ok && idpPattern.MatchString(idp)
}
