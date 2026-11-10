package auth4

import (
	"strings"
	"time"
)

// AccessToken holds the claims of a verified access token.
type AccessToken struct {
	// Subject (sub) is the player's user ID. It stays the same when a guest upgrades.
	Subject string
	// TenantID (tenant_id) always equals the configured project ID.
	TenantID string
	// Issuer (iss) always equals the configured issuer.
	Issuer string
	// Audience (aud) always equals the configured audience.
	Audience string
	// ClientID (client_id) is the application the token was issued to.
	ClientID string
	// Scope is the space-separated scope claim; Scopes splits it.
	Scope  string
	Scopes []string
	// SessionID (sid) is empty when the token doesn't belong to a session.
	SessionID string
	// TokenID (jti) is unique per token.
	TokenID   string
	IssuedAt  time.Time
	ExpiresAt time.Time
	// NotBefore is the zero time when the token has no nbf claim.
	NotBefore time.Time
	// IsGuest is true only when the signed auth4_guest claim is true (AUTH4D-64). The claim is
	// re-evaluated on every issuance, so it is false on the first token after a guest upgrades.
	IsGuest bool
	// Roles are the subject's roles in the token's application, from the signed auth4_roles claim
	// (AUTH4D-154). Empty when the claim is absent. A change made in the console reaches the next
	// token, at the latest after one five-minute lifetime.
	Roles []string
	// Metadata is the signed auth4_meta claim: flat per-user metadata whose values are string,
	// float64, bool or nil. Empty, never nil, when the claim is absent.
	Metadata map[string]any
}

// HasRole is true when the token includes role for its application. Exact and case-sensitive.
func (t *AccessToken) HasRole(role string) bool {
	for _, held := range t.Roles {
		if held == role {
			return true
		}
	}
	return false
}

// HasAnyRole is true when the token includes at least one of roles. No roles never matches.
func (t *AccessToken) HasAnyRole(roles ...string) bool {
	for _, role := range roles {
		if t.HasRole(role) {
			return true
		}
	}
	return false
}

// HasScope is true when scope was granted.
func (t *AccessToken) HasScope(scope string) bool {
	for _, granted := range t.Scopes {
		if granted == scope {
			return true
		}
	}
	return false
}

// IDToken holds the claims of a verified ID token. Use it only to confirm a sign-in for your own
// client ID, never to authorize an API call.
type IDToken struct {
	Subject   string
	TenantID  string
	Issuer    string
	Audience  string
	TokenID   string
	IssuedAt  time.Time
	ExpiresAt time.Time
	AuthTime  time.Time
	// Nonce is empty when the authorization request sent none.
	Nonce string
	// Email is empty when the token has no email claim.
	Email string
	// EmailVerified is nil when the token has no email_verified claim.
	EmailVerified *bool
}

// Discovery holds the checked parts of a tenant's OpenID Connect discovery document.
type Discovery struct {
	// Issuer equals the configured issuer.
	Issuer string
	// JWKSURI equals the derived JWKS URL.
	JWKSURI          string
	TokenEndpoint    string
	UserInfoEndpoint string
	// IntrospectionEndpoint is empty when the issuer doesn't offer introspection.
	IntrospectionEndpoint string
}

func splitScopes(scope string) []string {
	return strings.Split(scope, " ")
}
