package auth4

import "errors"

// ErrorCode says why a token was refused. The values match @auth4/sdk-server's error codes.
type ErrorCode string

const (
	// CodeInvalidToken: the token is malformed, expired, revoked or not for this API.
	CodeInvalidToken ErrorCode = "invalid_token"
	// CodeJWKSUnavailable: signing keys could not be fetched from the configured issuer.
	CodeJWKSUnavailable ErrorCode = "jwks_unavailable"
	// CodeJWKSRefreshLimited: a key refresh was attempted too recently.
	CodeJWKSRefreshLimited ErrorCode = "jwks_refresh_limited"
	// CodeIntrospectionUnavailable: introspect mode could not check the session.
	CodeIntrospectionUnavailable ErrorCode = "introspection_unavailable"
)

// TokenError is returned when verification fails. Only CodeInvalidToken means the token itself is
// bad; the other codes are outages, which callers may report as 503 instead of signing players out.
type TokenError struct {
	Code    ErrorCode
	Message string
	// Err is the underlying cause, if any. It never contains the token.
	Err error
}

// Sentinels for errors.Is, which compares codes only.
var (
	ErrInvalidToken             = &TokenError{Code: CodeInvalidToken, Message: "The token is invalid."}
	ErrJWKSUnavailable          = &TokenError{Code: CodeJWKSUnavailable, Message: "Signing keys are unavailable."}
	ErrJWKSRefreshLimited       = &TokenError{Code: CodeJWKSRefreshLimited, Message: "A signing-key refresh was recently attempted."}
	ErrIntrospectionUnavailable = &TokenError{Code: CodeIntrospectionUnavailable, Message: "Introspection is unavailable."}
)

func (e *TokenError) Error() string {
	return "auth4: " + string(e.Code) + ": " + e.Message
}

func (e *TokenError) Unwrap() error { return e.Err }

// Is reports whether target is a *TokenError with the same code.
func (e *TokenError) Is(target error) bool {
	other, ok := target.(*TokenError)
	return ok && other.Code == e.Code
}

// IsOutage is true for every code except CodeInvalidToken.
func (e *TokenError) IsOutage() bool { return e.Code != CodeInvalidToken }

// IsOutage reports whether err is a *TokenError for an outage rather than a bad token.
func IsOutage(err error) bool {
	var tokenError *TokenError
	return errors.As(err, &tokenError) && tokenError.IsOutage()
}

func invalidToken(cause error) *TokenError {
	return &TokenError{Code: CodeInvalidToken, Message: "The token is invalid.", Err: cause}
}

// DiscoveryError is returned by Client.Discover when the issuer's metadata can't be used.
type DiscoveryError struct {
	Message string
	Err     error
}

func (e *DiscoveryError) Error() string { return "auth4: " + e.Message }

func (e *DiscoveryError) Unwrap() error { return e.Err }
