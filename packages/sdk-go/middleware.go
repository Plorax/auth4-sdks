package auth4

import (
	"context"
	"errors"
	"net/http"
)

// MiddlewareOptions configure Client.Middleware.
type MiddlewareOptions struct {
	// AllowAnonymous lets requests without an Authorization header through with no token in the
	// context. A header that is present but invalid is still refused.
	AllowAnonymous bool
	// OutageAsUnauthorized answers outages (keys or introspection unavailable) with 401 instead of
	// 503 with Retry-After: 5. The default 503 keeps players signed in during an outage.
	OutageAsUnauthorized bool
	// OnError is called for every refused credential, for logging. The error carries a code and a
	// cause but never the token.
	OnError func(r *http.Request, err *TokenError)
}

type contextKey struct{}

// WithAccessToken returns a copy of ctx that carries token. The middleware calls it; tests of your
// own handlers can too.
func WithAccessToken(ctx context.Context, token *AccessToken) context.Context {
	return context.WithValue(ctx, contextKey{}, token)
}

// AccessTokenFromContext returns the verified token the middleware stored for this request.
func AccessTokenFromContext(ctx context.Context) (*AccessToken, bool) {
	token, ok := ctx.Value(contextKey{}).(*AccessToken)
	return token, ok && token != nil
}

// Middleware returns net/http middleware that verifies the request's Bearer access token and
// stores it in the request context (see AccessTokenFromContext). A missing or invalid token gets
// 401 with WWW-Authenticate: Bearer realm="auth4"; an outage gets 503 with Retry-After: 5.
func (c *Client) Middleware(options MiddlewareOptions) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			header := r.Header.Get("Authorization")
			if header == "" && options.AllowAnonymous {
				next.ServeHTTP(w, r)
				return
			}
			token, err := c.ValidateAuthorizationHeader(r.Context(), header)
			if err != nil {
				var tokenError *TokenError
				if !errors.As(err, &tokenError) {
					tokenError = invalidToken(err)
				}
				if options.OnError != nil {
					options.OnError(r, tokenError)
				}
				if tokenError.IsOutage() && !options.OutageAsUnauthorized {
					w.Header().Set("Retry-After", "5")
					writeError(w, http.StatusServiceUnavailable, "temporarily_unavailable")
					return
				}
				challenge := `Bearer realm="auth4"`
				if header != "" {
					challenge += `, error="invalid_token"`
				}
				w.Header().Set("WWW-Authenticate", challenge)
				writeError(w, http.StatusUnauthorized, "unauthorized")
				return
			}
			next.ServeHTTP(w, r.WithContext(WithAccessToken(r.Context(), token)))
		})
	}
}

// RequireToken is Middleware with the default options: every request needs a valid token.
func (c *Client) RequireToken(next http.Handler) http.Handler {
	return c.Middleware(MiddlewareOptions{})(next)
}

// RequireRole lets a request through only when its verified token has at least one of roles, and
// answers 403 otherwise. Use it inside Client.Middleware; without a token it answers 401.
func RequireRole(roles ...string) func(http.Handler) http.Handler {
	return requireToken(func(token *AccessToken) bool { return token.HasAnyRole(roles...) }, "")
}

// RequireScope lets a request through only when scope was granted, and answers 403 with
// error="insufficient_scope" otherwise.
func RequireScope(scope string) func(http.Handler) http.Handler {
	return requireToken(func(token *AccessToken) bool { return token.HasScope(scope) }, scope)
}

// RequireNonGuest lets only players who have upgraded their guest account through, and answers
// 403 for guests.
func RequireNonGuest(next http.Handler) http.Handler {
	return requireToken(func(token *AccessToken) bool { return !token.IsGuest }, "")(next)
}

func requireToken(allowed func(*AccessToken) bool, scope string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token, ok := AccessTokenFromContext(r.Context())
			if !ok {
				w.Header().Set("WWW-Authenticate", `Bearer realm="auth4"`)
				writeError(w, http.StatusUnauthorized, "unauthorized")
				return
			}
			if !allowed(token) {
				if scopeNamePattern.MatchString(scope) {
					w.Header().Set("WWW-Authenticate", `Bearer realm="auth4", error="insufficient_scope", scope="`+scope+`"`)
				}
				writeError(w, http.StatusForbidden, "forbidden")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func writeError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	// code is always one of this file's constants, so it needs no escaping.
	_, _ = w.Write([]byte(`{"error":"` + code + `"}`))
}
