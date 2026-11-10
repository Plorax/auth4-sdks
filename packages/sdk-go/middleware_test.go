package auth4

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

type recorded struct {
	status int
	header http.Header
	body   map[string]string
}

func serve(t *testing.T, handler http.Handler, authorization string) recorded {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, "/profile", nil)
	if authorization != "" {
		request.Header.Set("Authorization", authorization)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	var body map[string]string
	_ = json.Unmarshal(response.Body.Bytes(), &body)
	return recorded{response.Code, response.Header(), body}
}

func profileHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, ok := AccessTokenFromContext(r.Context())
		subject := "anonymous"
		if ok {
			subject = token.Subject
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"sub": subject})
	})
}

func TestMiddlewareRequiresAValidToken(t *testing.T) {
	keys := testKeys(t)
	client := newTestClient(t, newFakeIssuer(publicJWK("k1", keys[0])), newClock(), nil)
	handler := client.RequireToken(profileHandler())

	ok := serve(t, handler, "Bearer "+sign(keys[0], accessHeader("k1"), accessClaims()))
	if ok.status != http.StatusOK || ok.body["sub"] != "usr_player0000000001" {
		t.Fatalf("valid token: %+v", ok)
	}

	missing := serve(t, handler, "")
	if missing.status != http.StatusUnauthorized || missing.header.Get("WWW-Authenticate") != `Bearer realm="auth4"` ||
		missing.body["error"] != "unauthorized" || missing.header.Get("Cache-Control") != "no-store" {
		t.Fatalf("missing token: %+v", missing)
	}

	for _, header := range []string{"Basic abc", "Bearer " + sign(keys[1], accessHeader("k1"), accessClaims())} {
		invalid := serve(t, handler, header)
		if invalid.status != http.StatusUnauthorized ||
			invalid.header.Get("WWW-Authenticate") != `Bearer realm="auth4", error="invalid_token"` {
			t.Fatalf("invalid token: %+v", invalid)
		}
	}
}

func TestMiddlewareOutages(t *testing.T) {
	key := testKeys(t)[0]
	issuer := newFakeIssuer(publicJWK("k1", key))
	issuer.jwksStatus = http.StatusInternalServerError
	token := "Bearer " + sign(key, accessHeader("k1"), accessClaims())

	var logged []ErrorCode
	client := newTestClient(t, issuer, newClock(), nil)
	outage := serve(t, client.Middleware(MiddlewareOptions{
		OnError: func(_ *http.Request, err *TokenError) { logged = append(logged, err.Code) },
	})(profileHandler()), token)
	if outage.status != http.StatusServiceUnavailable || outage.header.Get("Retry-After") != "5" ||
		outage.body["error"] != "temporarily_unavailable" {
		t.Fatalf("outage: %+v", outage)
	}
	if len(logged) != 1 || logged[0] != CodeJWKSUnavailable {
		t.Fatalf("OnError: %v", logged)
	}

	strict := newTestClient(t, issuer, newClock(), nil)
	unauthorized := serve(t, strict.Middleware(MiddlewareOptions{OutageAsUnauthorized: true})(profileHandler()), token)
	if unauthorized.status != http.StatusUnauthorized {
		t.Fatalf("OutageAsUnauthorized: %+v", unauthorized)
	}
}

func TestMiddlewareAllowAnonymous(t *testing.T) {
	key := testKeys(t)[0]
	client := newTestClient(t, newFakeIssuer(publicJWK("k1", key)), newClock(), nil)
	handler := client.Middleware(MiddlewareOptions{AllowAnonymous: true})(profileHandler())
	if anonymous := serve(t, handler, ""); anonymous.status != http.StatusOK || anonymous.body["sub"] != "anonymous" {
		t.Fatalf("anonymous: %+v", anonymous)
	}
	if invalid := serve(t, handler, "Bearer nope"); invalid.status != http.StatusUnauthorized {
		t.Fatalf("a presented invalid token must still fail: %+v", invalid)
	}
}

func TestRoleScopeAndGuestGuards(t *testing.T) {
	key := testKeys(t)[0]
	client := newTestClient(t, newFakeIssuer(publicJWK("k1", key)), newClock(), nil)
	moderator := "Bearer " + sign(key, accessHeader("k1"), with(accessClaims(), map[string]any{"auth4_roles": []string{"moderator"}}))
	guest := "Bearer " + sign(key, accessHeader("k1"), with(accessClaims(), map[string]any{"auth4_guest": true}))
	player := "Bearer " + sign(key, accessHeader("k1"), accessClaims())

	roles := client.RequireToken(RequireRole("moderator", "admin")(profileHandler()))
	if got := serve(t, roles, moderator); got.status != http.StatusOK {
		t.Fatalf("moderator: %+v", got)
	}
	if got := serve(t, roles, player); got.status != http.StatusForbidden || got.body["error"] != "forbidden" {
		t.Fatalf("player without the role: %+v", got)
	}

	nonGuest := client.RequireToken(RequireNonGuest(profileHandler()))
	if got := serve(t, nonGuest, guest); got.status != http.StatusForbidden {
		t.Fatalf("guest: %+v", got)
	}
	if got := serve(t, nonGuest, player); got.status != http.StatusOK {
		t.Fatalf("upgraded player: %+v", got)
	}

	scoped := client.RequireToken(RequireScope("email")(profileHandler()))
	got := serve(t, scoped, player)
	if got.status != http.StatusForbidden ||
		got.header.Get("WWW-Authenticate") != `Bearer realm="auth4", error="insufficient_scope", scope="email"` {
		t.Fatalf("missing scope: %+v", got)
	}
	if got := serve(t, client.RequireToken(RequireScope("profile")(profileHandler())), player); got.status != http.StatusOK {
		t.Fatalf("granted scope: %+v", got)
	}

	// A guard without the middleware in front of it has no token to check.
	if got := serve(t, RequireRole("moderator")(profileHandler()), moderator); got.status != http.StatusUnauthorized {
		t.Fatalf("guard without middleware: %+v", got)
	}
}
