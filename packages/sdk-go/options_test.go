package auth4

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"
)

func TestOptionsAreChecked(t *testing.T) {
	valid := Options{TenantID: testTenant, Issuer: testIssuer, Audience: testAudience}
	cases := map[string]func(*Options){
		"bad tenant":           func(o *Options) { o.TenantID = "tenant" },
		"no issuer":            func(o *Options) { o.Issuer = "" },
		"plain http":           func(o *Options) { o.Issuer = "http://auth.example.test/t/" + testTenant },
		"other tenant path":    func(o *Options) { o.Issuer = "https://auth.example.test/t/ten_qrstuvwxyzabcdef" },
		"trailing slash":       func(o *Options) { o.Issuer = testIssuer + "/" },
		"query":                func(o *Options) { o.Issuer = testIssuer + "?x=1" },
		"fragment":             func(o *Options) { o.Issuer = testIssuer + "#x" },
		"credentials":          func(o *Options) { o.Issuer = "https://user:pw@auth.example.test/t/" + testTenant },
		"uppercase host":       func(o *Options) { o.Issuer = "https://AUTH.example.test/t/" + testTenant },
		"default port":         func(o *Options) { o.Issuer = "https://auth.example.test:443/t/" + testTenant },
		"no audience":          func(o *Options) { o.Audience = "" },
		"management audience":  func(o *Options) { o.Audience = managementAudience },
		"short cache":          func(o *Options) { o.JWKSCacheTTL = time.Second },
		"long cooldown":        func(o *Options) { o.JWKSRefreshCooldown = time.Hour },
		"long fetch timeout":   func(o *Options) { o.JWKSFetchTimeout = time.Minute },
		"long tolerance":       func(o *Options) { o.ClockTolerance = 61 * time.Second },
		"fractional tolerance": func(o *Options) { o.ClockTolerance = 1500 * time.Millisecond },
		"origin with a path":   func(o *Options) { o.Issuer = ""; o.AuthOrigin = "https://auth.example.test/t" },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			options := valid
			change(&options)
			if _, err := New(options); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
	if _, err := New(valid); err != nil {
		t.Fatalf("valid options: %v", err)
	}
}

func TestIssuerDerivation(t *testing.T) {
	for origin, want := range map[string]string{
		"https://auth.auth4.dev":     "https://auth.auth4.dev/t/" + testTenant,
		"https://auth.auth4.dev/":    "https://auth.auth4.dev/t/" + testTenant,
		"https://AUTH.auth4.dev:443": "https://auth.auth4.dev/t/" + testTenant,
		"http://localhost:8787":      "http://localhost:8787/t/" + testTenant,
		"http://127.0.0.1:8787":      "http://127.0.0.1:8787/t/" + testTenant,
		"http://[::1]:8787":          "http://[::1]:8787/t/" + testTenant,
	} {
		got, err := IssuerFor(origin, testTenant)
		if err != nil || got != want {
			t.Fatalf("IssuerFor(%q) = %q, %v; want %q", origin, got, err, want)
		}
		client, err := New(Options{TenantID: testTenant, AuthOrigin: origin, Audience: testAudience})
		if err != nil || client.Issuer() != want || client.JWKSURL() != want+"/.well-known/jwks.json" {
			t.Fatalf("AuthOrigin %q: %v %v", origin, client, err)
		}
	}
	for _, origin := range []string{"http://auth.auth4.dev", "auth.auth4.dev", "https://auth.auth4.dev?x=1"} {
		if _, err := IssuerFor(origin, testTenant); err == nil {
			t.Fatalf("IssuerFor(%q) should fail", origin)
		}
	}
	if _, err := IssuerFor("https://auth.auth4.dev", "tenant"); err == nil {
		t.Fatal("IssuerFor should check the tenant ID")
	}
}

func discoveryDocument() map[string]any {
	return map[string]any{
		"issuer":                                testIssuer,
		"jwks_uri":                              testJWKSURL,
		"token_endpoint":                        "https://auth.example.test/oauth/token?tenant_id=" + testTenant,
		"userinfo_endpoint":                     "https://auth.example.test/oauth/userinfo?tenant_id=" + testTenant,
		"introspection_endpoint":                "https://auth.example.test/oauth/introspect?tenant_id=" + testTenant,
		"id_token_signing_alg_values_supported": []string{"RS256"},
	}
}

func TestDiscover(t *testing.T) {
	issuer := newFakeIssuer()
	issuer.discovery = discoveryDocument()
	client := introspectingClient(t, issuer, newClock(), nil)
	discovery, err := client.Discover(context.Background())
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if discovery.Issuer != testIssuer || discovery.JWKSURI != testJWKSURL ||
		discovery.IntrospectionEndpoint != client.IntrospectionURL() || discovery.TokenEndpoint == "" {
		t.Fatalf("unexpected discovery: %+v", discovery)
	}

	for name, change := range map[string]map[string]any{
		"other issuer":     {"issuer": "https://evil.example.test/t/" + testTenant},
		"other jwks":       {"jwks_uri": "https://evil.example.test/jwks.json"},
		"no RS256":         {"id_token_signing_alg_values_supported": []string{"HS256"}},
		"no introspection": {"introspection_endpoint": nil},
	} {
		t.Run(name, func(t *testing.T) {
			issuer.discovery = with(discoveryDocument(), change)
			_, err := client.Discover(context.Background())
			var discoveryError *DiscoveryError
			if !errors.As(err, &discoveryError) {
				t.Fatalf("expected a DiscoveryError, got %v", err)
			}
		})
	}

	// Without introspect mode an issuer that doesn't advertise it is fine.
	issuer.discovery = with(discoveryDocument(), map[string]any{"introspection_endpoint": nil})
	plain := newTestClient(t, issuer, newClock(), nil)
	if _, err := plain.Discover(context.Background()); err != nil {
		t.Fatalf("Discover without introspection: %v", err)
	}
	if plain.IntrospectionURL() != "" {
		t.Fatal("IntrospectionURL should be empty when introspect mode is off")
	}
}

func TestDiscoverUnavailable(t *testing.T) {
	client := newTestClient(t, newFakeIssuer(), newClock(), func(o *Options) {
		o.HTTPClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return respond(http.StatusBadGateway, `{}`, nil), nil
		})}
	})
	var discoveryError *DiscoveryError
	if _, err := client.Discover(context.Background()); !errors.As(err, &discoveryError) {
		t.Fatalf("expected a DiscoveryError, got %v", err)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
