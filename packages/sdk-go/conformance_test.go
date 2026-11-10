package auth4

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"testing"
	"time"
)

// The verdicts in packages/sdk-dotnet/tests/fixtures/conformance.json (AUTH4D-169) hold for every
// server SDK: @auth4/sdk-server and Auth4.Server check them too.
const conformanceFixture = "../sdk-dotnet/tests/fixtures/conformance.json"

type conformanceCase struct {
	Name  string `json:"name"`
	Kind  string `json:"kind"`
	Valid bool   `json:"valid"`
	Token string `json:"token"`
}

type conformance struct {
	TenantID string            `json:"tenantId"`
	Issuer   string            `json:"issuer"`
	Audience string            `json:"audience"`
	Now      int64             `json:"now"`
	JWKS     json.RawMessage   `json:"jwks"`
	Cases    []conformanceCase `json:"cases"`
}

func TestConformance(t *testing.T) {
	data, err := os.ReadFile(conformanceFixture)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var fixture conformance
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	if len(fixture.Cases) < 10 {
		t.Fatalf("fixture has only %d cases", len(fixture.Cases))
	}
	for _, item := range fixture.Cases {
		t.Run(item.Name, func(t *testing.T) {
			client, err := New(Options{
				TenantID: fixture.TenantID,
				Issuer:   fixture.Issuer,
				Audience: fixture.Audience,
				HTTPClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
					if r.URL.String() != fixture.Issuer+"/.well-known/jwks.json" {
						t.Errorf("unexpected request to %s", r.URL)
					}
					return respond(http.StatusOK, string(fixture.JWKS), nil), nil
				})},
				Now: func() time.Time { return time.Unix(fixture.Now, 0) },
			})
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			if item.Kind == "id" {
				_, err = client.ValidateIDToken(context.Background(), item.Token, fixture.Audience, "")
			} else {
				_, err = client.ValidateAccessToken(context.Background(), item.Token)
			}
			if item.Valid && err != nil {
				t.Fatalf("expected valid, got %v", err)
			}
			if !item.Valid && !errors.Is(err, ErrInvalidToken) {
				t.Fatalf("expected invalid_token, got %v", err)
			}
		})
	}
}
