# auth4.dev Go server SDK

Package `auth4` verifies auth4.dev access tokens in Go game backends and APIs, and adds `net/http`
middleware. It matches [`@auth4/sdk-server`](../sdk-server) and the
[.NET SDK](../sdk-dotnet): same checks, same error codes, same introspect mode. It uses the
standard library only.

```
module github.com/Plorax/auth4-sdks/packages/sdk-go
```

The guide is [auth4.dev/docs/go](https://auth4.dev/docs/go/).

## What it checks

- The issuer is configured, never read from a token: `{AUTH_ORIGIN}/t/{tenantId}`. Signing keys
  come only from `{issuer}/.well-known/jwks.json`; `Discover` optionally confirms the issuer's
  discovery document matches.
- Access tokens: RS256 with a cached key, `typ` `at+jwt`, `iss`, `aud`, `exp`, `nbf`, `tenant_id`,
  `token_use` `access`, a lifetime of at most five minutes and the strict claim contract from
  `packages/contracts`. Unknown or duplicate claims make the token invalid.
- ID tokens have their own method, `ValidateIDToken`, with `typ` `JWT`, `token_use` `id`, the
  client ID as audience and an optional nonce. Neither method accepts the other kind of token.
- Signing keys are cached for five minutes. An unknown `kid` triggers one refresh per 30-second
  cooldown, so key rotation needs no restart. Concurrent requests share one fetch.
- `IsGuest`, `Roles`, `HasRole`, `HasAnyRole` and `Metadata` read the signed `auth4_guest`,
  `auth4_roles` and `auth4_meta` claims.
- Introspect mode (AUTH4D-155) is opt-in and fails closed with `introspection_unavailable`.

Failures are `*auth4.TokenError`. Only `invalid_token` means the token is bad; the other codes are
outages (`auth4.IsOutage`). The middleware answers outages with 503 and `Retry-After: 5`.

| File                                     | Contents                                         |
| ---------------------------------------- | ------------------------------------------------ |
| [`client.go`](client.go)                 | `Options`, `New`, `Discover`, token validation   |
| [`middleware.go`](middleware.go)         | `Middleware`, `RequireRole`, `RequireNonGuest` … |
| [`introspection.go`](introspection.go)   | Introspect mode                                  |
| [`jwks.go`](jwks.go), [`jwt.go`](jwt.go) | Key cache and RS256 verification                 |
| [`rules.go`](rules.go)                   | Copies of the contract rules                     |

## Test

```sh
cd packages/sdk-go
go vet ./...
go test ./...
```

The tests generate RSA keys in memory and answer JWKS, discovery and introspection requests with a
fake `http.RoundTripper`; nothing calls a live endpoint. `conformance_test.go` also checks every
token in [`../sdk-dotnet/tests/fixtures/conformance.json`](../sdk-dotnet/tests/fixtures/conformance.json),
whose verdicts the TypeScript and .NET SDKs share.

## Publishing

The module isn't tagged yet. Tagging `packages/sdk-go/v0.1.0` (Go's subdirectory-module tag form)
is an owner action under AUTH4D-151; until then, use a `replace` directive pointing at a copy of
the repository.

## Licence

MIT. See [LICENSE](LICENSE).
