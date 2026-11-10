# auth4.dev .NET server SDK

`Auth4.Server` verifies auth4.dev access tokens in .NET game backends and Unity dedicated servers.
`Auth4.Server.AspNetCore` adds an ASP.NET Core authentication handler. Both match
[`@auth4/sdk-server`](../sdk-server): same checks, same error codes, same introspect mode.

| Project                                                              | Targets                         |
| -------------------------------------------------------------------- | ------------------------------- |
| [`src/Auth4.Server`](src/Auth4.Server)                               | `net8.0`, `netstandard2.1`      |
| [`src/Auth4.Server.AspNetCore`](src/Auth4.Server.AspNetCore)         | `net8.0` (ASP.NET Core 8+)      |
| [`tests/Auth4.Server.Tests`](tests/Auth4.Server.Tests)               | NUnit, local JWKS fixtures      |
| [`tests/fixtures/conformance.json`](tests/fixtures/conformance.json) | Verdicts shared with the TS SDK |

The guide is [auth4.dev/docs/dotnet](https://auth4.dev/docs/dotnet/).

## What it checks

- The issuer is configured, never read from a token: `{AUTH_ORIGIN}/t/{tenantId}`. Signing keys
  come only from `{issuer}/.well-known/jwks.json`; `DiscoverAsync()` optionally confirms the
  issuer's discovery document matches.
- Access tokens: RS256 with a cached key, `typ` `at+jwt`, `iss`, `aud`, `exp`, `nbf`, `tenant_id`,
  `token_use` `access`, a lifetime of at most five minutes and the strict claim contract from
  `packages/contracts`. Unknown claims make the token invalid.
- ID tokens have their own method, `ValidateIdTokenAsync`, with `typ` `JWT`, `token_use` `id`, the
  client ID as audience and an optional nonce. Neither method accepts the other kind of token.
- Signing keys are cached for five minutes. An unknown `kid` triggers one refresh per 30-second
  cooldown, so key rotation needs no restart. Concurrent requests share one fetch.
- `IsGuest`, `Roles`, `HasRole`, `HasAnyRole` and `Metadata` read the signed `auth4_guest`,
  `auth4_roles` and `auth4_meta` claims.
- Introspect mode (AUTH4D-155) is opt-in and fails closed with `IntrospectionUnavailable`.

Failures throw `Auth4TokenException`. Only `InvalidToken` means the token is bad; the other codes
are outages. The ASP.NET Core handler answers outages with 503 and `Retry-After: 5`.

## Diagnostics (net8.0 only)

AUTH4D-391: the net8.0 build emits `System.Diagnostics` traces and metrics. The netstandard2.1
build (Unity dedicated servers) emits none. Nothing is exported unless your host subscribes; the SDK
adds no OpenTelemetry dependency.

| Signal         | Name           | Notes                                                                                                        |
| -------------- | -------------- | ------------------------------------------------------------------------------------------------------------ |
| ActivitySource | `Auth4.Server` | Activities `auth4.validate_access_token`, `auth4.validate_id_token`, `auth4.jwks_fetch`, `auth4.introspect`. |
| Meter          | `Auth4.Server` | Histogram `auth4.server.operation.duration` (seconds) and counter `auth4.server.operation.count`.            |

Every activity and measurement has exactly two tags: `auth4.operation` (the four operations above)
and `auth4.outcome`:

- `success`.
- `invalid_token`: the credential is bad (`Auth4TokenErrorCode.InvalidToken`, including an inactive session).
- `unavailable`: the JWKS or introspection endpoint could not be used (`JwksUnavailable`, `IntrospectionUnavailable`).
- `refresh_limited`: a signing-key refresh was refused by the cooldown (`JwksRefreshLimited`).
- `error`: any other exception.

`jwks_fetch` counts network fetches and refused refreshes, not cache hits; `introspect` counts calls to
the endpoint, not cached answers. Activities with `unavailable`, `refresh_limited` or `error` have
status Error; `invalid_token` does not, because a bad token is not a fault in your service. The SDK
records no tokens, credentials, claims, player or project IDs, request bodies or exception messages,
and verification results and exceptions are unchanged.

Subscribe in ASP.NET Core with the OpenTelemetry packages you already use:

```csharp
using Auth4.Server;
using OpenTelemetry.Metrics;
using OpenTelemetry.Trace;

builder.Services.AddOpenTelemetry()
    .WithTracing(tracing => tracing
        .AddSource(Auth4Diagnostics.ActivitySourceName)
        .AddOtlpExporter())
    .WithMetrics(metrics => metrics
        .AddMeter(Auth4Diagnostics.MeterName)
        .AddOtlpExporter());
```

To alert on dependency outages rather than bad tokens, filter `auth4.outcome` to `unavailable` and
`refresh_limited`.

## Build and test

```sh
dotnet test packages/sdk-dotnet/tests/Auth4.Server.Tests
```

The tests need the .NET 8 runtime. They generate RSA keys in memory and serve JWKS, discovery and
introspection through a fake `HttpMessageHandler`; nothing calls a live endpoint.

`tests/fixtures/conformance.json` holds a public test key and signed tokens with the verdict both
SDKs must reach.

To regenerate the fixture after a contract change (the private key is discarded):

```sh
AUTH4D169_WRITE_FIXTURE=1 dotnet test packages/sdk-dotnet/tests/Auth4.Server.Tests --filter Conformance
```

## Unity dedicated servers

Build `src/Auth4.Server` for `netstandard2.1` and copy `Auth4.Server.dll` into the server project
with `System.Text.Json` and its dependencies, which Unity doesn't include. Use it only in server
builds: game clients use the [Unity SDK](../sdk-unity) and never verify tokens themselves.

## Publishing

The packages aren't on NuGet yet. Publishing is an owner action under AUTH4D-151; until then,
reference the projects from the repository.

## Licence

MIT. See [LICENSE](LICENSE).
