# Changelog

## [Unreleased]

### Added

- AUTH4D-324: access tokens may carry a `name` claim, the player's `Name#1234`, when the project
  turns it on. It is accepted when it matches `^[^#]{1,64}#[0-9]{4}$`; a malformed `name` makes the
  token invalid.
- AUTH4D-258: access and ID tokens may carry an `idp` claim naming the sign-in method. It is
  accepted when it matches `^[a-z][a-z0-9_]{1,31}$`; a malformed `idp` makes the token invalid.

## [0.1.1] - 2026-10-10

### Fixed

- Discovery, JWKS and introspection requests now send `User-Agent: auth4-python/<version>`. With
  the default transport, the SDK sent `Python-urllib/3.x`, which Cloudflare answers with 403
  (error 1010) on auth.auth4.dev and auth.staging.auth4.dev, so token validation failed as
  `jwks_unavailable` (BUG-AUTH4D-198-1). Custom transports receive the header and may replace it.
- `USER_AGENT` and `__version__` are exported from `auth4`.

## [0.1.0] - 2026-10-07

### Added

- AUTH4D-171: `Auth4ServerClient` with access-token and ID-token validation, discovery checks and
  opt-in introspect mode, plus the FastAPI and Django integrations.
