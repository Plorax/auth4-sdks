# auth4.dev Python server SDK

`auth4` verifies auth4.dev access tokens and ID tokens in Python game backends, with integrations
for FastAPI (`auth4.fastapi`) and Django (`auth4.django`). It matches
[`@auth4/sdk-server`](../sdk-server): same checks, same error codes, same introspect mode. It needs
Python 3.10 or later and depends only on `cryptography`.

| Path                                           | Contents                                 |
| ---------------------------------------------- | ---------------------------------------- |
| [`src/auth4`](src/auth4)                       | The client, token types and errors       |
| [`src/auth4/fastapi.py`](src/auth4/fastapi.py) | `Auth4Bearer`, a FastAPI dependency      |
| [`src/auth4/django.py`](src/auth4/django.py)   | `auth4_required`, `get_client`, settings |
| [`tests`](tests)                               | pytest, local fixtures only              |
| [`CHANGELOG.md`](CHANGELOG.md)                 | Changes by version                       |

The guide is [auth4.dev/docs/python](https://auth4.dev/docs/python/).

## What it checks

- The issuer is configured, never read from a token: `{AUTH_ORIGIN}/t/{tenant_id}`. Signing keys
  come only from `{issuer}/.well-known/jwks.json`; `discover()` optionally confirms the issuer's
  discovery document matches.
- Access tokens: RS256 with a cached key, `typ` `at+jwt`, `iss`, `aud`, `exp`, `nbf`, `tenant_id`,
  `token_use` `access`, a lifetime of at most five minutes and the strict claim contract from
  `packages/contracts`. Unknown or duplicate claims make the token invalid.
- ID tokens have their own method, `validate_id_token`, with `typ` `JWT`, `token_use` `id`, the
  client ID as audience and an optional nonce. Neither method accepts the other kind of token.
- Signing keys are cached for five minutes. An unknown `kid` triggers one refresh per 30-second
  cooldown, so key rotation needs no restart. Concurrent requests share one fetch.
- `is_guest`, `roles`, `has_role`, `has_any_role` and `metadata` read the signed `auth4_guest`,
  `auth4_roles` and `auth4_meta` claims.
- Introspect mode (AUTH4D-155) is opt-in and fails closed with `introspection_unavailable`.

Failures raise `Auth4TokenError`. Only `invalid_token` means the token is bad; the other codes are
outages (`is_outage`). The FastAPI and Django integrations answer outages with 503 and
`Retry-After: 5`.

Discovery, JWKS and introspection requests send `User-Agent: auth4-python/<version>` (the
`USER_AGENT` constant). Cloudflare refuses the standard library's default `Python-urllib/3.x` on the
auth4.dev hosts. A custom `transport=` receives the header on each `HttpRequest` and may replace
it; the default transport keeps a `User-Agent` that a request already carries.

The client is synchronous and thread-safe. `Auth4Bearer` is a plain dependency, so FastAPI runs it in
its threadpool; `auth4_required` runs the check through `sync_to_async` for async Django views.

## Test

```sh
cd packages/sdk-python
python -m venv .venv
.venv/bin/pip install -e ".[test]"
.venv/bin/python -m pytest
.venv/bin/python -m ruff check src tests
.venv/bin/python -m ruff format --check src tests
.venv/bin/python -m mypy
```

The tests generate RSA keys in memory and serve JWKS, discovery and introspection through a fake
transport or a loopback HTTP server; nothing calls a live endpoint. `tests/test_conformance.py` runs
the shared verdicts in
[`packages/sdk-dotnet/tests/fixtures/conformance.json`](../sdk-dotnet/tests/fixtures/conformance.json),
which the TypeScript and C# SDKs also reach.

## Publishing

The package isn't on PyPI yet. Publishing is an owner action under AUTH4D-151; until then, install
it from the repository with `pip install -e "path/to/auth4/packages/sdk-python[fastapi]"`. The
`Private :: Do Not Upload` classifier blocks an accidental upload; remove it when publishing.

## Licence

MIT. See [LICENSE](LICENSE).
