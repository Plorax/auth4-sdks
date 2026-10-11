# @auth4/nextjs

Next.js App Router SDK for [auth4.dev](https://auth4.dev). Your Next.js server signs players in
through the hosted login page with the authorization-code flow and PKCE, keeps the tokens in an
encrypted `HttpOnly` cookie, and refreshes them on the server. It runs on Node.js, the Edge runtime
and Cloudflare (OpenNext), using only `jose` and the Web Crypto API.

```ts
// lib/auth4.ts: reads AUTH4_ORIGIN, AUTH4_TENANT_ID, AUTH4_CLIENT_ID, APP_BASE_URL, AUTH4_SECRET
import { Auth4Client } from "@auth4/nextjs/server";

export const auth4 = new Auth4Client({ refresh: true });
```

```ts
// proxy.ts (middleware.ts on Next.js 15)
import type { NextRequest } from "next/server";
import { auth4 } from "./lib/auth4";

export async function proxy(request: NextRequest) {
  return auth4.middleware(request);
}
```

`middleware()` answers `/auth/login`, `/auth/callback`, `/auth/logout`, `/auth/profile` and, when
`enableAccessTokenEndpoint` is on, `/auth/access-token`. Server code calls `auth4.getSession()` and
`auth4.getAccessToken()`; client components use `Auth4Provider` and `useUser()` from
`@auth4/nextjs`.

Register the app as a **Browser** application with `https://your-app/auth/callback` as a redirect
URI. Use `refresh: true` only when the application allows refresh tokens in the browser.

See the [Next.js quickstart](https://auth4.dev/docs/nextjs/), including a section for apps coming
from `@auth0/nextjs-auth0`, and [limitations](https://auth4.dev/docs/limitations/).

## Development

```sh
pnpm --filter @auth4/nextjs test    # unit tests against a mock issuer
pnpm --filter @auth4/nextjs build   # dist/ with both entry points
```

The integration test `tests/integration/auth4d-231.nextjs.test.ts` runs the SDK against the real
API composition, and `tests/e2e/auth4d-231.playwright.config.ts` drives `examples/nextjs` in a
browser.
