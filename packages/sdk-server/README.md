# @auth4/sdk-server

Server SDK for [auth4.dev](https://auth4.dev). Your game API uses it to verify the auth4.dev access
token on each request: it checks the signature, issuer, project, audience and expiry, and fetches
signing keys only from your configured issuer. Opt-in introspection also refuses revoked sessions
straight away.

```sh
npm install @auth4/sdk-server
```

```ts
import { Auth4ServerClient, authenticateRequest, unauthorizedResponse } from "@auth4/sdk-server";

const auth4 = new Auth4ServerClient({
  tenantId: "ten_abcdefghijklmnop",
  issuer: "https://auth.auth4.dev/t/ten_abcdefghijklmnop",
  audience: "cli_…", // the client ID of the application calling your API
});

export async function handle(request: Request): Promise<Response> {
  const claims = await authenticateRequest(request, auth4);
  if (!claims) return unauthorizedResponse();
  return Response.json({ player: claims.sub });
}
```

It runs on Node.js 22 or later, Cloudflare Workers and other runtimes with `fetch` and Web Crypto.
The package is ES2022 JavaScript with TypeScript declarations, built on `jose` and `zod`.

See the [server quickstart](https://auth4.dev/docs/server/) for Node.js, Workers and Hono examples,
and [limitations](https://auth4.dev/docs/limitations/) for what isn't supported yet.
