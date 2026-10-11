# @auth4/sdk-browser

Browser SDK for [auth4.dev](https://auth4.dev). It sends players to the hosted login page, completes
the authorization-code flow with PKCE, and keeps tokens in memory. It also supports guest sessions,
upgrading a guest to a full account, and restoring a session after a reload.

```sh
npm install @auth4/sdk-browser
```

```ts
import { Auth4BrowserClient } from "@auth4/sdk-browser";

const auth4 = new Auth4BrowserClient({
  issuer: "https://auth.auth4.dev/t/ten_replace_with_your_tenant",
  clientId: "cli_replace_with_your_browser_client",
  redirectUri: `${window.location.origin}${window.location.pathname}`,
});

// On every page load, including the redirect URI.
const result = await auth4.restoreSession();
if (result.status === "signed_out") await auth4.login(); // navigates to hosted login
```

The package is ES2022 JavaScript with TypeScript declarations and has no runtime dependencies.

See the [browser quickstart](https://auth4.dev/docs/browser/) for the full guide, and
[limitations](https://auth4.dev/docs/limitations/) for what isn't supported yet.
