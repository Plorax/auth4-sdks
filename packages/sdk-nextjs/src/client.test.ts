import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { NextRequest } from "next/server.js";
import { beforeAll, describe, expect, it } from "vitest";
import { Auth4Client, ConfigurationError, type Auth4ClientOptions, type User } from "./server.ts";

// AUTH4D-231 unit tests: the middleware routes against a mock auth4.dev issuer that signs real
// RS256 ID tokens. Every network call goes through the injected fetch.

const AUTH = "https://auth.example.test";
const TENANT = "ten_AAAAAAAAAAAAAAAA";
const CLIENT = "cli_BBBBBBBBBBBBBBBB";
const APP = "https://play.example.test";
const ISSUER = `${AUTH}/t/${TENANT}`;
const SECRET = "unit-test-secret-0123456789abcdefghijklmnop";
const START = Date.UTC(2026, 9, 11, 12, 0, 0);

let privateKey: CryptoKey;
let publicJwk: Record<string, unknown>;

beforeAll(async () => {
  const pair = await generateKeyPair("RS256", { extractable: true });
  privateKey = pair.privateKey;
  publicJwk = { ...(await exportJWK(pair.publicKey)), kid: "k1", alg: "RS256", use: "sig" };
});

interface IssuerOptions {
  /** Overrides claims of the next ID token. */
  idClaims?: Record<string, unknown>;
  refreshAnswer?: "rotate" | "invalid_grant" | "unavailable";
}

class MockIssuer {
  clock = START;
  nonce = "";
  readonly tokenForms: URLSearchParams[] = [];
  readonly revoked: URLSearchParams[] = [];
  readonly requests: string[] = [];
  options: IssuerOptions = {};
  #counter = 0;

  readonly fetch: typeof fetch = async (input, init) => {
    const url = new URL(typeof input === "string" ? input : input.toString());
    this.requests.push(url.toString());
    // Server-side calls never carry an Origin, so they are not browser CORS requests.
    expect(new Headers(init?.headers).has("Origin")).toBe(false);
    if (url.toString() === `${ISSUER}/.well-known/openid-configuration`) {
      return Response.json({
        issuer: ISSUER,
        authorization_endpoint: `${AUTH}/oauth/authorize?tenant_id=${TENANT}`,
        token_endpoint: `${AUTH}/oauth/token?tenant_id=${TENANT}`,
        userinfo_endpoint: `${AUTH}/oauth/userinfo?tenant_id=${TENANT}`,
        jwks_uri: `${ISSUER}/.well-known/jwks.json`,
        revocation_endpoint: `${AUTH}/oauth/revoke?tenant_id=${TENANT}`,
        response_types_supported: ["code"],
        code_challenge_methods_supported: ["S256"],
        id_token_signing_alg_values_supported: ["RS256"],
      });
    }
    if (url.toString() === `${ISSUER}/.well-known/jwks.json`) {
      return Response.json({ keys: [publicJwk] });
    }
    const form = new URLSearchParams(String(init?.body ?? ""));
    if (url.pathname === "/oauth/token") {
      this.tokenForms.push(form);
      if (form.get("grant_type") === "refresh_token") {
        if (this.options.refreshAnswer === "invalid_grant") {
          return Response.json({ error: "invalid_grant" }, { status: 400 });
        }
        if (this.options.refreshAnswer === "unavailable") {
          return Response.json({ error: "temporarily_unavailable" }, { status: 503 });
        }
        return Response.json(await this.tokens(false));
      }
      return Response.json(await this.tokens(true));
    }
    if (url.pathname === "/oauth/revoke") {
      this.revoked.push(form);
      return Response.json({});
    }
    return new Response(null, { status: 404 });
  };

  async idToken(withNonce: boolean): Promise<string> {
    const now = Math.floor(this.clock / 1_000);
    const claims: Record<string, unknown> = {
      iss: ISSUER,
      sub: "usr_player0000000001",
      aud: CLIENT,
      jti: `jti_${this.#counter}`,
      iat: now,
      exp: now + 300,
      tenant_id: TENANT,
      token_use: "id",
      auth_time: now - 10,
      email: "player@example.test",
      email_verified: true,
      ...(withNonce ? { nonce: this.nonce } : {}),
      ...this.options.idClaims,
    };
    for (const [claim, value] of Object.entries(claims)) {
      if (value === undefined) delete claims[claim];
    }
    return new SignJWT(claims)
      .setProtectedHeader({ alg: "RS256", typ: "JWT", kid: "k1" })
      .sign(privateKey);
  }

  async tokens(withNonce: boolean) {
    this.#counter += 1;
    return {
      access_token: `access-${this.#counter}`,
      token_type: "Bearer",
      expires_in: 300,
      scope: "openid profile email offline_access",
      refresh_token: `rfr_refresh-${this.#counter}`,
      id_token: await this.idToken(withNonce),
    };
  }
}

function setup(options: Partial<Auth4ClientOptions> = {}) {
  const issuer = new MockIssuer();
  const auth4 = new Auth4Client({
    authOrigin: AUTH,
    tenantId: TENANT,
    clientId: CLIENT,
    appBaseUrl: APP,
    secret: SECRET,
    fetch: issuer.fetch,
    now: () => issuer.clock,
    ...options,
  });
  return { issuer, auth4 };
}

/** A browser that keeps cookies per path, like the real one does for the transaction cookie. */
class Browser {
  readonly jar = new Map<string, { value: string; path: string }>();

  request(path: string, init: { method?: string; headers?: Record<string, string> } = {}) {
    const url = new URL(path, APP);
    const cookie = [...this.jar]
      .filter(([, entry]) => url.pathname.startsWith(entry.path))
      .map(([name, entry]) => `${name}=${entry.value}`)
      .join("; ");
    return new NextRequest(url, {
      method: init.method ?? "GET",
      headers: { ...(cookie ? { cookie } : {}), ...init.headers },
    });
  }

  store(response: Response): void {
    for (const header of response.headers.getSetCookie()) {
      const [pair, ...attributes] = header.split(";").map((part) => part.trim());
      const index = pair!.indexOf("=");
      const name = pair!.slice(0, index);
      const value = decodeURIComponent(pair!.slice(index + 1));
      const path = attributes.find((part) => /^path=/iu.test(part))?.slice(5) ?? "/";
      const maxAge = attributes.find((part) => /^max-age=/iu.test(part));
      if (maxAge && Number(maxAge.slice(8)) <= 0) this.jar.delete(name);
      else this.jar.set(name, { value, path });
    }
  }

  names(): string[] {
    return [...this.jar.keys()];
  }
}

async function startLogin(auth4: Auth4Client, browser: Browser, issuer: MockIssuer, query = "") {
  const response = await auth4.middleware(browser.request(`/auth/login${query}`));
  expect(response.status).toBe(302);
  browser.store(response);
  const location = new URL(response.headers.get("Location")!);
  issuer.nonce = location.searchParams.get("nonce")!;
  return { response, location, state: location.searchParams.get("state")! };
}

async function signIn(auth4: Auth4Client, browser: Browser, issuer: MockIssuer, query = "") {
  const { state } = await startLogin(auth4, browser, issuer, query);
  const callback = await auth4.middleware(
    browser.request(`/auth/callback?code=code-1&state=${state}&iss=${encodeURIComponent(ISSUER)}`),
  );
  browser.store(callback);
  return callback;
}

describe("AUTH4D-231 login", () => {
  it("redirects to the authorization endpoint with S256 PKCE, state, nonce and a sealed transaction", async () => {
    const { auth4, issuer } = setup();
    const browser = new Browser();
    const { response, location, state } = await startLogin(auth4, browser, issuer);
    expect(`${location.origin}${location.pathname}`).toBe(`${AUTH}/oauth/authorize`);
    expect(location.searchParams.get("tenant_id")).toBe(TENANT);
    expect(location.searchParams.get("client_id")).toBe(CLIENT);
    expect(location.searchParams.get("redirect_uri")).toBe(`${APP}/auth/callback`);
    expect(location.searchParams.get("response_type")).toBe("code");
    expect(location.searchParams.get("scope")).toBe("openid profile email");
    expect(location.searchParams.get("code_challenge_method")).toBe("S256");
    expect(location.searchParams.get("code_challenge")).toMatch(/^[\w-]{43}$/u);
    expect(state).toMatch(/^[\w-]{43}$/u);
    expect(location.searchParams.get("nonce")).toMatch(/^[\w-]{43}$/u);
    expect(location.searchParams.has("provider_hint")).toBe(false);
    expect(response.headers.get("Cache-Control")).toBe("no-store");

    const [cookie] = response.headers.getSetCookie();
    expect(cookie).toMatch(new RegExp(`^auth4_tx_${state}=`, "u"));
    expect(cookie).toMatch(/Path=\/auth\/callback/iu);
    expect(cookie).toMatch(/HttpOnly/iu);
    expect(cookie).toMatch(/SameSite=lax/iu);
    expect(cookie).toMatch(/Secure/iu);
    // The verifier and nonce are encrypted, not readable in the cookie.
    expect(cookie).not.toContain(issuer.nonce);
  });

  it("asks for offline_access only when refresh is on, and passes a provider hint", async () => {
    const { auth4, issuer } = setup({ refresh: true, scope: "openid email offline_access" });
    const { location } = await startLogin(auth4, new Browser(), issuer, "?provider=discord");
    expect(location.searchParams.get("scope")).toBe("openid email offline_access");
    expect(location.searchParams.get("provider_hint")).toBe("discord");

    const plain = setup({ scope: "openid offline_access" });
    const second = await startLogin(plain.auth4, new Browser(), plain.issuer);
    expect(second.location.searchParams.get("scope")).toBe("openid");

    const unknown = await auth4.middleware(new Browser().request("/auth/login?provider=myspace"));
    expect(unknown.status).toBe(400);
  });

  it.each([
    "https://evil.example.test/steal",
    "//evil.example.test/steal",
    "/\\evil.example.test",
    "\\\\evil.example.test",
    "javascript:alert(1)",
    "http://play.example.test/downgrade",
    "https://user:pass@play.example.test/",
    "/\t/evil.example.test",
  ])("never returns to %s after sign-in", async (returnTo) => {
    const { auth4, issuer } = setup();
    const browser = new Browser();
    const callback = await signIn(
      auth4,
      browser,
      issuer,
      `?returnTo=${encodeURIComponent(returnTo)}`,
    );
    expect(callback.status).toBe(302);
    expect(callback.headers.get("Location")).toBe(`${APP}/`);
  });

  it("returns to a same-origin path with its query", async () => {
    const { auth4, issuer } = setup();
    const callback = await signIn(
      auth4,
      new Browser(),
      issuer,
      `?returnTo=${encodeURIComponent("/play/level-2?mode=ranked")}`,
    );
    expect(callback.headers.get("Location")).toBe(`${APP}/play/level-2?mode=ranked`);
  });
});

describe("AUTH4D-231 callback", () => {
  it("exchanges the code with the verifier and stores an encrypted, HttpOnly session", async () => {
    const { auth4, issuer } = setup();
    const browser = new Browser();
    const { location, state } = await startLogin(auth4, browser, issuer);
    const callback = await auth4.middleware(
      browser.request(`/auth/callback?code=code-1&state=${state}`),
    );
    expect(callback.status).toBe(302);
    const form = issuer.tokenForms[0]!;
    expect(form.get("grant_type")).toBe("authorization_code");
    expect(form.get("code")).toBe("code-1");
    expect(form.get("client_id")).toBe(CLIENT);
    expect(form.get("redirect_uri")).toBe(`${APP}/auth/callback`);
    const verifier = form.get("code_verifier")!;
    const digest = new Uint8Array(
      await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier)),
    );
    const challenge = btoa(String.fromCharCode(...digest))
      .replaceAll("+", "-")
      .replaceAll("/", "_")
      .replace(/=+$/u, "");
    expect(location.searchParams.get("code_challenge")).toBe(challenge);

    const cookies = callback.headers.getSetCookie();
    const session = cookies.find((cookie) => cookie.startsWith("auth4_session="))!;
    expect(session).toMatch(/HttpOnly/iu);
    expect(session).toMatch(/SameSite=lax/iu);
    expect(session).toMatch(/Path=\//iu);
    expect(session).toMatch(/Max-Age=86400/iu);
    // Tokens are never visible in a cookie.
    expect(cookies.join("\n")).not.toContain("access-1");
    expect(cookies.join("\n")).not.toContain("rfr_refresh-1");
    // The transaction is single use.
    expect(cookies.some((cookie) => /^auth4_tx_[\w-]+=;/u.test(cookie))).toBe(true);
    browser.store(callback);
    expect(browser.names()).toEqual(["auth4_session"]);

    const session1 = await auth4.getSession(browser.request("/"));
    expect(session1?.user).toEqual({
      sub: "usr_player0000000001",
      email: "player@example.test",
      email_verified: true,
    });
    expect(session1?.refreshable).toBe(false);
    expect(JSON.stringify(session1)).not.toContain("access-1");

    // Replaying the same callback finds no transaction.
    const replay = await auth4.middleware(
      browser.request(`/auth/callback?code=code-1&state=${state}`),
    );
    expect(replay.status).toBe(400);
    expect(await replay.text()).toContain("invalid_state");
  });

  it("rejects a bad state without calling the token endpoint", async () => {
    const { auth4, issuer } = setup();
    const browser = new Browser();
    const { state } = await startLogin(auth4, browser, issuer);
    const other = await startLogin(auth4, new Browser(), issuer);

    const cases = [
      `/auth/callback?code=c`,
      `/auth/callback?code=c&state=${other.state}`,
      `/auth/callback?code=c&state=${state}&state=${state}`,
      `/auth/callback?code=c&state=short`,
    ];
    for (const path of cases) {
      const response = await auth4.middleware(browser.request(path));
      expect(response.status, path).toBe(400);
      expect(await response.text()).toContain("invalid_state");
    }
    // A transaction cookie swapped onto another state, or sealed with another secret.
    const forged = new Browser();
    forged.jar.set(`auth4_tx_${other.state}`, {
      value: browser.jar.get(`auth4_tx_${state}`)!.value,
      path: "/auth/callback",
    });
    const swapped = await auth4.middleware(
      forged.request(`/auth/callback?code=c&state=${other.state}`),
    );
    expect(swapped.status).toBe(400);
    const foreign = setup({ secret: "another-secret-0123456789abcdefghijklmnop" });
    const sealedElsewhere = await foreign.auth4.middleware(
      browser.request(`/auth/callback?code=c&state=${state}`),
    );
    expect(sealedElsewhere.status).toBe(400);
    expect(issuer.tokenForms).toHaveLength(0);
    expect(foreign.issuer.tokenForms).toHaveLength(0);
  });

  it("rejects an expired transaction", async () => {
    const { auth4, issuer } = setup();
    const browser = new Browser();
    const { state } = await startLogin(auth4, browser, issuer);
    issuer.clock += 16 * 60_000;
    const response = await auth4.middleware(
      browser.request(`/auth/callback?code=c&state=${state}`),
    );
    expect(response.status).toBe(400);
    expect(issuer.tokenForms).toHaveLength(0);
  });

  it("rejects a bad nonce and revokes what was issued", async () => {
    const { auth4, issuer } = setup();
    const browser = new Browser();
    const { state } = await startLogin(auth4, browser, issuer);
    issuer.nonce = "a-different-nonce-from-another-sign-in";
    const response = await auth4.middleware(
      browser.request(`/auth/callback?code=c&state=${state}`),
    );
    expect(response.status).toBe(400);
    expect(await response.text()).toContain("invalid_id_token");
    expect(response.headers.getSetCookie().some((c) => c.startsWith("auth4_session="))).toBe(false);
    expect(issuer.revoked.map((form) => form.get("token"))).toEqual(["rfr_refresh-1", "access-1"]);
  });

  it.each([
    ["another issuer", { iss: `${AUTH}/t/ten_CCCCCCCCCCCCCCCC` }],
    ["another audience", { aud: "cli_DDDDDDDDDDDDDDDD" }],
    ["an access token", { token_use: "access" }],
    ["another tenant", { tenant_id: "ten_CCCCCCCCCCCCCCCC" }],
    ["an expired token", { exp: Math.floor(START / 1_000) - 120 }],
    ["a missing nonce", { nonce: undefined }],
  ])("rejects an ID token from %s", async (_label, claims) => {
    const { auth4, issuer } = setup();
    issuer.options.idClaims = claims;
    const browser = new Browser();
    const { state } = await startLogin(auth4, browser, issuer);
    const response = await auth4.middleware(
      browser.request(`/auth/callback?code=c&state=${state}`),
    );
    expect(response.status).toBe(400);
    expect(await response.text()).toContain("invalid_id_token");
  });

  it("rejects a mismatched iss parameter and never shows the issuer's error text", async () => {
    const { auth4, issuer } = setup();
    const browser = new Browser();
    const first = await startLogin(auth4, browser, issuer);
    const wrongIssuer = await auth4.middleware(
      browser.request(
        `/auth/callback?code=c&state=${first.state}&iss=${encodeURIComponent("https://evil.test/t/x")}`,
      ),
    );
    expect(wrongIssuer.status).toBe(400);
    expect(await wrongIssuer.text()).toContain("invalid_callback");

    const second = await startLogin(auth4, browser, issuer);
    const denied = await auth4.middleware(
      browser.request(
        `/auth/callback?error=access_denied&error_description=${encodeURIComponent("<script>x</script>")}&state=${second.state}`,
      ),
    );
    expect(denied.status).toBe(400);
    const text = await denied.text();
    expect(text).toBe("Sign-in was cancelled.");
    expect(issuer.tokenForms).toHaveLength(0);
  });

  it("lets the application render its own callback error", async () => {
    const { auth4 } = setup({
      onCallbackError: (code) => Response.redirect(`${APP}/signin-failed?reason=${code}`, 302),
    });
    const response = await auth4.middleware(new Browser().request("/auth/callback?code=c"));
    expect(response.status).toBe(302);
    expect(response.headers.get("Location")).toBe(`${APP}/signin-failed?reason=invalid_state`);
  });
});

describe("AUTH4D-231 refresh", () => {
  it("keeps no refresh token unless the application opted in", async () => {
    const { auth4, issuer } = setup();
    const browser = new Browser();
    await signIn(auth4, browser, issuer);
    issuer.clock += 290_000;
    const response = await auth4.middleware(browser.request("/play"));
    expect(issuer.tokenForms).toHaveLength(1);
    expect(response.headers.get("x-middleware-next")).toBe("1");
    expect((await auth4.getSession(browser.request("/")))?.refreshable).toBe(false);
  });

  it("rotates the refresh token in middleware and forwards the new session to the page", async () => {
    const { auth4, issuer } = setup({ refresh: true });
    const browser = new Browser();
    await signIn(auth4, browser, issuer);
    expect((await auth4.getSession(browser.request("/")))?.refreshable).toBe(true);

    // Well inside the token lifetime nothing happens.
    issuer.clock += 60_000;
    const quiet = await auth4.middleware(browser.request("/play"));
    expect(quiet.headers.getSetCookie()).toEqual([]);
    expect(issuer.tokenForms).toHaveLength(1);

    // Inside the last minute the middleware refreshes before the page renders.
    issuer.clock += 200_000;
    const before = (await auth4.getSession(browser.request("/")))!.accessTokenExpiresAt;
    const response = await auth4.middleware(browser.request("/play"));
    expect(issuer.tokenForms).toHaveLength(2);
    expect(issuer.tokenForms[1]!.get("grant_type")).toBe("refresh_token");
    expect(issuer.tokenForms[1]!.get("refresh_token")).toBe("rfr_refresh-1");
    expect(response.headers.get("x-middleware-next")).toBe("1");
    expect(response.headers.get("x-middleware-request-cookie")).toMatch(/auth4_session=/u);
    browser.store(response);
    const after = (await auth4.getSession(browser.request("/")))!;
    expect(after.accessTokenExpiresAt).toBeGreaterThan(before);

    // The next refresh presents the rotated token.
    issuer.clock += 250_000;
    browser.store(await auth4.middleware(browser.request("/play")));
    expect(issuer.tokenForms[2]!.get("refresh_token")).toBe("rfr_refresh-2");
  });

  it("shares one refresh between parallel requests carrying the same refresh token", async () => {
    const { auth4, issuer } = setup({ refresh: true });
    const browser = new Browser();
    await signIn(auth4, browser, issuer);
    issuer.clock += 280_000;
    const responses = await Promise.all(
      [1, 2, 3].map(() => auth4.middleware(browser.request("/play"))),
    );
    // A late request with the old cookie still gets the same result instead of a reuse.
    issuer.clock += 5_000;
    responses.push(await auth4.middleware(browser.request("/play")));
    expect(
      issuer.tokenForms.filter((form) => form.get("grant_type") === "refresh_token"),
    ).toHaveLength(1);
    for (const response of responses) {
      expect(response.headers.getSetCookie().some((c) => c.startsWith("auth4_session="))).toBe(
        true,
      );
    }
  });

  it("signs the player out when the refresh token is rejected as reused", async () => {
    const { auth4, issuer } = setup({ refresh: true });
    const browser = new Browser();
    await signIn(auth4, browser, issuer);
    issuer.options.refreshAnswer = "invalid_grant";
    issuer.clock += 280_000;
    const response = await auth4.middleware(browser.request("/play"));
    expect(response.headers.getSetCookie()).toEqual([
      expect.stringMatching(/^auth4_session=; .*Max-Age=0/iu),
    ]);
    // The page on the same request already sees the player signed out.
    expect(response.headers.get("x-middleware-request-cookie")).not.toMatch(/auth4_session/u);
    browser.store(response);
    expect(await auth4.getSession(browser.request("/"))).toBeNull();
  });

  it("signs the player out when a refreshed ID token names someone else", async () => {
    const { auth4, issuer } = setup({ refresh: true });
    const browser = new Browser();
    await signIn(auth4, browser, issuer);
    issuer.options.idClaims = { sub: "usr_someoneelse00000001" };
    issuer.clock += 280_000;
    const response = await auth4.middleware(browser.request("/play"));
    browser.store(response);
    expect(await auth4.getSession(browser.request("/"))).toBeNull();
    expect(issuer.revoked.map((form) => form.get("token"))).toEqual(["rfr_refresh-2", "access-2"]);
  });

  it("keeps the session when auth4.dev is briefly unavailable", async () => {
    const { auth4, issuer } = setup({ refresh: true });
    const browser = new Browser();
    await signIn(auth4, browser, issuer);
    issuer.options.refreshAnswer = "unavailable";
    issuer.clock += 280_000;
    const response = await auth4.middleware(browser.request("/play"));
    expect(response.headers.getSetCookie()).toEqual([]);
    expect(await auth4.getSession(browser.request("/"))).not.toBeNull();
  });

  it("ends the session after the rolling and absolute durations", async () => {
    const { auth4, issuer } = setup({ session: { rollingDuration: 600, absoluteDuration: 900 } });
    const browser = new Browser();
    await signIn(auth4, browser, issuer);
    issuer.clock += 500_000;
    browser.store(await auth4.middleware(browser.request("/play")));
    issuer.clock += 500_000;
    expect(await auth4.getSession(browser.request("/"))).toBeNull();
  });
});

describe("AUTH4D-231 profile, access token and cookies", () => {
  it("answers the profile without tokens, and 204 when signed out", async () => {
    const { auth4, issuer } = setup({ refresh: true });
    const browser = new Browser();
    const signedOut = await auth4.middleware(browser.request("/auth/profile"));
    expect(signedOut.status).toBe(204);
    await signIn(auth4, browser, issuer);
    const profile = await auth4.middleware(browser.request("/auth/profile"));
    expect(profile.status).toBe(200);
    expect(profile.headers.get("Cache-Control")).toBe("no-store");
    const text = await profile.text();
    expect(JSON.parse(text)).toEqual({
      sub: "usr_player0000000001",
      email: "player@example.test",
      email_verified: true,
    });
    expect(text).not.toMatch(/access-|rfr_|eyJ/u);
  });

  it("does not answer /auth/access-token unless it is turned on", async () => {
    const { auth4, issuer } = setup();
    const browser = new Browser();
    await signIn(auth4, browser, issuer);
    const response = await auth4.middleware(browser.request("/auth/access-token"));
    expect(response.headers.get("x-middleware-next")).toBe("1");
    expect(await response.text()).not.toContain("access-1");
  });

  it("returns and refreshes the access token when the route is turned on", async () => {
    const { auth4, issuer } = setup({ refresh: true, enableAccessTokenEndpoint: true });
    const browser = new Browser();
    const signedOut = await auth4.middleware(browser.request("/auth/access-token"));
    expect(signedOut.status).toBe(401);
    expect(await signedOut.json()).toEqual({ error: "not_signed_in" });
    await signIn(auth4, browser, issuer);
    const first = await auth4.middleware(browser.request("/auth/access-token"));
    expect(await first.json()).toEqual({
      token: "access-1",
      expires_at: Math.floor(START / 1_000) + 300,
      scope: "openid profile email offline_access",
    });
    expect(first.headers.get("Cache-Control")).toBe("no-store");
    issuer.clock += 290_000;
    const second = await auth4.middleware(browser.request("/auth/access-token"));
    expect(((await second.json()) as { token: string }).token).toBe("access-2");
    const crossSite = await auth4.middleware(
      browser.request("/auth/access-token", { headers: { "Sec-Fetch-Site": "cross-site" } }),
    );
    expect(crossSite.status).toBe(403);
  });

  it("splits a large session into chunks under 4 KB and reads it back", async () => {
    const { auth4, issuer } = setup({ refresh: true });
    issuer.options.idClaims = { auth4_meta: { bio: "x".repeat(5_000) } };
    const browser = new Browser();
    const callback = await signIn(auth4, browser, issuer);
    const chunks = callback.headers
      .getSetCookie()
      .filter((cookie) => cookie.startsWith("auth4_session."));
    expect(chunks.length).toBeGreaterThan(1);
    for (const chunk of chunks) expect(chunk.length).toBeLessThan(4_000);
    const session = await auth4.getSession(browser.request("/"));
    expect((session?.user["auth4_meta"] as { bio: string }).bio).toHaveLength(5_000);

    // A smaller session afterwards removes the chunks it no longer needs.
    issuer.options.idClaims = {};
    const again = await signIn(auth4, browser, issuer);
    expect(
      again.headers.getSetCookie().filter((c) => /^auth4_session\.\d+=;/u.test(c)).length,
    ).toBe(chunks.length);
    expect(browser.names()).toEqual(["auth4_session"]);
  });

  it("decrypts with an older secret during a rotation", async () => {
    const { auth4, issuer } = setup();
    const browser = new Browser();
    await signIn(auth4, browser, issuer);
    const rotated = new Auth4Client({
      authOrigin: AUTH,
      tenantId: TENANT,
      clientId: CLIENT,
      appBaseUrl: APP,
      secret: ["a-brand-new-secret-0123456789abcdefghijkl", SECRET],
      fetch: issuer.fetch,
      now: () => issuer.clock,
    });
    expect((await rotated.getSession(browser.request("/")))?.user.sub).toBe("usr_player0000000001");
    const tampered = new Browser();
    const value = browser.jar.get("auth4_session")!.value;
    tampered.jar.set("auth4_session", { value: `${value.slice(0, -4)}AAAA`, path: "/" });
    expect(await auth4.getSession(tampered.request("/"))).toBeNull();
  });
});

describe("AUTH4D-270 idp claim", () => {
  async function userFor(idClaims: Record<string, unknown>) {
    const { auth4, issuer } = setup();
    issuer.options.idClaims = idClaims;
    const browser = new Browser();
    await signIn(auth4, browser, issuer);
    return (await auth4.getSession(browser.request("/")))?.user;
  }

  it("types a Steam sign-in with a verified email and idp", async () => {
    const user: User | undefined = await userFor({ idp: "steam" });
    expect(user).toEqual({
      sub: "usr_player0000000001",
      email: "player@example.test",
      email_verified: true,
      idp: "steam",
    });
    const idp: string | undefined = user?.idp;
    expect(idp).toBe("steam");
  });

  it("leaves email and idp out when the token has none", async () => {
    const user = await userFor({ email: undefined, email_verified: undefined });
    expect(user).toEqual({ sub: "usr_player0000000001" });
    expect(user?.idp).toBeUndefined();
  });

  it("accepts an idp this SDK version does not know yet", async () => {
    expect((await userFor({ idp: "future_method" }))?.idp).toBe("future_method");
  });

  it.each([
    ["a malformed idp", { idp: "Steam!" }],
    ["a non-string idp", { idp: 7 }],
    ["a non-string email", { email: 7 }],
    ["a non-boolean email_verified", { email_verified: "true" }],
  ])("rejects an ID token with %s", async (_label, claims) => {
    const { auth4, issuer } = setup();
    issuer.options.idClaims = claims;
    const browser = new Browser();
    const { state } = await startLogin(auth4, browser, issuer);
    const response = await auth4.middleware(
      browser.request(`/auth/callback?code=c&state=${state}`),
    );
    expect(response.status).toBe(400);
    expect(await response.text()).toContain("invalid_id_token");
  });
});

describe("AUTH4D-231 logout", () => {
  it("revokes the refresh and access tokens, clears the session and returns on this origin", async () => {
    const { auth4, issuer } = setup({ refresh: true });
    const browser = new Browser();
    await signIn(auth4, browser, issuer);
    const response = await auth4.middleware(
      browser.request(`/auth/logout?returnTo=${encodeURIComponent("https://evil.example.test")}`),
    );
    expect(response.status).toBe(302);
    expect(response.headers.get("Location")).toBe(`${APP}/`);
    expect(issuer.revoked.map((form) => [form.get("token_type_hint"), form.get("token")])).toEqual([
      ["refresh_token", "rfr_refresh-1"],
      ["access_token", "access-1"],
    ]);
    expect(issuer.revoked[0]!.get("client_id")).toBe(CLIENT);
    browser.store(response);
    expect(browser.names()).toEqual([]);
    expect(await auth4.getSession(browser.request("/"))).toBeNull();

    const crossSite = await auth4.middleware(
      browser.request("/auth/logout", { headers: { "Sec-Fetch-Site": "cross-site" } }),
    );
    expect(crossSite.status).toBe(403);
  });

  it("goes through the hosted sign-out page and back through the callback when asked", async () => {
    const { auth4, issuer } = setup({ hostedLogout: true });
    const browser = new Browser();
    await signIn(auth4, browser, issuer);
    const response = await auth4.middleware(browser.request("/auth/logout?returnTo=/bye"));
    browser.store(response);
    const hosted = new URL(response.headers.get("Location")!);
    expect(`${hosted.origin}${hosted.pathname}`).toBe(`${AUTH}/login/logout`);
    expect(hosted.searchParams.get("tenant_id")).toBe(TENANT);
    expect(hosted.searchParams.get("client_id")).toBe(CLIENT);
    expect(hosted.searchParams.get("post_logout_redirect_uri")).toBe(`${APP}/auth/callback`);
    const state = hosted.searchParams.get("state")!;
    const back = await auth4.middleware(browser.request(`/auth/callback?state=${state}`));
    expect(back.status).toBe(302);
    expect(back.headers.get("Location")).toBe(`${APP}/bye`);
    expect(issuer.tokenForms).toHaveLength(1);
  });
});

describe("AUTH4D-231 configuration", () => {
  it.each([
    [{ secret: "too-short" }, /32 characters/u],
    [{ tenantId: "tenant" }, /tenantId/u],
    [{ clientId: "app" }, /clientId/u],
    [{ appBaseUrl: "http://play.example.test" }, /https/u],
    [{ authOrigin: "https://auth.example.test/path" }, /no path/u],
  ])("rejects %j", async (override, message) => {
    const { auth4 } = setup(override as Partial<Auth4ClientOptions>);
    const error = await auth4.middleware(new Browser().request("/")).catch((cause) => cause);
    expect(error).toBeInstanceOf(ConfigurationError);
    expect((error as Error).message).toMatch(message);
  });

  it("allows http on localhost, with cookies that are not Secure", async () => {
    const { auth4, issuer } = setup({ appBaseUrl: "http://localhost:3000" });
    const response = await auth4.middleware(
      new NextRequest("http://localhost:3000/auth/login", { method: "GET" }),
    );
    expect(response.status).toBe(302);
    expect(response.headers.getSetCookie()[0]).not.toMatch(/Secure/iu);
    expect(issuer.requests[0]).toBe(`${ISSUER}/.well-known/openid-configuration`);
  });
});
