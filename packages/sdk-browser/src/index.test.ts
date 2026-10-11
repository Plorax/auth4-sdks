import { beforeAll, describe, expect, it, vi } from "vitest";
import {
  Auth4BrowserClient,
  Auth4BrowserError,
  type BrowserStorage,
  type SocialProvider,
} from "./index.ts";

const issuer = "https://auth.auth4.dev/t/ten_browserfixture0001";
const clientId = "cli_browserfixture0001";
const redirectUri = "https://game.example.test/callback?campaign=browser";
const fixedNow = Date.UTC(2026, 9, 3, 12, 0, 0);
const tenantId = "ten_browserfixture0001";

class MemoryStorage implements BrowserStorage {
  readonly values = new Map<string, string>();

  getItem(key: string): string | null {
    return this.values.get(key) ?? null;
  }

  setItem(key: string, value: string): void {
    this.values.set(key, value);
  }

  removeItem(key: string): void {
    this.values.delete(key);
  }
}

let signingKey: CryptoKey;
let publicJwk: JsonWebKey & { kid?: string; use?: string; alg?: string };

beforeAll(async () => {
  const pair = await crypto.subtle.generateKey(
    {
      name: "RSASSA-PKCS1-v1_5",
      modulusLength: 2_048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true,
    ["sign", "verify"],
  );
  signingKey = pair.privateKey;
  publicJwk = await crypto.subtle.exportKey("jwk", pair.publicKey);
  publicJwk.kid = "browser-fixture-key";
  publicJwk.use = "sig";
  publicJwk.alg = "RS256";
});

function jsonResponse(body: unknown, cacheControl = "no-store"): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "Content-Type": "application/json", "Cache-Control": cacheControl },
  });
}

function discovery(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    issuer,
    authorization_endpoint:
      "https://auth.auth4.dev/oauth/authorize?tenant_id=ten_browserfixture0001",
    token_endpoint: "https://auth.auth4.dev/oauth/token?tenant_id=ten_browserfixture0001",
    userinfo_endpoint: "https://auth.auth4.dev/oauth/userinfo?tenant_id=ten_browserfixture0001",
    jwks_uri: `${issuer}/.well-known/jwks.json`,
    revocation_endpoint: "https://auth.auth4.dev/oauth/revoke?tenant_id=ten_browserfixture0001",
    device_authorization_endpoint:
      "https://auth.auth4.dev/device/authorization?tenant_id=ten_browserfixture0001",
    response_types_supported: ["code"],
    grant_types_supported: [
      "authorization_code",
      "refresh_token",
      "urn:ietf:params:oauth:grant-type:device_code",
    ],
    id_token_signing_alg_values_supported: ["RS256"],
    code_challenge_methods_supported: ["S256"],
    ...overrides,
  };
}

async function signIdToken(claims: Record<string, unknown>): Promise<string> {
  const encode = (value: unknown) => {
    const text = JSON.stringify(value);
    const bytes = new TextEncoder().encode(text);
    let binary = "";
    for (const byte of bytes) binary += String.fromCharCode(byte);
    return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
  };
  const header = encode({ alg: "RS256", kid: "browser-fixture-key", typ: "JWT" });
  const payload = encode(claims);
  const signingInput = `${header}.${payload}`;
  const signature = await crypto.subtle.sign(
    "RSASSA-PKCS1-v1_5",
    signingKey,
    new TextEncoder().encode(signingInput),
  );
  const encodedSignature = encodeBase64(new Uint8Array(signature));
  return `${signingInput}.${encodedSignature}`;
}

function encodeBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
}

function validClaims(
  nonce: string,
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  const nowSeconds = Math.floor(fixedNow / 1_000);
  return {
    iss: issuer,
    sub: "usr_browserfixture0001",
    aud: clientId,
    tenant_id: tenantId,
    token_use: "id",
    jti: "jti_browserfixture0001",
    iat: nowSeconds,
    exp: nowSeconds + 300,
    auth_time: nowSeconds,
    nonce,
    ...overrides,
  };
}

function makeClient(
  args: {
    storage?: MemoryStorage;
    now?: () => number;
    discoveryBody?: Record<string, unknown>;
    tokenBody?: (form: URLSearchParams) => Promise<unknown> | unknown;
    onRequest?: (url: string, init?: RequestInit) => Promise<Response> | Response;
    navigate?: (url: string) => void;
    replaceUrl?: (url: string) => void;
    refresh?: boolean;
  } = {},
): { client: Auth4BrowserClient; storage: MemoryStorage; requests: string[] } {
  const storage = args.storage ?? new MemoryStorage();
  const requests: string[] = [];
  const fetcher: typeof fetch = async (input, init) => {
    const url =
      typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
    requests.push(url);
    if (args.onRequest) return args.onRequest(url, init);
    if (url === `${issuer}/.well-known/openid-configuration`) {
      return jsonResponse(args.discoveryBody ?? discovery());
    }
    if (url === `${issuer}/.well-known/jwks.json`) return jsonResponse({ keys: [publicJwk] });
    if (url.startsWith("https://auth.auth4.dev/oauth/token")) {
      const form = new URLSearchParams(String(init?.body ?? ""));
      const body = args.tokenBody ? await args.tokenBody(form) : {};
      return jsonResponse(body);
    }
    if (url.startsWith("https://auth.auth4.dev/oauth/userinfo")) {
      return jsonResponse({
        sub: "usr_browserfixture0001",
        email: "player@example.test",
        email_verified: true,
      });
    }
    if (url.startsWith("https://auth.auth4.dev/oauth/revoke")) return jsonResponse({});
    return new Response(null, { status: 404 });
  };
  const client = new Auth4BrowserClient({
    issuer,
    clientId,
    redirectUri,
    fetch: fetcher,
    storage,
    now: args.now ?? (() => fixedNow),
    ...(args.navigate === undefined ? {} : { navigate: args.navigate }),
    ...(args.replaceUrl === undefined ? {} : { replaceUrl: args.replaceUrl }),
    ...(args.refresh === undefined ? {} : { refresh: args.refresh }),
  });
  return { client, storage, requests };
}

async function beginFlow(
  client: Auth4BrowserClient,
  storage = client.options.storage!,
): Promise<{ state: string; nonce: string; key: string }> {
  const authorization = new URL(await client.authorizationUrl());
  const state = authorization.searchParams.get("state")!;
  const key = `auth4:oauth-flow:${state}`;
  const flow = JSON.parse(storage.getItem(key)!) as { nonce: string };
  return { state, nonce: flow.nonce, key };
}

async function tokenBody(
  nonce: string,
  claimsOverrides: Record<string, unknown> = {},
  expiresIn = 300,
) {
  return {
    access_token: "access-token-fixture-secret",
    refresh_token: "refresh-token-fixture-secret",
    token_type: "Bearer",
    expires_in: expiresIn,
    id_token: await signIdToken(validClaims(nonce, claimsOverrides)),
  };
}

describe("Auth4BrowserClient", () => {
  it("uses authorization code with S256, random state and nonce, and never requests offline access", async () => {
    let navigated = "";
    const { client, storage } = makeClient({
      navigate: (url) => {
        navigated = url;
      },
    });
    const url = new URL(await client.login());
    const state = url.searchParams.get("state")!;
    const nonce = url.searchParams.get("nonce")!;
    expect(navigated).toBe(url.toString());
    expect(state).toMatch(/^[A-Za-z0-9_-]{43}$/u);
    expect(nonce).toMatch(/^[A-Za-z0-9_-]{43}$/u);
    expect(url.searchParams.get("response_type")).toBe("code");
    expect(url.searchParams.get("scope")).toBe("openid profile email");
    expect(url.searchParams.has("offline_access")).toBe(false);

    const flow = JSON.parse(storage.getItem(`auth4:oauth-flow:${state}`)!) as {
      verifier: string;
      nonce: string;
    };
    const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(flow.verifier));
    expect(url.searchParams.get("code_challenge")).toBe(encodeBase64(new Uint8Array(digest)));
    expect(url.searchParams.get("code_challenge_method")).toBe("S256");
    expect(flow.nonce).toBe(nonce);
    expect(flow.verifier).toHaveLength(43);
    await expect(client.authorizationUrl({ scope: "openid offline_access" })).rejects.toMatchObject(
      { code: "configuration_error" },
    );
  });

  it("sends a supported provider hint only when asked (AUTH4D-125, AUTH4D-147, AUTH4D-213)", async () => {
    const { client } = makeClient();
    const plain = new URL(await client.authorizationUrl());
    expect(plain.searchParams.has("provider_hint")).toBe(false);
    for (const provider of ["discord", "steam", "epic", "google", "apple", "microsoft"] as const) {
      const url = new URL(await client.authorizationUrl({ provider }));
      expect(url.searchParams.getAll("provider_hint")).toEqual([provider]);
    }
    await expect(
      client.authorizationUrl({ provider: "twitch" as unknown as SocialProvider }),
    ).rejects.toMatchObject({ code: "configuration_error" });
  });

  it("runs a mocked flow with only issuer, client ID, and redirect URI configuration", async () => {
    const sessionStorage = new MemoryStorage();
    const localStorage = new MemoryStorage();
    let expectedNonce = "";
    const fetcher: typeof fetch = async (input) => {
      const url =
        typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
      if (url === `${issuer}/.well-known/openid-configuration`) return jsonResponse(discovery());
      if (url === `${issuer}/.well-known/jwks.json`) return jsonResponse({ keys: [publicJwk] });
      if (url.startsWith("https://auth.auth4.dev/oauth/token")) {
        const nowSeconds = Math.floor(Date.now() / 1_000);
        return jsonResponse(
          await tokenBody(expectedNonce, {
            iat: nowSeconds,
            exp: nowSeconds + 300,
            auth_time: nowSeconds,
          }),
        );
      }
      return new Response(null, { status: 404 });
    };
    vi.stubGlobal("fetch", fetcher);
    vi.stubGlobal("sessionStorage", sessionStorage);
    vi.stubGlobal("localStorage", localStorage);
    try {
      const client = new Auth4BrowserClient({ issuer, clientId, redirectUri });
      const authorization = new URL(await client.authorizationUrl());
      const state = authorization.searchParams.get("state")!;
      expectedNonce = authorization.searchParams.get("nonce")!;
      const callback = new URL(redirectUri);
      callback.searchParams.set("code", "code");
      callback.searchParams.set("state", state);
      await client.handleCallback(callback);
      expect(client.getAccessToken()).toBe("access-token-fixture-secret");
      expect(sessionStorage.values.size).toBe(0);
      expect(localStorage.values.size).toBe(0);
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it("validates issuer discovery and bounds discovery caching to five minutes", async () => {
    let now = fixedNow;
    const { client, requests } = makeClient({
      now: () => now,
      onRequest: async (url) => {
        if (url === `${issuer}/.well-known/openid-configuration`)
          return jsonResponse(discovery(), "public, max-age=3600");
        return new Response(null, { status: 404 });
      },
    });
    await client.discover();
    now += 4 * 60 * 1_000;
    await client.discover();
    expect(requests.filter((url) => url.includes("openid-configuration"))).toHaveLength(1);
    now += 61 * 1_000;
    await client.discover();
    expect(requests.filter((url) => url.includes("openid-configuration"))).toHaveLength(2);

    const { client: wrongIssuer } = makeClient({
      discoveryBody: discovery({ issuer: "https://attacker.example/t/ten_browserfixture0001" }),
    });
    await expect(wrongIssuer.discover()).rejects.toMatchObject({ code: "issuer_mismatch" });
    const { client: unsafeEndpoint } = makeClient({
      discoveryBody: discovery({
        token_endpoint: "https://attacker.example/oauth/token?tenant_id=ten_browserfixture0001",
      }),
    });
    await expect(unsafeEndpoint.discover()).rejects.toMatchObject({ code: "discovery_failed" });
  });

  it("checks state, nonce, issuer and claims, exchanges PKCE, and cleans the callback URL", async () => {
    const cleaned: string[] = [];
    let currentNonce = "";
    const { client, storage } = makeClient({
      replaceUrl: (url) => cleaned.push(url),
      tokenBody: async (form) => {
        expect(form.get("grant_type")).toBe("authorization_code");
        expect(form.get("client_id")).toBe(clientId);
        expect(form.get("redirect_uri")).toBe(redirectUri);
        expect(form.get("code_verifier")).toMatch(/^[A-Za-z0-9_-]{43}$/u);
        return tokenBody(currentNonce);
      },
    });
    const flow = await beginFlow(client);
    currentNonce = flow.nonce;
    const callback = new URL(redirectUri);
    callback.searchParams.set("code", "one-time-code-fixture");
    callback.searchParams.set("state", flow.state);
    const session = await client.handleCallback(callback);
    expect(session.user.sub).toBe("usr_browserfixture0001");
    expect(client.getAccessToken()).toBe("access-token-fixture-secret");
    expect(storage.getItem(flow.key)).toBeNull();
    expect(cleaned).toEqual([redirectUri]);
    expect(client.getSession()?.user.sub).toBe("usr_browserfixture0001");
    expect([...storage.values.values()].join("\n")).not.toContain("access-token-fixture-secret");
    expect([...storage.values.values()].join("\n")).not.toContain("refresh-token-fixture-secret");
    await expect(client.authorizationUrl({ scope: "openid offline_access" })).rejects.toMatchObject(
      { code: "configuration_error" },
    );

    const wrongStateFlow = await beginFlow(client);
    const wrongStateCallback = new URL(redirectUri);
    wrongStateCallback.searchParams.set("code", "code");
    wrongStateCallback.searchParams.set("state", `${wrongStateFlow.state}wrong`);
    await expect(client.handleCallback(wrongStateCallback)).rejects.toMatchObject({
      code: "state_mismatch",
    });
    expect(cleaned.at(-1)).toBe(redirectUri);

    const wrongNonceFlow = await beginFlow(client);
    currentNonce = wrongNonceFlow.nonce;
    const wrongNonceCallback = new URL(redirectUri);
    wrongNonceCallback.searchParams.set("code", "code");
    wrongNonceCallback.searchParams.set("state", wrongNonceFlow.state);
    const wrongNonceClient = makeClient({
      storage,
      replaceUrl: (url) => cleaned.push(url),
      tokenBody: () => tokenBody("not-the-stored-nonce"),
    }).client;
    await expect(wrongNonceClient.handleCallback(wrongNonceCallback)).rejects.toMatchObject({
      code: "invalid_id_token",
    });
    expect(cleaned.at(-1)).toBe(redirectUri);
  });

  it("rejects ID tokens with a different issuer, audience, tenant, or nonce", async () => {
    for (const override of [
      { iss: "https://attacker.example/t/ten_browserfixture0001" },
      { aud: "cli_otherbrowser0001" },
      { tenant_id: "ten_otherbrowser0001" },
      { nonce: "different-nonce" },
    ]) {
      const storage = new MemoryStorage();
      let expectedNonce = "";
      const { client } = makeClient({
        storage,
        tokenBody: async () => tokenBody(expectedNonce, override),
      });
      const flow = await beginFlow(client);
      expectedNonce = flow.nonce;
      const callback = new URL(redirectUri);
      callback.searchParams.set("code", "code");
      callback.searchParams.set("state", flow.state);
      await expect(client.handleCallback(callback)).rejects.toMatchObject({
        code: "invalid_id_token",
      });
    }
  });

  it("retrieves UserInfo, expires tokens on time, and revokes tokens on logout", async () => {
    let now = fixedNow;
    let revokedForm: URLSearchParams | undefined;
    let expectedNonce = "";
    const { client } = makeClient({
      now: () => now,
      onRequest: async (url, init) => {
        if (url === `${issuer}/.well-known/openid-configuration`) return jsonResponse(discovery());
        if (url === `${issuer}/.well-known/jwks.json`) return jsonResponse({ keys: [publicJwk] });
        if (url.startsWith("https://auth.auth4.dev/oauth/token")) {
          return jsonResponse(await tokenBody(expectedNonce, {}, 2));
        }
        if (url.startsWith("https://auth.auth4.dev/oauth/userinfo")) {
          return jsonResponse({
            sub: "usr_browserfixture0001",
            email: "player@example.test",
            email_verified: true,
          });
        }
        if (url.startsWith("https://auth.auth4.dev/oauth/revoke")) {
          revokedForm = new URLSearchParams(String(init?.body ?? ""));
          return jsonResponse({});
        }
        return new Response(null, { status: 404 });
      },
    });
    const flow = await beginFlow(client);
    expectedNonce = flow.nonce;
    const callback = new URL(redirectUri);
    callback.searchParams.set("code", "code");
    callback.searchParams.set("state", flow.state);
    await client.handleCallback(callback);
    await expect(client.getUser()).resolves.toEqual({
      sub: "usr_browserfixture0001",
      email: "player@example.test",
      email_verified: true,
    });
    expect(revokedForm).toBeUndefined();
    await client.logout();
    expect(revokedForm?.get("token")).toBe("access-token-fixture-secret");
    expect(revokedForm?.get("client_id")).toBe(clientId);
    expect(client.getSession()).toBeNull();

    let expiringNonce = "";
    const { client: expiringClient } = makeClient({
      now: () => now,
      tokenBody: async () => tokenBody(expiringNonce, {}, 1),
    });
    const expiringFlow = await beginFlow(expiringClient);
    expiringNonce = expiringFlow.nonce;
    const expiringCallback = new URL(redirectUri);
    expiringCallback.searchParams.set("code", "code");
    expiringCallback.searchParams.set("state", expiringFlow.state);
    await expiringClient.handleCallback(expiringCallback);
    now += 1_001;
    expect(() => expiringClient.getAccessToken()).toThrowError(Auth4BrowserError);
    expect(expiringClient.getSession()).toBeNull();
  });

  it("uses typed cancellation errors and cleans OAuth parameters on failed callbacks", async () => {
    const cleaned: string[] = [];
    const { client } = makeClient({ replaceUrl: (url) => cleaned.push(url) });
    const controller = new AbortController();
    controller.abort();
    await expect(client.discover(controller.signal)).rejects.toMatchObject({ code: "cancelled" });
    const callback = new URL(`${redirectUri}&error=access_denied&state=state-that-is-not-stored`);
    await expect(client.handleCallback(callback)).rejects.toMatchObject({ code: "state_mismatch" });
    expect(cleaned).toEqual([redirectUri]);
  });
});

function refreshHarness(
  args: {
    now?: () => number;
    refresh?: boolean;
    refreshResponse?: (form: URLSearchParams) => Promise<Response> | Response;
  } = {},
) {
  const now = args.now ?? (() => fixedNow);
  const refreshForms: URLSearchParams[] = [];
  const revokeForms: URLSearchParams[] = [];
  let nonce = "";
  let issued = 0;
  const timeClaims = () => {
    const nowSeconds = Math.floor(now() / 1_000);
    return { iat: nowSeconds, exp: nowSeconds + 300, auth_time: Math.floor(fixedNow / 1_000) };
  };
  const { client, storage, requests } = makeClient({
    now,
    refresh: args.refresh ?? true,
    onRequest: async (url, init) => {
      if (url === `${issuer}/.well-known/openid-configuration`) return jsonResponse(discovery());
      if (url === `${issuer}/.well-known/jwks.json`) return jsonResponse({ keys: [publicJwk] });
      const form = new URLSearchParams(String(init?.body ?? ""));
      if (url.startsWith("https://auth.auth4.dev/oauth/token")) {
        if (form.get("grant_type") === "authorization_code") {
          return jsonResponse({
            access_token: "access-token-0",
            refresh_token: "rfr_refresh-secret-0",
            token_type: "Bearer",
            expires_in: 300,
            id_token: await signIdToken(validClaims(nonce, timeClaims())),
          });
        }
        refreshForms.push(form);
        if (args.refreshResponse) return args.refreshResponse(form);
        issued += 1;
        // Refresh-issued ID tokens carry no nonce, as the Auth4 token endpoint returns them.
        const claims = validClaims(nonce, { ...timeClaims(), nonce: undefined });
        return jsonResponse({
          access_token: `access-token-${issued}`,
          refresh_token: `rfr_refresh-secret-${issued}`,
          token_type: "Bearer",
          expires_in: 300,
          id_token: await signIdToken(claims),
        });
      }
      if (url.startsWith("https://auth.auth4.dev/oauth/revoke")) {
        revokeForms.push(form);
        return jsonResponse({});
      }
      return new Response(null, { status: 404 });
    },
  });
  const signIn = async () => {
    const flow = await beginFlow(client, storage);
    nonce = flow.nonce;
    const callback = new URL(redirectUri);
    callback.searchParams.set("code", "code");
    callback.searchParams.set("state", flow.state);
    return client.handleCallback(callback);
  };
  return { client, storage, requests, refreshForms, revokeForms, signIn };
}

const settle = () => new Promise<void>((resolve) => setImmediate(resolve));

describe("Auth4BrowserClient refresh (AUTH4D-65)", () => {
  it("requests offline_access only with the refresh option", async () => {
    const { client } = refreshHarness();
    const url = new URL(await client.authorizationUrl());
    expect(url.searchParams.get("scope")).toBe("openid profile email offline_access");
    const custom = new URL(await client.authorizationUrl({ scope: "openid" }));
    expect(custom.searchParams.get("scope")).toBe("openid offline_access");
    const explicit = new URL(await client.authorizationUrl({ scope: "openid offline_access" }));
    expect(explicit.searchParams.get("scope")).toBe("openid offline_access");

    const { client: plain } = refreshHarness({ refresh: false });
    expect(new URL(await plain.authorizationUrl()).searchParams.get("scope")).toBe(
      "openid profile email",
    );
    await expect(plain.authorizationUrl({ scope: "openid offline_access" })).rejects.toMatchObject({
      code: "configuration_error",
    });
  });

  it("drops a refresh token without the opt-in and keeps the old expiry behavior", async () => {
    let now = fixedNow;
    const { client, refreshForms, signIn } = refreshHarness({ now: () => now, refresh: false });
    await signIn();
    expect(JSON.stringify(client)).not.toContain("rfr_refresh-secret");
    now += 300_000;
    await expect(client.getAccessTokenSilently()).rejects.toMatchObject({ code: "token_expired" });
    expect(client.getSession()).toBeNull();
    expect(refreshForms).toHaveLength(0);
  });

  it("renews automatically before expiry with jittered early renewal (fake clock)", async () => {
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout", "Date"] });
    vi.setSystemTime(fixedNow);
    const random = vi.spyOn(Math, "random").mockReturnValue(0.5);
    try {
      const { client, refreshForms, signIn } = refreshHarness({ now: () => Date.now() });
      const events: string[] = [];
      client.onSessionEvent((event) => events.push(event.type));
      const session = await signIn();
      expect(session.expiresAt).toBe(fixedNow + 300_000);

      // Lead is 60s plus half of the 30s jitter, so renewal starts 225s after sign-in.
      await vi.advanceTimersByTimeAsync(224_000);
      await settle();
      expect(refreshForms).toHaveLength(0);
      expect(client.getAccessToken()).toBe("access-token-0");

      await vi.advanceTimersByTimeAsync(1_000);
      await vi.waitFor(() => expect(events).toEqual(["renewed"]));
      expect(refreshForms[0]?.get("grant_type")).toBe("refresh_token");
      expect(refreshForms[0]?.get("refresh_token")).toBe("rfr_refresh-secret-0");
      expect(refreshForms[0]?.get("client_id")).toBe(clientId);
      expect(client.getAccessToken()).toBe("access-token-1");

      // The next renewal presents the rotated refresh token.
      await vi.advanceTimersByTimeAsync(225_000);
      await vi.waitFor(() => expect(events).toEqual(["renewed", "renewed"]));
      expect(refreshForms[1]?.get("refresh_token")).toBe("rfr_refresh-secret-1");
      expect(client.getAccessToken()).toBe("access-token-2");
      await client.logout();
    } finally {
      random.mockRestore();
      vi.useRealTimers();
    }
  });

  it("shares one refresh request between concurrent getAccessTokenSilently calls", async () => {
    let now = fixedNow;
    let release: () => void = () => undefined;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    let calls = 0;
    const { client, signIn } = refreshHarness({
      now: () => now,
      refreshResponse: async () => {
        calls += 1;
        await gate;
        return jsonResponse({
          access_token: "access-token-shared",
          refresh_token: "rfr_refresh-secret-shared",
          token_type: "Bearer",
          expires_in: 300,
        });
      },
    });
    await signIn();
    await expect(client.getAccessTokenSilently()).resolves.toBe("access-token-0");
    now += 250_000;
    const pending = Array.from({ length: 5 }, () => client.getAccessTokenSilently());
    await settle();
    release();
    await expect(Promise.all(pending)).resolves.toEqual(Array(5).fill("access-token-shared"));
    expect(calls).toBe(1);
    await client.logout();
  });

  it("clears the session and emits signed_out when the refresh grant is rejected", async () => {
    let now = fixedNow;
    let status = 503;
    const { client, signIn } = refreshHarness({
      now: () => now,
      refreshResponse: () =>
        new Response(
          JSON.stringify({ error: status === 503 ? "temporarily_unavailable" : "invalid_grant" }),
          { status, headers: { "Content-Type": "application/json" } },
        ),
    });
    const events: unknown[] = [];
    client.onSessionEvent((event) => events.push(event));
    await signIn();
    now += 250_000;

    // A transient failure inside the renewal window keeps the still-valid token.
    await expect(client.getAccessTokenSilently()).resolves.toBe("access-token-0");
    expect(client.getSession()).not.toBeNull();
    expect(events).toEqual([]);

    // Reuse, revocation or expiry surfaces as invalid_grant and ends the session.
    status = 400;
    await expect(client.getAccessTokenSilently()).rejects.toMatchObject({
      code: "refresh_failed",
    });
    expect(events).toEqual([{ type: "signed_out", reason: "refresh_rejected" }]);
    expect(client.getSession()).toBeNull();
    expect(client.getAccessToken()).toBeNull();
    await expect(client.getAccessTokenSilently()).resolves.toBeNull();
  });

  it("signs out when a renewed ID token belongs to another user", async () => {
    let now = fixedNow;
    const { client, signIn } = refreshHarness({
      now: () => now,
      refreshResponse: async () => {
        const nowSeconds = Math.floor(now / 1_000);
        const claims = validClaims("", {
          nonce: undefined,
          sub: "usr_someoneelse0001",
          iat: nowSeconds,
          exp: nowSeconds + 300,
        });
        return jsonResponse({
          access_token: "access-token-other",
          refresh_token: "rfr_refresh-secret-other",
          token_type: "Bearer",
          expires_in: 300,
          id_token: await signIdToken(claims),
        });
      },
    });
    await signIn();
    now += 250_000;
    await expect(client.getAccessTokenSilently()).rejects.toMatchObject({
      code: "refresh_failed",
    });
    expect(client.getSession()).toBeNull();
  });

  it("revokes the refresh token on sign-out and emits signed_out", async () => {
    const { client, revokeForms, signIn } = refreshHarness();
    const events: unknown[] = [];
    client.onSessionEvent((event) => events.push(event));
    await signIn();
    await client.logout();
    expect(revokeForms.map((form) => [form.get("token"), form.get("token_type_hint")])).toEqual([
      ["rfr_refresh-secret-0", "refresh_token"],
      ["access-token-0", "access_token"],
    ]);
    expect(revokeForms.every((form) => form.get("client_id") === clientId)).toBe(true);
    expect(events).toEqual([{ type: "signed_out", reason: "logout" }]);
    expect(client.getSession()).toBeNull();
    await expect(client.getAccessTokenSilently()).resolves.toBeNull();
  });

  it("never writes the refresh token to storage, cookies, the DOM, or events", async () => {
    const sessionStorage = new MemoryStorage();
    const localStorage = new MemoryStorage();
    const domAccess: PropertyKey[] = [];
    const document = new Proxy(
      {},
      {
        get: (_target, key) => {
          domAccess.push(key);
          return undefined;
        },
        set: (_target, key) => {
          domAccess.push(key);
          return true;
        },
      },
    );
    vi.stubGlobal("sessionStorage", sessionStorage);
    vi.stubGlobal("localStorage", localStorage);
    vi.stubGlobal("document", document);
    try {
      let now = fixedNow;
      const { client, storage, signIn } = refreshHarness({ now: () => now });
      const events: unknown[] = [];
      client.onSessionEvent((event) => events.push(event));
      await signIn();
      now += 250_000;
      await expect(client.getAccessTokenSilently()).resolves.toBe("access-token-1");
      const persisted = [
        ...storage.values.values(),
        ...sessionStorage.values.values(),
        ...localStorage.values.values(),
      ].join("\n");
      expect(persisted).not.toContain("rfr_refresh-secret");
      expect(persisted).not.toContain("access-token");
      // No cookie writes or any other document access: the SDK never touches the DOM.
      expect(domAccess).toEqual([]);
      expect(JSON.stringify(client)).not.toContain("rfr_refresh-secret");
      expect(JSON.stringify(events)).not.toContain("rfr_refresh-secret");
      expect(JSON.stringify(events)).not.toContain("access-token");
      await client.logout();
      expect(domAccess).toEqual([]);
    } finally {
      vi.unstubAllGlobals();
    }
  });
});
