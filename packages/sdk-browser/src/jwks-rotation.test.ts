import { beforeAll, describe, expect, it } from "vitest";
import { Auth4BrowserClient, type BrowserStorage } from "./index.ts";

// AUTH4D-413: unknown-kid recovery against a still-fresh cached JWKS.
const issuer = "https://auth.auth4.dev/t/ten_browserfixture0001";
const clientId = "cli_browserfixture0001";
const redirectUri = "https://game.example.test/callback";
const tenantId = "ten_browserfixture0001";
const startNow = Date.UTC(2026, 9, 3, 12, 0, 0);

type Jwk = JsonWebKey & { kid: string; use: string; alg: string };
type Fixture = { kid: string; privateKey: CryptoKey; jwk: Jwk };

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

async function makeKey(kid: string): Promise<Fixture> {
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
  const jwk = (await crypto.subtle.exportKey("jwk", pair.publicKey)) as Jwk;
  jwk.kid = kid;
  jwk.use = "sig";
  jwk.alg = "RS256";
  return { kid, privateKey: pair.privateKey, jwk };
}

let keyA: Fixture;
let keyB: Fixture;
let keyC: Fixture;

beforeAll(async () => {
  [keyA, keyB, keyC] = await Promise.all([makeKey("key-a"), makeKey("key-b"), makeKey("key-c")]);
});

function b64url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
}

const json = (value: unknown) => b64url(new TextEncoder().encode(JSON.stringify(value)));

async function sign(
  key: Fixture,
  claims: Record<string, unknown>,
  kid = key.kid,
  signWith: Fixture = key,
): Promise<string> {
  const input = `${json({ alg: "RS256", kid, typ: "JWT" })}.${json(claims)}`;
  const signature = await crypto.subtle.sign(
    "RSASSA-PKCS1-v1_5",
    signWith.privateKey,
    new TextEncoder().encode(input),
  );
  return `${input}.${b64url(new Uint8Array(signature))}`;
}

function response(body: unknown, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "Content-Type": "application/json", ...headers },
  });
}

function harness() {
  const state = {
    now: startNow,
    published: [keyA.jwk] as Jwk[],
    jwksFetches: 0,
    jwksGate: undefined as Promise<void> | undefined,
    nonce: "",
    tokenFor: async (...args: [string]): Promise<string> => String(args.length && ""),
    byCode: new Map<string, string>(),
  };
  let codes = 0;
  const storage = new MemoryStorage();
  const claims = (overrides: Record<string, unknown> = {}) => {
    const seconds = Math.floor(state.now / 1_000);
    return {
      iss: issuer,
      sub: "usr_browserfixture0001",
      aud: clientId,
      tenant_id: tenantId,
      token_use: "id",
      jti: "jti_browserfixture0001",
      iat: seconds,
      exp: seconds + 300,
      auth_time: seconds,
      nonce: state.nonce,
      ...overrides,
    };
  };
  const fetcher: typeof fetch = async (input, init) => {
    const url =
      typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
    if (url === `${issuer}/.well-known/openid-configuration`) {
      return response(
        {
          issuer,
          authorization_endpoint: "https://auth.auth4.dev/oauth/authorize?tenant_id=" + tenantId,
          token_endpoint: "https://auth.auth4.dev/oauth/token?tenant_id=" + tenantId,
          userinfo_endpoint: "https://auth.auth4.dev/oauth/userinfo?tenant_id=" + tenantId,
          jwks_uri: `${issuer}/.well-known/jwks.json`,
          revocation_endpoint: "https://auth.auth4.dev/oauth/revoke?tenant_id=" + tenantId,
          response_types_supported: ["code"],
          grant_types_supported: ["authorization_code", "refresh_token"],
          id_token_signing_alg_values_supported: ["RS256"],
          code_challenge_methods_supported: ["S256"],
        },
        { "Cache-Control": "max-age=3600" },
      );
    }
    if (url === `${issuer}/.well-known/jwks.json`) {
      state.jwksFetches += 1;
      const keys = [...state.published];
      if (state.jwksGate) await state.jwksGate;
      return response({ keys }, { "Cache-Control": "max-age=300" });
    }
    if (url.startsWith("https://auth.auth4.dev/oauth/token")) {
      const form = new URLSearchParams(String(init?.body ?? ""));
      const grant = form.get("grant_type") ?? "";
      return response({
        access_token: "access-token",
        refresh_token: "rfr_refresh-secret",
        token_type: "Bearer",
        expires_in: 300,
        id_token: state.byCode.get(form.get("code") ?? "") ?? (await state.tokenFor(grant)),
      });
    }
    if (url.startsWith("https://auth.auth4.dev/oauth/revoke")) return response({});
    return new Response(null, { status: 404 });
  };
  const client = new Auth4BrowserClient({
    issuer,
    clientId,
    redirectUri,
    fetch: fetcher,
    storage,
    now: () => state.now,
    refresh: true,
  });
  const callback = async () => {
    const authorization = new URL(await client.authorizationUrl());
    const stateParam = authorization.searchParams.get("state")!;
    const nonce = authorization.searchParams.get("nonce")!;
    const url = new URL(redirectUri);
    codes += 1;
    url.searchParams.set("code", `code-${codes}`);
    url.searchParams.set("state", stateParam);
    return { url, nonce };
  };
  return { state, client, claims, callback };
}

describe("Auth4BrowserClient unknown signing key recovery (AUTH4D-413)", () => {
  it("accepts a token from a newly published key with one extra JWKS fetch", async () => {
    const h = harness();
    h.state.tokenFor = async () => sign(keyA, h.claims());
    const first = await h.callback();
    h.state.nonce = first.nonce;
    await h.client.handleCallback(first.url);
    expect(h.state.jwksFetches).toBe(1);

    h.state.published = [keyA.jwk, keyB.jwk];
    h.state.now += 10_000; // cache (300 s) is still fresh
    const second = await h.callback();
    h.state.nonce = second.nonce;
    h.state.tokenFor = async () => sign(keyB, h.claims());
    await expect(h.client.handleCallback(second.url)).resolves.toMatchObject({
      user: { sub: "usr_browserfixture0001" },
    });
    expect(h.state.jwksFetches).toBe(2);
  });

  it("shares one fetch between concurrent unknown-key validations", async () => {
    const h = harness();
    h.state.tokenFor = async () => sign(keyA, h.claims());
    const first = await h.callback();
    h.state.nonce = first.nonce;
    await h.client.handleCallback(first.url);

    h.state.published = [keyA.jwk, keyB.jwk];
    let release!: () => void;
    h.state.jwksGate = new Promise<void>((resolve) => (release = resolve));
    const flows = [await h.callback(), await h.callback(), await h.callback()];
    for (const flow of flows) {
      h.state.nonce = flow.nonce;
      h.state.byCode.set(flow.url.searchParams.get("code")!, await sign(keyB, h.claims()));
    }
    const results = flows.map((flow) => h.client.handleCallback(flow.url));
    await new Promise((resolve) => setTimeout(resolve, 20));
    release();
    await Promise.all(results);
    expect(h.state.jwksFetches).toBe(2);
  });

  it("recovers during refresh and keeps the session", async () => {
    const h = harness();
    h.state.tokenFor = async (grant) =>
      sign(keyA, h.claims(grant === "refresh_token" ? { nonce: undefined } : {}));
    const first = await h.callback();
    h.state.nonce = first.nonce;
    await h.client.handleCallback(first.url);

    h.state.published = [keyA.jwk, keyB.jwk];
    h.state.now += 250_000;
    h.state.tokenFor = async () => sign(keyB, h.claims({ nonce: undefined }));
    await expect(h.client.getAccessTokenSilently()).resolves.toBe("access-token");
    expect(h.client.getSession()).not.toBeNull();
    expect(h.state.jwksFetches).toBe(2);
  });

  it("does not repopulate a session cleared while the key fetch is in flight", async () => {
    const h = harness();
    h.state.tokenFor = async () => sign(keyA, h.claims());
    const first = await h.callback();
    h.state.nonce = first.nonce;
    await h.client.handleCallback(first.url);

    h.state.published = [keyA.jwk, keyB.jwk];
    let release!: () => void;
    h.state.jwksGate = new Promise<void>((resolve) => (release = resolve));
    h.state.now += 250_000;
    h.state.tokenFor = async () => sign(keyB, h.claims({ nonce: undefined }));
    const refreshing = h.client.getAccessTokenSilently().catch((error: unknown) => error);
    await new Promise((resolve) => setTimeout(resolve, 20));
    await h.client.logout();
    release();
    await refreshing;
    expect(h.client.getSession()).toBeNull();
  });

  it("rejects persistent unknown keys and bounds refetches with a cooldown", async () => {
    const h = harness();
    h.state.tokenFor = async () => sign(keyA, h.claims());
    const first = await h.callback();
    h.state.nonce = first.nonce;
    await h.client.handleCallback(first.url);

    const attempt = async () => {
      const flow = await h.callback();
      h.state.nonce = flow.nonce;
      h.state.tokenFor = async () => sign(keyC, h.claims());
      return h.client.handleCallback(flow.url);
    };
    h.state.now += 1_000;
    await expect(attempt()).rejects.toMatchObject({ code: "invalid_id_token" });
    expect(h.state.jwksFetches).toBe(2);
    await expect(attempt()).rejects.toMatchObject({ code: "invalid_id_token" });
    await expect(attempt()).rejects.toMatchObject({ code: "invalid_id_token" });
    expect(h.state.jwksFetches).toBe(2);

    // After the cooldown (still inside the 300 s cache) one more fetch is allowed.
    h.state.now += 31_000;
    await expect(attempt()).rejects.toMatchObject({ code: "invalid_id_token" });
    expect(h.state.jwksFetches).toBe(3);
  });

  it("fails closed on a bad signature for a known key without refetching", async () => {
    const h = harness();
    h.state.tokenFor = async () => sign(keyA, h.claims());
    const first = await h.callback();
    h.state.nonce = first.nonce;
    await h.client.handleCallback(first.url);

    for (let i = 0; i < 3; i += 1) {
      const flow = await h.callback();
      h.state.nonce = flow.nonce;
      h.state.tokenFor = async () => sign(keyA, h.claims(), "key-a", keyB);
      await expect(h.client.handleCallback(flow.url)).rejects.toMatchObject({
        code: "invalid_id_token",
      });
    }
    expect(h.state.jwksFetches).toBe(1);
  });

  it("rejects an ambiguous key after refetch", async () => {
    const h = harness();
    h.state.tokenFor = async () => sign(keyA, h.claims());
    const first = await h.callback();
    h.state.nonce = first.nonce;
    await h.client.handleCallback(first.url);

    h.state.published = [keyA.jwk, keyB.jwk, { ...keyC.jwk, kid: "key-b" }];
    const flow = await h.callback();
    h.state.nonce = flow.nonce;
    h.state.tokenFor = async () => sign(keyB, h.claims());
    await expect(h.client.handleCallback(flow.url)).rejects.toMatchObject({
      code: "invalid_id_token",
    });
  });
});
