import { beforeAll, describe, expect, it } from "vitest";
import { Auth4BrowserClient, Auth4BrowserError } from "./index.ts";

// AUTH4D-312: signInWithDiscordActivity(). The API is a mocked fetch that signs ID tokens with a
// throwaway key and echoes the request's nonce, as the code exchange endpoint does.

const authOrigin = "https://auth.auth4.dev";
const tenantId = "ten_activityfixture0001";
const issuer = `${authOrigin}/t/${tenantId}`;
const clientId = "cli_activityfixture0001";
const userId = "usr_activityfixture0001";
const fixedNow = Date.UTC(2026, 9, 22, 12, 0, 0);
const discordCode = "discordActivityCode0123";

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
  publicJwk.kid = "activity-fixture-key";
  publicJwk.use = "sig";
  publicJwk.alg = "RS256";
});

function encode(value: unknown): string {
  return encodeBytes(new TextEncoder().encode(JSON.stringify(value)));
}

function encodeBytes(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
}

async function signIdToken(claims: Record<string, unknown>): Promise<string> {
  const input = `${encode({ alg: "RS256", kid: "activity-fixture-key", typ: "JWT" })}.${encode(claims)}`;
  const signature = await crypto.subtle.sign(
    "RSASSA-PKCS1-v1_5",
    signingKey,
    new TextEncoder().encode(input),
  );
  return `${input}.${encodeBytes(new Uint8Array(signature))}`;
}

function accessToken(sub = userId): string {
  return `${encode({ alg: "RS256", typ: "at+jwt" })}.${encode({ iss: issuer, sub })}.c2lnbmF0dXJl`;
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
  });
}

type Exchange = { nonce: string; body: Record<string, unknown> };

function makeClient(
  answer: (exchange: Exchange) => Promise<Response> | Response,
  requests: { url: string; init?: RequestInit }[] = [],
) {
  const fetcher = async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    requests.push({ url, ...(init === undefined ? {} : { init }) });
    if (url === `${issuer}/.well-known/openid-configuration`) {
      return json({
        issuer,
        authorization_endpoint: `${authOrigin}/oauth/authorize?tenant_id=${tenantId}`,
        token_endpoint: `${authOrigin}/oauth/token?tenant_id=${tenantId}`,
        userinfo_endpoint: `${authOrigin}/oauth/userinfo?tenant_id=${tenantId}`,
        jwks_uri: `${issuer}/.well-known/jwks.json`,
        response_types_supported: ["code"],
        id_token_signing_alg_values_supported: ["RS256"],
        code_challenge_methods_supported: ["S256"],
      });
    }
    if (url === `${issuer}/.well-known/jwks.json`) return json({ keys: [publicJwk] });
    if (url === `${issuer}/identity/discord/activity`) {
      const body = JSON.parse(String(init?.body)) as Record<string, unknown>;
      return answer({ nonce: String(body["nonce"]), body });
    }
    return json({ error: "not_found" }, 404);
  };
  return new Auth4BrowserClient({
    issuer,
    clientId,
    redirectUri: "https://123456789012345678.discordsays.com/",
    fetch: fetcher as typeof fetch,
    now: () => fixedNow,
  });
}

async function success(exchange: Exchange, overrides: Record<string, unknown> = {}) {
  const seconds = Math.floor(fixedNow / 1_000);
  return json({
    user_id: userId,
    session_id: "ses_activityfixture0001",
    access_token: accessToken(),
    token_type: "Bearer",
    expires_in: 300,
    id_token: await signIdToken({
      iss: issuer,
      sub: userId,
      aud: clientId,
      tenant_id: tenantId,
      token_use: "id",
      jti: "jti_activityfixture0001",
      iat: seconds,
      exp: seconds + 300,
      auth_time: seconds,
      nonce: exchange.nonce,
      idp: "discord",
    }),
    scope: "openid profile",
    discord: {
      access_token: "discord-access-token-fixture",
      token_type: "Bearer",
      expires_in: 604_800,
      scope: "identify",
    },
    ...overrides,
  });
}

describe("AUTH4D-312 signInWithDiscordActivity", () => {
  it("exchanges the code, checks the ID token and keeps the tokens in memory", async () => {
    const requests: { url: string; init?: RequestInit }[] = [];
    const client = makeClient((exchange) => success(exchange), requests);
    const result = await client.signInWithDiscordActivity({ code: discordCode });

    expect(result.session.user).toEqual({ sub: userId, idp: "discord" });
    expect(result.session.isGuest).toBe(false);
    expect(result.discord).toEqual({
      accessToken: "discord-access-token-fixture",
      expiresIn: 604_800,
      scope: "identify",
    });
    expect(client.getAccessToken()).toBe(accessToken());

    const exchange = requests.find((request) => request.url.endsWith("/identity/discord/activity"));
    expect(exchange?.init).toMatchObject({
      method: "POST",
      credentials: "omit",
      cache: "no-store",
    });
    const body = JSON.parse(String(exchange?.init?.body)) as Record<string, unknown>;
    expect(body).toEqual({ client_id: clientId, code: discordCode, nonce: body["nonce"] });
    expect(String(body["nonce"])).toMatch(/^[A-Za-z0-9_-]{43}$/u);
    // Nothing secret travels in a URL.
    for (const request of requests) {
      expect(request.url).not.toContain(discordCode);
      expect(request.url).not.toContain(String(body["nonce"]));
    }
  });

  it("refuses an ID token for another sign-in", async () => {
    const client = makeClient((exchange) => success({ ...exchange, nonce: `${exchange.nonce}x` }));
    await expect(client.signInWithDiscordActivity({ code: discordCode })).rejects.toMatchObject({
      code: "invalid_id_token",
    });
    expect(client.getSession()).toBeNull();
  });

  it("refuses tokens for different users", async () => {
    const client = makeClient((exchange) =>
      success(exchange, { access_token: accessToken("usr_someoneelse000001") }),
    );
    await expect(client.signInWithDiscordActivity({ code: discordCode })).rejects.toMatchObject({
      code: "discord_activity_failed",
    });
    expect(client.getSession()).toBeNull();
  });

  it("names the server's error code and never its description", async () => {
    const client = makeClient(() =>
      json({ error: "interaction_required", error_description: "<b>details</b>" }, 403),
    );
    const failure = await client
      .signInWithDiscordActivity({ code: discordCode })
      .catch((error: unknown) => error);
    expect(failure).toBeInstanceOf(Auth4BrowserError);
    expect((failure as Auth4BrowserError).code).toBe("discord_activity_failed");
    expect((failure as Auth4BrowserError).message).toContain("interaction_required");
    expect((failure as Auth4BrowserError).message).not.toContain("details");
  });

  it("requires a Discord token in the response", async () => {
    const client = makeClient((exchange) => success(exchange, { discord: undefined }));
    await expect(client.signInWithDiscordActivity({ code: discordCode })).rejects.toMatchObject({
      code: "discord_activity_failed",
    });
  });

  it("rejects a missing code before calling the API", async () => {
    const requests: { url: string }[] = [];
    const client = makeClient((exchange) => success(exchange), requests);
    await expect(client.signInWithDiscordActivity({ code: "" })).rejects.toMatchObject({
      code: "configuration_error",
    });
    expect(requests).toEqual([]);
  });
});
