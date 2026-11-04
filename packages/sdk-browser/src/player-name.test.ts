import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Auth4BrowserClient } from "./index.ts";

// AUTH4D-324: reading and setting the player's display name from the browser SDK. The API is a
// mocked fetch; the session comes from a guest sign-in.

const authOrigin = "https://auth.auth4.dev";
const tenantId = "ten_browserfixture0324";
const issuer = `${authOrigin}/t/${tenantId}`;
const clientId = "cli_browserfixture0324";
const userId = "usr_namefixture0000324";

function base64Url(value: unknown): string {
  const bytes = new TextEncoder().encode(JSON.stringify(value));
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
}

const ACCESS_TOKEN = `${base64Url({ alg: "RS256", typ: "at+jwt" })}.${base64Url({
  iss: issuer,
  sub: userId,
  jti: "signed-in",
})}.c2lnbmF0dXJl`;

beforeEach(() => {
  vi.useFakeTimers({ now: Date.UTC(2026, 9, 24, 12, 0, 0) });
  vi.stubGlobal("window", { addEventListener() {}, removeEventListener() {} });
});

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

type Reply = { status: number; body: unknown };

function makeClient(reply: Reply) {
  const requests: { url: string; init: RequestInit | undefined }[] = [];
  const fetcher: typeof fetch = async (input, init) => {
    const url = typeof input === "string" ? input : input.toString();
    requests.push({ url, init });
    if (url === `${issuer}/guest`) {
      return Response.json({
        user_id: userId,
        access_token: ACCESS_TOKEN,
        token_type: "Bearer",
        expires_in: 300,
      });
    }
    if (url === `${issuer}/me/name`) return Response.json(reply.body, { status: reply.status });
    return new Response(null, { status: 404 });
  };
  const client = new Auth4BrowserClient({
    issuer,
    clientId,
    redirectUri: "https://game.example.test/callback",
    fetch: fetcher,
    now: () => Date.now(),
  });
  return { client, requests };
}

describe("AUTH4D-324 browser getPlayerName and setPlayerName", () => {
  it("needs a session", async () => {
    const { client, requests } = makeClient({ status: 200, body: {} });
    await expect(client.getPlayerName()).rejects.toMatchObject({ code: "invalid_session" });
    await expect(client.setPlayerName("Ace")).rejects.toMatchObject({ code: "invalid_session" });
    expect(requests).toHaveLength(0);
  });

  it("reads an unset name", async () => {
    const { client, requests } = makeClient({
      status: 200,
      body: { name: null, discriminator: null, tag: null },
    });
    await client.signInAsGuest();
    expect(await client.getPlayerName()).toEqual({ name: null, discriminator: null, tag: null });
    const call = requests.at(-1)!;
    expect(call.init?.method).toBe("GET");
    expect(call.init?.body).toBeUndefined();
    expect(call.init?.credentials).toBe("omit");
    expect(new Headers(call.init?.headers).get("Authorization")).toBe(`Bearer ${ACCESS_TOKEN}`);
  });

  it("sets a name with a bearer token and returns the server's discriminator", async () => {
    const { client, requests } = makeClient({
      status: 200,
      body: { name: "Ace", discriminator: "0427", tag: "Ace#0427" },
    });
    await client.signInAsGuest();
    expect(await client.setPlayerName("Ace")).toEqual({
      name: "Ace",
      discriminator: "0427",
      tag: "Ace#0427",
    });
    const call = requests.at(-1)!;
    expect(call.url).toBe(`${issuer}/me/name`);
    expect(call.init?.method).toBe("PUT");
    expect(JSON.parse(String(call.init?.body))).toEqual({ name: "Ace" });
    expect(new Headers(call.init?.headers).get("Content-Type")).toBe("application/json");
  });

  it("clears a name with null", async () => {
    const { client, requests } = makeClient({
      status: 200,
      body: { name: null, discriminator: null, tag: null },
    });
    await client.signInAsGuest();
    await client.setPlayerName(null);
    expect(JSON.parse(String(requests.at(-1)!.init?.body))).toEqual({ name: null });
  });

  it.each([
    [{ status: 400, body: { error: "invalid_name" } }, "invalid_name"],
    [{ status: 409, body: { error: "name_unavailable" } }, "name_unavailable"],
    [{ status: 429, body: { error: "rate_limited" } }, "name_unavailable"],
    [{ status: 401, body: { error: "invalid_token" } }, "invalid_session"],
    [{ status: 503, body: { error: "temporarily_unavailable" } }, "player_name_failed"],
    [
      { status: 200, body: { name: "Ace", discriminator: "12", tag: "Ace#12" } },
      "player_name_failed",
    ],
    [
      { status: 200, body: { name: "Ace", discriminator: "1234", tag: "Bob#1234" } },
      "player_name_failed",
    ],
  ] as const)("maps %j to %s", async (reply, code) => {
    const { client } = makeClient(reply);
    await client.signInAsGuest();
    await expect(client.setPlayerName("Ace")).rejects.toMatchObject({ code });
  });
});
