import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  Auth4BrowserClient,
  Auth4BrowserError,
  type BrowserSessionEvent,
  type BrowserStorage,
  type SocialProvider,
} from "./index.ts";

// AUTH4D-66: guest sign-in and the opener side of the guest-upgrade window protocol. The browser
// window, the upgrade popup and postMessage are in-memory fakes; the API is a mocked fetch.

const authOrigin = "https://auth.auth4.dev";
const tenantId = "ten_browserfixture0001";
const issuer = `${authOrigin}/t/${tenantId}`;
const clientId = "cli_browserfixture0001";
const redirectUri = "https://game.example.test/callback";
const userId = "usr_guestfixture000001";
const fixedNow = Date.UTC(2026, 9, 5, 12, 0, 0);

function base64Url(value: unknown): string {
  const bytes = new TextEncoder().encode(JSON.stringify(value));
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
}

/** The SDK only reads access-token claims, so the fixtures carry a placeholder signature. */
function accessToken(claims: Record<string, unknown>, marker: string): string {
  return `${base64Url({ alg: "RS256", typ: "at+jwt" })}.${base64Url({
    iss: issuer,
    sub: userId,
    jti: marker,
    ...claims,
  })}.c2lnbmF0dXJl`;
}

const GUEST_TOKEN = accessToken({ auth4_guest: true }, "guest");
const UPGRADED_TOKEN = accessToken({}, "upgraded");

function guestBody(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    user_id: userId,
    upgrade_proof: { proof_id: "prf_guestfixture0001", expires_in: 300 },
    access_token: GUEST_TOKEN,
    token_type: "Bearer",
    expires_in: 300,
    refresh_token: "guest-refresh-token-secret",
    scope: "openid profile offline_access",
    session_id: "ses_guestfixture0001",
    ...overrides,
  };
}

function upgradeResult(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    user_id: userId,
    identity: { identity_id: "idn_emailfixture0001", provider: "email" },
    access_token: UPGRADED_TOKEN,
    token_type: "Bearer",
    expires_in: 300,
    refresh_token: "upgraded-refresh-token-secret",
    session_id: "ses_upgradedfixture01",
    ...overrides,
  };
}

class ThrowingStorage implements BrowserStorage {
  getItem(): string | null {
    throw new Error("storage must not be used");
  }
  setItem(): void {
    throw new Error("storage must not be used");
  }
  removeItem(): void {
    throw new Error("storage must not be used");
  }
}

interface FakePopup {
  closed: boolean;
  posted: { message: unknown; targetOrigin: string }[];
  postMessage(message: unknown, targetOrigin: string): void;
  close(): void;
  focus(): void;
}

function fakePopup(): FakePopup {
  return {
    closed: false,
    posted: [],
    postMessage(message, targetOrigin) {
      this.posted.push({ message, targetOrigin });
    },
    close() {
      this.closed = true;
    },
    focus() {},
  };
}

class FakeWindow {
  readonly listeners = new Set<(event: MessageEvent) => void>();
  readonly opened: { url: string; target: string; features: string }[] = [];
  popup: FakePopup | null = fakePopup();

  open(url: string, target: string, features: string): FakePopup | null {
    this.opened.push({ url, target, features });
    return this.popup;
  }

  addEventListener(type: string, listener: (event: MessageEvent) => void): void {
    if (type === "message") this.listeners.add(listener);
  }

  removeEventListener(type: string, listener: (event: MessageEvent) => void): void {
    if (type === "message") this.listeners.delete(listener);
  }

  /** Deliver a message as the browser would: with the sender's origin and window. */
  deliver(data: unknown, origin = authOrigin, source: unknown = this.popup): void {
    for (const listener of [...this.listeners]) {
      listener({ data, origin, source } as MessageEvent);
    }
  }
}

let browser: FakeWindow;
let clock = fixedNow;

beforeEach(() => {
  clock = fixedNow;
  browser = new FakeWindow();
  vi.stubGlobal("window", browser);
});

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

function makeClient(
  args: {
    guestResponse?: () => Response;
    refresh?: boolean;
    tokenBody?: (form: URLSearchParams) => unknown;
  } = {},
) {
  const requests: { url: string; init: RequestInit | undefined }[] = [];
  const fetcher: typeof fetch = async (input, init) => {
    const url = typeof input === "string" ? input : input.toString();
    requests.push({ url, init });
    if (url === `${issuer}/guest`) {
      return args.guestResponse?.() ?? Response.json(guestBody());
    }
    if (url === `${issuer}/.well-known/openid-configuration`) {
      return Response.json({
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
    if (url.startsWith(`${authOrigin}/oauth/token`)) {
      const form = new URLSearchParams(String(init?.body ?? ""));
      return Response.json(args.tokenBody?.(form) ?? {});
    }
    return new Response(null, { status: 404 });
  };
  const client = new Auth4BrowserClient({
    issuer,
    clientId,
    redirectUri,
    fetch: fetcher,
    storage: new ThrowingStorage(),
    now: () => clock,
    ...(args.refresh === undefined ? {} : { refresh: args.refresh }),
  });
  const events: BrowserSessionEvent[] = [];
  client.onSessionEvent((event) => events.push(event));
  return { client, requests, events };
}

async function settle(): Promise<void> {
  for (let index = 0; index < 5; index += 1) await Promise.resolve();
}

function ready(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    type: "auth4:guest-upgrade:ready",
    tenant_id: tenantId,
    client_id: clientId,
    ...overrides,
  };
}

async function errorOf(promise: Promise<unknown>): Promise<Auth4BrowserError> {
  try {
    await promise;
  } catch (error) {
    expect(error).toBeInstanceOf(Auth4BrowserError);
    return error as Auth4BrowserError;
  }
  throw new Error("Expected the promise to reject.");
}

describe("signInAsGuest", () => {
  it("creates a guest session from the guest endpoint and flags it from the auth4_guest claim", async () => {
    const { client, requests } = makeClient();
    const session = await client.signInAsGuest();

    expect(session).toEqual({
      user: { sub: userId },
      expiresAt: fixedNow + 300_000,
      isGuest: true,
    });
    expect(client.getSession()).toEqual(session);
    expect(client.getAccessToken()).toBe(GUEST_TOKEN);

    expect(requests).toHaveLength(1);
    const [request] = requests;
    expect(request!.url).toBe(`${issuer}/guest`);
    expect(request!.init?.method).toBe("POST");
    expect(request!.init?.credentials).toBe("omit");
    const body = JSON.parse(String(request!.init?.body)) as Record<string, unknown>;
    expect(Object.keys(body).sort()).toEqual(["browser_flow_id", "client_id"]);
    expect(body["client_id"]).toBe(clientId);
    expect(body["browser_flow_id"]).toMatch(/^flw_[A-Za-z0-9_-]{43}$/u);
  });

  it("uses a fresh browser flow per call and drops the refresh token without the refresh option", async () => {
    const { client, requests } = makeClient();
    await client.signInAsGuest();
    await client.signInAsGuest();
    const flows = requests.map(
      (request) =>
        (JSON.parse(String(request.init?.body)) as { browser_flow_id: string }).browser_flow_id,
    );
    expect(new Set(flows).size).toBe(2);
    expect(JSON.stringify(client)).not.toContain("guest-refresh-token-secret");
  });

  it("reports isGuest false when the access token has no guest claim", async () => {
    const { client } = makeClient({
      guestResponse: () => Response.json(guestBody({ access_token: UPGRADED_TOKEN })),
    });
    expect((await client.signInAsGuest()).isGuest).toBe(false);
  });

  it.each([
    ["an HTTP error", () => Response.json({ error: "slow_down" }, { status: 429 })],
    ["a missing user_id", () => Response.json(guestBody({ user_id: undefined }))],
    [
      "a token for another user",
      () =>
        Response.json(
          guestBody({ access_token: accessToken({ sub: "usr_someoneelse0001" }, "x") }),
        ),
    ],
    ["an over-long token lifetime", () => Response.json(guestBody({ expires_in: 3_600 }))],
    ["invalid JSON", () => new Response("<html>", { status: 200 })],
  ])("rejects %s with guest_sign_in_failed and keeps no session", async (_label, response) => {
    const { client } = makeClient({ guestResponse: response });
    expect((await errorOf(client.signInAsGuest())).code).toBe("guest_sign_in_failed");
    expect(client.getSession()).toBeNull();
  });
});

describe("upgradeGuest", () => {
  async function guestClient(options: { refresh?: boolean } = {}) {
    const made = makeClient(options);
    await made.client.signInAsGuest();
    return made;
  }

  it("opens the hosted upgrade page synchronously with no token in the URL", async () => {
    const { client } = await guestClient();
    const upgrade = client.upgradeGuest();
    // window.open ran before the method returned, inside the caller's gesture.
    expect(browser.opened).toHaveLength(1);
    const opened = browser.opened[0]!;
    expect(opened.url).toBe(
      `${authOrigin}/login/upgrade?tenant_id=${tenantId}&client_id=${clientId}`,
    );
    expect(opened.url).not.toContain(GUEST_TOKEN);
    expect(opened.features).not.toContain("noopener");
    browser.deliver({ type: "auth4:guest-upgrade:cancelled" });
    await expect(upgrade).rejects.toMatchObject({ code: "cancelled" });
  });

  it("asks the upgrade page to offer a supported provider first (AUTH4D-125, AUTH4D-147, AUTH4D-213)", async () => {
    for (const provider of ["steam", "discord", "epic", "google", "apple", "microsoft"] as const) {
      const { client } = await guestClient();
      const upgrade = client.upgradeGuest({ provider });
      expect(browser.opened.at(-1)!.url).toBe(
        `${authOrigin}/login/upgrade?tenant_id=${tenantId}&client_id=${clientId}&provider=${provider}`,
      );
      browser.deliver({ type: "auth4:guest-upgrade:cancelled" });
      await expect(upgrade).rejects.toMatchObject({ code: "cancelled" });
    }
  });

  it("rejects an unknown provider without opening a window", async () => {
    const { client } = await guestClient();
    const upgrade = client.upgradeGuest({ provider: "twitch" as unknown as SocialProvider });
    expect((await errorOf(upgrade)).code).toBe("configuration_error");
    expect(browser.opened).toEqual([]);
  });

  it("answers ready only from the upgrade window on the auth origin, and sends the token only there", async () => {
    const { client } = await guestClient();
    const upgrade = client.upgradeGuest();
    const popup = browser.popup!;
    const otherWindow = fakePopup();

    browser.deliver(ready(), "https://evil.example.test");
    browser.deliver(ready(), authOrigin, otherWindow);
    browser.deliver(ready(), `${authOrigin}:8443`);
    browser.deliver(ready({ tenant_id: "ten_othertenant00001" }));
    browser.deliver(ready({ client_id: "cli_otherclient00001" }));
    browser.deliver("auth4:guest-upgrade:ready");
    await settle();
    expect(popup.posted).toEqual([]);
    expect(otherWindow.posted).toEqual([]);

    browser.deliver(ready());
    await settle();
    expect(popup.posted).toEqual([
      {
        message: { type: "auth4:guest-upgrade:token", access_token: GUEST_TOKEN },
        targetOrigin: authOrigin,
      },
    ]);

    browser.deliver({ type: "auth4:guest-upgrade:cancelled" });
    await upgrade.catch(() => undefined);
  });

  it("replaces the token set atomically on complete and keeps the user ID", async () => {
    const { client, events } = await guestClient();
    const upgrade = client.upgradeGuest();
    browser.deliver(ready());
    await settle();

    // A completion from anywhere but the upgrade window on the auth origin is ignored.
    browser.deliver(
      { type: "auth4:guest-upgrade:complete", result: upgradeResult() },
      "https://evil.example.test",
    );
    browser.deliver(
      { type: "auth4:guest-upgrade:complete", result: upgradeResult() },
      authOrigin,
      fakePopup(),
    );
    expect(client.getAccessToken()).toBe(GUEST_TOKEN);

    browser.deliver({ type: "auth4:guest-upgrade:complete", result: upgradeResult() });
    const result = await upgrade;
    expect(result).toEqual({
      session: { user: { sub: userId }, expiresAt: fixedNow + 300_000, isGuest: false },
      identity: { identityId: "idn_emailfixture0001", provider: "email" },
    });
    expect(client.getAccessToken()).toBe(UPGRADED_TOKEN);
    expect(client.getSession()).toEqual(result.session);
    expect(events).toContainEqual({ type: "upgraded", session: result.session });
    expect(JSON.stringify(events)).not.toContain(UPGRADED_TOKEN);
    expect(browser.listeners.size).toBe(0);
  });

  it("renews with the replacement refresh token after an upgrade", async () => {
    const forms: URLSearchParams[] = [];
    const made = makeClient({
      refresh: true,
      tokenBody: (form) => {
        forms.push(form);
        return { access_token: UPGRADED_TOKEN, token_type: "Bearer", expires_in: 300 };
      },
    });
    await made.client.signInAsGuest();
    const upgrade = made.client.upgradeGuest();
    browser.deliver({ type: "auth4:guest-upgrade:complete", result: upgradeResult() });
    await upgrade;

    // Inside the renewal window, the renewal presents the replacement refresh token.
    clock = fixedNow + 290_000;
    expect(await made.client.getAccessTokenSilently()).toBe(UPGRADED_TOKEN);
    expect(forms.map((form) => form.get("refresh_token"))).toEqual([
      "upgraded-refresh-token-secret",
    ]);
    expect(made.client.getSession()?.isGuest).toBe(false);
    await made.client.logout().catch(() => undefined);
  });

  it("rejects an upgrade result for another user and keeps the guest token set", async () => {
    const { client } = await guestClient();
    const upgrade = client.upgradeGuest();
    browser.deliver({
      type: "auth4:guest-upgrade:complete",
      result: upgradeResult({ user_id: "usr_someoneelse0001" }),
    });
    expect((await errorOf(upgrade)).code).toBe("upgrade_failed");
    expect(client.getAccessToken()).toBe(GUEST_TOKEN);
    expect(client.getSession()?.isGuest).toBe(true);
  });

  it("rejects with identity_in_use and still accepts a later completion from the same window", async () => {
    const { client, events } = await guestClient();
    const upgrade = client.upgradeGuest();
    browser.deliver({ type: "auth4:guest-upgrade:error", error: "identity_in_use" });
    expect((await errorOf(upgrade)).code).toBe("identity_in_use");
    expect(client.getAccessToken()).toBe(GUEST_TOKEN);

    // The player links a different credential in the same window.
    browser.deliver(ready());
    await settle();
    expect(browser.popup!.posted).toHaveLength(1);
    browser.deliver({ type: "auth4:guest-upgrade:complete", result: upgradeResult() });
    expect(client.getAccessToken()).toBe(UPGRADED_TOKEN);
    expect(events.some((event) => event.type === "upgraded")).toBe(true);
    expect(browser.listeners.size).toBe(0);
  });

  it.each([
    [{ type: "auth4:guest-upgrade:error", error: "invalid_session" }, "invalid_session"],
    [{ type: "auth4:guest-upgrade:cancelled" }, "cancelled"],
  ])("rejects %o with a typed error", async (message, code) => {
    const { client } = await guestClient();
    const upgrade = client.upgradeGuest();
    browser.deliver(message);
    expect((await errorOf(upgrade)).code).toBe(code);
    expect(browser.listeners.size).toBe(0);
  });

  it("rejects with window_closed when the player closes the window", async () => {
    const { client } = await guestClient();
    vi.useFakeTimers();
    const upgrade = client.upgradeGuest();
    browser.popup!.closed = true;
    vi.advanceTimersByTime(600);
    expect((await errorOf(upgrade)).code).toBe("window_closed");
    expect(browser.listeners.size).toBe(0);
  });

  it("closes the window and rejects with cancelled when the signal aborts", async () => {
    const { client } = await guestClient();
    const controller = new AbortController();
    const upgrade = client.upgradeGuest({ signal: controller.signal });
    controller.abort();
    expect((await errorOf(upgrade)).code).toBe("cancelled");
    expect(browser.popup!.closed).toBe(true);
  });

  it("stops sending the token once the local session has ended", async () => {
    const { client } = await guestClient();
    const upgrade = client.upgradeGuest();
    await client.logout().catch(() => undefined);
    browser.deliver(ready());
    expect((await errorOf(upgrade)).code).toBe("invalid_session");
    expect(browser.popup!.posted).toEqual([]);
  });

  it("refuses to open a window without a guest session", async () => {
    const { client } = makeClient();
    expect((await errorOf(client.upgradeGuest())).code).toBe("invalid_session");

    const upgraded = makeClient({
      guestResponse: () => Response.json(guestBody({ access_token: UPGRADED_TOKEN })),
    });
    await upgraded.client.signInAsGuest();
    expect((await errorOf(upgraded.client.upgradeGuest())).code).toBe("not_guest");
    expect(browser.opened).toEqual([]);
  });

  it("rejects with popup_blocked when the browser blocks the window", async () => {
    const { client } = await guestClient();
    browser.popup = null;
    expect((await errorOf(client.upgradeGuest())).code).toBe("popup_blocked");
  });

  it("returns the pending upgrade instead of opening a second window", async () => {
    const { client } = await guestClient();
    const first = client.upgradeGuest();
    const second = client.upgradeGuest();
    expect(second).toBe(first);
    expect(browser.opened).toHaveLength(1);
    browser.deliver({ type: "auth4:guest-upgrade:cancelled" });
    await first.catch(() => undefined);
  });
});
