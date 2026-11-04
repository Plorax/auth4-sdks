import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Auth4BrowserClient, type BrowserSessionEvent } from "./index.ts";

// AUTH4D-308: linking and unlinking provider accounts from the browser SDK. The window and the
// link-account popup are in-memory fakes; the API is a mocked fetch, and polling runs on fake timers.

const authOrigin = "https://auth.auth4.dev";
const tenantId = "ten_browserfixture0308";
const issuer = `${authOrigin}/t/${tenantId}`;
const clientId = "cli_browserfixture0308";
const redirectUri = "https://game.example.test/callback";
const userId = "usr_emailfixture000308";
const intent = `lai_${"I".repeat(32)}`;
const pollSecret = `lap_${"S".repeat(43)}`;
const linkUri = `${authOrigin}/login/link-account?tenant_id=${tenantId}&client_id=${clientId}&intent=${intent}`;

function base64Url(value: unknown): string {
  const bytes = new TextEncoder().encode(JSON.stringify(value));
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
}

function accessToken(marker: string): string {
  return `${base64Url({ alg: "RS256", typ: "at+jwt" })}.${base64Url({
    iss: issuer,
    sub: userId,
    jti: marker,
  })}.c2lnbmF0dXJl`;
}

const SIGNED_IN_TOKEN = accessToken("signed-in");
const REFRESHED_TOKEN = accessToken("refreshed");

interface FakePopup {
  closed: boolean;
  location: { replace(url: string): void; url: string | null };
  close(): void;
  focus(): void;
}

function fakePopup(): FakePopup {
  return {
    closed: false,
    location: {
      url: null,
      replace(url) {
        this.url = url;
      },
    },
    close() {
      this.closed = true;
    },
    focus() {},
  };
}

class FakeWindow {
  readonly opened: { url: string; target: string }[] = [];
  popup: FakePopup | null = fakePopup();
  open(url: string, target: string): FakePopup | null {
    this.opened.push({ url, target });
    return this.popup;
  }
  addEventListener(): void {}
  removeEventListener(): void {}
}

let browser: FakeWindow;

beforeEach(() => {
  vi.useFakeTimers({ now: Date.UTC(2026, 9, 22, 12, 0, 0) });
  browser = new FakeWindow();
  vi.stubGlobal("window", browser);
});

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

type Reply = { status: number; body: Record<string, unknown> };

function makeClient(
  polls: Reply[],
  create: Reply = { status: 200, body: createdBody() },
  list: Reply = { status: 200, body: { accounts: [] } },
) {
  const requests: { url: string; init: RequestInit | undefined }[] = [];
  const fetcher: typeof fetch = async (input, init) => {
    const url = typeof input === "string" ? input : input.toString();
    requests.push({ url, init });
    if (url === `${issuer}/guest`) {
      return Response.json({
        user_id: userId,
        upgrade_proof: { proof_id: "prf_fixture0000000308", expires_in: 300 },
        access_token: SIGNED_IN_TOKEN,
        token_type: "Bearer",
        expires_in: 300,
      });
    }
    if (url === `${issuer}/account/link/intent`) {
      return Response.json(create.body, { status: create.status });
    }
    if (url === `${issuer}/account/link/intent/token`) {
      const next = polls.shift() ?? { status: 400, body: { error: "authorization_pending" } };
      return Response.json(next.body, { status: next.status });
    }
    if (url === `${issuer}/account/identities`) {
      return Response.json(list.body, { status: list.status });
    }
    return new Response(null, { status: 404 });
  };
  const client = new Auth4BrowserClient({
    issuer,
    clientId,
    redirectUri,
    fetch: fetcher,
    now: () => Date.now(),
  });
  const events: BrowserSessionEvent[] = [];
  client.onSessionEvent((event) => events.push(event));
  return { client, requests, events };
}

function createdBody(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    intent,
    poll_secret: pollSecret,
    link_uri: linkUri,
    expires_in: 600,
    interval: 5,
    ...overrides,
  };
}

const tokens = {
  user_id: userId,
  access_token: REFRESHED_TOKEN,
  token_type: "Bearer",
  expires_in: 300,
  session_id: "ses_refreshedfixture1",
};

const linked: Reply = {
  status: 200,
  body: { ...tokens, identity: { identity_id: "idn_steamfixture0308", provider: "steam" } },
};

/** A signed-in, non-guest session: the guest fixture's token carries no auth4_guest claim. */
async function signedIn(client: Auth4BrowserClient): Promise<void> {
  await client.signInAsGuest();
  expect(client.getSession()?.isGuest).toBe(false);
}

describe("AUTH4D-308 browser linkAccount and unlinkAccount", () => {
  it("opens the window in the gesture, polls with the secret and keeps the same user", async () => {
    const { client, requests, events } = makeClient([
      { status: 400, body: { error: "authorization_pending", interval: 5 } },
      linked,
    ]);
    await signedIn(client);
    const result = client.linkAccount("steam");
    // The window opens synchronously, before any request.
    expect(browser.opened).toEqual([{ url: "about:blank", target: "auth4-link-account" }]);
    await vi.advanceTimersByTimeAsync(11_000);
    const outcome = await result;
    expect(outcome.identity).toEqual({ identityId: "idn_steamfixture0308", provider: "steam" });
    expect(outcome.session.user.sub).toBe(userId);
    expect(client.getAccessToken()).toBe(REFRESHED_TOKEN);
    expect(events.map((event) => event.type)).toEqual(["account_linked"]);
    expect(browser.popup?.location.url).toBe(linkUri);

    const create = requests.find((entry) => entry.url.endsWith("/account/link/intent"))!;
    expect(new Headers(create.init?.headers).get("Authorization")).toBe(
      `Bearer ${SIGNED_IN_TOKEN}`,
    );
    expect(create.init?.credentials).toBe("omit");
    expect(JSON.parse(String(create.init?.body))).toEqual({
      client_id: clientId,
      provider: "steam",
      action: "link",
    });
    const polls = requests.filter((entry) => entry.url.endsWith("/intent/token"));
    expect(polls).toHaveLength(2);
    expect(JSON.parse(String(polls[0]!.init?.body))).toEqual({
      client_id: clientId,
      intent,
      poll_secret: pollSecret,
    });
    // The poll secret never reaches the window.
    expect(browser.popup?.location.url).not.toContain(pollSecret);
  });

  it("unlinks and emits account_unlinked", async () => {
    const { client, requests, events } = makeClient([{ status: 200, body: tokens }]);
    await signedIn(client);
    const result = client.unlinkAccount("discord");
    await vi.advanceTimersByTimeAsync(6_000);
    expect((await result).session.user.sub).toBe(userId);
    expect(events.map((event) => event.type)).toEqual(["account_unlinked"]);
    const create = requests.find((entry) => entry.url.endsWith("/account/link/intent"))!;
    expect(JSON.parse(String(create.init?.body))).toMatchObject({
      provider: "discord",
      action: "unlink",
    });
  });

  it("maps refusals at creation and closes the window", async () => {
    for (const [code, status] of [
      ["only_sign_in_method", 409],
      ["provider_already_linked", 409],
      ["provider_disabled", 409],
      // AUTH4D-343: a sign-in older than five minutes.
      ["login_required", 403],
    ] as const) {
      browser.popup = fakePopup();
      const { client } = makeClient([], { status, body: { error: code } });
      await signedIn(client);
      await expect(client.linkAccount("epic")).rejects.toMatchObject({ code });
      expect(browser.popup?.closed).toBe(true);
    }
  });

  it("reports Not now as cancelled and rejects a link result for another provider", async () => {
    const denied = makeClient([{ status: 400, body: { error: "access_denied" } }]);
    await signedIn(denied.client);
    const cancelled = denied.client.linkAccount("steam");
    const cancelledCheck = expect(cancelled).rejects.toMatchObject({ code: "cancelled" });
    await vi.advanceTimersByTimeAsync(6_000);
    await cancelledCheck;

    browser.popup = fakePopup();
    const wrong = makeClient([linked]);
    await signedIn(wrong.client);
    const pending = wrong.client.linkAccount("discord");
    const wrongCheck = expect(pending).rejects.toMatchObject({ code: "link_account_failed" });
    await vi.advanceTimersByTimeAsync(6_000);
    await wrongCheck;
  });

  it("rejects a page URL off the auth origin, a second window and a missing session", async () => {
    const { client } = makeClient([], {
      status: 200,
      body: createdBody({ link_uri: "https://evil.example.test/login/link-account" }),
    });
    await expect(client.linkAccount("steam")).rejects.toMatchObject({ code: "invalid_session" });
    await signedIn(client);
    await expect(client.linkAccount("steam")).rejects.toMatchObject({
      code: "link_account_failed",
    });
    expect(browser.popup?.location.url).toBeNull();

    browser.popup = fakePopup();
    const busy = makeClient([]);
    await signedIn(busy.client);
    const first = busy.client.linkAccount("steam");
    expect(busy.client.linkAccount("steam")).toBe(first);
    await expect(busy.client.unlinkAccount("steam")).rejects.toMatchObject({
      code: "account_window_open",
    });
    browser.popup.closed = true;
    const closedCheck = expect(first).rejects.toMatchObject({ code: "window_closed" });
    await vi.advanceTimersByTimeAsync(6_000);
    await closedCheck;
  });

  it("lists linked accounts without subjects", async () => {
    const { client, requests } = makeClient([], undefined, {
      status: 200,
      body: {
        accounts: [
          { identity_id: "idn_a", provider: "email", linked_at: "2026-10-01T00:00:00.000Z" },
          { identity_id: "idn_b", provider: "steam", linked_at: "2026-10-02T00:00:00.000Z" },
        ],
      },
    });
    await expect(client.linkedAccounts()).rejects.toMatchObject({ code: "invalid_session" });
    await signedIn(client);
    expect(await client.linkedAccounts()).toEqual([
      { identityId: "idn_a", provider: "email", linkedAt: "2026-10-01T00:00:00.000Z" },
      { identityId: "idn_b", provider: "steam", linkedAt: "2026-10-02T00:00:00.000Z" },
    ]);
    const list = requests.find((entry) => entry.url.endsWith("/account/identities"))!;
    expect(new Headers(list.init?.headers).get("Authorization")).toBe(`Bearer ${SIGNED_IN_TOKEN}`);
  });
});
