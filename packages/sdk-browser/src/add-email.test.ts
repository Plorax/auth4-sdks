import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Auth4BrowserClient, type BrowserSessionEvent } from "./index.ts";

// AUTH4D-149: adding an email address from the browser SDK. The window and the add-email popup are
// in-memory fakes; the API is a mocked fetch, and polling runs on fake timers.

const authOrigin = "https://auth.auth4.dev";
const tenantId = "ten_browserfixture0149";
const issuer = `${authOrigin}/t/${tenantId}`;
const clientId = "cli_browserfixture0149";
const redirectUri = "https://game.example.test/callback";
const userId = "usr_steamfixture000149";
const intent = `aei_${"I".repeat(32)}`;
const pollSecret = `aep_${"S".repeat(43)}`;
const addEmailUri = `${authOrigin}/login/add-email?tenant_id=${tenantId}&client_id=${clientId}&intent=${intent}`;

function base64Url(value: unknown): string {
  const bytes = new TextEncoder().encode(JSON.stringify(value));
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
}

function accessToken(claims: Record<string, unknown>, marker: string): string {
  return `${base64Url({ alg: "RS256", typ: "at+jwt" })}.${base64Url({
    iss: issuer,
    sub: userId,
    jti: marker,
    ...claims,
  })}.c2lnbmF0dXJl`;
}

const STEAM_TOKEN = accessToken({}, "steam");
const REFRESHED_TOKEN = accessToken({ email: "player@example.test" }, "refreshed");

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
  vi.useFakeTimers({ now: Date.UTC(2026, 9, 6, 12, 0, 0) });
  browser = new FakeWindow();
  vi.stubGlobal("window", browser);
});

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

type Reply = { status: number; body: Record<string, unknown> };

function makeClient(polls: Reply[], create: Reply = { status: 200, body: createdBody() }) {
  const requests: { url: string; init: RequestInit | undefined }[] = [];
  const fetcher: typeof fetch = async (input, init) => {
    const url = typeof input === "string" ? input : input.toString();
    requests.push({ url, init });
    if (url === `${issuer}/guest`) {
      return Response.json({
        user_id: userId,
        upgrade_proof: { proof_id: "prf_fixture0000000149", expires_in: 300 },
        access_token: STEAM_TOKEN,
        token_type: "Bearer",
        expires_in: 300,
      });
    }
    if (url === `${issuer}/account/email/intent`) {
      return Response.json(create.body, { status: create.status });
    }
    if (url === `${issuer}/account/email/intent/token`) {
      const next = polls.shift() ?? { status: 400, body: { error: "authorization_pending" } };
      return Response.json(next.body, { status: next.status });
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
    add_email_uri: addEmailUri,
    expires_in: 600,
    interval: 5,
    ...overrides,
  };
}

const approved: Reply = {
  status: 200,
  body: {
    user_id: userId,
    identity: { identity_id: "idn_emailfixture0149", provider: "email" },
    email: "player@example.test",
    access_token: REFRESHED_TOKEN,
    token_type: "Bearer",
    expires_in: 300,
    session_id: "ses_refreshedfixture1",
  },
};

/** A signed-in, non-guest session: the guest fixture's token carries no auth4_guest claim. */
async function signedIn(client: Auth4BrowserClient): Promise<void> {
  await client.signInAsGuest();
  expect(client.getSession()?.isGuest).toBe(false);
}

describe("AUTH4D-149 browser addEmail", () => {
  it("opens the window in the gesture, polls with the secret and swaps in the refreshed session", async () => {
    const { client, requests, events } = makeClient([
      { status: 400, body: { error: "authorization_pending", interval: 5 } },
      approved,
    ]);
    await signedIn(client);
    const result = client.addEmail();
    // The window opens synchronously, before any request.
    expect(browser.opened).toEqual([{ url: "about:blank", target: "auth4-add-email" }]);
    await vi.advanceTimersByTimeAsync(11_000);
    const outcome = await result;
    expect(outcome.email).toBe("player@example.test");
    expect(outcome.identity).toEqual({ identityId: "idn_emailfixture0149", provider: "email" });
    expect(outcome.session.user).toEqual({
      sub: userId,
      email: "player@example.test",
      email_verified: true,
    });
    expect(client.getAccessToken()).toBe(REFRESHED_TOKEN);
    expect(events.map((event) => event.type)).toEqual(["email_added"]);
    expect(browser.popup?.location.url).toBe(addEmailUri);

    const create = requests.find((entry) => entry.url.endsWith("/account/email/intent"))!;
    expect(new Headers(create.init?.headers).get("Authorization")).toBe(`Bearer ${STEAM_TOKEN}`);
    expect(create.init?.credentials).toBe("omit");
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

  it("maps refusals at creation and closes the window", async () => {
    const { client } = makeClient([], { status: 409, body: { error: "email_already_added" } });
    await signedIn(client);
    await expect(client.addEmail()).rejects.toMatchObject({ code: "email_already_added" });
    expect(browser.popup?.closed).toBe(true);
  });

  it("reports Not now as cancelled and a closed window as window_closed", async () => {
    const denied = makeClient([{ status: 400, body: { error: "access_denied" } }]);
    await signedIn(denied.client);
    const cancelled = denied.client.addEmail();
    const cancelledCheck = expect(cancelled).rejects.toMatchObject({ code: "cancelled" });
    await vi.advanceTimersByTimeAsync(6_000);
    await cancelledCheck;

    browser.popup = fakePopup();
    const closed = makeClient([]);
    await signedIn(closed.client);
    const pending = closed.client.addEmail();
    const closedCheck = expect(pending).rejects.toMatchObject({ code: "window_closed" });
    browser.popup.closed = true;
    await vi.advanceTimersByTimeAsync(6_000);
    await closedCheck;
  });

  it("rejects a page URL off the auth origin and requires a session", async () => {
    const { client } = makeClient([], {
      status: 200,
      body: createdBody({ add_email_uri: "https://evil.example.test/login/add-email" }),
    });
    await expect(client.addEmail()).rejects.toMatchObject({ code: "invalid_session" });
    await signedIn(client);
    await expect(client.addEmail()).rejects.toMatchObject({ code: "add_email_failed" });
    expect(browser.popup?.location.url).toBeNull();
  });

  it("rejects popup_blocked when the browser refuses the window", async () => {
    const { client } = makeClient([]);
    await signedIn(client);
    browser.popup = null;
    await expect(client.addEmail()).rejects.toMatchObject({ code: "popup_blocked" });
  });
});
