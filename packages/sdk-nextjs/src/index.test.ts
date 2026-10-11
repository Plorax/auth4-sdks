import { createElement } from "react";
import { renderToString } from "react-dom/server";
import { afterEach, describe, expect, it, vi } from "vitest";
import { AccessTokenRequestError, Auth4Provider, getAccessToken, useUser } from "./index.ts";

// AUTH4D-231: the client entry. The provider hands the server-rendered user to useUser() without a
// request, and getAccessToken() only reads the opt-in route.

function Badge() {
  const { user, isLoading } = useUser();
  return createElement("p", null, isLoading ? "loading" : (user?.email ?? "signed out"));
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("AUTH4D-231 client entry", () => {
  it("renders the user from Auth4Provider without fetching", () => {
    const fetch = vi.fn();
    vi.stubGlobal("fetch", fetch);
    const html = renderToString(
      createElement(
        Auth4Provider,
        { user: { sub: "usr_1", email: "player@example.test" } },
        createElement(Badge),
      ),
    );
    expect(html).toContain("player@example.test");
    const signedOut = renderToString(
      createElement(Auth4Provider, { user: null }, createElement(Badge)),
    );
    expect(signedOut).toContain("signed out");
    expect(fetch).not.toHaveBeenCalled();
  });

  it("is loading without a provider until the profile arrives", () => {
    expect(renderToString(createElement(Badge))).toContain("loading");
  });

  it("reads /auth/access-token and reports the route's error code", async () => {
    const fetch = vi
      .fn()
      .mockResolvedValueOnce(Response.json({ token: "at", expires_at: 1, scope: "openid" }))
      .mockResolvedValueOnce(Response.json({ error: "not_signed_in" }, { status: 401 }))
      .mockResolvedValueOnce(new Response("Not found", { status: 404 }));
    vi.stubGlobal("fetch", fetch);
    expect(await getAccessToken()).toEqual({ token: "at", expires_at: 1, scope: "openid" });
    expect(fetch.mock.calls[0]![0]).toBe("/auth/access-token");
    expect(fetch.mock.calls[0]![1]).toMatchObject({
      credentials: "same-origin",
      cache: "no-store",
    });
    const signedOut = await getAccessToken().catch((error: unknown) => error);
    expect(signedOut).toBeInstanceOf(AccessTokenRequestError);
    expect(signedOut).toMatchObject({ code: "not_signed_in", status: 401 });
    const off = await getAccessToken().catch((error: unknown) => error);
    expect(off).toMatchObject({ code: "unavailable", status: 404 });
  });
});
