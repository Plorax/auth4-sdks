// A local stand-in for the auth4.dev endpoints the Godot addon calls. It mirrors the response shapes
// of the real API (device authorization, token, revoke, guest, linking intent, email verification,
// guest upgrade and upgrade intent) with deterministic values, so the GDScript suite needs no
// network or credentials. Tests steer it through POST /__mock/reset and /__mock/patch and read what
// it saw through /__mock/state. For the web export path (AUTH4D-219) it also redeems authorization
// codes registered through /__mock/patch ({ codes: { code: { challenge, redirect_uri } } }) and
// answers /__mock/upgrade-result as the hosted upgrade window's POST /t/{tenantId}/guest/upgrade
// would, for the guest access token the game posted to the window.
//
//   node packages/sdk-godot/tests/mock-server.mjs [port]   # prints the origin on stdout
import { createHash } from "node:crypto";
import { createServer } from "node:http";
import { pathToFileURL } from "node:url";

export const TENANT_ID = "ten_godotmocktenant0001";
export const CLIENT_ID = "cli_godotmockclient0001";
const FLOW_COOKIE_PREFIX = "__Host-auth4_flow_";
const EMAIL_CODE = "123456";
// Shaped like the real handles: gui_ plus 32 or more characters, gps_ plus 43 or more.
const INTENT = `gui_${"i".repeat(32)}`;
const POLL_SECRET = `gps_${"s".repeat(43)}`;

function freshState() {
  return {
    // Per-poll outcomes, consumed in order; the last one repeats.
    device: ["approve"],
    deviceResponse: {},
    upgrade: ["approve"],
    refresh: "rotate",
    emailInUse: false,
    codes: {},
    accessExpiresIn: 300,
    counter: 0,
    guests: 0,
    access: new Map(),
    refresh_tokens: new Map(),
    requests: [],
    revoked: [],
    reuse: 0,
  };
}

export function createMockServer() {
  let state = freshState();
  let origin = "";

  function next(prefix) {
    state.counter += 1;
    return `${prefix}_${String(state.counter).padStart(4, "0")}`;
  }

  function issue(user, { refresh = true } = {}) {
    const accessToken = next("at");
    const sessionId = user.sessionId ?? next("ses");
    const family = user.family ?? next("fam");
    state.access.set(accessToken, { ...user, sessionId, family });
    const tokens = {
      access_token: accessToken,
      token_type: "Bearer",
      expires_in: state.accessExpiresIn,
      scope: "openid offline_access",
      session_id: sessionId,
    };
    if (refresh) {
      const refreshToken = next("rt");
      state.refresh_tokens.set(refreshToken, { ...user, sessionId, family, used: false });
      tokens.refresh_token = refreshToken;
    }
    return tokens;
  }

  function revokeFamily(family) {
    for (const [token, entry] of state.refresh_tokens) {
      if (entry.family === family) state.refresh_tokens.set(token, { ...entry, used: true });
    }
    for (const [token, entry] of state.access) {
      if (entry.family === family) state.access.delete(token);
    }
  }

  function bearer(headers) {
    const match = /^Bearer (\S+)$/u.exec(headers.authorization ?? "");
    return match ? state.access.get(match[1]) : undefined;
  }

  function outcome(list) {
    return list.length > 1 ? list.shift() : list[0];
  }

  function guestTokens(user) {
    return { user_id: user.userId, ...issue(user) };
  }

  const routes = {
    "POST /device/authorization": ({ form }) => {
      if (form.client_id !== CLIENT_ID) return [401, { error: "invalid_client" }];
      return [
        200,
        {
          device_code: "dvc_mock_device_code",
          user_code: "WXYZ-1234",
          verification_uri: `${origin}/device`,
          verification_uri_complete: `${origin}/device?user_code=WXYZ-1234`,
          expires_in: 600,
          interval: 5,
          ...state.deviceResponse,
        },
      ];
    },
    "POST /oauth/token": ({ form }) => {
      if (form.client_id !== CLIENT_ID) return [401, { error: "invalid_client" }];
      if (form.grant_type === "urn:ietf:params:oauth:grant-type:device_code") {
        const next = outcome(state.device);
        if (next === "approve") return [200, issue({ userId: "", guest: false })];
        if (next === "unavailable") return [503, {}];
        return [400, { error: next }];
      }
      if (form.grant_type === "authorization_code") {
        // The test registers the code with the challenge it saw in the authorization URL.
        const code = state.codes[form.code];
        if (!code) return [400, { error: "invalid_grant" }];
        delete state.codes[form.code];
        const challenge = createHash("sha256")
          .update(form.code_verifier ?? "")
          .digest("base64url");
        if (challenge !== code.challenge || form.redirect_uri !== code.redirect_uri) {
          return [400, { error: "invalid_grant" }];
        }
        return [200, issue({ userId: "", guest: false })];
      }
      if (form.grant_type === "refresh_token") {
        if (state.refresh === "unavailable") return [503, { error: "temporarily_unavailable" }];
        const entry = state.refresh_tokens.get(form.refresh_token);
        if (state.refresh === "reject" || !entry) return [400, { error: "invalid_grant" }];
        if (entry.used) {
          // Reuse of a rotated token revokes the whole family, as the real API does.
          state.reuse += 1;
          revokeFamily(entry.family);
          return [400, { error: "invalid_grant" }];
        }
        state.refresh_tokens.set(form.refresh_token, { ...entry, used: true });
        return [200, issue(entry)];
      }
      return [400, { error: "unsupported_grant_type" }];
    },
    "POST /oauth/revoke": ({ form }) => {
      state.revoked.push(form.token_type_hint);
      const entry = state.refresh_tokens.get(form.token) ?? state.access.get(form.token);
      if (entry) revokeFamily(entry.family);
      return [200, {}];
    },
    "POST /t/:tenant/guest": ({ json }) => {
      if (json.client_id !== CLIENT_ID || !/^flw_[\w-]{32}$/u.test(json.browser_flow_id ?? "")) {
        return [400, { error: "invalid_request" }];
      }
      state.guests += 1;
      return [201, guestTokens({ userId: `usr_guest_${state.guests}`, guest: true })];
    },
    "POST /t/:tenant/guest/linking-intent": ({ json, headers }) => {
      const user = bearer(headers);
      if (!user?.guest) return [401, { error: "invalid_token" }];
      const cookie = `${FLOW_COOKIE_PREFIX}${json.browser_flow_id}=flowcookie_${json.browser_flow_id}`;
      return [
        201,
        { upgrade_proof: { expires_in: 300 } },
        { "set-cookie": [`${cookie}; Path=/; Secure; HttpOnly; SameSite=Lax`] },
      ];
    },
    "POST /t/:tenant/email/verification/start": ({ json, headers }) => {
      if (!flowCookieMatches(headers, json) || headers.origin !== origin) {
        return [403, { error: "invalid_request" }];
      }
      return [202, {}];
    },
    "POST /t/:tenant/email/verification/confirm": ({ json, headers }) => {
      if (!flowCookieMatches(headers, json) || headers.origin !== origin) {
        return [403, { error: "invalid_request" }];
      }
      if (json.code !== EMAIL_CODE) return [400, { error: "invalid_code" }];
      return [200, { proof: { proof_id: "prf_mock_email_proof" } }];
    },
    "POST /t/:tenant/guest/upgrade": ({ json, headers }) => {
      const user = bearer(headers);
      if (!user?.guest || !flowCookieMatches(headers, json))
        return [401, { error: "invalid_token" }];
      if (json.proof_id !== "prf_mock_email_proof") return [400, { error: "invalid_grant" }];
      if (state.emailInUse) return [409, { error: "identity_in_use" }];
      revokeFamily(user.family);
      const upgraded = { userId: user.userId, guest: false };
      return [
        200,
        {
          ...guestTokens(upgraded),
          identity: { identity_id: "idn_mock_email", provider: "email" },
        },
      ];
    },
    "POST /t/:tenant/guest/upgrade-intent": ({ headers }) => {
      const user = bearer(headers);
      if (!user?.guest) return [401, { error: "invalid_token" }];
      state.upgradeGuest = user;
      return [
        201,
        {
          intent: INTENT,
          poll_secret: POLL_SECRET,
          upgrade_uri: `${origin}/login/upgrade?intent=${INTENT}`,
          expires_in: 600,
          interval: 5,
        },
      ];
    },
    "POST /t/:tenant/guest/upgrade-intent/token": ({ json }) => {
      if (json.poll_secret !== POLL_SECRET) {
        return [400, { error: "invalid_grant" }];
      }
      const next = outcome(state.upgrade);
      if (next === "approve") {
        const user = state.upgradeGuest;
        revokeFamily(user.family);
        return [
          200,
          {
            ...guestTokens({ userId: user.userId, guest: false }),
            identity: { identity_id: "idn_mock_steam", provider: "steam" },
          },
        ];
      }
      if (next === "slow_down") return [400, { error: "slow_down", interval: 10 }];
      if (next === "conflict") return [409, { error: "identity_in_use" }];
      return [400, { error: next }];
    },
  };

  function flowCookieMatches(headers, json) {
    const expected = `${FLOW_COOKIE_PREFIX}${json.browser_flow_id}=flowcookie_${json.browser_flow_id}`;
    return headers.cookie === expected;
  }

  function route(method, path) {
    const tenantPath = path.replace(/^\/t\/[^/]+/u, "/t/:tenant");
    return routes[`${method} ${tenantPath}`];
  }

  const server = createServer((request, response) => {
    const chunks = [];
    request.on("data", (chunk) => chunks.push(chunk));
    request.on("end", () => {
      const url = new URL(request.url ?? "/", origin);
      const text = Buffer.concat(chunks).toString("utf8");
      const send = (status, body, headers = {}) => {
        response.writeHead(status, {
          "content-type": "application/json",
          "cache-control": "no-store",
          ...headers,
        });
        response.end(JSON.stringify(body));
      };

      if (url.pathname === "/__mock/reset") {
        state = { ...freshState(), ...(text ? JSON.parse(text) : {}) };
        return send(200, {});
      }
      if (url.pathname === "/__mock/patch") {
        // Changes the scenario but keeps issued tokens and recorded requests.
        Object.assign(state, text ? JSON.parse(text) : {});
        return send(200, {});
      }
      if (url.pathname === "/__mock/upgrade-result") {
        const user = state.access.get(text ? JSON.parse(text).access_token : "");
        if (!user?.guest) return send(401, { error: "invalid_token" });
        revokeFamily(user.family);
        return send(200, {
          ...guestTokens({ userId: user.userId, guest: false }),
          identity: { identity_id: "idn_mock_email", provider: "email" },
        });
      }
      if (url.pathname === "/__mock/state") {
        // Request records hold only paths and header names, never token values.
        return send(200, { requests: state.requests, revoked: state.revoked, reuse: state.reuse });
      }

      const handler = route(request.method ?? "GET", url.pathname);
      const isForm = (request.headers["content-type"] ?? "").startsWith(
        "application/x-www-form-urlencoded",
      );
      const form = isForm ? Object.fromEntries(new URLSearchParams(text)) : {};
      const json = !isForm && text ? JSON.parse(text) : {};
      state.requests.push({
        path: url.pathname,
        tenant: url.searchParams.get("tenant_id") ?? url.pathname.split("/")[2] ?? "",
        grant: form.grant_type ?? "",
        origin: request.headers.origin ?? "",
        cookie: request.headers.cookie ? "present" : "",
        authorization: request.headers.authorization ? "present" : "",
      });
      if (!handler) return send(404, { error: "not_found" });
      const [status, body, headers] = handler({ form, json, headers: request.headers });
      return send(status, body, headers);
    });
  });

  return {
    async listen(port = 0) {
      await new Promise((resolve) => server.listen(port, "127.0.0.1", resolve));
      const address = server.address();
      origin = `http://127.0.0.1:${typeof address === "object" && address ? address.port : port}`;
      return origin;
    },
    close() {
      return new Promise((resolve) => server.close(() => resolve()));
    },
  };
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  const mock = createMockServer();
  console.log(await mock.listen(Number(process.argv[2] ?? 0)));
}
