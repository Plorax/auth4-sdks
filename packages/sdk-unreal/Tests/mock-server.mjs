// Local mock of the auth4.dev endpoints the Unreal SDK calls, for Tests/MockServerTests.cpp. It
// follows the wire shapes in docs/api-spec (auth4d-15 guests, auth4d-16 device authorization,
// auth4d-67 upgrade intents) and fails any request that breaks the contract: wrong content type,
// wrong tenant or client, anything but tenant_id in a query string (so tokens never travel in URLs),
// or a bearer token where none belongs. Outcomes for polling are scripted per test through
// POST /__mock/reset. It makes no outbound requests.
//
//   node packages/sdk-unreal/Tests/mock-server.mjs [port]
import { createServer } from "node:http";
import { pathToFileURL } from "node:url";

export const TENANT = "ten_mockTenant0000000001";
export const CLIENT = "cli_mockNative000000001";
const ACCESS_TTL = 300;

function freshState(script = {}) {
  return {
    script: {
      device: [...(script.device ?? [])],
      upgrade: [...(script.upgrade ?? [])],
      upgradeProvider: script.upgradeProvider ?? "email",
    },
    counter: 0,
    requests: 0,
    refreshes: 0,
    violations: [],
    users: new Map(),
    access: new Map(),
    refresh: new Map(),
    families: new Map(),
    devices: new Map(),
    intents: new Map(),
    rotated: [],
  };
}

export function startMockServer({ port = 0, host = "127.0.0.1" } = {}) {
  let state = freshState();
  let origin = "";
  const next = (prefix, length = 24) => {
    state.counter += 1;
    return `${prefix}${String(state.counter).padStart(length, "0")}`;
  };

  const issue = ({ userId, guest, sessionId, family }) => {
    const accessToken = next("at_");
    const refreshToken = next("rt_");
    const fam = family ?? next("fam_");
    const sid = sessionId ?? next("ses_");
    if (!state.families.has(fam)) state.families.set(fam, { revoked: false, sessionId: sid });
    state.access.set(accessToken, { userId, guest, sessionId: sid, family: fam, revoked: false });
    state.refresh.set(refreshToken, { userId, guest, sessionId: sid, family: fam, used: false });
    return {
      access_token: accessToken,
      token_type: "Bearer",
      expires_in: ACCESS_TTL,
      refresh_token: refreshToken,
      id_token: "mock.id.token",
      scope: "openid profile offline_access",
      session_id: sid,
    };
  };

  const revokeFamily = (family) => {
    const entry = state.families.get(family);
    if (entry) entry.revoked = true;
    for (const token of state.access.values()) if (token.family === family) token.revoked = true;
  };

  const handlers = {
    "POST /device/authorization": ({ form }) => {
      if (form.client_id !== CLIENT) return [401, { error: "invalid_client" }];
      if (!(form.scope ?? "").split(" ").includes("openid"))
        return [400, { error: "invalid_scope" }];
      const deviceCode = next("dc_");
      state.devices.set(deviceCode, { done: false });
      return [
        200,
        {
          device_code: deviceCode,
          user_code: "BCDF-GHJK",
          verification_uri: `${origin}/device`,
          verification_uri_complete: `${origin}/device?user_code=BCDF-GHJK`,
          expires_in: 600,
          interval: 5,
        },
      ];
    },
    "POST /oauth/token": ({ form }) => {
      if (form.client_id !== CLIENT) return [401, { error: "invalid_client" }];
      if (form.grant_type === "urn:ietf:params:oauth:grant-type:device_code") {
        const device = state.devices.get(form.device_code);
        if (!device || device.done) return [400, { error: "invalid_grant" }];
        const step = state.script.device.shift() ?? "authorization_pending";
        if (step === "temporarily_unavailable") return [503, { error: step }];
        if (step !== "approve") {
          if (step !== "authorization_pending" && step !== "slow_down") device.done = true;
          return [400, { error: step }];
        }
        device.done = true;
        return [200, issue({ userId: next("usr_"), guest: false })];
      }
      if (form.grant_type === "refresh_token") {
        state.refreshes += 1;
        const token = state.refresh.get(form.refresh_token);
        if (!token) return [400, { error: "invalid_grant" }];
        const family = state.families.get(token.family);
        if (token.used || family.revoked) {
          // Reuse of a rotated token revokes the whole family.
          revokeFamily(token.family);
          return [400, { error: "invalid_grant" }];
        }
        token.used = true;
        state.rotated.push(form.refresh_token);
        return [200, issue({ ...token, family: token.family })];
      }
      return [400, { error: "unsupported_grant_type" }];
    },
    "POST /oauth/revoke": ({ form }) => {
      if (form.client_id !== CLIENT) return [401, { error: "invalid_client" }];
      const refresh = state.refresh.get(form.token);
      if (refresh) revokeFamily(refresh.family);
      const access = state.access.get(form.token);
      if (access) access.revoked = true;
      return [200, {}];
    },
    "POST /t/{tenant}/guest": ({ json }) => {
      if (json.client_id !== CLIENT) return [401, { error: "unauthorized_client" }];
      if (!/^flw_[A-Za-z0-9_-]{16,}$/u.test(json.browser_flow_id ?? "")) {
        return [400, { error: "invalid_request" }];
      }
      const userId = next("usr_");
      return [201, { user_id: userId, ...issue({ userId, guest: true }) }];
    },
    "POST /t/{tenant}/guest/upgrade-intent": ({ json, bearer }) => {
      if (json.client_id !== CLIENT) return [401, { error: "unauthorized_client" }];
      const token = state.access.get(bearer ?? "");
      if (!token || token.revoked || !token.guest) return [401, { error: "invalid_session" }];
      const intent = `gui_${next("", 40)}`;
      const pollSecret = `gps_${next("", 48)}`;
      state.intents.set(intent, { pollSecret, token, collected: false });
      return [
        200,
        {
          intent,
          poll_secret: pollSecret,
          upgrade_uri: `${origin}/login/upgrade?tenant_id=${TENANT}&client_id=${CLIENT}&intent=${intent}`,
          expires_in: 600,
          interval: 5,
        },
      ];
    },
    "POST /t/{tenant}/guest/upgrade-intent/token": ({ json }) => {
      if (json.client_id !== CLIENT) return [401, { error: "invalid_client" }];
      const intent = state.intents.get(json.intent);
      if (!intent) return [400, { error: "expired_token" }];
      if (intent.pollSecret !== json.poll_secret || intent.collected)
        return [400, { error: "invalid_grant" }];
      const step = state.script.upgrade.shift() ?? "authorization_pending";
      if (step === "authorization_pending") return [400, { error: step, interval: 5 }];
      if (step === "slow_down") return [400, { error: step, interval: 10 }];
      intent.collected = true;
      if (step !== "approve") return [400, { error: step }];
      // Linking revokes the guest session that created the intent and issues a replacement.
      revokeFamily(intent.token.family);
      const tokens = issue({ userId: intent.token.userId, guest: false });
      return [
        200,
        {
          user_id: intent.token.userId,
          identity: { identity_id: next("idn_"), provider: state.script.upgradeProvider },
          ...tokens,
        },
      ];
    },
  };

  const route = (method, path) => {
    const tenantPath = path.match(/^\/t\/([^/]+)(\/.*)$/u);
    if (tenantPath) {
      return {
        key: `${method} /t/{tenant}${tenantPath[2]}`,
        tenant: decodeURIComponent(tenantPath[1]),
      };
    }
    return { key: `${method} ${path}`, tenant: null };
  };

  const server = createServer((request, response) => {
    const chunks = [];
    request.on("data", (chunk) => chunks.push(chunk));
    request.on("end", () => {
      const body = Buffer.concat(chunks).toString("utf8");
      const url = new URL(request.url, origin);
      const send = (status, payload) => {
        const text = JSON.stringify(payload);
        response.writeHead(status, {
          "Content-Type": "application/json",
          "Cache-Control": "no-store",
          "Content-Length": Buffer.byteLength(text),
        });
        response.end(text);
      };

      // Test control endpoints. They are not part of the API and are never counted.
      if (url.pathname === "/__mock/reset") {
        state = freshState(body ? JSON.parse(body) : {});
        return send(200, { ok: true });
      }
      if (url.pathname === "/__mock/state") {
        return send(200, {
          requests: state.requests,
          refreshes: state.refreshes,
          revokedFamilies: [...state.families.values()].filter((family) => family.revoked).length,
          violations: state.violations.length,
          violationDetails: state.violations,
        });
      }
      if (url.pathname === "/__mock/replay-rotated") {
        // Simulates a stolen, already-rotated refresh token being presented by someone else.
        const stolen = state.rotated.at(-1);
        const token = stolen && state.refresh.get(stolen);
        if (token) revokeFamily(token.family);
        return send(token ? 200 : 404, { ok: Boolean(token) });
      }

      state.requests += 1;
      const violation = (message) => {
        state.violations.push(`${request.method} ${url.pathname}: ${message}`);
        return send(400, { error: "mock_contract_violation" });
      };
      const { key, tenant } = route(request.method, url.pathname);
      const handler = handlers[key];
      if (!handler) return send(404, { error: "not_found" });

      const queryKeys = [...url.searchParams.keys()];
      const contentType = request.headers["content-type"] ?? "";
      const authorization = request.headers.authorization;
      let form = {};
      let json = {};
      if (tenant === null) {
        if (queryKeys.join(",") !== "tenant_id" || url.searchParams.get("tenant_id") !== TENANT) {
          return violation("expected exactly ?tenant_id={tenant}");
        }
        if (contentType !== "application/x-www-form-urlencoded")
          return violation("expected a form body");
        form = Object.fromEntries(new URLSearchParams(body));
      } else {
        if (tenant !== TENANT) return violation("wrong tenant in path");
        if (queryKeys.length > 0) return violation("unexpected query string");
        if (contentType !== "application/json") return violation("expected a JSON body");
        try {
          json = JSON.parse(body);
        } catch {
          return violation("malformed JSON");
        }
      }
      if (authorization !== undefined && key !== "POST /t/{tenant}/guest/upgrade-intent") {
        return violation("unexpected Authorization header");
      }
      const bearer = authorization?.startsWith("Bearer ") ? authorization.slice(7) : undefined;
      const [status, payload] = handler({ form, json, bearer });
      return send(status, payload);
    });
  });

  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, host, () => {
      const address = server.address();
      origin = `http://${host}:${address.port}`;
      resolve({
        origin,
        close: () => new Promise((done) => server.close(() => done())),
      });
    });
  });
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  const { origin } = await startMockServer({ port: Number(process.argv[2] ?? 0) });
  console.log(`auth4.dev mock server listening on ${origin}`);
}
