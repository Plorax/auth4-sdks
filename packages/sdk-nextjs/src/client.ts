// AUTH4D-238: "next" has no exports map, so plain Node ESM (tests, servers that don't bundle the
// SDK) only resolves its subpaths with the file extension. Bundlers accept both.
import { cookies as nextCookies } from "next/headers.js";
import { NextRequest, NextResponse } from "next/server.js";
import {
  CookieChanges,
  clearChunked,
  deriveKeys,
  readChunked,
  seal,
  unseal,
  writeChunked,
  type CookieOptions,
  type CookieReader,
  type CookieWriter,
} from "./cookies.ts";
import { OidcClient, TokenEndpointError, type TokenSet } from "./oidc.ts";
import type { AccessTokenResponse, User } from "./types.ts";

/** Third-party sign-in providers the hosted login can open first. */
export type SocialProvider = "discord" | "steam" | "epic" | "google" | "apple" | "microsoft";
const PROVIDERS: readonly SocialProvider[] = [
  "discord",
  "steam",
  "epic",
  "google",
  "apple",
  "microsoft",
];

export interface Auth4Routes {
  login: string;
  callback: string;
  logout: string;
  profile: string;
  accessToken: string;
}

export interface Auth4ClientOptions {
  /** Defaults to AUTH4_ORIGIN, then https://auth.auth4.dev. */
  authOrigin?: string;
  /** Defaults to AUTH4_TENANT_ID. */
  tenantId?: string;
  /** A browser application's client ID. Defaults to AUTH4_CLIENT_ID. */
  clientId?: string;
  /** The application's own origin, such as https://play.example.com. Defaults to APP_BASE_URL. */
  appBaseUrl?: string;
  /**
   * At least 32 characters that encrypt the session and login cookies. Defaults to AUTH4_SECRET.
   * Pass an array to rotate: the first secret encrypts, every secret decrypts.
   */
  secret?: string | readonly string[];
  /** Scopes to request. Defaults to "openid profile email"; offline_access is added by `refresh`. */
  scope?: string;
  /**
   * Keep a rotating refresh token in the session cookie. Turn this on only when the application
   * has "Allow refresh tokens in the browser" (allowBrowserRefresh) switched on in the console.
   */
  refresh?: boolean;
  /** Provider to open first when /auth/login has no `provider` parameter. */
  provider?: SocialProvider;
  /** Paths of the routes middleware() answers. */
  routes?: Partial<Auth4Routes>;
  /** Answer /auth/access-token so client components can read the access token. Off by default. */
  enableAccessTokenEndpoint?: boolean;
  /**
   * After revoking the tokens, also show the hosted auth4.dev sign-out page, which ends the
   * auth4.dev sign-in in this browser and returns to the application. Off by default.
   */
  hostedLogout?: boolean;
  session?: {
    /** Seconds without a request before the session ends. Default one day. */
    rollingDuration?: number;
    /** Seconds after sign-in when the session ends regardless. Default seven days. */
    absoluteDuration?: number;
    /** Session cookie name. Default auth4_session. */
    cookieName?: string;
  };
  /** Replaces the callback's error page; `code` is one of the SDK's callback error codes. */
  onCallbackError?: (code: CallbackErrorCode, request: NextRequest) => Response | Promise<Response>;
  /** For tests and custom runtimes. */
  fetch?: typeof fetch;
  /** Milliseconds since the epoch; for tests. */
  now?: () => number;
}

/** The session as server code sees it. Tokens are deliberately not part of it. */
export interface Session {
  user: User;
  /** Unix time in seconds when the current access token expires. */
  accessTokenExpiresAt: number;
  scope?: string;
  /** Unix time in seconds of the sign-in. */
  createdAt: number;
  /** Whether a refresh token is kept, so the session can outlive its access token. */
  refreshable: boolean;
}

export type CallbackErrorCode =
  | "invalid_state"
  | "invalid_callback"
  | "access_denied"
  | "authorization_failed"
  | "token_exchange_failed"
  | "invalid_id_token";

export type AccessTokenErrorCode =
  "not_signed_in" | "expired" | "refresh_rejected" | "refresh_failed" | "read_only";

export class AccessTokenError extends Error {
  constructor(
    readonly code: AccessTokenErrorCode,
    message: string,
  ) {
    super(message);
    this.name = "AccessTokenError";
  }
}

export class ConfigurationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ConfigurationError";
  }
}

interface ResolvedConfig {
  authOrigin: string;
  tenantId: string;
  clientId: string;
  appBaseUrl: string;
  appOrigin: string;
  redirectUri: string;
  scope: string;
  refresh: boolean;
  provider: SocialProvider | undefined;
  routes: Auth4Routes;
  enableAccessTokenEndpoint: boolean;
  hostedLogout: boolean;
  rollingDuration: number;
  absoluteDuration: number;
  cookieName: string;
  secure: boolean;
  sessionKeys: Uint8Array[];
  transactionKeys: Uint8Array[];
}

/** What the session cookie holds once decrypted. Only the server ever sees it. */
interface StoredSession {
  v: 1;
  user: User;
  accessToken: string;
  accessTokenExpiresAt: number;
  scope?: string;
  refreshToken?: string;
  createdAt: number;
  touchedAt: number;
}

interface Transaction {
  kind: "login" | "logout";
  state: string;
  returnTo: string;
  nonce?: string;
  verifier?: string;
}

const DEFAULT_ROUTES: Auth4Routes = {
  login: "/auth/login",
  callback: "/auth/callback",
  logout: "/auth/logout",
  profile: "/auth/profile",
  accessToken: "/auth/access-token",
};
const TENANT_ID = /^ten_[A-Za-z0-9]{16,64}$/u;
const CLIENT_ID = /^cli_[A-Za-z0-9]{16,64}$/u;
const STATE = /^[A-Za-z0-9_-]{16,512}$/u;
const COOKIE_NAME = /^[A-Za-z0-9_-]{1,64}$/u;
/** Long enough to type an emailed code; the hosted flow itself expires sooner. */
const TRANSACTION_SECONDS = 900;
/** Refresh this long before the five-minute access token runs out. */
const REFRESH_LEEWAY_SECONDS = 60;
/** Rewrite the cookie for the rolling expiry at most this often. */
const TOUCH_INTERVAL_SECONDS = 300;
/**
 * A refresh result is reused this long for requests that still carry the old refresh token
 * (parallel requests that left the browser before the new cookie arrived), because presenting a
 * rotated refresh token again counts as reuse and ends the session.
 */
const REFRESH_REUSE_MS = 60_000;
const NO_STORE = { "Cache-Control": "no-store" };

function base64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
}

function randomValue(): string {
  return base64Url(crypto.getRandomValues(new Uint8Array(32)));
}

async function sha256(value: string): Promise<string> {
  return base64Url(
    new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value))),
  );
}

function env(name: string): string | undefined {
  const value = typeof process === "undefined" ? undefined : process.env[name];
  return value === undefined || value === "" ? undefined : value;
}

function isLoopback(url: URL): boolean {
  return ["127.0.0.1", "localhost", "[::1]"].includes(url.hostname);
}

function plainResponse(status: number, message: string): NextResponse {
  return new NextResponse(message, {
    status,
    headers: { "Content-Type": "text/plain; charset=utf-8", ...NO_STORE },
  });
}

function crossSite(request: Request): boolean {
  // Browsers send Sec-Fetch-Site on every request; requests without it come from other software.
  return request.headers.get("Sec-Fetch-Site") === "cross-site";
}

/** A NextRequest's cookies, or the Cookie header of a plain Request. */
function requestCookies(request: Request | NextRequest): CookieReader {
  const withCookies = request as { cookies?: CookieReader };
  if (withCookies.cookies && typeof withCookies.cookies.getAll === "function") {
    return withCookies.cookies;
  }
  const header = request.headers.get("cookie") ?? "";
  const values = header
    .split(";")
    .map((pair) => pair.trim())
    .filter((pair) => pair.includes("="))
    .map((pair) => {
      const index = pair.indexOf("=");
      const raw = pair.slice(index + 1);
      let value = raw;
      try {
        value = decodeURIComponent(raw);
      } catch {
        // Keep values that are not percent-encoded as they are.
      }
      return { name: pair.slice(0, index), value };
    });
  return { getAll: () => values };
}

/**
 * auth4.dev sign-in for Next.js App Router applications. The Next.js server is the OAuth client:
 * it runs authorization code with S256 PKCE as the application's public browser client, keeps the
 * tokens in an encrypted HttpOnly cookie, and never hands them to client JavaScript unless
 * `enableAccessTokenEndpoint` is on.
 */
export class Auth4Client {
  readonly #options: Auth4ClientOptions;
  #config: Promise<ResolvedConfig> | undefined;
  #oidc: OidcClient | undefined;
  readonly #fetch: typeof fetch;
  readonly #now: () => number;
  readonly #refreshes = new Map<string, { result: Promise<StoredSession>; settledAt?: number }>();

  constructor(options: Auth4ClientOptions = {}) {
    this.#options = options;
    this.#fetch = options.fetch ?? ((input, init) => fetch(input, init));
    this.#now = options.now ?? (() => Date.now());
  }

  #seconds(): number {
    return Math.floor(this.#now() / 1_000);
  }

  /** Configuration is read on first use, so `next build` works before the variables are set. */
  #resolve(): Promise<ResolvedConfig> {
    this.#config ??= this.#readConfig();
    return this.#config;
  }

  async #readConfig(): Promise<ResolvedConfig> {
    const options = this.#options;
    const authOriginValue = options.authOrigin ?? env("AUTH4_ORIGIN") ?? "https://auth.auth4.dev";
    const tenantId = options.tenantId ?? env("AUTH4_TENANT_ID");
    const clientId = options.clientId ?? env("AUTH4_CLIENT_ID");
    const appBaseUrlValue = options.appBaseUrl ?? env("APP_BASE_URL");
    const secretValue = options.secret ?? env("AUTH4_SECRET");

    let authOrigin: URL;
    try {
      authOrigin = new URL(authOriginValue);
    } catch {
      throw new ConfigurationError("authOrigin must be an absolute URL.");
    }
    if (
      authOrigin.origin !== authOriginValue.replace(/\/$/u, "") ||
      (authOrigin.protocol !== "https:" && !isLoopback(authOrigin))
    ) {
      throw new ConfigurationError(
        "authOrigin must be an https origin with no path, such as https://auth.auth4.dev.",
      );
    }
    if (!tenantId || !TENANT_ID.test(tenantId)) {
      throw new ConfigurationError("tenantId (AUTH4_TENANT_ID) must be a project ID: ten_…");
    }
    if (!clientId || !CLIENT_ID.test(clientId)) {
      throw new ConfigurationError("clientId (AUTH4_CLIENT_ID) must be an application ID: cli_…");
    }
    let appBase: URL;
    try {
      appBase = new URL(appBaseUrlValue ?? "");
    } catch {
      throw new ConfigurationError("appBaseUrl (APP_BASE_URL) must be an absolute URL.");
    }
    if (
      (appBase.protocol !== "https:" && !(appBase.protocol === "http:" && isLoopback(appBase))) ||
      appBase.username !== "" ||
      appBase.password !== "" ||
      appBase.search !== "" ||
      appBase.hash !== ""
    ) {
      throw new ConfigurationError(
        "appBaseUrl must use https (http only for localhost) and have no query or fragment.",
      );
    }
    const secrets = typeof secretValue === "string" ? [secretValue] : [...(secretValue ?? [])];
    if (secrets.length === 0 || secrets.some((secret) => secret.length < 32)) {
      throw new ConfigurationError("secret (AUTH4_SECRET) must be at least 32 characters.");
    }
    const routes = { ...DEFAULT_ROUTES, ...options.routes };
    if (Object.values(routes).some((path) => !path.startsWith("/") || path.startsWith("//"))) {
      throw new ConfigurationError("Every route must be a path starting with a single /.");
    }
    if (options.provider !== undefined && !PROVIDERS.includes(options.provider)) {
      throw new ConfigurationError(`provider must be one of ${PROVIDERS.join(", ")}.`);
    }
    const cookieName = options.session?.cookieName ?? "auth4_session";
    if (!COOKIE_NAME.test(cookieName)) {
      throw new ConfigurationError("session.cookieName may use letters, digits, _ and - only.");
    }
    const rollingDuration = options.session?.rollingDuration ?? 86_400;
    const absoluteDuration = options.session?.absoluteDuration ?? 604_800;
    if (
      !Number.isInteger(rollingDuration) ||
      !Number.isInteger(absoluteDuration) ||
      rollingDuration <= 0 ||
      absoluteDuration < rollingDuration
    ) {
      throw new ConfigurationError(
        "session durations must be whole seconds, with absoluteDuration ≥ rollingDuration.",
      );
    }
    const scopes = (options.scope ?? "openid profile email").split(/\s+/u).filter(Boolean);
    if (!scopes.includes("openid")) scopes.unshift("openid");
    const refresh = options.refresh === true;
    const withRefresh = scopes.filter((scope) => scope !== "offline_access");
    if (refresh) withRefresh.push("offline_access");
    const appBaseUrl = appBase.toString().replace(/\/$/u, "");

    this.#oidc = new OidcClient({
      authOrigin: authOrigin.origin,
      tenantId,
      clientId,
      fetch: this.#fetch,
      now: this.#now,
    });
    return {
      authOrigin: authOrigin.origin,
      tenantId,
      clientId,
      appBaseUrl,
      appOrigin: appBase.origin,
      redirectUri: `${appBaseUrl}${routes.callback}`,
      scope: withRefresh.join(" "),
      refresh,
      provider: options.provider,
      routes,
      enableAccessTokenEndpoint: options.enableAccessTokenEndpoint === true,
      hostedLogout: options.hostedLogout === true,
      rollingDuration,
      absoluteDuration,
      cookieName,
      secure: appBase.protocol === "https:",
      sessionKeys: await deriveKeys(secrets, "session"),
      transactionKeys: await deriveKeys(secrets, "transaction"),
    };
  }

  async #setup(): Promise<{ config: ResolvedConfig; oidc: OidcClient }> {
    const config = await this.#resolve();
    return { config, oidc: this.#oidc! };
  }

  #cookieOptions(config: ResolvedConfig, maxAge: number, path = "/"): CookieOptions {
    return { httpOnly: true, secure: config.secure, sameSite: "lax", path, maxAge };
  }

  /** Only same-origin destinations; anything else falls back to the application root. */
  #safeReturnTo(config: ResolvedConfig, value: string | null): string {
    const fallback = `${config.appBaseUrl}/`;
    // Browsers treat backslashes as slashes, and control characters can hide a scheme.
    if (
      !value ||
      value.includes("\\") ||
      [...value].some((character) => character.charCodeAt(0) < 0x20 || character === "\u007f")
    ) {
      return fallback;
    }
    let url: URL;
    try {
      url = new URL(value, fallback);
    } catch {
      return fallback;
    }
    if (url.origin !== config.appOrigin || url.username !== "" || url.password !== "") {
      return fallback;
    }
    return url.toString();
  }

  // --- Session cookie ----------------------------------------------------------------------

  async #readSession(config: ResolvedConfig, reader: CookieReader): Promise<StoredSession | null> {
    const sealed = readChunked(reader, config.cookieName);
    if (!sealed) return null;
    const payload = await unseal(sealed, config.sessionKeys, this.#seconds());
    if (
      !payload ||
      payload["v"] !== 1 ||
      typeof payload["accessToken"] !== "string" ||
      typeof (payload["user"] as User | undefined)?.sub !== "string"
    ) {
      return null;
    }
    const session = payload as unknown as StoredSession;
    const now = this.#seconds();
    if (
      session.createdAt + config.absoluteDuration <= now ||
      session.touchedAt + config.rollingDuration <= now
    ) {
      return null;
    }
    return session;
  }

  async #writeSession(
    config: ResolvedConfig,
    reader: CookieReader,
    writer: CookieWriter,
    session: StoredSession,
  ): Promise<void> {
    const now = this.#seconds();
    const touched: StoredSession = { ...session, touchedAt: now };
    const expiresAt = Math.min(
      touched.createdAt + config.absoluteDuration,
      now + config.rollingDuration,
    );
    const sealed = await seal(
      touched as unknown as Record<string, unknown>,
      config.sessionKeys[0]!,
      now,
      expiresAt,
    );
    writeChunked(
      reader,
      writer,
      config.cookieName,
      sealed,
      this.#cookieOptions(config, expiresAt - now),
    );
  }

  #clearSession(config: ResolvedConfig, reader: CookieReader, writer: CookieWriter): void {
    clearChunked(reader, writer, config.cookieName, this.#cookieOptions(config, 0));
  }

  #publicSession(session: StoredSession): Session {
    return {
      user: session.user,
      accessTokenExpiresAt: session.accessTokenExpiresAt,
      ...(session.scope === undefined ? {} : { scope: session.scope }),
      createdAt: session.createdAt,
      refreshable: session.refreshToken !== undefined,
    };
  }

  #sessionFromTokens(
    config: ResolvedConfig,
    tokens: TokenSet,
    user: User,
    createdAt: number,
  ): StoredSession {
    const now = this.#seconds();
    return {
      v: 1,
      user,
      accessToken: tokens.accessToken,
      accessTokenExpiresAt: now + tokens.expiresIn,
      ...(tokens.scope === undefined ? {} : { scope: tokens.scope }),
      // Refresh tokens are kept only when the application opted in.
      ...(config.refresh && tokens.refreshToken !== undefined
        ? { refreshToken: tokens.refreshToken }
        : {}),
      createdAt,
      touchedAt: now,
    };
  }

  // --- Refresh -----------------------------------------------------------------------------

  #needsRefresh(session: StoredSession): boolean {
    return (
      session.refreshToken !== undefined &&
      session.accessTokenExpiresAt - this.#seconds() <= REFRESH_LEEWAY_SECONDS
    );
  }

  /**
   * Rotates the refresh token. Concurrent and closely following requests carrying the same refresh
   * token share one call, because auth4.dev treats a second use as theft and ends the session.
   */
  async #refresh(config: ResolvedConfig, oidc: OidcClient, session: StoredSession) {
    const key = await sha256(session.refreshToken!);
    const now = this.#now();
    for (const [stale, entry] of this.#refreshes) {
      if (entry.settledAt !== undefined && now - entry.settledAt > REFRESH_REUSE_MS) {
        this.#refreshes.delete(stale);
      }
    }
    const existing = this.#refreshes.get(key);
    if (existing) return existing.result;
    const entry: { result: Promise<StoredSession>; settledAt?: number } = {
      result: (async () => {
        const tokens = await oidc.refresh(session.refreshToken!);
        let user = session.user;
        if (tokens.idToken !== undefined) {
          try {
            const verified = await oidc.verifyIdToken(tokens.idToken, {
              nonce: "",
              nonceOptional: true,
              sub: session.user.sub,
            });
            user = verified.user;
          } catch {
            // A refreshed ID token for someone else, or one that fails verification, ends the
            // session rather than keeping tokens that can't be trusted.
            if (tokens.refreshToken) await oidc.revoke(tokens.refreshToken, "refresh_token");
            await oidc.revoke(tokens.accessToken, "access_token");
            throw new TokenEndpointError("rejected", "The refreshed ID token is invalid.");
          }
        }
        const next = this.#sessionFromTokens(config, tokens, user, session.createdAt);
        // A refresh response without a new refresh token keeps the current one.
        if (config.refresh && next.refreshToken === undefined) {
          next.refreshToken = session.refreshToken!;
        }
        return next;
      })(),
    };
    this.#refreshes.set(key, entry);
    entry.result.then(
      () => (entry.settledAt = this.#now()),
      () => this.#refreshes.delete(key),
    );
    return entry.result;
  }

  /**
   * Refreshes when the access token is about to expire and keeps the rolling expiry current.
   * A rejected refresh token (expired, revoked or reused) signs the player out.
   */
  async #maintain(
    config: ResolvedConfig,
    oidc: OidcClient,
    session: StoredSession,
    changes: CookieChanges,
  ): Promise<StoredSession | null> {
    if (this.#needsRefresh(session)) {
      try {
        const next = await this.#refresh(config, oidc, session);
        await this.#writeSession(config, changes, changes, next);
        return next;
      } catch (cause) {
        if (cause instanceof TokenEndpointError && cause.kind === "rejected") {
          this.#clearSession(config, changes, changes);
          return null;
        }
        // auth4.dev is briefly unreachable: keep the session and try again on the next request.
        return session;
      }
    }
    if (this.#seconds() - session.touchedAt >= TOUCH_INTERVAL_SECONDS) {
      await this.#writeSession(config, changes, changes, session);
    }
    return session;
  }

  // --- Middleware --------------------------------------------------------------------------

  /**
   * Call from proxy.ts (Next.js 16) or middleware.ts. Answers the /auth/* routes and, on every
   * other matched request, refreshes the access token ahead of expiry and keeps the session alive.
   */
  async middleware(input: NextRequest | Request): Promise<NextResponse> {
    const { config, oidc } = await this.#setup();
    // A plain Request (custom servers, tests) gets the same parsed URL and cookies.
    const request = input instanceof NextRequest ? input : new NextRequest(input);
    const path = request.nextUrl.pathname;
    const method = request.method;
    if (method === "GET" && path === config.routes.login) return this.#login(config, oidc, request);
    if (method === "GET" && path === config.routes.callback) {
      return this.#callback(config, oidc, request);
    }
    if ((method === "GET" || method === "POST") && path === config.routes.logout) {
      return this.#logout(config, oidc, request);
    }
    if (method === "GET" && path === config.routes.profile) return this.#profile(config, request);
    if (
      method === "GET" &&
      config.enableAccessTokenEndpoint &&
      path === config.routes.accessToken
    ) {
      return this.#accessTokenRoute(config, oidc, request);
    }

    const changes = new CookieChanges(request.cookies);
    const session = await this.#readSession(config, changes);
    if (session) await this.#maintain(config, oidc, session, changes);
    if (!changes.changed) return NextResponse.next();
    // Forward the updated cookies so server components on this request see the new session.
    const headers = new Headers(request.headers);
    headers.set("cookie", changes.header(request.headers.get("cookie")));
    const response = NextResponse.next({ request: { headers } });
    changes.applyTo(response.cookies);
    return response;
  }

  async #login(config: ResolvedConfig, oidc: OidcClient, request: NextRequest) {
    const params = request.nextUrl.searchParams;
    const returnTo = this.#safeReturnTo(config, params.get("returnTo"));
    const providerParam = params.get("provider");
    let provider = config.provider;
    if (providerParam !== null) {
      if (!PROVIDERS.includes(providerParam as SocialProvider)) {
        return plainResponse(400, "Unknown sign-in provider.");
      }
      provider = providerParam as SocialProvider;
    }
    let authorizationEndpoint: string;
    try {
      authorizationEndpoint = (await oidc.discover()).authorization_endpoint;
    } catch {
      return plainResponse(503, "Sign-in is unavailable. Try again in a moment.");
    }
    const state = randomValue();
    const nonce = randomValue();
    const verifier = randomValue();
    const transaction: Transaction = { kind: "login", state, nonce, verifier, returnTo };
    const now = this.#seconds();
    const sealed = await seal(
      transaction as unknown as Record<string, unknown>,
      config.transactionKeys[0]!,
      now,
      now + TRANSACTION_SECONDS,
    );

    const url = new URL(authorizationEndpoint);
    url.searchParams.set("response_type", "code");
    url.searchParams.set("client_id", config.clientId);
    url.searchParams.set("redirect_uri", config.redirectUri);
    url.searchParams.set("scope", config.scope);
    url.searchParams.set("state", state);
    url.searchParams.set("nonce", nonce);
    url.searchParams.set("code_challenge", await sha256(verifier));
    url.searchParams.set("code_challenge_method", "S256");
    if (provider) url.searchParams.set("provider_hint", provider);

    const response = NextResponse.redirect(url, { status: 302, headers: NO_STORE });
    // One cookie per attempt, scoped to the callback, so two tabs can sign in at once.
    response.cookies.set(
      `auth4_tx_${state}`,
      sealed,
      this.#cookieOptions(config, TRANSACTION_SECONDS, config.routes.callback),
    );
    return response;
  }

  async #callback(config: ResolvedConfig, oidc: OidcClient, request: NextRequest) {
    const params = request.nextUrl.searchParams;
    const states = params.getAll("state");
    const state = states.length === 1 && STATE.test(states[0]!) ? states[0]! : null;
    const transactionCookie = state ? `auth4_tx_${state}` : null;
    const sealed = transactionCookie ? request.cookies.get(transactionCookie)?.value : undefined;
    const raw = sealed ? await unseal(sealed, config.transactionKeys, this.#seconds()) : null;
    const transaction = raw as unknown as Transaction | null;

    const fail = async (code: CallbackErrorCode): Promise<NextResponse> => {
      const custom = this.#options.onCallbackError
        ? await this.#options.onCallbackError(code, request)
        : plainResponse(
            400,
            code === "access_denied"
              ? "Sign-in was cancelled."
              : `Sign-in could not be completed. Go back and try again. (${code})`,
          );
      const response = new NextResponse(custom.body, custom);
      if (transactionCookie) {
        response.cookies.set(
          transactionCookie,
          "",
          this.#cookieOptions(config, 0, config.routes.callback),
        );
      }
      return response;
    };

    // The state must name a transaction this browser started, sealed with this app's secret.
    if (!state || !transaction || transaction.state !== state) return fail("invalid_state");
    const finish = (response: NextResponse, changes?: CookieChanges): NextResponse => {
      response.headers.set("Cache-Control", "no-store");
      response.cookies.set(
        transactionCookie!,
        "",
        this.#cookieOptions(config, 0, config.routes.callback),
      );
      changes?.applyTo(response.cookies);
      return response;
    };
    if (transaction.kind === "logout") {
      return finish(NextResponse.redirect(transaction.returnTo, 302));
    }

    const issuers = params.getAll("iss");
    if (issuers.length > 1 || (issuers.length === 1 && issuers[0] !== oidc.issuer)) {
      return fail("invalid_callback");
    }
    const errors = params.getAll("error");
    const codes = params.getAll("code");
    // The issuer's error_description is never shown: only the SDK's own wording reaches users.
    if (errors.length > 0) {
      return fail(
        errors.length === 1 && errors[0] === "access_denied"
          ? "access_denied"
          : "authorization_failed",
      );
    }
    if (codes.length !== 1 || !codes[0] || codes[0].length > 4_096) {
      return fail("invalid_callback");
    }

    let tokens: TokenSet;
    try {
      tokens = await oidc.exchangeCode(codes[0], config.redirectUri, transaction.verifier!);
    } catch {
      return fail("token_exchange_failed");
    }
    let user: User;
    try {
      ({ user } = await oidc.verifyIdToken(tokens.idToken!, { nonce: transaction.nonce! }));
    } catch {
      // Revoke what was issued so a token set that failed verification never stays live.
      if (tokens.refreshToken) await oidc.revoke(tokens.refreshToken, "refresh_token");
      await oidc.revoke(tokens.accessToken, "access_token");
      return fail("invalid_id_token");
    }
    const changes = new CookieChanges(request.cookies);
    const session = this.#sessionFromTokens(config, tokens, user, this.#seconds());
    await this.#writeSession(config, changes, changes, session);
    return finish(NextResponse.redirect(transaction.returnTo, 302), changes);
  }

  async #logout(config: ResolvedConfig, oidc: OidcClient, request: NextRequest) {
    // A cross-site page must not be able to sign players out.
    if (crossSite(request)) return plainResponse(403, "Sign-out must start on this site.");
    const returnTo = this.#safeReturnTo(config, request.nextUrl.searchParams.get("returnTo"));
    const changes = new CookieChanges(request.cookies);
    const session = await this.#readSession(config, changes);
    this.#clearSession(config, changes, changes);
    if (session) {
      // Revoking the refresh token ends its family; revoking the access token ends the session.
      if (session.refreshToken) await oidc.revoke(session.refreshToken, "refresh_token");
      if (session.accessTokenExpiresAt > this.#seconds()) {
        await oidc.revoke(session.accessToken, "access_token");
      }
    }
    let target = returnTo;
    let transaction: string | undefined;
    let state: string | undefined;
    if (config.hostedLogout) {
      state = randomValue();
      const now = this.#seconds();
      transaction = await seal(
        { kind: "logout", state, returnTo } satisfies Transaction,
        config.transactionKeys[0]!,
        now,
        now + TRANSACTION_SECONDS,
      );
      const hosted = new URL(`${config.authOrigin}/login/logout`);
      hosted.searchParams.set("tenant_id", config.tenantId);
      hosted.searchParams.set("client_id", config.clientId);
      // The callback is already a registered redirect URI, so no extra address is needed.
      hosted.searchParams.set("post_logout_redirect_uri", config.redirectUri);
      hosted.searchParams.set("state", state);
      target = hosted.toString();
    }
    const response = NextResponse.redirect(target, { status: 302, headers: NO_STORE });
    changes.applyTo(response.cookies);
    if (transaction && state) {
      response.cookies.set(
        `auth4_tx_${state}`,
        transaction,
        this.#cookieOptions(config, TRANSACTION_SECONDS, config.routes.callback),
      );
    }
    return response;
  }

  async #profile(config: ResolvedConfig, request: NextRequest) {
    const session = await this.#readSession(config, request.cookies);
    if (!session) return new NextResponse(null, { status: 204, headers: NO_STORE });
    return NextResponse.json(session.user, { headers: NO_STORE });
  }

  async #accessTokenRoute(config: ResolvedConfig, oidc: OidcClient, request: NextRequest) {
    if (crossSite(request))
      return NextResponse.json({ error: "forbidden" }, { status: 403, headers: NO_STORE });
    const changes = new CookieChanges(request.cookies);
    let body: AccessTokenResponse;
    let status = 200;
    try {
      body = await this.#accessToken(config, oidc, changes, changes);
    } catch (cause) {
      const code = cause instanceof AccessTokenError ? cause.code : "refresh_failed";
      status = code === "refresh_failed" ? 503 : 401;
      const response = NextResponse.json({ error: code }, { status, headers: NO_STORE });
      changes.applyTo(response.cookies);
      return response;
    }
    const response = NextResponse.json(body, { status, headers: NO_STORE });
    changes.applyTo(response.cookies);
    return response;
  }

  async #accessToken(
    config: ResolvedConfig,
    oidc: OidcClient,
    reader: CookieReader,
    writer: CookieWriter,
    options: { canWrite?: () => boolean } = {},
  ): Promise<AccessTokenResponse> {
    const session = await this.#readSession(config, reader);
    if (!session) throw new AccessTokenError("not_signed_in", "No one is signed in.");
    let current = session;
    if (this.#needsRefresh(session)) {
      if (options.canWrite && !options.canWrite()) {
        // Server components cannot set cookies, and a rotated refresh token that is not saved
        // would be reused later and end the session. Middleware normally refreshes first.
        if (session.accessTokenExpiresAt <= this.#seconds()) {
          throw new AccessTokenError(
            "read_only",
            "The access token expired and cannot be refreshed while rendering. Run auth4.middleware() for this path, or call getAccessToken() from a route handler or server action.",
          );
        }
      } else {
        try {
          current = await this.#refresh(config, oidc, session);
          await this.#writeSession(config, reader, writer, current);
        } catch (cause) {
          if (cause instanceof TokenEndpointError && cause.kind === "rejected") {
            this.#clearSession(config, reader, writer);
            throw new AccessTokenError(
              "refresh_rejected",
              "The refresh token was rejected; the player has been signed out.",
            );
          }
          if (session.accessTokenExpiresAt <= this.#seconds()) {
            throw new AccessTokenError(
              "refresh_failed",
              "The access token could not be refreshed.",
            );
          }
        }
      }
    }
    if (current.accessTokenExpiresAt <= this.#seconds()) {
      throw new AccessTokenError("expired", "The access token expired; sign in again.");
    }
    return {
      token: current.accessToken,
      expires_at: current.accessTokenExpiresAt,
      ...(current.scope === undefined ? {} : { scope: current.scope }),
    };
  }

  // --- Server helpers ----------------------------------------------------------------------

  /**
   * The signed-in session, or null. Without an argument it reads the current request's cookies
   * (server components, route handlers, server actions); pass the request in middleware.
   */
  async getSession(request?: Request | NextRequest): Promise<Session | null> {
    // cookies() first: during `next build` it marks the page dynamic before configuration is read.
    const reader = request ? requestCookies(request) : await nextCookies();
    const { config } = await this.#setup();
    const session = await this.#readSession(config, reader);
    return session ? this.#publicSession(session) : null;
  }

  /**
   * A live access token for calling your own APIs from the server. It is refreshed when it is
   * about to expire and the session holds a refresh token; in server components, where cookies
   * are read-only, the refresh is left to middleware. Throws AccessTokenError.
   */
  async getAccessToken(): Promise<AccessTokenResponse> {
    const store = await nextCookies();
    const { config, oidc } = await this.#setup();
    const writer: CookieWriter = {
      set: (name, value, options) => store.set(name, value, options),
    };
    return this.#accessToken(config, oidc, store, writer, {
      canWrite: () => {
        try {
          // Deleting a cookie that does not exist is a harmless probe for a writable store.
          store.set(`${config.cookieName}-probe`, "", this.#cookieOptions(config, 0));
          return true;
        } catch {
          return false;
        }
      },
    });
  }
}
