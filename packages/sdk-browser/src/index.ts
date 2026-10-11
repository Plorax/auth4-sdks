const FLOW_STORAGE_PREFIX = "auth4:oauth-flow:";
const FLOW_LIFETIME_MS = 10 * 60 * 1_000;
const MAX_CACHE_AGE_MS = 5 * 60 * 1_000;
const DEFAULT_CACHE_AGE_MS = 60 * 1_000;
const TOKEN_LIFETIME_LIMIT_SECONDS = 300;
/** Renew this long before access-token expiry, plus up to RENEW_JITTER_MS of random lead. */
const RENEW_LEAD_MS = 60 * 1_000;
const RENEW_JITTER_MS = 30 * 1_000;
const RENEW_RETRY_MS = 15 * 1_000;
/** Access-token claim marking an un-upgraded guest (AUTH4D-64). Absent means not a guest. */
const GUEST_CLAIM = "auth4_guest";
/** Guest upgrade window protocol (docs/api-spec/auth4d-23.md). */
const UPGRADE_MESSAGE = {
  ready: "auth4:guest-upgrade:ready",
  token: "auth4:guest-upgrade:token",
  complete: "auth4:guest-upgrade:complete",
  failed: "auth4:guest-upgrade:error",
  cancelled: "auth4:guest-upgrade:cancelled",
} as const;
const UPGRADE_WINDOW_NAME = "auth4-guest-upgrade";
const UPGRADE_WINDOW_FEATURES = "popup,width=480,height=720";
const UPGRADE_WINDOW_POLL_MS = 500;
/** Add-email window (AUTH4D-149). The app polls the API; the window never receives a token. */
const ADD_EMAIL_WINDOW_NAME = "auth4-add-email";
const ADD_EMAIL_INTENT = /^aei_[A-Za-z0-9_-]{32,64}$/u;
const ADD_EMAIL_POLL_SECRET = /^aep_[A-Za-z0-9_-]{43,86}$/u;
const ADD_EMAIL_MIN_INTERVAL_SECONDS = 5;
const ADD_EMAIL_MAX_INTERVAL_SECONDS = 60;
const CALLBACK_PARAMETERS = [
  "code",
  "state",
  "error",
  "error_description",
  "error_uri",
  "iss",
  "session_state",
  "access_token",
  "id_token",
  "token_type",
  "expires_in",
] as const;

export interface BrowserStorage {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
  removeItem(key: string): void;
}

export interface BrowserClientOptions {
  /** Tenant issuer, including the `/t/{tenantId}` path. */
  issuer: string;
  clientId: string;
  redirectUri: string;
  /**
   * Opt in to rotating refresh tokens (AUTH4D-65). Login then requests offline_access, the
   * refresh token is held in memory only, and the access token is renewed shortly before it
   * expires. The browser application must have allowBrowserRefresh enabled. Because nothing is
   * persisted, a page reload needs restoreSession() (AUTH4D-140) or a new sign-in.
   */
  refresh?: boolean;
  /** Optional adapters make local and deterministic browser tests straightforward. */
  fetch?: typeof fetch;
  storage?: BrowserStorage;
  now?: () => number;
  navigate?: (url: string) => void;
  replaceUrl?: (url: string) => void;
}

export type Auth4BrowserErrorCode =
  | "configuration_error"
  | "cancelled"
  | "storage_unavailable"
  | "discovery_failed"
  | "issuer_mismatch"
  | "invalid_callback"
  | "state_mismatch"
  | "authorization_failed"
  | "token_exchange_failed"
  | "invalid_id_token"
  | "token_expired"
  | "userinfo_failed"
  | "refresh_failed"
  | "logout_failed"
  | "guest_sign_in_failed"
  | "not_guest"
  | "invalid_session"
  | "identity_in_use"
  | "popup_blocked"
  | "window_closed"
  | "upgrade_failed"
  | "guest_account"
  | "email_already_added"
  | "email_sign_in_disabled"
  | "add_email_failed";

export class Auth4BrowserError extends Error {
  readonly code: Auth4BrowserErrorCode;
  override readonly cause?: unknown;

  constructor(code: Auth4BrowserErrorCode, message: string, cause?: unknown) {
    super(message);
    this.name = "Auth4BrowserError";
    this.code = code;
    if (cause !== undefined) this.cause = cause;
  }
}

/**
 * Third-party sign-in providers the hosted pages can offer first: Discord, Steam (AUTH4D-124),
 * Google, Apple and Microsoft (AUTH4D-213), and Epic Games (AUTH4D-147).
 */
export type SocialProvider = "discord" | "steam" | "epic" | "google" | "apple" | "microsoft";

const SOCIAL_PROVIDERS: readonly SocialProvider[] = [
  "discord",
  "steam",
  "epic",
  "google",
  "apple",
  "microsoft",
];

export interface LoginOptions {
  scope?: string | readonly string[];
  /**
   * Go straight to this provider instead of the sign-in method list (AUTH4D-125). It is a hint:
   * if the application has the provider turned off, hosted login shows the usual list.
   */
  provider?: SocialProvider;
  signal?: AbortSignal;
}

export interface RestoreSessionOptions {
  /** Scopes to request; they must already be consented. Defaults to the login() defaults. */
  scope?: string | readonly string[];
  /** The current page URL, for hosts that own routing. Defaults to window.location.href. */
  url?: string | URL;
  signal?: AbortSignal;
}

/** Errors a `prompt=none` request returns when the player has to interact (AUTH4D-140). */
export type SilentAuthorizationError =
  "login_required" | "consent_required" | "interaction_required";

const SILENT_ERRORS: readonly SilentAuthorizationError[] = [
  "login_required",
  "consent_required",
  "interaction_required",
];

/**
 * The outcome of restoreSession(). `redirecting` means the page is navigating to the issuer and
 * restoreSession() must be called again on the redirect URI when the browser comes back.
 */
export type RestoreSessionResult =
  | { status: "signed_in"; session: BrowserSession }
  | { status: "signed_out"; reason: SilentAuthorizationError }
  | { status: "redirecting" };

export interface CallbackOptions {
  signal?: AbortSignal;
}

export interface UserOptions {
  signal?: AbortSignal;
}

export interface LogoutOptions {
  signal?: AbortSignal;
  /** Optional same-page or application destination after local logout completes. */
  returnTo?: string;
}

export interface BrowserUser {
  sub: string;
  email?: string;
  email_verified?: boolean;
}

export interface BrowserSession {
  user: BrowserUser;
  expiresAt: number;
  /** True while the access token carries the auth4_guest claim (an un-upgraded guest). */
  isGuest: boolean;
}

export interface GuestSignInOptions {
  signal?: AbortSignal;
}

export interface GuestUpgradeOptions {
  /**
   * Offer this provider first in the upgrade window (AUTH4D-125). The player still confirms, and
   * other enabled methods stay available. Ignored if the application has the provider turned off.
   */
  provider?: SocialProvider;
  /** Aborting closes the upgrade window and rejects with `cancelled`. */
  signal?: AbortSignal;
}

export interface GuestUpgradeResult {
  /** The replacement session. The user ID is unchanged and isGuest is false. */
  session: BrowserSession;
  /** The credential that was linked to the guest account, such as "email", "discord" or "epic". */
  identity: { identityId: string; provider: string };
}

export interface AddEmailOptions {
  /** Aborting closes the window and rejects with `cancelled`. */
  signal?: AbortSignal;
}

export interface AddEmailResult {
  /** The refreshed session for the same user, with the verified address. */
  session: BrowserSession;
  /** The address the player verified and added. */
  email: string;
  identity: { identityId: string; provider: "email" };
}

/** Session lifecycle events. They never carry token values. */
export type BrowserSessionEvent =
  | { type: "renewed"; session: BrowserSession }
  | { type: "upgraded"; session: BrowserSession }
  | { type: "email_added"; session: BrowserSession }
  | { type: "signed_out"; reason: "logout" | "refresh_rejected" };

export type BrowserSessionListener = (event: BrowserSessionEvent) => void;

interface DiscoveryDocument {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  userinfo_endpoint: string;
  jwks_uri: string;
  revocation_endpoint?: string;
  response_types_supported?: string[];
  id_token_signing_alg_values_supported?: string[];
  code_challenge_methods_supported?: string[];
  prompt_values_supported?: string[];
}

interface VerifiedIdClaims {
  sub: string;
  nonce: string;
}

interface StoredFlow {
  issuer: string;
  clientId: string;
  redirectUri: string;
  nonce: string;
  verifier: string;
  createdAt: number;
  /** Set for silent re-authorization, whose interaction errors end in signed_out (AUTH4D-140). */
  prompt?: "none";
}

interface ActiveTokens {
  accessToken: string;
  user: BrowserUser;
  expiresAt: number;
  /** When a refresh-enabled session starts renewing; equal to expiresAt otherwise. */
  renewAt: number;
  /** The sign-in nonce; empty for guest sessions, which are not created by an authorize request. */
  nonce: string;
  isGuest: boolean;
}

interface PendingUpgrade {
  popup: Window;
  promise: Promise<GuestUpgradeResult>;
  settled: boolean;
  stop: () => void;
}

interface ParsedTokenSet {
  accessToken: string;
  expiresIn: number;
  idToken?: string;
  refreshToken?: string;
}

interface SigningJwk extends JsonWebKey {
  kid?: string;
  use?: string;
  alg?: string;
}

interface JsonWebKeySet {
  keys: SigningJwk[];
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function validateSecureUrl(
  value: string,
  label: string,
  allowFragment: boolean,
  allowQuery = false,
): URL {
  let url: URL;
  try {
    url = new URL(value);
  } catch (cause) {
    throw new Auth4BrowserError("configuration_error", `${label} must be an absolute URL.`, cause);
  }
  const loopback = ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
  if (
    url.username !== "" ||
    url.password !== "" ||
    (url.protocol !== "https:" && !(url.protocol === "http:" && loopback)) ||
    (!allowQuery && url.search !== "") ||
    (!allowFragment && url.hash !== "")
  ) {
    throw new Auth4BrowserError(
      "configuration_error",
      `${label} must be a secure URL without credentials or query parameters.`,
    );
  }
  return url;
}

function validateOptions(options: BrowserClientOptions): void {
  const issuer = validateSecureUrl(options.issuer, "issuer", false);
  if (
    issuer.href !== options.issuer ||
    issuer.hash !== "" ||
    issuer.search !== "" ||
    !/^\/t\/[^/]+$/u.test(issuer.pathname)
  ) {
    throw new Auth4BrowserError(
      "configuration_error",
      "issuer must be canonical and include exactly one tenant path, such as https://auth.example/t/ten_… .",
    );
  }
  const redirect = validateSecureUrl(options.redirectUri, "redirectUri", false, true);
  if (redirect.href !== options.redirectUri || options.redirectUri.length > 2_048) {
    throw new Auth4BrowserError(
      "configuration_error",
      "redirectUri must be a canonical absolute URL without a fragment.",
    );
  }
  if (CALLBACK_PARAMETERS.some((parameter) => redirect.searchParams.has(parameter))) {
    throw new Auth4BrowserError(
      "configuration_error",
      "redirectUri cannot contain OAuth callback parameters.",
    );
  }
  if (!/^[A-Za-z0-9._~-]{1,200}$/u.test(options.clientId)) {
    throw new Auth4BrowserError("configuration_error", "clientId is not valid.");
  }
}

function checkAbort(signal?: AbortSignal): void {
  if (signal?.aborted) {
    throw new Auth4BrowserError("cancelled", "The Auth4 operation was cancelled.", signal.reason);
  }
}

function fromAbort(error: unknown, signal?: AbortSignal): Auth4BrowserError | null {
  if (
    signal?.aborted ||
    (typeof DOMException !== "undefined" &&
      error instanceof DOMException &&
      error.name === "AbortError")
  ) {
    return new Auth4BrowserError("cancelled", "The Auth4 operation was cancelled.", error);
  }
  return null;
}

function encodeBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
}

function randomValue(): string {
  const bytes = new Uint8Array(32);
  globalThis.crypto.getRandomValues(bytes);
  return encodeBase64Url(bytes);
}

async function createChallenge(verifier: string): Promise<string> {
  const digest = await globalThis.crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(verifier),
  );
  return encodeBase64Url(new Uint8Array(digest));
}

function decodeBase64Url(value: string): Uint8Array<ArrayBuffer> {
  if (!/^[A-Za-z0-9_-]+$/u.test(value)) throw new Error("Invalid base64url value.");
  const normalized = value.replaceAll("-", "+").replaceAll("_", "/");
  const binary = atob(normalized + "=".repeat((4 - (normalized.length % 4)) % 4));
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index);
  return bytes;
}

function decodeJsonSegment(value: string): Record<string, unknown> {
  const parsed: unknown = JSON.parse(new TextDecoder().decode(decodeBase64Url(value)));
  const record = asRecord(parsed);
  if (!record) throw new Error("JWT segment is not a JSON object.");
  return record;
}

function tokenParts(token: string): [string, string, string] {
  if (token.length > 16_384) throw new Error("JWT is too large.");
  const parts = token.split(".");
  if (parts.length !== 3 || parts.some((part) => part.length === 0))
    throw new Error("Malformed JWT.");
  return [parts[0]!, parts[1]!, parts[2]!];
}

function arrayOfStrings(value: unknown): string[] | null {
  if (!Array.isArray(value) || value.some((item) => typeof item !== "string")) return null;
  return value as string[];
}

function tenantIdFromIssuer(issuer: string): string {
  const match = /^\/t\/([^/]+)$/u.exec(new URL(issuer).pathname);
  if (!match?.[1])
    throw new Auth4BrowserError("configuration_error", "issuer must identify one tenant.");
  return match[1];
}

/** Rejects provider names the hosted pages do not know, so a typo fails here and not at /authorize. */
function parseProvider(value: unknown): SocialProvider | undefined {
  if (value === undefined) return undefined;
  if (typeof value === "string" && (SOCIAL_PROVIDERS as readonly string[]).includes(value)) {
    return value as SocialProvider;
  }
  throw new Auth4BrowserError(
    "configuration_error",
    'The provider must be "discord", "steam", "epic", "google", "apple" or "microsoft".',
  );
}

function parseScope(value: string | readonly string[] | undefined, refresh: boolean): string[] {
  const scopes =
    value === undefined
      ? ["openid", "profile", "email"]
      : typeof value === "string"
        ? value.split(" ")
        : [...value];
  if (refresh && !scopes.includes("offline_access")) scopes.push("offline_access");
  if (
    scopes.length === 0 ||
    scopes.length > 32 ||
    scopes.some((scope) => !/^[a-z][a-z0-9:_-]{0,63}$/u.test(scope)) ||
    new Set(scopes).size !== scopes.length ||
    !scopes.includes("openid")
  ) {
    throw new Auth4BrowserError(
      "configuration_error",
      "Scopes must be unique names and include openid.",
    );
  }
  if (!refresh && scopes.includes("offline_access")) {
    throw new Auth4BrowserError(
      "configuration_error",
      "Browser login requests offline_access only when the refresh option is enabled.",
    );
  }
  return scopes;
}

/** Start renewal 60s (bounded to a quarter of the lifetime) before expiry, plus random jitter. */
function renewalTime(issuedAt: number, expiresAt: number): number {
  const lifetime = expiresAt - issuedAt;
  const lead = Math.min(RENEW_LEAD_MS, lifetime / 4);
  const jitter = Math.min(RENEW_JITTER_MS, lifetime / 4) * Math.random();
  return Math.floor(expiresAt - lead - jitter);
}

async function readTokenSet(
  response: Response,
  code: Auth4BrowserErrorCode,
  requireIdToken: boolean,
): Promise<ParsedTokenSet> {
  let rawTokens: unknown;
  try {
    rawTokens = await response.json();
  } catch (cause) {
    throw new Auth4BrowserError(code, "Token endpoint returned invalid JSON.", cause);
  }
  return parseTokenSet(rawTokens, code, requireIdToken);
}

function parseTokenSet(
  rawTokens: unknown,
  code: Auth4BrowserErrorCode,
  requireIdToken: boolean,
): ParsedTokenSet {
  const tokenSet = asRecord(rawTokens);
  const accessToken = tokenSet?.["access_token"];
  const idToken = tokenSet?.["id_token"];
  const refreshToken = tokenSet?.["refresh_token"];
  const tokenType = tokenSet?.["token_type"];
  const expiresIn = tokenSet?.["expires_in"];
  if (
    typeof accessToken !== "string" ||
    accessToken.length === 0 ||
    accessToken.length > 16_384 ||
    (requireIdToken
      ? typeof idToken !== "string"
      : idToken !== undefined && typeof idToken !== "string") ||
    idToken === "" ||
    (refreshToken !== undefined &&
      (typeof refreshToken !== "string" ||
        refreshToken.length === 0 ||
        refreshToken.length > 4_096)) ||
    typeof tokenType !== "string" ||
    tokenType.toLowerCase() !== "bearer" ||
    typeof expiresIn !== "number" ||
    !Number.isInteger(expiresIn) ||
    expiresIn <= 0 ||
    expiresIn > TOKEN_LIFETIME_LIMIT_SECONDS
  ) {
    throw new Auth4BrowserError(code, "Token endpoint returned an invalid browser token set.");
  }
  return {
    accessToken,
    expiresIn,
    ...(typeof idToken === "string" ? { idToken } : {}),
    ...(typeof refreshToken === "string" ? { refreshToken } : {}),
  };
}

/**
 * Read access-token claims without verifying the signature. The SDK uses them only to describe a
 * token it just received over TLS from the issuer (the subject and guest flag); resource servers
 * must still verify access tokens.
 */
function accessTokenClaims(token: string): Record<string, unknown> | null {
  try {
    return decodeJsonSegment(tokenParts(token)[1]);
  } catch {
    return null;
  }
}

function isGuestAccessToken(token: string): boolean {
  return accessTokenClaims(token)?.[GUEST_CLAIM] === true;
}

/** A guest token set must be for the expected user: the response user_id and the token subject. */
function readGuestTokenSet(
  raw: unknown,
  code: Auth4BrowserErrorCode,
  expectedUserId?: string,
): { userId: string; tokens: ParsedTokenSet; record: Record<string, unknown> } {
  const record = asRecord(raw);
  const userId = record?.["user_id"];
  if (
    !record ||
    typeof userId !== "string" ||
    !/^usr_[A-Za-z0-9_-]{1,200}$/u.test(userId) ||
    (expectedUserId !== undefined && userId !== expectedUserId)
  ) {
    throw new Auth4BrowserError(code, "The response is not for the expected guest user.");
  }
  const tokens = parseTokenSet(record, code, false);
  if (accessTokenClaims(tokens.accessToken)?.["sub"] !== userId) {
    throw new Auth4BrowserError(code, "The access token is not for the expected guest user.");
  }
  return { userId, tokens, record };
}

function maxAgeFromHeaders(headers: Headers): number {
  const header = headers.get("Cache-Control") ?? "";
  if (/(?:^|,)\s*(?:no-store|no-cache)(?:\s|,|$)/iu.test(header)) return 0;
  const match = /(?:^|,)\s*max-age\s*=\s*"?(\d+)"?/iu.exec(header);
  if (!match?.[1]) return DEFAULT_CACHE_AGE_MS;
  const seconds = Number(match[1]);
  if (!Number.isFinite(seconds) || seconds <= 0) return 0;
  return Math.min(seconds * 1_000, MAX_CACHE_AGE_MS);
}

function callbackValues(url: URL, name: string): string[] {
  return url.searchParams.getAll(name);
}

function cleanCallbackUrl(input: URL): string {
  const cleaned = new URL(input.toString());
  for (const parameter of CALLBACK_PARAMETERS) cleaned.searchParams.delete(parameter);

  const fragment = cleaned.hash.slice(1);
  if (fragment && !fragment.startsWith("/")) {
    const fragmentParams = new URLSearchParams(fragment);
    let changed = false;
    for (const parameter of CALLBACK_PARAMETERS) {
      if (fragmentParams.has(parameter)) {
        fragmentParams.delete(parameter);
        changed = true;
      }
    }
    if (changed) cleaned.hash = fragmentParams.toString();
  }
  return cleaned.toString();
}

/** Resolves after `ms`, or rejects with `cancelled` when the signal aborts first. */
function delay(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    const aborted = () => {
      clearTimeout(timer);
      reject(
        new Auth4BrowserError("cancelled", "The Auth4 operation was cancelled.", signal?.reason),
      );
    };
    const timer = setTimeout(() => {
      signal?.removeEventListener("abort", aborted);
      resolve();
    }, ms);
    if (signal?.aborted) aborted();
    else signal?.addEventListener("abort", aborted, { once: true });
  });
}

export class Auth4BrowserClient {
  private readonly fetcher: typeof fetch;
  private discoveryCache: { document: DiscoveryDocument; expiresAt: number } | undefined;
  private jwksCache: { jwks: JsonWebKeySet; expiresAt: number } | undefined;
  private activeTokens: ActiveTokens | undefined;
  // Refresh state lives in ES private fields: memory only, never serialized or persisted.
  #refreshToken: string | undefined;
  #refreshing: Promise<void> | undefined;
  #renewTimer: ReturnType<typeof setTimeout> | undefined;
  #generation = 0;
  #upgrade: PendingUpgrade | undefined;
  #addEmail: { popup: Window; promise: Promise<AddEmailResult> } | undefined;
  readonly #listeners = new Set<BrowserSessionListener>();

  constructor(readonly options: BrowserClientOptions) {
    validateOptions(options);
    this.fetcher = options.fetch ?? globalThis.fetch.bind(globalThis);
  }

  /** Fetch and validate tenant discovery. Results are cached in memory for at most five minutes. */
  async discover(signal?: AbortSignal): Promise<Readonly<DiscoveryDocument>> {
    checkAbort(signal);
    const now = this.currentTime();
    if (this.discoveryCache && this.discoveryCache.expiresAt > now)
      return this.discoveryCache.document;

    const discoveryUrl = `${this.options.issuer}/.well-known/openid-configuration`;
    let response: Response;
    try {
      response = await this.fetcher(discoveryUrl, {
        method: "GET",
        headers: { Accept: "application/json" },
        cache: "no-cache",
        ...(signal === undefined ? {} : { signal }),
      });
    } catch (cause) {
      const cancelled = fromAbort(cause, signal);
      if (cancelled) throw cancelled;
      throw new Auth4BrowserError("discovery_failed", "Unable to load Auth4 discovery.", cause);
    }
    if (!response.ok)
      throw new Auth4BrowserError(
        "discovery_failed",
        `Discovery returned HTTP ${response.status}.`,
      );

    let raw: unknown;
    try {
      raw = await response.json();
    } catch (cause) {
      throw new Auth4BrowserError("discovery_failed", "Discovery returned invalid JSON.", cause);
    }
    const record = asRecord(raw);
    if (!record || record["issuer"] !== this.options.issuer) {
      throw new Auth4BrowserError(
        "issuer_mismatch",
        "Discovery issuer does not match the configured issuer.",
      );
    }

    try {
      const endpoint = (key: string, required = true): string | undefined => {
        const value = record[key];
        if (value === undefined && !required) return undefined;
        if (typeof value !== "string") throw new Error(`Missing ${key}.`);
        const url = new URL(value);
        const issuerUrl = new URL(this.options.issuer);
        const issuerPath = new URL(this.options.issuer).pathname;
        const tenantId = tenantIdFromIssuer(this.options.issuer);
        const correctTenant =
          key === "jwks_uri"
            ? url.pathname === `${issuerPath}/.well-known/jwks.json` &&
              !url.searchParams.has("tenant_id")
            : url.searchParams.get("tenant_id") === tenantId;
        if (
          url.origin !== issuerUrl.origin ||
          url.username !== "" ||
          url.password !== "" ||
          url.hash !== "" ||
          !correctTenant
        ) {
          throw new Error(`Invalid ${key}.`);
        }
        return url.toString();
      };
      const responseTypes = arrayOfStrings(record["response_types_supported"]);
      const algorithms = arrayOfStrings(record["id_token_signing_alg_values_supported"]);
      const challengeMethods = arrayOfStrings(record["code_challenge_methods_supported"]);
      const promptValues = arrayOfStrings(record["prompt_values_supported"]);
      if (
        responseTypes?.includes("code") !== true ||
        algorithms?.includes("RS256") !== true ||
        challengeMethods?.includes("S256") !== true
      ) {
        throw new Error(
          "Discovery does not advertise the required authorization-code and RS256 profile.",
        );
      }
      const document: DiscoveryDocument = {
        issuer: this.options.issuer,
        authorization_endpoint: endpoint("authorization_endpoint")!,
        token_endpoint: endpoint("token_endpoint")!,
        userinfo_endpoint: endpoint("userinfo_endpoint")!,
        jwks_uri: endpoint("jwks_uri")!,
        ...(endpoint("revocation_endpoint", false) === undefined
          ? {}
          : { revocation_endpoint: endpoint("revocation_endpoint", false)! }),
        response_types_supported: responseTypes,
        id_token_signing_alg_values_supported: algorithms,
        code_challenge_methods_supported: challengeMethods,
        ...(promptValues === null ? {} : { prompt_values_supported: promptValues }),
      };
      this.discoveryCache = {
        document,
        expiresAt: this.currentTime() + maxAgeFromHeaders(response.headers),
      };
      return document;
    } catch (cause) {
      if (cause instanceof Auth4BrowserError) throw cause;
      throw new Auth4BrowserError(
        "discovery_failed",
        "Discovery is missing a safe supported endpoint configuration.",
        cause,
      );
    }
  }

  /** Build the hosted-login URL and persist only short-lived PKCE/state data in sessionStorage. */
  async authorizationUrl(options: LoginOptions = {}): Promise<string> {
    return this.buildAuthorizationUrl(options);
  }

  private async buildAuthorizationUrl(
    options: LoginOptions,
    prompt?: "none",
    guest = false,
  ): Promise<string> {
    checkAbort(options.signal);
    const provider = guest ? undefined : parseProvider(options.provider);
    const discovery = await this.discover(options.signal);
    if (prompt !== undefined && discovery.prompt_values_supported?.includes(prompt) !== true) {
      throw new Auth4BrowserError(
        "authorization_failed",
        "The issuer does not support silent re-authorization.",
      );
    }
    const scopes = parseScope(options.scope, this.options.refresh === true);
    const state = randomValue();
    const nonce = randomValue();
    const verifier = randomValue();
    const challenge = await createChallenge(verifier);
    const flow: StoredFlow = {
      issuer: this.options.issuer,
      clientId: this.options.clientId,
      redirectUri: this.options.redirectUri,
      nonce,
      verifier,
      createdAt: this.currentTime(),
      ...(prompt === undefined ? {} : { prompt }),
    };
    try {
      this.storage().setItem(`${FLOW_STORAGE_PREFIX}${state}`, JSON.stringify(flow));
    } catch (cause) {
      if (cause instanceof Auth4BrowserError) throw cause;
      throw new Auth4BrowserError(
        "storage_unavailable",
        "Unable to save temporary authorization state.",
        cause,
      );
    }

    // AUTH4D-167: the hosted guest start answers like the authorization endpoint.
    const url = new URL(
      guest ? `${this.options.issuer}/guest/authorize` : discovery.authorization_endpoint,
    );
    url.searchParams.set("response_type", "code");
    url.searchParams.set("client_id", this.options.clientId);
    url.searchParams.set("redirect_uri", this.options.redirectUri);
    url.searchParams.set("scope", scopes.join(" "));
    url.searchParams.set("state", state);
    url.searchParams.set("nonce", nonce);
    url.searchParams.set("code_challenge", challenge);
    url.searchParams.set("code_challenge_method", "S256");
    if (provider) url.searchParams.set("provider_hint", provider);
    if (prompt) url.searchParams.set("prompt", prompt);
    return url.toString();
  }

  /** Start hosted login by navigating to Auth4's authorization endpoint. */
  async login(options: LoginOptions = {}): Promise<string> {
    const url = await this.authorizationUrl(options);
    checkAbort(options.signal);
    this.navigateTo(url);
    return url;
  }

  /**
   * Start a guest that survives page reloads (AUTH4D-167). Navigates the top-level page to
   * {issuer}/guest/authorize, which creates the guest, sets a hosted session cookie on the auth
   * origin and returns an authorization code to the redirect URI. Finish with handleCallback() or
   * restoreSession() there; the session has isGuest set. Tokens stay in memory, and nothing is
   * written to this origin's storage except the short-lived PKCE state, as for login(). Later
   * reloads restore the guest with restoreSession(). The `provider` option is ignored.
   */
  async loginAsGuest(options: LoginOptions = {}): Promise<string> {
    const url = await this.buildAuthorizationUrl(options, undefined, true);
    checkAbort(options.signal);
    this.navigateTo(url);
    return url;
  }

  /**
   * Sign a returning player back in without UI after a page reload (AUTH4D-140). Call it on page
   * load. Away from a callback it navigates the top-level page to the authorization endpoint with
   * `prompt=none` (no hidden iframe, so it works when third-party cookies are blocked) and resolves
   * `redirecting`. On the redirect URI it completes the callback: `signed_in` when the hosted-login
   * session and consent are still valid, or `signed_out` with the issuer's reason, usually
   * `login_required`. Tokens stay in memory. Guests started with loginAsGuest() are restored too
   * (AUTH4D-167); guests started with signInAsGuest() are not.
   */
  async restoreSession(options: RestoreSessionOptions = {}): Promise<RestoreSessionResult> {
    checkAbort(options.signal);
    const active = this.getSession();
    if (active) return { status: "signed_in", session: active };
    const url = this.callbackOnPage(options.url);
    if (url) {
      const result = await this.completeCallback(url, options, true);
      if ("error" in result) return { status: "signed_out", reason: result.error };
      return { status: "signed_in", session: result };
    }
    const target = await this.buildAuthorizationUrl(
      {
        ...(options.scope === undefined ? {} : { scope: options.scope }),
        ...(options.signal === undefined ? {} : { signal: options.signal }),
      },
      "none",
    );
    checkAbort(options.signal);
    this.navigateTo(target);
    return { status: "redirecting" };
  }

  /** The current page URL when it is the redirect URI carrying an authorization response. */
  private callbackOnPage(href?: string | URL): URL | null {
    try {
      const url = new URL((href ?? this.currentHref()).toString());
      this.validateCallbackLocation(url);
      return url.searchParams.has("state") ? url : null;
    } catch {
      return null;
    }
  }

  private navigateTo(url: string): void {
    try {
      if (this.options.navigate) this.options.navigate(url);
      else this.browserWindow().location.assign(url);
    } catch (cause) {
      throw new Auth4BrowserError(
        "authorization_failed",
        "Unable to navigate to hosted login.",
        cause,
      );
    }
  }

  /** Validate and consume the authorization callback, then establish an in-memory session. */
  async handleCallback(
    callbackUrl?: string | URL,
    options: CallbackOptions = {},
  ): Promise<BrowserSession> {
    const input = callbackUrl ?? this.currentHref();
    let url: URL;
    try {
      url = new URL(input.toString());
    } catch (cause) {
      throw new Auth4BrowserError("invalid_callback", "Callback URL is not valid.", cause);
    }
    return (await this.completeCallback(url, options, false)) as BrowserSession;
  }

  /**
   * Consume one authorization callback. With `silent`, an interaction error answering this
   * client's own `prompt=none` request is returned instead of thrown.
   */
  private async completeCallback(
    url: URL,
    options: CallbackOptions,
    silent: boolean,
  ): Promise<BrowserSession | { error: SilentAuthorizationError }> {
    this.clearSession();

    try {
      checkAbort(options.signal);
      this.validateCallbackLocation(url);
      const codes = callbackValues(url, "code");
      const states = callbackValues(url, "state");
      const errors = callbackValues(url, "error");
      if (states.length !== 1 || states[0]!.length < 16 || states[0]!.length > 512) {
        throw new Auth4BrowserError(
          "state_mismatch",
          "Authorization callback state is missing or ambiguous.",
        );
      }
      const state = states[0]!;
      const stored = this.takeFlow(state);
      if (!stored)
        throw new Auth4BrowserError(
          "state_mismatch",
          "Authorization state is missing, expired, or already used.",
        );
      if (
        stored.issuer !== this.options.issuer ||
        stored.clientId !== this.options.clientId ||
        stored.redirectUri !== this.options.redirectUri
      ) {
        throw new Auth4BrowserError(
          "state_mismatch",
          "Authorization state belongs to a different client configuration.",
        );
      }
      const responseIssuer = callbackValues(url, "iss");
      if (
        responseIssuer.length > 1 ||
        (responseIssuer.length === 1 && responseIssuer[0] !== this.options.issuer)
      ) {
        throw new Auth4BrowserError(
          "issuer_mismatch",
          "Authorization response issuer does not match the configured issuer.",
        );
      }
      if (errors.length > 0) {
        if (errors.length !== 1 || codes.length !== 0)
          throw new Auth4BrowserError("invalid_callback", "Authorization callback is ambiguous.");
        const silentError = SILENT_ERRORS.find((value) => value === errors[0]);
        if (silent && stored.prompt === "none" && silentError) return { error: silentError };
        throw new Auth4BrowserError("authorization_failed", `Hosted login returned ${errors[0]}.`);
      }
      if (codes.length !== 1 || !codes[0] || codes[0].length > 4_096) {
        throw new Auth4BrowserError(
          "invalid_callback",
          "Authorization callback code is missing or ambiguous.",
        );
      }

      const discovery = await this.discover(options.signal);
      const tokenResponse = await this.fetcher(discovery.token_endpoint, {
        method: "POST",
        headers: {
          Accept: "application/json",
          "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",
        },
        body: new URLSearchParams({
          grant_type: "authorization_code",
          code: codes[0],
          redirect_uri: this.options.redirectUri,
          client_id: this.options.clientId,
          code_verifier: stored.verifier,
        }).toString(),
        cache: "no-store",
        ...(options.signal === undefined ? {} : { signal: options.signal }),
      });
      if (!tokenResponse.ok) {
        throw new Auth4BrowserError(
          "token_exchange_failed",
          `Token exchange returned HTTP ${tokenResponse.status}.`,
        );
      }
      const tokens = await readTokenSet(tokenResponse, "token_exchange_failed", true);
      const claims = await this.validateIdToken(
        tokens.idToken!,
        stored.nonce,
        discovery,
        options.signal,
      );
      return this.startSession(tokens, { sub: claims.sub }, stored.nonce);
    } catch (cause) {
      const cancelled = fromAbort(cause, options.signal);
      if (cancelled) throw cancelled;
      if (cause instanceof Auth4BrowserError) throw cause;
      throw new Auth4BrowserError(
        "token_exchange_failed",
        "Unable to complete the authorization callback.",
        cause,
      );
    } finally {
      this.replaceCallbackUrl(url);
    }
  }

  /** Return the live access token. Expired in-memory credentials are discarded immediately. */
  getAccessToken(): string | null {
    if (!this.activeTokens) return null;
    if (this.activeTokens.expiresAt <= this.currentTime()) {
      if (this.#refreshToken !== undefined) {
        // A late timer (for example in a throttled background tab) can leave an expired token.
        void this.renew().catch(() => undefined);
        throw new Auth4BrowserError(
          "token_expired",
          "The browser access token is being renewed; await getAccessTokenSilently() instead.",
        );
      }
      this.activeTokens = undefined;
      throw new Auth4BrowserError(
        "token_expired",
        "The browser access token has expired; sign in again.",
      );
    }
    return this.activeTokens.accessToken;
  }

  /**
   * Return a live access token, renewing it first when a refresh-enabled session is inside its
   * renewal window. Concurrent callers share one refresh request. Without the refresh option this
   * behaves like getAccessToken().
   */
  async getAccessTokenSilently(): Promise<string | null> {
    const active = this.activeTokens;
    if (!active) return null;
    if (this.#refreshToken === undefined || this.currentTime() < active.renewAt) {
      return this.getAccessToken();
    }
    try {
      await this.renew();
    } catch (cause) {
      // A transient failure inside the renewal window still leaves a usable token.
      if (this.activeTokens === active && active.expiresAt > this.currentTime()) {
        return active.accessToken;
      }
      throw cause;
    }
    return this.getAccessToken();
  }

  /** Subscribe to renewed and signed_out events. Returns an unsubscribe function. */
  onSessionEvent(listener: BrowserSessionListener): () => void {
    this.#listeners.add(listener);
    return () => {
      this.#listeners.delete(listener);
    };
  }

  /** Fetch tenant UserInfo using the in-memory bearer token and enforce subject consistency. */
  async getUser(options: UserOptions = {}): Promise<BrowserUser> {
    checkAbort(options.signal);
    const accessToken = this.getAccessToken();
    if (!accessToken || !this.activeTokens) {
      throw new Auth4BrowserError("token_expired", "No active browser session is available.");
    }
    const expectedSubject = this.activeTokens.user.sub;
    try {
      const discovery = await this.discover(options.signal);
      const response = await this.fetcher(discovery.userinfo_endpoint, {
        method: "GET",
        headers: { Accept: "application/json", Authorization: `Bearer ${accessToken}` },
        cache: "no-store",
        ...(options.signal === undefined ? {} : { signal: options.signal }),
      });
      if (!response.ok)
        throw new Auth4BrowserError(
          "userinfo_failed",
          `UserInfo returned HTTP ${response.status}.`,
        );
      const record = asRecord(await response.json());
      if (record?.["sub"] !== expectedSubject) {
        throw new Auth4BrowserError(
          "userinfo_failed",
          "UserInfo subject does not match the validated ID token.",
        );
      }
      const user: BrowserUser = { sub: expectedSubject };
      if (typeof record["email"] === "string") user.email = record["email"];
      if (typeof record["email_verified"] === "boolean")
        user.email_verified = record["email_verified"];
      this.activeTokens.user = user;
      return user;
    } catch (cause) {
      const cancelled = fromAbort(cause, options.signal);
      if (cancelled) throw cancelled;
      if (cause instanceof Auth4BrowserError) throw cause;
      throw new Auth4BrowserError(
        "userinfo_failed",
        "Unable to retrieve the signed-in user.",
        cause,
      );
    }
  }

  /**
   * Revoke the refresh token (when present) and the access token, clear memory, and optionally
   * navigate to an application URL.
   */
  async logout(options: LogoutOptions = {}): Promise<void> {
    const active = this.activeTokens;
    const refreshToken = this.#refreshToken;
    this.clearSession();
    if (active) this.emit({ type: "signed_out", reason: "logout" });
    try {
      if (active) {
        checkAbort(options.signal);
        const discovery = await this.discover(options.signal);
        if (!discovery.revocation_endpoint) {
          throw new Auth4BrowserError(
            "logout_failed",
            "Discovery does not publish a token revocation endpoint.",
          );
        }
        // Revoking the refresh token ends its whole family and the server session.
        const revocations: [string, string][] =
          refreshToken === undefined
            ? [[active.accessToken, "access_token"]]
            : [
                [refreshToken, "refresh_token"],
                [active.accessToken, "access_token"],
              ];
        for (const [token, hint] of revocations) {
          const response = await this.fetcher(discovery.revocation_endpoint, {
            method: "POST",
            headers: {
              Accept: "application/json",
              "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",
            },
            body: new URLSearchParams({
              token,
              token_type_hint: hint,
              client_id: this.options.clientId,
            }).toString(),
            cache: "no-store",
            ...(options.signal === undefined ? {} : { signal: options.signal }),
          });
          if (!response.ok)
            throw new Auth4BrowserError(
              "logout_failed",
              `Token revocation returned HTTP ${response.status}.`,
            );
        }
      }
      if (options.returnTo) {
        const returnTo = new URL(options.returnTo, this.options.redirectUri);
        const redirectOrigin = new URL(this.options.redirectUri).origin;
        if (returnTo.origin !== redirectOrigin) {
          throw new Auth4BrowserError(
            "configuration_error",
            "returnTo must use the configured redirect origin.",
          );
        }
        if (this.options.navigate) this.options.navigate(returnTo.toString());
        else this.browserWindow().location.assign(returnTo.toString());
      }
    } catch (cause) {
      const cancelled = fromAbort(cause, options.signal);
      if (cancelled) throw cancelled;
      if (cause instanceof Auth4BrowserError) throw cause;
      throw new Auth4BrowserError("logout_failed", "Unable to revoke the browser session.", cause);
    }
  }

  getSession(): BrowserSession | null {
    if (!this.activeTokens) return null;
    try {
      this.getAccessToken();
    } catch {
      // A refresh-enabled session stays signed in while its renewal is pending.
      if (this.#refreshToken === undefined) return null;
    }
    if (!this.activeTokens) return null;
    return this.sessionOf(this.activeTokens);
  }

  /**
   * Start a guest session with POST {issuer}/guest (AUTH4D-15). Any current session is replaced.
   * The returned session has isGuest set from the access token's auth4_guest claim. Like every
   * session it is held in memory only; the response's ID token is not retained.
   */
  async signInAsGuest(options: GuestSignInOptions = {}): Promise<BrowserSession> {
    checkAbort(options.signal);
    this.clearSession();
    let response: Response;
    try {
      response = await this.fetcher(`${this.options.issuer}/guest`, {
        method: "POST",
        headers: { Accept: "application/json", "Content-Type": "application/json" },
        body: JSON.stringify({
          client_id: this.options.clientId,
          browser_flow_id: `flw_${randomValue()}`,
        }),
        // The SDK keeps tokens in memory; it never asks the browser to store session cookies.
        credentials: "omit",
        cache: "no-store",
        ...(options.signal === undefined ? {} : { signal: options.signal }),
      });
    } catch (cause) {
      const cancelled = fromAbort(cause, options.signal);
      if (cancelled) throw cancelled;
      throw new Auth4BrowserError(
        "guest_sign_in_failed",
        "Unable to reach the guest endpoint.",
        cause,
      );
    }
    let raw: unknown;
    try {
      raw = await response.json();
    } catch (cause) {
      const cancelled = fromAbort(cause, options.signal);
      if (cancelled) throw cancelled;
      throw new Auth4BrowserError(
        "guest_sign_in_failed",
        `Guest sign-in returned HTTP ${response.status}.`,
        cause,
      );
    }
    if (!response.ok) {
      const error = asRecord(raw)?.["error"];
      throw new Auth4BrowserError(
        "guest_sign_in_failed",
        `Guest sign-in returned HTTP ${response.status}${typeof error === "string" ? ` (${error.slice(0, 64)})` : ""}.`,
      );
    }
    checkAbort(options.signal);
    const { userId, tokens } = readGuestTokenSet(raw, "guest_sign_in_failed");
    return this.startSession(tokens, { sub: userId }, "");
  }

  /**
   * Open the hosted guest-upgrade window and run the opener side of the window protocol. Call it
   * synchronously from a user gesture such as a click, or the browser blocks the window. The guest
   * access token is sent only by postMessage to the auth origin, in answer to a ready message from
   * that window; it never enters a URL. On completion the in-memory token set is replaced in one
   * step and the promise resolves with the new session for the same user.
   *
   * Rejects with `invalid_session` (no live session, or the server ended it), `not_guest`,
   * `popup_blocked`, `identity_in_use`, `cancelled` ("Not now" or an aborted signal),
   * `window_closed` or `upgrade_failed`. After `identity_in_use` the window lets the player link a
   * different credential; a later completion in that window still replaces the token set and
   * emits an `upgraded` session event.
   */
  upgradeGuest(options: GuestUpgradeOptions = {}): Promise<GuestUpgradeResult> {
    const pending = this.#upgrade;
    if (pending && !pending.settled) {
      try {
        pending.popup.focus();
      } catch {
        // Focus is best effort.
      }
      return pending.promise;
    }
    pending?.stop();

    let browser: Window;
    let provider: SocialProvider | undefined;
    try {
      checkAbort(options.signal);
      provider = parseProvider(options.provider);
      browser = this.browserWindow();
      const session = this.getSession();
      if (!session || !this.activeTokens) {
        throw new Auth4BrowserError("invalid_session", "No active guest session is available.");
      }
      if (!session.isGuest) {
        throw new Auth4BrowserError("not_guest", "The signed-in user is not a guest.");
      }
    } catch (cause) {
      return Promise.reject(
        cause instanceof Auth4BrowserError
          ? cause
          : new Auth4BrowserError("configuration_error", "Guest upgrade needs a browser.", cause),
      );
    }

    const authOrigin = new URL(this.options.issuer).origin;
    const tenantId = tenantIdFromIssuer(this.options.issuer);
    const url = new URL("/login/upgrade", authOrigin);
    url.searchParams.set("tenant_id", tenantId);
    url.searchParams.set("client_id", this.options.clientId);
    if (provider) url.searchParams.set("provider", provider);
    let opened: Window | null;
    try {
      // Synchronous inside the caller's gesture, and without noopener: the page needs window.opener.
      opened = browser.open(url.toString(), UPGRADE_WINDOW_NAME, UPGRADE_WINDOW_FEATURES);
    } catch {
      opened = null;
    }
    if (!opened) {
      return Promise.reject(
        new Auth4BrowserError("popup_blocked", "The browser blocked the guest upgrade window."),
      );
    }
    const popup = opened;
    const generation = this.#generation;
    const subject = this.activeTokens!.user.sub;
    const signal = options.signal;

    let resolvePromise!: (result: GuestUpgradeResult) => void;
    let rejectPromise!: (error: Auth4BrowserError) => void;
    const promise = new Promise<GuestUpgradeResult>((resolve, reject) => {
      resolvePromise = resolve;
      rejectPromise = reject;
    });
    const upgrade: PendingUpgrade = {
      popup,
      promise,
      settled: false,
      stop: () => {
        browser.removeEventListener("message", onMessage);
        clearInterval(poll);
        signal?.removeEventListener("abort", onAbort);
        if (this.#upgrade === upgrade) this.#upgrade = undefined;
      },
    };
    const settle = (outcome: GuestUpgradeResult | Auth4BrowserError, keepListening = false) => {
      if (!keepListening) upgrade.stop();
      if (upgrade.settled) return;
      upgrade.settled = true;
      if (outcome instanceof Auth4BrowserError) rejectPromise(outcome);
      else resolvePromise(outcome);
    };
    const sessionEnded = () =>
      new Auth4BrowserError("invalid_session", "The guest session ended during the upgrade.");

    const onMessage = (event: MessageEvent): void => {
      // Every message must come from the upgrade window, on the exact auth origin.
      if (event.origin !== authOrigin || event.source !== popup) return;
      const message = asRecord(event.data);
      if (!message) return;
      switch (message["type"]) {
        case UPGRADE_MESSAGE.ready:
          if (message["tenant_id"] !== tenantId || message["client_id"] !== this.options.clientId)
            return;
          void this.guestTokenFor(generation, subject).then(
            (accessToken) => {
              try {
                popup.postMessage(
                  { type: UPGRADE_MESSAGE.token, access_token: accessToken },
                  authOrigin,
                );
              } catch {
                // The window navigated away; it repeats the handshake when it returns.
              }
            },
            () => settle(sessionEnded()),
          );
          return;
        case UPGRADE_MESSAGE.complete: {
          let result: GuestUpgradeResult;
          try {
            result = this.completeUpgrade(message["result"], generation, subject);
          } catch (cause) {
            settle(
              cause instanceof Auth4BrowserError
                ? cause
                : new Auth4BrowserError("upgrade_failed", "The upgrade result is invalid.", cause),
            );
            return;
          }
          settle(result);
          return;
        }
        case UPGRADE_MESSAGE.failed:
          if (message["error"] === "identity_in_use") {
            // The window offers to link a different credential, so keep answering it.
            settle(
              new Auth4BrowserError(
                "identity_in_use",
                "That credential already belongs to another account. Nothing was merged.",
              ),
              true,
            );
          } else if (message["error"] === "invalid_session") {
            settle(sessionEnded());
          }
          return;
        case UPGRADE_MESSAGE.cancelled:
          settle(new Auth4BrowserError("cancelled", "The player chose not to upgrade."));
          return;
        default:
          return;
      }
    };
    const onAbort = (): void => {
      try {
        popup.close();
      } catch {
        // Already closed.
      }
      settle(
        new Auth4BrowserError("cancelled", "The guest upgrade was cancelled.", signal?.reason),
      );
    };

    this.#upgrade = upgrade;
    browser.addEventListener("message", onMessage);
    signal?.addEventListener("abort", onAbort, { once: true });
    const poll = setInterval(() => {
      let closed = true;
      try {
        closed = popup.closed;
      } catch {
        // Treat an inaccessible window as closed.
      }
      if (closed)
        settle(new Auth4BrowserError("window_closed", "The guest upgrade window was closed."));
    }, UPGRADE_WINDOW_POLL_MS);
    return promise;
  }

  /** The current guest access token, only while the session that started the upgrade is live. */
  private async guestTokenFor(generation: number, subject: string): Promise<string> {
    const current = () =>
      generation === this.#generation &&
      this.activeTokens?.user.sub === subject &&
      this.activeTokens.isGuest;
    if (!current()) throw new Error("Session changed.");
    const token = await this.getAccessTokenSilently();
    if (!token || !current()) throw new Error("Session changed.");
    return token;
  }

  /** Validate the upgrade response and swap the in-memory token set in one synchronous step. */
  private completeUpgrade(raw: unknown, generation: number, subject: string): GuestUpgradeResult {
    if (generation !== this.#generation || this.activeTokens?.user.sub !== subject) {
      throw new Auth4BrowserError(
        "invalid_session",
        "The local session changed during the upgrade; sign in again.",
      );
    }
    const { tokens, record } = readGuestTokenSet(raw, "upgrade_failed", subject);
    const identity = asRecord(record["identity"]);
    const identityId = identity?.["identity_id"];
    const provider = identity?.["provider"];
    if (typeof identityId !== "string" || typeof provider !== "string") {
      throw new Auth4BrowserError("upgrade_failed", "The upgrade result has no linked identity.");
    }
    const session = this.startSession(tokens, { sub: subject }, this.activeTokens.nonce);
    this.emit({ type: "upgraded", session });
    return { session, identity: { identityId, provider } };
  }

  /**
   * Let a signed-in player who has no email address (for example one who signed in with Steam) add
   * one (AUTH4D-149). Call it synchronously from a user gesture such as a click: the hosted
   * add-email window opens before the first await. The SDK creates an add-email intent with the
   * in-memory access token, points the window at the hosted page, and polls the API with a poll
   * secret it keeps in memory; the window never receives a token. When the player has verified
   * the address, the in-memory token set is replaced with the refreshed session for the same user
   * and an `email_added` session event is emitted.
   *
   * Rejects with `invalid_session`, `guest_account` (use upgradeGuest), `email_already_added`,
   * `email_sign_in_disabled`, `popup_blocked`, `cancelled` ("Not now" or an aborted signal),
   * `window_closed` or `add_email_failed` (for example when the request expired). An address that
   * already belongs to another account is refused in the window, which lets the player try another.
   */
  addEmail(options: AddEmailOptions = {}): Promise<AddEmailResult> {
    const pending = this.#addEmail;
    if (pending) {
      try {
        pending.popup.focus();
      } catch {
        // Focus is best effort.
      }
      return pending.promise;
    }
    let browser: Window;
    try {
      checkAbort(options.signal);
      browser = this.browserWindow();
      const session = this.getSession();
      if (!session || !this.activeTokens) {
        throw new Auth4BrowserError("invalid_session", "No active session is available.");
      }
      if (session.isGuest) {
        throw new Auth4BrowserError(
          "guest_account",
          "Guests save their progress with upgradeGuest(), which can link an email address.",
        );
      }
    } catch (cause) {
      return Promise.reject(
        cause instanceof Auth4BrowserError
          ? cause
          : new Auth4BrowserError("configuration_error", "Adding an email needs a browser.", cause),
      );
    }
    let opened: Window | null;
    try {
      // Opened blank inside the caller's gesture; the page URL is known only once the intent exists.
      opened = browser.open("about:blank", ADD_EMAIL_WINDOW_NAME, UPGRADE_WINDOW_FEATURES);
    } catch {
      opened = null;
    }
    if (!opened) {
      return Promise.reject(
        new Auth4BrowserError("popup_blocked", "The browser blocked the add-email window."),
      );
    }
    const popup = opened;
    const promise = this.runAddEmail(popup, options.signal).finally(() => {
      if (this.#addEmail?.promise === promise) this.#addEmail = undefined;
    });
    this.#addEmail = { popup, promise };
    return promise;
  }

  private async runAddEmail(popup: Window, signal?: AbortSignal): Promise<AddEmailResult> {
    const generation = this.#generation;
    const subject = this.activeTokens!.user.sub;
    const authOrigin = new URL(this.options.issuer).origin;
    const sessionEnded = () =>
      new Auth4BrowserError("invalid_session", "The session ended while adding an email address.");
    try {
      const accessToken = await this.getAccessTokenSilently();
      if (!accessToken || generation !== this.#generation) throw sessionEnded();
      const created = await this.addEmailRequest(
        "/account/email/intent",
        { client_id: this.options.clientId },
        signal,
        accessToken,
      );
      if (!created.ok) {
        if (created.error === "invalid_session" || created.status === 401) throw sessionEnded();
        if (
          created.error === "guest_account" ||
          created.error === "email_already_added" ||
          created.error === "email_sign_in_disabled"
        ) {
          throw new Auth4BrowserError(created.error, `Adding an email address was refused.`);
        }
        throw new Auth4BrowserError(
          "add_email_failed",
          `The add-email request returned HTTP ${created.status}.`,
        );
      }
      const { intent, poll_secret: pollSecret, expires_in: expiresIn } = created.body;
      const interval = created.body["interval"];
      let page: URL | null = null;
      try {
        page = new URL(String(created.body["add_email_uri"]));
      } catch {
        page = null;
      }
      if (
        typeof intent !== "string" ||
        !ADD_EMAIL_INTENT.test(intent) ||
        typeof pollSecret !== "string" ||
        !ADD_EMAIL_POLL_SECRET.test(pollSecret) ||
        page?.origin !== authOrigin ||
        page.pathname !== "/login/add-email" ||
        typeof expiresIn !== "number" ||
        expiresIn <= 0 ||
        typeof interval !== "number"
      ) {
        throw new Auth4BrowserError("add_email_failed", "The add-email response is malformed.");
      }
      popup.location.replace(page.toString());

      const deadline = this.currentTime() + expiresIn * 1_000;
      let wait = Math.min(
        ADD_EMAIL_MAX_INTERVAL_SECONDS,
        Math.max(ADD_EMAIL_MIN_INTERVAL_SECONDS, Math.ceil(interval)),
      );
      for (;;) {
        await delay(wait * 1_000, signal);
        if (generation !== this.#generation) throw sessionEnded();
        let windowClosed = true;
        try {
          windowClosed = popup.closed;
        } catch {
          // Treat an inaccessible window as closed.
        }
        // Not cancellable once sent: the refreshed session is released exactly once.
        const polled = await this.addEmailRequest("/account/email/intent/token", {
          client_id: this.options.clientId,
          intent,
          poll_secret: pollSecret,
        });
        if (polled.ok) return this.completeAddEmail(polled.body, generation, subject);
        if (polled.error === "access_denied") {
          throw new Auth4BrowserError("cancelled", "The player chose not to add an email address.");
        }
        if (polled.error === "slow_down") {
          const serverInterval = polled.body["interval"];
          wait = Math.min(
            ADD_EMAIL_MAX_INTERVAL_SECONDS,
            Math.max(wait + 5, typeof serverInterval === "number" ? serverInterval : 0),
          );
        } else if (polled.error !== "authorization_pending") {
          throw new Auth4BrowserError(
            "add_email_failed",
            polled.error === "expired_token"
              ? "The add-email request expired."
              : `Adding an email address failed with HTTP ${polled.status}.`,
          );
        } else if (windowClosed) {
          // The window was closed before the player finished, so nothing more can happen.
          throw new Auth4BrowserError("window_closed", "The add-email window was closed.");
        }
        if (this.currentTime() >= deadline) {
          throw new Auth4BrowserError("add_email_failed", "The add-email request expired.");
        }
      }
    } catch (cause) {
      try {
        popup.close();
      } catch {
        // Already closed.
      }
      const cancelled = fromAbort(cause, signal);
      if (cancelled) throw cancelled;
      if (cause instanceof Auth4BrowserError) throw cause;
      throw new Auth4BrowserError("add_email_failed", "Unable to add an email address.", cause);
    }
  }

  /** JSON POST to the tenant's add-email endpoints, without cookies. */
  private async addEmailRequest(
    path: string,
    body: Record<string, string>,
    signal?: AbortSignal,
    accessToken?: string,
  ): Promise<{ ok: boolean; status: number; error: string; body: Record<string, unknown> }> {
    const response = await this.fetcher(`${this.options.issuer}${path}`, {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
        ...(accessToken === undefined ? {} : { Authorization: `Bearer ${accessToken}` }),
      },
      body: JSON.stringify(body),
      credentials: "omit",
      cache: "no-store",
      ...(signal === undefined ? {} : { signal }),
    });
    let raw: unknown = null;
    try {
      raw = await response.json();
    } catch {
      // A non-JSON body is reported by its status only.
    }
    const record = asRecord(raw) ?? {};
    const error = record["error"];
    return {
      ok: response.ok,
      status: response.status,
      error: typeof error === "string" ? error.slice(0, 64) : "",
      body: record,
    };
  }

  /** Validate the refreshed session and swap the in-memory token set in one synchronous step. */
  private completeAddEmail(
    raw: Record<string, unknown>,
    generation: number,
    subject: string,
  ): AddEmailResult {
    if (generation !== this.#generation || this.activeTokens?.user.sub !== subject) {
      throw new Auth4BrowserError(
        "invalid_session",
        "The local session changed while adding an email address; sign in again.",
      );
    }
    const { tokens, record } = readGuestTokenSet(raw, "add_email_failed", subject);
    const identity = asRecord(record["identity"]);
    const identityId = identity?.["identity_id"];
    const email = record["email"];
    if (
      typeof identityId !== "string" ||
      identity?.["provider"] !== "email" ||
      typeof email !== "string" ||
      email.length === 0 ||
      email.length > 320
    ) {
      throw new Auth4BrowserError("add_email_failed", "The add-email result is invalid.");
    }
    const session = this.startSession(
      tokens,
      { sub: subject, email, email_verified: true },
      this.activeTokens.nonce,
    );
    this.emit({ type: "email_added", session });
    return { session, email, identity: { identityId, provider: "email" } };
  }

  /**
   * Replace every in-memory credential at once. Bumping the generation (in clearSession) makes any
   * renewal still in flight for the previous token set discard its result.
   */
  private startSession(tokens: ParsedTokenSet, user: BrowserUser, nonce: string): BrowserSession {
    const issuedAt = this.currentTime();
    const expiresAt = issuedAt + tokens.expiresIn * 1_000;
    // Without the refresh opt-in any refresh token is dropped here and never retained.
    const refreshToken = this.options.refresh === true ? tokens.refreshToken : undefined;
    const next: ActiveTokens = {
      accessToken: tokens.accessToken,
      user,
      expiresAt,
      renewAt: refreshToken === undefined ? expiresAt : renewalTime(issuedAt, expiresAt),
      nonce,
      isGuest: isGuestAccessToken(tokens.accessToken),
    };
    this.clearSession();
    this.activeTokens = next;
    this.#refreshToken = refreshToken;
    this.scheduleRenewal();
    return this.sessionOf(next);
  }

  private sessionOf(active: ActiveTokens): BrowserSession {
    return { user: active.user, expiresAt: active.expiresAt, isGuest: active.isGuest };
  }

  /** Single-flight renewal: every caller during a refresh awaits the same request. */
  private renew(): Promise<void> {
    if (this.#refreshing) return this.#refreshing;
    const pending = this.performRefresh().finally(() => {
      if (this.#refreshing === pending) this.#refreshing = undefined;
    });
    this.#refreshing = pending;
    return pending;
  }

  private async performRefresh(): Promise<void> {
    const generation = this.#generation;
    const active = this.activeTokens;
    const refreshToken = this.#refreshToken;
    if (!active || refreshToken === undefined) {
      throw new Auth4BrowserError("refresh_failed", "No refreshable browser session is active.");
    }
    const superseded = () =>
      new Auth4BrowserError("refresh_failed", "The browser session changed during renewal.");

    let discovery: DiscoveryDocument;
    let response: Response;
    try {
      discovery = await this.discover();
      response = await this.fetcher(discovery.token_endpoint, {
        method: "POST",
        headers: {
          Accept: "application/json",
          "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",
        },
        body: new URLSearchParams({
          grant_type: "refresh_token",
          refresh_token: refreshToken,
          client_id: this.options.clientId,
        }).toString(),
        cache: "no-store",
      });
    } catch (cause) {
      if (generation !== this.#generation) throw superseded();
      this.scheduleRetry();
      throw new Auth4BrowserError("refresh_failed", "Unable to reach the token endpoint.", cause);
    }
    if (generation !== this.#generation) throw superseded();
    if (response.status >= 500 || response.status === 429) {
      this.scheduleRetry();
      throw new Auth4BrowserError(
        "refresh_failed",
        `Token refresh returned HTTP ${response.status}; it will be retried.`,
      );
    }

    // From here the presented refresh token is spent, so every failure ends the session: a
    // rejected grant (invalid_grant after reuse, revocation or expiry; unauthorized_client after an
    // opt-out) or a response that cannot be trusted.
    try {
      if (!response.ok) {
        throw new Auth4BrowserError(
          "refresh_failed",
          `Token refresh was rejected with HTTP ${response.status}; sign in again.`,
        );
      }
      const tokens = await readTokenSet(response, "refresh_failed", false);
      if (tokens.idToken !== undefined) {
        const claims = await this.validateIdToken(
          tokens.idToken,
          active.nonce,
          discovery,
          undefined,
          true,
        );
        if (claims.sub !== active.user.sub) {
          throw new Auth4BrowserError("refresh_failed", "Renewed ID token is for another user.");
        }
      }
      if (generation !== this.#generation) throw superseded();
      const issuedAt = this.currentTime();
      const expiresAt = issuedAt + tokens.expiresIn * 1_000;
      const renewed: ActiveTokens = {
        ...active,
        accessToken: tokens.accessToken,
        expiresAt,
        renewAt: tokens.refreshToken === undefined ? expiresAt : renewalTime(issuedAt, expiresAt),
        isGuest: isGuestAccessToken(tokens.accessToken),
      };
      this.activeTokens = renewed;
      this.#refreshToken = tokens.refreshToken;
      this.scheduleRenewal();
      this.emit({ type: "renewed", session: this.sessionOf(renewed) });
    } catch (cause) {
      if (generation !== this.#generation) throw superseded();
      this.clearSession();
      this.emit({ type: "signed_out", reason: "refresh_rejected" });
      if (cause instanceof Auth4BrowserError && cause.code === "refresh_failed") throw cause;
      throw new Auth4BrowserError("refresh_failed", "Token refresh failed; sign in again.", cause);
    }
  }

  private scheduleRenewal(): void {
    this.cancelRenewal();
    const active = this.activeTokens;
    if (!active || this.#refreshToken === undefined) return;
    this.startTimer(Math.max(0, active.renewAt - this.currentTime()));
  }

  /** Retry a transiently failed renewal while the current access token is still valid. */
  private scheduleRetry(): void {
    this.cancelRenewal();
    const active = this.activeTokens;
    if (!active || this.#refreshToken === undefined) return;
    const remaining = active.expiresAt - this.currentTime();
    if (remaining <= 0) return;
    this.startTimer(Math.min(RENEW_RETRY_MS, Math.max(1_000, remaining / 2)));
  }

  private startTimer(delay: number): void {
    const generation = this.#generation;
    this.#renewTimer = setTimeout(() => {
      this.#renewTimer = undefined;
      if (generation === this.#generation) void this.renew().catch(() => undefined);
    }, delay);
  }

  private cancelRenewal(): void {
    if (this.#renewTimer !== undefined) clearTimeout(this.#renewTimer);
    this.#renewTimer = undefined;
  }

  /** Forget every credential and invalidate any refresh still in flight. */
  private clearSession(): void {
    this.#generation += 1;
    this.cancelRenewal();
    this.activeTokens = undefined;
    this.#refreshToken = undefined;
    this.#refreshing = undefined;
  }

  private emit(event: BrowserSessionEvent): void {
    for (const listener of [...this.#listeners]) {
      try {
        listener(event);
      } catch {
        // Application listeners cannot break session handling.
      }
    }
  }

  private async validateIdToken(
    token: string,
    expectedNonce: string,
    discovery: DiscoveryDocument,
    signal?: AbortSignal,
    /** Refresh responses may omit the nonce; when present it must still match the sign-in. */
    nonceOptional = false,
  ): Promise<VerifiedIdClaims> {
    try {
      const [encodedHeader, encodedClaims, encodedSignature] = tokenParts(token);
      const header = decodeJsonSegment(encodedHeader);
      const claims = decodeJsonSegment(encodedClaims);
      if (
        header["alg"] !== "RS256" ||
        header["typ"] !== "JWT" ||
        typeof header["kid"] !== "string" ||
        header["kid"].length === 0
      ) {
        throw new Error("Unsupported ID-token algorithm or key.");
      }
      if (header["crit"] !== undefined || header["b64"] !== undefined)
        throw new Error("Unsupported critical JWT header.");

      const jwks = await this.getJwks(discovery, signal);
      const matchingKeys = jwks.keys.filter(
        (key) =>
          key.kid === header["kid"] &&
          key.kty === "RSA" &&
          (key.use === undefined || key.use === "sig") &&
          (key.alg === undefined || key.alg === "RS256"),
      );
      if (matchingKeys.length !== 1)
        throw new Error("ID-token signing key is missing or ambiguous.");
      const publicKey = await globalThis.crypto.subtle.importKey(
        "jwk",
        matchingKeys[0]!,
        { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
        false,
        ["verify"],
      );
      const signatureValid = await globalThis.crypto.subtle.verify(
        "RSASSA-PKCS1-v1_5",
        publicKey,
        decodeBase64Url(encodedSignature),
        new TextEncoder().encode(`${encodedHeader}.${encodedClaims}`),
      );
      if (!signatureValid) throw new Error("ID-token signature is invalid.");

      const tenantId = tenantIdFromIssuer(this.options.issuer);
      const audience = claims["aud"];
      const audiences = typeof audience === "string" ? [audience] : arrayOfStrings(audience);
      const nowSeconds = Math.floor(this.currentTime() / 1_000);
      const exp = claims["exp"];
      const iat = claims["iat"];
      const nbf = claims["nbf"];
      if (
        claims["iss"] !== this.options.issuer ||
        claims["tenant_id"] !== tenantId ||
        typeof claims["sub"] !== "string" ||
        claims["sub"].length === 0 ||
        claims["sub"].length > 255 ||
        !audiences?.includes(this.options.clientId) ||
        (audiences.length > 1 && claims["azp"] !== this.options.clientId) ||
        (claims["azp"] !== undefined && claims["azp"] !== this.options.clientId) ||
        claims["token_use"] !== "id" ||
        typeof claims["jti"] !== "string" ||
        claims["jti"].length === 0 ||
        typeof exp !== "number" ||
        !Number.isInteger(exp) ||
        exp <= nowSeconds ||
        typeof iat !== "number" ||
        !Number.isInteger(iat) ||
        iat <= 0 ||
        iat > nowSeconds ||
        exp <= iat ||
        exp - iat > TOKEN_LIFETIME_LIMIT_SECONDS ||
        (nbf !== undefined &&
          (typeof nbf !== "number" || !Number.isInteger(nbf) || nbf > nowSeconds)) ||
        (claims["nonce"] !== expectedNonce && !(nonceOptional && claims["nonce"] === undefined)) ||
        typeof claims["auth_time"] !== "number" ||
        !Number.isInteger(claims["auth_time"]) ||
        claims["auth_time"] <= 0 ||
        claims["auth_time"] > nowSeconds
      ) {
        throw new Error("ID-token claims are invalid.");
      }
      return { sub: claims["sub"], nonce: expectedNonce };
    } catch (cause) {
      const cancelled = fromAbort(cause, signal);
      if (cancelled) throw cancelled;
      if (cause instanceof Auth4BrowserError) throw cause;
      throw new Auth4BrowserError(
        "invalid_id_token",
        "ID token signature or claims could not be validated.",
        cause,
      );
    }
  }

  private async getJwks(
    discovery: DiscoveryDocument,
    signal?: AbortSignal,
  ): Promise<JsonWebKeySet> {
    checkAbort(signal);
    if (this.jwksCache && this.jwksCache.expiresAt > this.currentTime()) return this.jwksCache.jwks;
    let response: Response;
    try {
      response = await this.fetcher(discovery.jwks_uri, {
        method: "GET",
        headers: { Accept: "application/json" },
        cache: "no-cache",
        ...(signal === undefined ? {} : { signal }),
      });
    } catch (cause) {
      const cancelled = fromAbort(cause, signal);
      if (cancelled) throw cancelled;
      throw new Auth4BrowserError(
        "invalid_id_token",
        "Unable to load ID-token signing keys.",
        cause,
      );
    }
    if (!response.ok)
      throw new Auth4BrowserError("invalid_id_token", `JWKS returned HTTP ${response.status}.`);
    const record = asRecord(await response.json());
    if (!Array.isArray(record?.["keys"]))
      throw new Auth4BrowserError("invalid_id_token", "JWKS response is invalid.");
    const keys = record["keys"].filter((key): key is SigningJwk => {
      const jwk = asRecord(key);
      return (
        jwk?.["kty"] === "RSA" &&
        typeof jwk["kid"] === "string" &&
        typeof jwk["n"] === "string" &&
        typeof jwk["e"] === "string"
      );
    }) as SigningJwk[];
    const jwks: JsonWebKeySet = { keys };
    this.jwksCache = { jwks, expiresAt: this.currentTime() + maxAgeFromHeaders(response.headers) };
    return jwks;
  }

  private takeFlow(state: string): StoredFlow | null {
    let storage: BrowserStorage;
    try {
      storage = this.storage();
    } catch {
      return null;
    }
    const key = `${FLOW_STORAGE_PREFIX}${state}`;
    let value: string | null;
    try {
      value = storage.getItem(key);
      storage.removeItem(key);
    } catch {
      return null;
    }
    if (!value || value.length > 4_096) return null;
    try {
      const record = asRecord(JSON.parse(value));
      if (
        record?.["issuer"] !== this.options.issuer ||
        record["clientId"] !== this.options.clientId ||
        record["redirectUri"] !== this.options.redirectUri ||
        typeof record["nonce"] !== "string" ||
        !/^[A-Za-z0-9_-]{43}$/u.test(record["nonce"]) ||
        typeof record["verifier"] !== "string" ||
        !/^[A-Za-z0-9_-]{43}$/u.test(record["verifier"]) ||
        typeof record["createdAt"] !== "number" ||
        !Number.isFinite(record["createdAt"]) ||
        record["createdAt"] > this.currentTime() ||
        this.currentTime() - record["createdAt"] > FLOW_LIFETIME_MS
      ) {
        return null;
      }
      return record as unknown as StoredFlow;
    } catch {
      return null;
    }
  }

  private storage(): BrowserStorage {
    try {
      const storage = this.options.storage ?? globalThis.sessionStorage;
      if (!storage) throw new Error("sessionStorage is unavailable.");
      return storage;
    } catch (cause) {
      throw new Auth4BrowserError(
        "storage_unavailable",
        "Browser sessionStorage is unavailable.",
        cause,
      );
    }
  }

  private currentTime(): number {
    return this.options.now?.() ?? Date.now();
  }

  private validateCallbackLocation(callback: URL): void {
    const registered = new URL(this.options.redirectUri);
    if (
      callback.origin !== registered.origin ||
      callback.pathname !== registered.pathname ||
      callback.hash !== registered.hash
    ) {
      throw new Auth4BrowserError(
        "invalid_callback",
        "Callback URL does not match the configured redirect URI.",
      );
    }
    const expectedParams = [...registered.searchParams.entries()];
    const actualParams = [...callback.searchParams.entries()].filter(
      ([name]) => !(CALLBACK_PARAMETERS as readonly string[]).includes(name),
    );
    if (
      expectedParams.length !== actualParams.length ||
      expectedParams.some(([name, value], index) => {
        const actual = actualParams[index];
        return !actual || actual[0] !== name || actual[1] !== value;
      })
    ) {
      throw new Auth4BrowserError(
        "invalid_callback",
        "Callback URL contains unexpected query parameters.",
      );
    }
  }

  private currentHref(): string {
    try {
      return this.browserWindow().location.href;
    } catch (cause) {
      throw new Auth4BrowserError("invalid_callback", "Callback URL is unavailable.", cause);
    }
  }

  private replaceCallbackUrl(url: URL): void {
    const cleanUrl = cleanCallbackUrl(url);
    try {
      if (this.options.replaceUrl) {
        this.options.replaceUrl(cleanUrl);
      } else {
        this.browserWindow().history.replaceState(this.browserWindow().history.state, "", cleanUrl);
      }
    } catch {
      // Callback validation remains authoritative even when a host router owns history updates.
    }
  }

  private browserWindow(): Window {
    if (typeof window === "undefined") throw new Error("This operation requires a browser window.");
    return window;
  }
}
