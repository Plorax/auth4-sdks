import {
  AccessTokenClaimsSchema,
  ClientIdSchema,
  GUEST_CLAIM,
  MANAGEMENT_AUDIENCE,
  METADATA_CLAIM,
  ROLES_CLAIM,
  TenantIdSchema,
  TokenAudienceSchema,
  type AccessTokenClaims,
  type UserClaimMetadata,
} from "@auth4/contracts/sdk";
import { decodeProtectedHeader, importJWK, jwtVerify } from "jose";
import type { JWK } from "jose";

const MAX_JWKS_BYTES = 256 * 1024;
const MAX_JWKS_KEYS = 64;
const MAX_TOKEN_LENGTH = 16_384;
const MIN_CACHE_TTL_MS = 10_000;
const MAX_CACHE_TTL_MS = 3_600_000;
const MIN_REFRESH_COOLDOWN_MS = 1_000;
const MAX_REFRESH_COOLDOWN_MS = 600_000;
const MIN_FETCH_TIMEOUT_MS = 10;
const MAX_FETCH_TIMEOUT_MS = 10_000;
const MAX_INTROSPECTION_CACHE_TTL_MS = 60_000;
const MAX_INTROSPECTION_CACHE_ENTRIES = 10_000;
const PRIVATE_RSA_PARAMETERS = ["d", "p", "q", "dp", "dq", "qi", "oth"] as const;

export interface ServerClientOptions {
  tenantId: string;
  /** Trusted, configured tenant issuer. Must be `{origin}/t/{tenantId}`. */
  issuer: string;
  /** The API/resource audience accepted by the protected server. */
  audience: string;
  /** Injectable for tests and custom runtimes. It is always called with the configured JWKS URL. */
  fetcher?: typeof fetch;
  jwksCacheTtlMs?: number;
  jwksRefreshCooldownMs?: number;
  jwksFetchTimeoutMs?: number;
  clockToleranceSeconds?: number;
  /** Injectable epoch clock, primarily for deterministic tests. */
  now?: () => number;
  /**
   * AUTH4D-155: opt in to a live revocation check. After local verification succeeds, the token is
   * also sent to the tenant's introspection endpoint, so a revoked session is refused within
   * `cacheTtlMs` instead of up to five minutes later. Off by default.
   */
  introspection?: IntrospectionOptions;
}

/** Confidential server client credentials and cache settings for introspect mode. */
export interface IntrospectionOptions {
  clientId: string;
  /** Keep this in a secret store. The SDK never exposes, logs or serializes it. */
  clientSecret: string;
  /** How long an active answer is reused for the same token. Default 5000; 0 disables caching. */
  cacheTtlMs?: number;
  introspectionTimeoutMs?: number;
}

/** Claims from a verified access token, using the protocol's wire names. */
export type VerifiedAccessTokenClaims = AccessTokenClaims & {
  /**
   * True only when the signed `auth4_guest` claim is true (AUTH4D-64). The claim is re-evaluated
   * on every issuance, so it becomes false on the first token issued after a guest upgrades.
   * Tokens without the claim, including those issued before it existed, are not guests.
   */
  isGuest: boolean;
  /**
   * The subject's roles in the token's application, from the signed `auth4_roles` claim
   * (AUTH4D-154). Empty when the claim is absent. Roles are re-read on every issuance, so a change
   * made in the console reaches the next token, at the latest after one five-minute lifetime.
   */
  roles: readonly string[];
  /** The signed `auth4_meta` claim: flat per-user metadata. Empty when the claim is absent. */
  metadata: Readonly<UserClaimMetadata>;
};

export type Auth4Subject = Pick<VerifiedAccessTokenClaims, "sub" | "tenant_id">;
export type Auth4ClientClaims = Pick<VerifiedAccessTokenClaims, "client_id" | "aud">;
export type Auth4SessionClaims = Pick<VerifiedAccessTokenClaims, "sid">;
export type Auth4GuestClaims = Pick<VerifiedAccessTokenClaims, "isGuest">;
export type Auth4RoleClaims = Pick<VerifiedAccessTokenClaims, "roles">;
export type Auth4MetadataClaims = Pick<VerifiedAccessTokenClaims, "metadata">;

/** True when verified claims include `role` for the token's application. Exact, case-sensitive. */
export function hasRole(claims: Auth4RoleClaims, role: string): boolean {
  return claims.roles.includes(role);
}

/** True when verified claims include at least one of `roles`. An empty list never matches. */
export function hasAnyRole(claims: Auth4RoleClaims, roles: readonly string[]): boolean {
  return roles.some((role) => claims.roles.includes(role));
}

export type TokenVerificationErrorCode =
  "invalid_token" | "jwks_unavailable" | "jwks_refresh_limited" | "introspection_unavailable";

export class TokenVerificationError extends Error {
  readonly code: TokenVerificationErrorCode;

  constructor(code: TokenVerificationErrorCode, message: string, options?: ErrorOptions) {
    super(message, options);
    this.code = code;
    this.name = "TokenVerificationError";
  }
}

type ImportedKey = Awaited<ReturnType<typeof importJWK>>;
interface CachedJwks {
  readonly keys: ReadonlyMap<string, ImportedKey>;
  readonly expiresAt: number;
}

function boundedInteger(
  name: string,
  value: number | undefined,
  fallback: number,
  minimum: number,
  maximum: number,
): number {
  const result = value ?? fallback;
  if (!Number.isInteger(result) || result < minimum || result > maximum) {
    throw new TypeError(`${name} must be an integer from ${minimum} to ${maximum}.`);
  }
  return result;
}

function validateIssuer(tenantId: string, issuer: string): string {
  const parsedTenantId = TenantIdSchema.parse(tenantId);
  let url: URL;
  try {
    url = new URL(issuer);
  } catch (cause) {
    throw new TypeError("issuer must be a valid absolute URL.", { cause });
  }

  const loopback = ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
  const secure = url.protocol === "https:" || (url.protocol === "http:" && loopback);
  if (
    !secure ||
    url.username !== "" ||
    url.password !== "" ||
    url.pathname !== `/t/${parsedTenantId}` ||
    url.search !== "" ||
    url.hash !== "" ||
    url.toString() !== issuer
  ) {
    throw new TypeError("issuer must be the canonical issuer URL for tenantId.");
  }
  return issuer;
}

function deriveJwksUrl(issuer: string): string {
  const url = new URL(`${issuer}/.well-known/jwks.json`);
  // No token-supplied issuer, jku, or x5u value is ever used to construct this URL.
  return url.toString();
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isPublicRs256Jwk(value: unknown): value is JWK & { kid: string; kty: "RSA" } {
  if (!isRecord(value)) return false;
  if (
    value["kty"] !== "RSA" ||
    typeof value["kid"] !== "string" ||
    value["kid"].length < 1 ||
    value["kid"].length > 128 ||
    typeof value["n"] !== "string" ||
    typeof value["e"] !== "string" ||
    (value["alg"] !== undefined && value["alg"] !== "RS256") ||
    (value["use"] !== undefined && value["use"] !== "sig") ||
    (value["key_ops"] !== undefined &&
      (!Array.isArray(value["key_ops"]) || !value["key_ops"].includes("verify")))
  ) {
    return false;
  }
  return PRIVATE_RSA_PARAMETERS.every((parameter) => value[parameter] === undefined);
}

async function readBoundedJson(response: Response): Promise<unknown> {
  const contentLength = response.headers.get("content-length");
  if (contentLength !== null && Number(contentLength) > MAX_JWKS_BYTES) {
    throw new Error("JWKS response exceeded its size limit.");
  }

  if (!response.body) return {};
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > MAX_JWKS_BYTES) {
        await reader.cancel();
        throw new Error("JWKS response exceeded its size limit.");
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }

  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return JSON.parse(new TextDecoder().decode(bytes)) as unknown;
}

interface IntrospectionSettings {
  readonly url: string;
  readonly authorization: string;
  readonly cacheTtlMs: number;
  readonly timeoutMs: number;
}

function introspectionSettings(
  issuer: string,
  tenantId: string,
  options: IntrospectionOptions,
): IntrospectionSettings {
  const clientId = ClientIdSchema.parse(options.clientId);
  if (
    typeof options.clientSecret !== "string" ||
    options.clientSecret.length < 32 ||
    options.clientSecret.length > 512
  ) {
    throw new TypeError("introspection.clientSecret must be the server client's secret.");
  }
  // Like the JWKS URL, the endpoint comes only from the configured issuer, never from a token.
  const url = new URL("/oauth/introspect", new URL(issuer).origin);
  url.searchParams.set("tenant_id", tenantId);
  // RFC 6749 section 2.3.1: form-encode each part before Basic encoding.
  const credentials = `${encodeURIComponent(clientId)}:${encodeURIComponent(options.clientSecret)}`;
  return {
    url: url.toString(),
    authorization: `Basic ${btoa(credentials)}`,
    cacheTtlMs: boundedInteger(
      "introspection.cacheTtlMs",
      options.cacheTtlMs,
      5_000,
      0,
      MAX_INTROSPECTION_CACHE_TTL_MS,
    ),
    timeoutMs: boundedInteger(
      "introspection.introspectionTimeoutMs",
      options.introspectionTimeoutMs,
      3_000,
      MIN_FETCH_TIMEOUT_MS,
      MAX_FETCH_TIMEOUT_MS,
    ),
  };
}

async function sha256(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function invalidToken(cause?: unknown): TokenVerificationError {
  return new TokenVerificationError("invalid_token", "The access token is invalid.", {
    cause,
  });
}

/**
 * Verifies Auth4 access tokens for one configured tenant and resource audience.
 * JWKS is fetched only from the URL derived from the configured issuer.
 */
export class Auth4ServerClient {
  readonly options: ServerClientOptions;
  readonly tenantId: string;
  readonly issuer: string;
  readonly audience: string;
  readonly jwksUrl: string;
  /** The endpoint introspect mode calls, derived from the configured issuer; undefined when off. */
  readonly introspectionUrl: string | undefined;

  private readonly fetcher: typeof fetch;
  private readonly cacheTtlMs: number;
  private readonly refreshCooldownMs: number;
  private readonly fetchTimeoutMs: number;
  private readonly clockToleranceSeconds: number;
  private readonly now: () => number;
  private cachedJwks: CachedJwks | undefined;
  private refreshPromise: Promise<void> | undefined;
  private lastFetchAttemptAt = Number.NEGATIVE_INFINITY;
  private lastUnknownKidRefreshAt = Number.NEGATIVE_INFINITY;
  /** Introspect mode only. A private field, so the credentials never appear in `options` or JSON. */
  readonly #introspection: IntrospectionSettings | undefined;
  private readonly introspectionCache = new Map<string, { active: boolean; expiresAt: number }>();
  private readonly introspectionRequests = new Map<string, Promise<Record<string, unknown>>>();

  constructor(options: ServerClientOptions) {
    // `options` keeps everything except the introspection credentials.
    const { introspection, ...publicOptions } = options;
    this.options = publicOptions;
    this.tenantId = TenantIdSchema.parse(options.tenantId);
    this.issuer = validateIssuer(this.tenantId, options.issuer);
    this.audience = TokenAudienceSchema.parse(options.audience);
    if (this.audience === MANAGEMENT_AUDIENCE) {
      throw new TypeError("Customer server clients cannot use the management audience.");
    }
    this.jwksUrl = deriveJwksUrl(this.issuer);
    this.fetcher = options.fetcher ?? fetch;
    this.cacheTtlMs = boundedInteger(
      "jwksCacheTtlMs",
      options.jwksCacheTtlMs,
      300_000,
      MIN_CACHE_TTL_MS,
      MAX_CACHE_TTL_MS,
    );
    this.refreshCooldownMs = boundedInteger(
      "jwksRefreshCooldownMs",
      options.jwksRefreshCooldownMs,
      30_000,
      MIN_REFRESH_COOLDOWN_MS,
      MAX_REFRESH_COOLDOWN_MS,
    );
    this.fetchTimeoutMs = boundedInteger(
      "jwksFetchTimeoutMs",
      options.jwksFetchTimeoutMs,
      3_000,
      MIN_FETCH_TIMEOUT_MS,
      MAX_FETCH_TIMEOUT_MS,
    );
    this.clockToleranceSeconds = boundedInteger(
      "clockToleranceSeconds",
      options.clockToleranceSeconds,
      0,
      0,
      60,
    );
    this.now = options.now ?? Date.now;
    this.#introspection = introspection
      ? introspectionSettings(this.issuer, this.tenantId, introspection)
      : undefined;
    this.introspectionUrl = this.#introspection?.url;
  }

  /** Compatibility-friendly name for server request handlers. */
  async validateAccessToken(token: string): Promise<VerifiedAccessTokenClaims> {
    if (typeof token !== "string" || token.length === 0 || token.length > MAX_TOKEN_LENGTH) {
      throw invalidToken();
    }

    let header: ReturnType<typeof decodeProtectedHeader>;
    try {
      header = decodeProtectedHeader(token);
    } catch (cause) {
      throw invalidToken(cause);
    }
    if (
      header.alg !== "RS256" ||
      typeof header.kid !== "string" ||
      header.kid.length < 1 ||
      header.kid.length > 128 ||
      "jku" in header ||
      "x5u" in header ||
      "jwk" in header
    ) {
      throw invalidToken();
    }

    const key = await this.getKey(header.kid);
    if (!key) throw invalidToken();

    let verified: VerifiedAccessTokenClaims;
    try {
      const { payload } = await jwtVerify(token, key, {
        issuer: this.issuer,
        audience: this.audience,
        algorithms: ["RS256"],
        requiredClaims: [
          "iss",
          "sub",
          "aud",
          "exp",
          "iat",
          "jti",
          "tenant_id",
          "token_use",
          "client_id",
          "scope",
        ],
        clockTolerance: this.clockToleranceSeconds,
        currentDate: new Date(this.now()),
      });

      // The contract schema rejects a non-boolean `auth4_guest` and malformed `auth4_roles` or
      // `auth4_meta`; absent claims mean not a guest, no roles and no metadata.
      const claims = AccessTokenClaimsSchema.safeParse(payload);
      if (!claims.success || claims.data.tenant_id !== this.tenantId) throw invalidToken();
      verified = {
        ...claims.data,
        isGuest: claims.data[GUEST_CLAIM] === true,
        roles: Object.freeze([...(claims.data[ROLES_CLAIM] ?? [])]),
        metadata: Object.freeze({ ...claims.data[METADATA_CLAIM] }),
      };
    } catch (cause) {
      if (cause instanceof TokenVerificationError) throw cause;
      throw invalidToken(cause);
    }
    if (this.#introspection) await this.assertActive(token, verified, this.#introspection);
    return verified;
  }

  /** Introspect mode: only a live session passes. Unreachable or unexpected answers fail closed. */
  private async assertActive(
    token: string,
    claims: VerifiedAccessTokenClaims,
    settings: IntrospectionSettings,
  ): Promise<void> {
    const cacheKey = await sha256(token);
    const now = this.now();
    const cached = this.introspectionCache.get(cacheKey);
    if (cached && cached.expiresAt > now) {
      if (!cached.active) throw invalidToken();
      return;
    }
    this.introspectionCache.delete(cacheKey);

    let pending = this.introspectionRequests.get(cacheKey);
    if (!pending) {
      pending = this.introspect(token, settings).finally(() => {
        this.introspectionRequests.delete(cacheKey);
      });
      this.introspectionRequests.set(cacheKey, pending);
    }
    const body = await pending;
    if (typeof body["active"] !== "boolean") {
      throw new TokenVerificationError(
        "introspection_unavailable",
        "The introspection response was not understood.",
      );
    }
    const active = body["active"];
    if (
      active &&
      (body["sub"] !== claims.sub ||
        body["client_id"] !== claims.client_id ||
        body["jti"] !== claims.jti ||
        body["tenant_id"] !== this.tenantId)
    ) {
      throw invalidToken();
    }
    // A revoked session never comes back, so an inactive answer is kept until the token expires.
    const tokenExpiresAt = claims.exp * 1_000;
    const expiresAt = active ? Math.min(now + settings.cacheTtlMs, tokenExpiresAt) : tokenExpiresAt;
    if (expiresAt > now && (settings.cacheTtlMs > 0 || !active)) {
      if (this.introspectionCache.size >= MAX_INTROSPECTION_CACHE_ENTRIES) {
        const oldest = this.introspectionCache.keys().next();
        if (!oldest.done) this.introspectionCache.delete(oldest.value);
      }
      this.introspectionCache.set(cacheKey, { active, expiresAt });
    }
    if (!active) throw invalidToken();
  }

  private async introspect(
    token: string,
    settings: IntrospectionSettings,
  ): Promise<Record<string, unknown>> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), settings.timeoutMs);
    try {
      const response = await this.fetcher(settings.url, {
        method: "POST",
        headers: {
          accept: "application/json",
          authorization: settings.authorization,
          "content-type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({ token }).toString(),
        redirect: "error",
        signal: controller.signal,
      });
      if (!response.ok) throw new Error(`Introspection returned HTTP ${response.status}.`);
      const body: unknown = await readBoundedJson(response);
      if (!isRecord(body)) throw new Error("Introspection returned a non-object body.");
      return body;
    } catch (cause) {
      throw new TokenVerificationError(
        "introspection_unavailable",
        "The token's session could not be checked with the configured issuer.",
        { cause },
      );
    } finally {
      clearTimeout(timeout);
    }
  }

  /** Verifies an Authorization header value and rejects absent or malformed Bearer credentials. */
  async validateAuthorizationHeader(
    header: string | null | undefined,
  ): Promise<VerifiedAccessTokenClaims> {
    const token = parseBearerToken(header);
    if (!token) throw invalidToken();
    return this.validateAccessToken(token);
  }

  private async getKey(kid: string): Promise<ImportedKey | undefined> {
    const now = this.now();
    const cached = this.cachedJwks;
    if (cached && cached.expiresAt > now) {
      const existing = cached.keys.get(kid);
      if (existing) return existing;
      await this.refreshJwks("unknown-kid");
    } else {
      await this.refreshJwks("expired");
    }
    return this.cachedJwks?.keys.get(kid);
  }

  private async refreshJwks(reason: "unknown-kid" | "expired"): Promise<void> {
    if (this.refreshPromise) return this.refreshPromise;
    const now = this.now();
    if (reason === "unknown-kid") {
      if (now - this.lastUnknownKidRefreshAt < this.refreshCooldownMs) {
        throw new TokenVerificationError(
          "jwks_refresh_limited",
          "A signing-key refresh was recently attempted.",
        );
      }
      this.lastUnknownKidRefreshAt = now;
    } else if (now - this.lastFetchAttemptAt < this.refreshCooldownMs) {
      throw new TokenVerificationError(
        "jwks_refresh_limited",
        "A signing-key refresh was recently attempted.",
      );
    }

    this.lastFetchAttemptAt = now;
    this.refreshPromise = this.fetchJwks();
    try {
      await this.refreshPromise;
    } finally {
      this.refreshPromise = undefined;
    }
  }

  private async fetchJwks(): Promise<void> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.fetchTimeoutMs);
    try {
      const response = await this.fetcher(this.jwksUrl, {
        method: "GET",
        headers: { accept: "application/jwk-set+json, application/json" },
        redirect: "error",
        signal: controller.signal,
      });
      if (!response.ok) throw new Error(`JWKS endpoint returned HTTP ${response.status}.`);
      const body: unknown = await readBoundedJson(response);
      if (!isRecord(body) || !Array.isArray(body["keys"]) || body["keys"].length > MAX_JWKS_KEYS) {
        throw new Error("JWKS response has an invalid or oversized key set.");
      }

      const keys = new Map<string, ImportedKey>();
      for (const candidate of body["keys"]) {
        if (!isPublicRs256Jwk(candidate)) continue;
        if (keys.has(candidate.kid)) throw new Error("JWKS contains duplicate key IDs.");
        keys.set(candidate.kid, await importJWK(candidate, "RS256"));
      }
      if (keys.size === 0) throw new Error("JWKS contains no usable RS256 public keys.");
      this.cachedJwks = { keys, expiresAt: this.now() + this.cacheTtlMs };
    } catch (cause) {
      throw new TokenVerificationError(
        "jwks_unavailable",
        "Signing keys could not be refreshed from the configured issuer.",
        { cause },
      );
    } finally {
      clearTimeout(timeout);
    }
  }
}

/** Parses a single RFC 6750-style Bearer credential. It does not validate the token. */
export function parseBearerToken(header: string | null | undefined): string | null {
  if (typeof header !== "string" || header.length > MAX_TOKEN_LENGTH + 16) return null;
  const match = /^Bearer ([^\s,]+)$/iu.exec(header);
  return match?.[1] ?? null;
}

export function unauthorizedResponse(): Response {
  return Response.json(
    { error: "unauthorized" },
    { status: 401, headers: { "www-authenticate": 'Bearer realm="auth4"' } },
  );
}

/** Framework-neutral Request adapter; invalid or unavailable credentials fail closed as 401. */
export async function authenticateRequest(
  request: Request,
  client: Auth4ServerClient,
): Promise<VerifiedAccessTokenClaims | null> {
  const token = parseBearerToken(request.headers.get("authorization"));
  if (!token) return null;
  try {
    return await client.validateAccessToken(token);
  } catch {
    return null;
  }
}

interface HonoAuthContext {
  req: { header(name: string): string | undefined };
  header(name: string, value: string): void;
  set(key: "auth4Auth", value: VerifiedAccessTokenClaims): void;
  json(body: { error: "unauthorized" }, status: 401): Response;
}

/** Structural Hono adapter, avoiding a runtime Hono dependency in framework-neutral SDK users. */
export function honoBearerAuth(client: Auth4ServerClient) {
  return async (context: HonoAuthContext, next: () => Promise<void>): Promise<Response | void> => {
    const token = parseBearerToken(context.req.header("authorization"));
    if (!token) {
      context.header("WWW-Authenticate", 'Bearer realm="auth4"');
      return context.json({ error: "unauthorized" }, 401);
    }
    let claims: VerifiedAccessTokenClaims;
    try {
      claims = await client.validateAccessToken(token);
    } catch {
      context.header("WWW-Authenticate", 'Bearer realm="auth4"');
      return context.json({ error: "unauthorized" }, 401);
    }
    context.set("auth4Auth", claims);
    await next();
  };
}

export * from "./flows.js";
