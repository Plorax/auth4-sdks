import { createLocalJWKSet, jwtVerify, type JSONWebKeySet } from "jose";
import type { User } from "./types.ts";

/** The tenant endpoints the SDK uses, each checked to belong to the configured issuer. */
export interface Discovery {
  authorization_endpoint: string;
  token_endpoint: string;
  jwks_uri: string;
  revocation_endpoint: string;
}

export interface TokenSet {
  accessToken: string;
  expiresIn: number;
  scope?: string;
  idToken?: string;
  refreshToken?: string;
}

/** Why a token-endpoint call failed: `rejected` means the grant itself is no longer valid. */
export class TokenEndpointError extends Error {
  constructor(
    readonly kind: "rejected" | "unavailable",
    message: string,
  ) {
    super(message);
    this.name = "TokenEndpointError";
  }
}

export interface OidcSettings {
  authOrigin: string;
  tenantId: string;
  clientId: string;
  fetch: typeof fetch;
  now: () => number;
}

/** auth4.dev tokens live five minutes; anything longer is not an auth4.dev response. */
const TOKEN_LIFETIME_LIMIT_SECONDS = 300;
const DISCOVERY_CACHE_MS = 600_000;
const JWKS_CACHE_MS = 300_000;
const CLOCK_TOLERANCE_SECONDS = 30;
const PROTOCOL_CLAIMS = new Set([
  "iss",
  "aud",
  "azp",
  "exp",
  "iat",
  "nbf",
  "jti",
  "nonce",
  "at_hash",
  "c_hash",
  "sid",
  "token_use",
  "auth_time",
  "tenant_id",
]);

function asRecord(value: unknown): Record<string, unknown> | null {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

export class OidcClient {
  readonly issuer: string;
  #discovery: { value: Discovery; expiresAt: number } | undefined;
  #jwks: { value: ReturnType<typeof createLocalJWKSet>; expiresAt: number } | undefined;

  constructor(private readonly settings: OidcSettings) {
    this.issuer = `${settings.authOrigin}/t/${settings.tenantId}`;
  }

  async discover(): Promise<Discovery> {
    const cached = this.#discovery;
    if (cached && cached.expiresAt > this.settings.now()) return cached.value;
    const response = await this.settings.fetch(`${this.issuer}/.well-known/openid-configuration`, {
      headers: { Accept: "application/json" },
      cache: "no-store",
    });
    if (!response.ok) throw new Error(`Discovery returned HTTP ${response.status}.`);
    const record = asRecord(await response.json());
    if (!record || record["issuer"] !== this.issuer) {
      throw new Error("Discovery issuer does not match the configured issuer.");
    }
    const endpoint = (key: string): string => {
      const value = record[key];
      if (typeof value !== "string") throw new Error(`Discovery has no ${key}.`);
      const url = new URL(value);
      const tenantBound =
        key === "jwks_uri"
          ? url.pathname === `/t/${this.settings.tenantId}/.well-known/jwks.json`
          : url.searchParams.get("tenant_id") === this.settings.tenantId;
      if (
        url.origin !== this.settings.authOrigin ||
        url.username !== "" ||
        url.password !== "" ||
        url.hash !== "" ||
        !tenantBound
      ) {
        throw new Error(`Discovery ${key} is not on the configured issuer.`);
      }
      return url.toString();
    };
    const methods = record["code_challenge_methods_supported"];
    if (!Array.isArray(methods) || !methods.includes("S256")) {
      throw new Error("Discovery does not advertise S256 PKCE.");
    }
    const value: Discovery = {
      authorization_endpoint: endpoint("authorization_endpoint"),
      token_endpoint: endpoint("token_endpoint"),
      jwks_uri: endpoint("jwks_uri"),
      revocation_endpoint: endpoint("revocation_endpoint"),
    };
    this.#discovery = { value, expiresAt: this.settings.now() + DISCOVERY_CACHE_MS };
    return value;
  }

  async #keys(refetch: boolean): Promise<ReturnType<typeof createLocalJWKSet>> {
    const cached = this.#jwks;
    if (!refetch && cached && cached.expiresAt > this.settings.now()) return cached.value;
    const { jwks_uri } = await this.discover();
    const response = await this.settings.fetch(jwks_uri, {
      headers: { Accept: "application/json" },
      cache: "no-store",
    });
    if (!response.ok) throw new Error(`JWKS returned HTTP ${response.status}.`);
    const value = createLocalJWKSet((await response.json()) as JSONWebKeySet);
    this.#jwks = { value, expiresAt: this.settings.now() + JWKS_CACHE_MS };
    return value;
  }

  /**
   * Verifies an ID token: RS256 signature from the tenant JWKS, issuer, audience, lifetime, the
   * auth4.dev `token_use` and `tenant_id` claims, and the nonce of this sign-in. Refresh responses
   * may leave the nonce out, but one that is present must still match.
   */
  async verifyIdToken(
    idToken: string,
    expected: { nonce: string; nonceOptional?: boolean; sub?: string },
  ): Promise<{ user: User; expiresAt: number }> {
    const verify = async (refetch: boolean) =>
      jwtVerify(idToken, await this.#keys(refetch), {
        issuer: this.issuer,
        audience: this.settings.clientId,
        algorithms: ["RS256"],
        typ: "JWT",
        clockTolerance: CLOCK_TOLERANCE_SECONDS,
        requiredClaims: ["sub", "exp", "iat"],
        currentDate: new Date(this.settings.now()),
      });
    let result: Awaited<ReturnType<typeof verify>>;
    try {
      result = await verify(false);
    } catch (cause) {
      // A signing-key rotation since the last JWKS fetch: fetch once more and retry.
      if ((cause as { code?: string }).code !== "ERR_JWKS_NO_MATCHING_KEY") throw cause;
      result = await verify(true);
    }
    const claims = result.payload as Record<string, unknown>;
    const nonce = claims["nonce"];
    const sub = claims["sub"];
    const authTime = claims["auth_time"];
    const exp = claims["exp"] as number;
    const iat = claims["iat"] as number;
    if (
      claims["token_use"] !== "id" ||
      claims["tenant_id"] !== this.settings.tenantId ||
      (claims["azp"] !== undefined && claims["azp"] !== this.settings.clientId) ||
      typeof sub !== "string" ||
      sub.length === 0 ||
      (expected.sub !== undefined && sub !== expected.sub) ||
      exp - iat > TOKEN_LIFETIME_LIMIT_SECONDS ||
      (nonce === undefined ? !expected.nonceOptional : nonce !== expected.nonce) ||
      typeof authTime !== "number" ||
      !Number.isInteger(authTime)
    ) {
      throw new Error("ID-token claims are invalid.");
    }
    const user: User = { sub };
    for (const [claim, value] of Object.entries(claims)) {
      if (!PROTOCOL_CLAIMS.has(claim) && claim !== "sub") user[claim] = value;
    }
    return { user, expiresAt: exp };
  }

  async #tokenRequest(fields: Record<string, string>, requireIdToken: boolean): Promise<TokenSet> {
    const { token_endpoint } = await this.discover();
    let response: Response;
    try {
      response = await this.settings.fetch(token_endpoint, {
        method: "POST",
        headers: {
          Accept: "application/json",
          "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",
        },
        body: new URLSearchParams({ ...fields, client_id: this.settings.clientId }).toString(),
        cache: "no-store",
      });
    } catch {
      throw new TokenEndpointError("unavailable", "The token endpoint could not be reached.");
    }
    const body = asRecord(await response.json().catch(() => null));
    if (!response.ok) {
      // invalid_grant: expired, revoked or reused; the server has already ended the family.
      if (response.status === 400 && body?.["error"] === "invalid_grant") {
        throw new TokenEndpointError("rejected", "The grant was rejected.");
      }
      throw new TokenEndpointError(
        response.status >= 500 ? "unavailable" : "rejected",
        `The token endpoint returned HTTP ${response.status}.`,
      );
    }
    const accessToken = body?.["access_token"];
    const idToken = body?.["id_token"];
    const refreshToken = body?.["refresh_token"];
    const expiresIn = body?.["expires_in"];
    const scope = body?.["scope"];
    const tokenType = body?.["token_type"];
    if (
      typeof accessToken !== "string" ||
      accessToken.length === 0 ||
      typeof tokenType !== "string" ||
      tokenType.toLowerCase() !== "bearer" ||
      typeof expiresIn !== "number" ||
      !Number.isInteger(expiresIn) ||
      expiresIn <= 0 ||
      expiresIn > TOKEN_LIFETIME_LIMIT_SECONDS ||
      (requireIdToken
        ? typeof idToken !== "string"
        : !["string", "undefined"].includes(typeof idToken)) ||
      !["string", "undefined"].includes(typeof refreshToken) ||
      !["string", "undefined"].includes(typeof scope)
    ) {
      throw new TokenEndpointError(
        "unavailable",
        "The token endpoint returned an invalid token set.",
      );
    }
    return {
      accessToken,
      expiresIn,
      ...(typeof scope === "string" ? { scope } : {}),
      ...(typeof idToken === "string" ? { idToken } : {}),
      ...(typeof refreshToken === "string" ? { refreshToken } : {}),
    };
  }

  exchangeCode(code: string, redirectUri: string, verifier: string): Promise<TokenSet> {
    return this.#tokenRequest(
      {
        grant_type: "authorization_code",
        code,
        redirect_uri: redirectUri,
        code_verifier: verifier,
      },
      true,
    );
  }

  refresh(refreshToken: string): Promise<TokenSet> {
    return this.#tokenRequest({ grant_type: "refresh_token", refresh_token: refreshToken }, false);
  }

  /** RFC 7009 revocation. Revoking either token ends the auth4.dev session behind it. */
  async revoke(token: string, hint: "refresh_token" | "access_token"): Promise<boolean> {
    try {
      const { revocation_endpoint } = await this.discover();
      const response = await this.settings.fetch(revocation_endpoint, {
        method: "POST",
        headers: {
          Accept: "application/json",
          "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",
        },
        body: new URLSearchParams({
          token,
          token_type_hint: hint,
          client_id: this.settings.clientId,
        }).toString(),
        cache: "no-store",
      });
      return response.ok;
    } catch {
      return false;
    }
  }
}
