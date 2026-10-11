import { z } from "zod";

/** Primitives shared by index.ts and feature contract modules; kept here to avoid import cycles. */
export const TenantIdSchema = z
  .string()
  .regex(/^ten_[A-Za-z0-9]{16,64}$/)
  .brand<"TenantId">();
export const IsoDateTimeSchema = z.string().datetime({ offset: true });

export function isSecureUrl(value: string): boolean {
  try {
    const url = new URL(value);
    const loopback = ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
    return (
      url.username === "" &&
      url.password === "" &&
      (url.protocol === "https:" || (url.protocol === "http:" && loopback))
    );
  } catch {
    return false;
  }
}

/** AUTH4D-240: values index.ts and sdk.ts both need; not re-exported from @auth4/contracts. */
export const ACCESS_TOKEN_LIFETIME_SECONDS = 300;
export const MAX_SCOPES_PER_REQUEST = 32;

export const absoluteUrl = z
  .string()
  .url()
  .refine(
    isSecureUrl,
    "URLs must use HTTPS, except for loopback HTTP, and must not contain credentials.",
  );

export function issuerMatchesTenant(issuer: string, tenantId: string): boolean {
  try {
    const url = new URL(issuer);
    return (
      isSecureUrl(issuer) &&
      url.pathname === `/t/${tenantId}` &&
      url.search === "" &&
      url.hash === ""
    );
  } catch {
    return false;
  }
}
