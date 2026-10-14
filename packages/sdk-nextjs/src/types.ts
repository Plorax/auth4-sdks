/**
 * The signed-in user as the application sees it: the subject and profile claims of the verified ID
 * token. Protocol claims (issuer, audience, nonce, lifetimes) are dropped, and tokens are never
 * part of it, so it is safe to pass to client components.
 */
export interface User {
  sub: string;
  email?: string;
  email_verified?: boolean;
  /**
   * The method used for this sign-in, such as "steam", "discord", "email" or "guest" (AUTH4D-258).
   * Later releases may add methods, so treat unknown values as valid.
   */
  idp?: string;
  [claim: string]: unknown;
}

/** What `/auth/access-token` returns when the application turns it on. */
export interface AccessTokenResponse {
  token: string;
  /** Unix time in seconds. */
  expires_at: number;
  scope?: string;
}
