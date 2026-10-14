import { z } from "zod";
import {
  ACCESS_TOKEN_LIFETIME_SECONDS,
  absoluteUrl,
  IsoDateTimeSchema,
  issuerMatchesTenant,
  MAX_SCOPES_PER_REQUEST,
  TenantIdSchema,
} from "./primitives.ts";

/*
 * AUTH4D-240: the wire shapes the published SDKs need (access-token claims and the Flows
 * call_backend request and response). @auth4/sdk-server imports only this module, and
 * scripts/sdk/build.mjs ships only this file and primitives.ts in its tarball, so it must depend on
 * nothing but zod and primitives.ts. index.ts re-exports everything here, so @auth4/contracts stays
 * the single source of truth.
 */

export { IsoDateTimeSchema, TenantIdSchema };

export const MANAGEMENT_AUDIENCE = "urn:auth4:management" as const;

export const ClientIdSchema = z
  .string()
  .regex(/^cli_[A-Za-z0-9]{16,64}$/)
  .brand<"ClientId">();
export const UserIdSchema = z
  .string()
  .regex(/^usr_[A-Za-z0-9]{16,64}$/)
  .brand<"UserId">();
export const SessionIdSchema = z
  .string()
  .regex(/^ses_[A-Za-z0-9]{16,64}$/)
  .brand<"SessionId">();

export const ScopeNameSchema = z.string().regex(/^[a-z][a-z0-9:_-]{0,63}$/);
export type ScopeName = z.infer<typeof ScopeNameSchema>;
export const ScopeListSchema = z
  .string()
  .min(1)
  .max(2_048)
  .refine((value) => {
    const scopes = value.split(" ");
    return (
      scopes.length <= MAX_SCOPES_PER_REQUEST &&
      scopes.every((scope) => ScopeNameSchema.safeParse(scope).success) &&
      new Set(scopes).size === scopes.length
    );
  }, "Scopes must be unique, space-delimited names within the configured limit.");

/**
 * AUTH4D-123: a Steam identity is keyed by SteamID64 and carries no email address. AUTH4D-146
 * adds the OpenID Connect presets. AUTH4D-145: a phone identity is keyed by its E.164 number and
 * carries no email address.
 */
export const IdentityProviderSchema = z.enum([
  "email",
  "discord",
  "guest",
  "steam",
  "google",
  "apple",
  "microsoft",
  "phone",
  // AUTH4D-147
  "epic",
  /**
   * AUTH4D-148: an enterprise single sign-on connection; the subject is `<connection id>:<the
   * provider's subject>`.
   */
  "sso",
]);

/**
 * AUTH4D-154 custom claims and player roles. Storage is migration 0018_custom_claims.sql, whose
 * CHECK constraints mirror these rules. Roles are defined per application and assigned per user;
 * the access token for an application carries only that application's roles. Metadata is per
 * user and nested under one namespaced claim, so it can never replace a protocol claim.
 */

/** Roles assigned to the subject for the token's application (`client_id`). Absent means none. */
export const ROLES_CLAIM = "auth4_roles" as const;
/** Per-user metadata object. Absent means the user has none. */
export const METADATA_CLAIM = "auth4_meta" as const;

export const CUSTOM_CLAIM_LIMITS = {
  /** Role definitions per application. */
  rolesPerApplication: 50,
  /** Roles one user can hold in one application, so in one access token. */
  rolesPerUserPerApplication: 20,
  /** Assignments one user can hold across all applications. */
  roleAssignmentsPerUser: 200,
  roleDescriptionLength: 200,
  /** UTF-8 bytes of the serialized metadata object; mirrored by the D1 CHECK. */
  metadataBytes: 2_048,
  metadataKeys: 32,
  metadataStringLength: 256,
} as const;

/**
 * Claim names a customer can never set or shadow, at the top level or as a metadata key: the
 * registered JWT and OIDC claims auth4.dev issues, its own protocol claims, and the whole
 * `auth4_` namespace.
 */
export const RESERVED_CLAIM_NAMES = [
  "iss",
  "sub",
  "aud",
  "exp",
  "iat",
  "nbf",
  "jti",
  "azp",
  "auth_time",
  "nonce",
  "acr",
  "amr",
  "sid",
  "scope",
  "client_id",
  "tenant_id",
  "token_use",
  "email",
  "email_verified",
] as const;
export const RESERVED_CLAIM_PREFIX = "auth4_" as const;

export function isReservedClaimName(name: string): boolean {
  return (
    (RESERVED_CLAIM_NAMES as readonly string[]).includes(name) ||
    name.startsWith(RESERVED_CLAIM_PREFIX)
  );
}

/** A lowercase letter, then up to 63 lowercase letters, digits, `_`, `.` or `-`. */
export const ApplicationRoleNameSchema = z.string().regex(/^[a-z][a-z0-9_.-]{0,63}$/);
export type ApplicationRoleName = z.infer<typeof ApplicationRoleNameSchema>;

/** The token claim: a sorted, duplicate-free role list for one application. */
export const RolesClaimSchema = z
  .array(ApplicationRoleNameSchema)
  .min(1)
  .max(CUSTOM_CLAIM_LIMITS.rolesPerUserPerApplication)
  .refine((roles) => new Set(roles).size === roles.length, "Roles must be unique.");

export const UserClaimMetadataKeySchema = z
  .string()
  .regex(/^[a-z][a-z0-9_]{0,39}$/)
  .refine((key) => !isReservedClaimName(key), "Metadata keys cannot use reserved claim names.");

/** Flat scalar values only, so the claim stays small and has one obvious shape in every SDK. */
export const UserClaimMetadataValueSchema = z.union([
  z.string().max(CUSTOM_CLAIM_LIMITS.metadataStringLength),
  z.number().finite(),
  z.boolean(),
  z.null(),
]);

export function metadataByteLength(value: unknown): number {
  return new TextEncoder().encode(JSON.stringify(value)).byteLength;
}

export const UserClaimMetadataSchema = z
  .record(UserClaimMetadataKeySchema, UserClaimMetadataValueSchema)
  .superRefine((metadata, ctx) => {
    if (Object.keys(metadata).length > CUSTOM_CLAIM_LIMITS.metadataKeys) {
      ctx.addIssue({
        code: "custom",
        message: `Metadata can have at most ${CUSTOM_CLAIM_LIMITS.metadataKeys} keys.`,
      });
    }
    if (metadataByteLength(metadata) > CUSTOM_CLAIM_LIMITS.metadataBytes) {
      ctx.addIssue({
        code: "custom",
        message: `Metadata can be at most ${CUSTOM_CLAIM_LIMITS.metadataBytes} bytes of JSON.`,
      });
    }
  });
export type UserClaimMetadata = z.infer<typeof UserClaimMetadataSchema>;

/** The token claim: present only when the user has at least one metadata key. */
export const MetadataClaimSchema = UserClaimMetadataSchema.refine(
  (metadata) => Object.keys(metadata).length > 0,
  "An empty metadata claim is omitted.",
);

/**
 * AUTH4D-258: the `idp` claim names the method used for this sign-in. `email` covers email codes,
 * magic links and passwords until a sign-in records which of them it was; `password` and
 * `magic_link` are reserved for that. `session` is a reused hosted-login session with no new
 * proof. A verified email step never changes it: a Steam sign-in stays `steam`.
 */
export const IdpSchema = z.enum([
  "email",
  "password",
  "magic_link",
  "passkey",
  "sms",
  "discord",
  "steam",
  "epic",
  "google",
  "apple",
  "microsoft",
  "oidc",
  "sso",
  "guest",
  "session",
]);
export type Idp = z.infer<typeof IdpSchema>;
/**
 * Token readers accept any well-formed value, so a method added later does not make older SDKs
 * refuse the token. Issuers only emit IdpSchema values.
 */
export const IdpClaimSchema = z.string().regex(/^[a-z][a-z0-9_]{1,31}$/);

export const TokenAudienceSchema = z.string().min(1).max(255);
/** Shared by access and ID tokens; index.ts extends it for IdTokenClaimsSchema. */
export const JwtBaseSchema = z
  .object({
    iss: absoluteUrl,
    sub: UserIdSchema,
    aud: TokenAudienceSchema,
    exp: z.number().int().positive(),
    iat: z.number().int().positive(),
    nbf: z.number().int().positive().optional(),
    jti: z.string().regex(/^jti_[A-Za-z0-9_-]{16,64}$/),
    tenant_id: TenantIdSchema,
  })
  .strict();

export const AccessTokenClaimsSchema = JwtBaseSchema.extend({
  token_use: z.literal("access"),
  client_id: ClientIdSchema,
  scope: ScopeListSchema,
  sid: SessionIdSchema.optional(),
  /** GUEST_CLAIM: true while the subject is an un-upgraded guest. Absent means not a guest. */
  auth4_guest: z.boolean().optional(),
  /** ROLES_CLAIM (AUTH4D-154): the subject's roles in this application. Absent means none. */
  auth4_roles: RolesClaimSchema.optional(),
  /** METADATA_CLAIM (AUTH4D-154): per-user metadata. Absent means none. */
  auth4_meta: MetadataClaimSchema.optional(),
  /** AUTH4D-258: the sign-in method (IdpSchema). ID tokens and userinfo carry it; absent is fine. */
  idp: IdpClaimSchema.optional(),
}).superRefine((claims, ctx) => {
  if (!issuerMatchesTenant(claims.iss, claims.tenant_id)) {
    ctx.addIssue({
      code: "custom",
      path: ["iss"],
      message: "Access-token issuer must match tenant_id.",
    });
  }
  if (claims.aud === MANAGEMENT_AUDIENCE) {
    ctx.addIssue({
      code: "custom",
      path: ["aud"],
      message: "Management tokens use the control-plane actor contract.",
    });
  }
  if (claims.exp <= claims.iat || claims.exp - claims.iat > ACCESS_TOKEN_LIFETIME_SECONDS) {
    ctx.addIssue({
      code: "custom",
      path: ["exp"],
      message: "Access-token lifetime must be positive and no longer than five minutes.",
    });
  }
});
export type AccessTokenClaims = z.infer<typeof AccessTokenClaimsSchema>;

/** Namespaced access-token claim marking guest subjects; never a bare `guest`. */
export const GUEST_CLAIM = "auth4_guest" as const;

/*
 * AUTH4D-158 Flows: versioned event and trigger contracts. Async events are broadcast after an
 * action commits; synchronous triggers run inside the action, after every protocol check (PKCE,
 * redirect_uri, CSRF, rate limits) and before the state change they guard. Payloads are strict and
 * carry only identifiers, the sign-in method and coarse context: never tokens, codes, proofs,
 * email addresses, IP addresses or secrets.
 */
export const FLOW_EVENT_VERSION = 1 as const;

/**
 * How the user proved who they are: an identity provider (`guest` is anonymous guest sign-in),
 * `session` when an existing hosted-login browser session was reused without a new proof, or
 * `device` when a native device received tokens after a browser approved its user code. AUTH4D-143
 * adds `passkey`: a passkey sign-in, or a passkey sign-up, on the hosted login.
 */
export const FlowMethodSchema = z.enum([
  ...IdentityProviderSchema.options,
  "passkey",
  "session",
  "device",
]);
export type FlowMethod = z.infer<typeof FlowMethodSchema>;

/** Coarse request context. Country is the edge's ISO 3166-1 alpha-2 guess, never an address. */
export const FlowContextSchema = z
  .object({
    country: z
      .string()
      .regex(/^[A-Z]{2}$/u)
      .optional(),
    provider: IdentityProviderSchema.optional(),
  })
  .strict();
export type FlowContext = z.infer<typeof FlowContextSchema>;

const flowTriggerEnvelope = {
  version: z.literal(FLOW_EVENT_VERSION),
  tenant_id: TenantIdSchema,
  method: FlowMethodSchema,
  context: FlowContextSchema,
};

export const FlowTriggerInputSchema = z.discriminatedUnion("trigger", [
  /** Before a new user is stored; there is no user id yet. */
  z
    .object({
      ...flowTriggerEnvelope,
      application_id: ClientIdSchema,
      trigger: z.literal("pre_registration"),
    })
    .strict(),
  /** After the user is authenticated and before any code or token is issued. */
  z
    .object({
      ...flowTriggerEnvelope,
      application_id: ClientIdSchema,
      trigger: z.literal("post_login"),
      user_id: UserIdSchema,
      /** AUTH4D-210: whether this sign-in created the account. */
      is_first_sign_in: z.boolean().optional(),
    })
    .strict(),
  /** Before a credential is attached to a guest; `method` is that credential's provider. */
  z
    .object({
      ...flowTriggerEnvelope,
      application_id: ClientIdSchema,
      trigger: z.literal("pre_guest_upgrade"),
      user_id: UserIdSchema,
    })
    .strict(),
  /** Before a device authorization is approved; `method` is how the approver signed in. */
  z
    .object({
      ...flowTriggerEnvelope,
      application_id: ClientIdSchema,
      trigger: z.literal("device_approval"),
      user_id: UserIdSchema,
    })
    .strict(),
  /** Before a presented refresh token is rotated; only local policy checks can run. */
  z
    .object({
      ...flowTriggerEnvelope,
      application_id: ClientIdSchema,
      trigger: z.literal("pre_refresh"),
      user_id: UserIdSchema,
    })
    .strict(),
  /** After a session has been revoked; there is no application decision to undo. */
  z
    .object({
      ...flowTriggerEnvelope,
      application_id: ClientIdSchema,
      trigger: z.literal("post_sign_out"),
      user_id: UserIdSchema,
    })
    .strict(),
  /** Before a project-level deletion request; it has no application-specific scope. */
  z
    .object({
      ...flowTriggerEnvelope,
      application_id: ClientIdSchema.nullable(),
      trigger: z.literal("pre_account_deletion"),
      user_id: UserIdSchema,
    })
    .strict(),
]);
export type FlowTriggerInput = z.infer<typeof FlowTriggerInputSchema>;

export const FlowStepIdSchema = z.string().regex(/^[a-z][a-z0-9_-]{0,31}$/u);
/** Machine-readable denial reason for traces and audit; never shown to end users. */
export const FlowReasonCodeSchema = z.string().regex(/^[a-z][a-z0-9_]{1,63}$/u);

/**
 * AUTH4D-160: the fixed messages hosted login can show for a denial. A flow picks one by key and
 * hosted login renders its own (translatable) text for it; tenants never supply message text.
 */
export const FlowDenyMessageSchema = z.enum([
  "not_allowed",
  "region_unavailable",
  "account_restricted",
  "email_unverified",
  "try_again_later",
]);
export type FlowDenyMessage = z.infer<typeof FlowDenyMessageSchema>;

export const FLOW_BACKEND_LIMITS = Object.freeze({
  minTimeoutMs: 100,
  maxTimeoutMs: 1_900,
  defaultTimeoutMs: 1_500,
  /** Response bodies above this are refused unread. */
  responseBytes: 4_096,
  /** Metadata keys one response may patch. */
  claims: 16,
});

/** Metadata keys and values a step may write into the AUTH4D-154 auth4_meta claim. */
const FlowMetadataPatchSchema = z
  .record(UserClaimMetadataKeySchema, UserClaimMetadataValueSchema)
  .refine(
    (claims) =>
      Object.keys(claims).length >= 1 && Object.keys(claims).length <= FLOW_BACKEND_LIMITS.claims,
    { message: `Patch between 1 and ${FLOW_BACKEND_LIMITS.claims} claims.` },
  );

/** What a call_backend endpoint may answer. Anything else fails the step. */
export const FlowBackendResponseSchema = z.discriminatedUnion("action", [
  z
    .object({
      action: z.literal("continue"),
      /** Merged into the user's auth4_meta metadata; null removes a key. */
      claims: FlowMetadataPatchSchema.optional(),
    })
    .strict(),
  z
    .object({
      action: z.literal("deny"),
      reason_code: FlowReasonCodeSchema,
      message: FlowDenyMessageSchema.optional(),
    })
    .strict(),
]);
export type FlowBackendResponse = z.infer<typeof FlowBackendResponseSchema>;

/*
 * AUTH4D-160 call_backend wire shapes. The request body is FlowBackendEventSchema, signed the
 * Standard Webhooks way (webhook-id, webhook-timestamp, webhook-signature: v1,<base64 HMAC-SHA256
 * of `${id}.${timestamp}.${body}`>) with the project's flows signing secret.
 */
export const FlowBackendEventSchema = z
  .object({
    type: z.literal("flow.step"),
    version: z.literal(FLOW_EVENT_VERSION),
    step: FlowStepIdSchema,
    sent_at: IsoDateTimeSchema,
    input: FlowTriggerInputSchema,
  })
  .strict();
export type FlowBackendEvent = z.infer<typeof FlowBackendEventSchema>;

/** `whsec_` plus the standard base64 of 32 random bytes. Shown once, when created or rotated. */
export const FlowSigningSecretSchema = z.string().regex(/^whsec_[A-Za-z0-9+/]{43}=$/u);
