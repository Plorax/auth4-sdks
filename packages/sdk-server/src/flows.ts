import {
  FlowBackendEventSchema,
  FlowBackendResponseSchema,
  FlowSigningSecretSchema,
  type FlowBackendEvent,
  type FlowBackendResponse,
} from "@auth4/contracts/sdk";

// AUTH4D-163: helpers for a call_backend endpoint. auth4.dev signs each flow step request the
// Standard Webhooks way (webhook-id, webhook-timestamp, webhook-signature) with the project's
// flows signing secret; these check the signature over the raw body before anything is parsed.

const DEFAULT_TOLERANCE_SECONDS = 300;
const MAX_TOLERANCE_SECONDS = 3_600;
/** Flow step events are a few hundred bytes; anything far larger is refused unread. */
const MAX_EVENT_BYTES = 16_384;
const MAX_SIGNATURE_HEADER_LENGTH = 1_024;

export interface FlowStepVerifyOptions {
  /** The project's flows signing secret, `whsec_…`. Keep it in your server's secret store. */
  secret: string;
  /** Accepted clock difference in seconds, either way. Default 300, at most 3600. */
  toleranceSeconds?: number;
  /** Current time in milliseconds, for tests. */
  now?: () => number;
}

export interface VerifiedFlowStep {
  /** `webhook-id`, unique per call. Store it if you want to refuse repeats. */
  id: string;
  /** `webhook-timestamp`, Unix seconds. */
  timestamp: number;
  event: FlowBackendEvent;
}

export type FlowStepVerificationErrorCode =
  "missing_headers" | "stale_timestamp" | "invalid_signature" | "invalid_body";

export class FlowStepVerificationError extends Error {
  readonly code: FlowStepVerificationErrorCode;

  constructor(code: FlowStepVerificationErrorCode, message: string) {
    super(message);
    this.name = "FlowStepVerificationError";
    this.code = code;
  }
}

type HeaderSource = Headers | Record<string, string | string[] | undefined>;

function header(headers: HeaderSource, name: string): string | null {
  if (headers instanceof Headers) return headers.get(name);
  const value = headers[name] ?? headers[name.toLowerCase()];
  return typeof value === "string" ? value : null;
}

function decodeBase64(value: string): Uint8Array<ArrayBuffer> | null {
  if (!/^[A-Za-z0-9+/]+={0,2}$/u.test(value)) return null;
  try {
    return Uint8Array.from(atob(value), (char) => char.charCodeAt(0));
  } catch {
    return null;
  }
}

function signingKey(secret: string): Promise<CryptoKey> {
  if (!FlowSigningSecretSchema.safeParse(secret).success) {
    throw new TypeError("secret must be the project's whsec_… flows signing secret.");
  }
  const raw = decodeBase64(secret.slice("whsec_".length))!;
  return crypto.subtle.importKey("raw", raw, { name: "HMAC", hash: "SHA-256" }, false, ["verify"]);
}

/**
 * Checks a call_backend request given its raw body and headers. Throws FlowStepVerificationError
 * when the request is not a fresh, correctly signed flow step event; answer it with 401.
 */
export async function verifyFlowStepSignature(
  rawBody: string,
  headers: HeaderSource,
  options: FlowStepVerifyOptions,
): Promise<VerifiedFlowStep> {
  const key = await signingKey(options.secret);
  const tolerance = Math.min(
    Math.max(options.toleranceSeconds ?? DEFAULT_TOLERANCE_SECONDS, 0),
    MAX_TOLERANCE_SECONDS,
  );
  const id = header(headers, "webhook-id");
  const timestampText = header(headers, "webhook-timestamp");
  const signatures = header(headers, "webhook-signature");
  if (!id || !timestampText || !signatures || signatures.length > MAX_SIGNATURE_HEADER_LENGTH) {
    throw new FlowStepVerificationError("missing_headers", "The signature headers are missing.");
  }
  if (!/^\d{1,12}$/u.test(timestampText)) {
    throw new FlowStepVerificationError("stale_timestamp", "The timestamp is not valid.");
  }
  const timestamp = Number(timestampText);
  const now = (options.now ?? Date.now)() / 1_000;
  if (Math.abs(now - timestamp) > tolerance) {
    throw new FlowStepVerificationError("stale_timestamp", "The request is too old or too new.");
  }
  const bodyBytes = new TextEncoder().encode(rawBody);
  if (bodyBytes.byteLength > MAX_EVENT_BYTES) {
    throw new FlowStepVerificationError("invalid_body", "The body is too large.");
  }
  const signed = new TextEncoder().encode(`${id}.${timestampText}.${rawBody}`);
  let valid = false;
  // Several space-separated signatures may be sent while a secret is being rotated.
  for (const entry of signatures.split(" ")) {
    const [version, value] = entry.split(",", 2);
    const mac = version === "v1" && value ? decodeBase64(value) : null;
    // crypto.subtle.verify compares in constant time.
    if (mac && (await crypto.subtle.verify("HMAC", key, mac, signed))) valid = true;
  }
  if (!valid) {
    throw new FlowStepVerificationError("invalid_signature", "The signature does not match.");
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(rawBody);
  } catch {
    throw new FlowStepVerificationError("invalid_body", "The body is not JSON.");
  }
  const event = FlowBackendEventSchema.safeParse(parsed);
  if (!event.success) {
    throw new FlowStepVerificationError("invalid_body", "The body is not a flow step event.");
  }
  return { id, timestamp, event: event.data };
}

/** Request adapter for Workers, Node.js 22, Deno and Bun. Reads the body once, as text. */
export async function verifyFlowStepRequest(
  request: Request,
  options: FlowStepVerifyOptions,
): Promise<VerifiedFlowStep> {
  const declared = Number(request.headers.get("content-length") ?? "0");
  if (declared > MAX_EVENT_BYTES) {
    throw new FlowStepVerificationError("invalid_body", "The body is too large.");
  }
  return verifyFlowStepSignature(await request.text(), request.headers, options);
}

/**
 * The answer auth4.dev expects: status 200 and a JSON body. Throws TypeError for an answer the
 * step would refuse (a free-text message, an unknown field, a bad metadata key), so the mistake
 * shows up in your own logs rather than as a failed step.
 */
export function flowStepResponse(answer: FlowBackendResponse): Response {
  const checked = FlowBackendResponseSchema.safeParse(answer);
  if (!checked.success) throw new TypeError("This is not an answer a flow step accepts.");
  return Response.json(checked.data, { status: 200, headers: { "cache-control": "no-store" } });
}

/** The 401 to send when verification fails. It says nothing about why. */
export function flowStepRejectedResponse(): Response {
  return Response.json({ error: "invalid_signature" }, { status: 401 });
}
