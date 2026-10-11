import { EncryptJWT, jwtDecrypt } from "jose";

export interface CookieOptions {
  httpOnly: true;
  secure: boolean;
  sameSite: "lax";
  path: string;
  /** Seconds; 0 deletes the cookie. */
  maxAge: number;
}

/** The subset of Next.js request cookies (and `cookies()` from next/headers) the SDK reads. */
export interface CookieReader {
  getAll(): { name: string; value: string }[];
}

/** The subset of Next.js response cookies (and a writable `cookies()`) the SDK writes. */
export interface CookieWriter {
  set(name: string, value: string, options: CookieOptions): unknown;
}

/**
 * Browsers cap one cookie at about 4 KB including its name and attributes, so larger values are
 * split into `<name>.0`, `<name>.1`, … of at most this many characters.
 */
export const CHUNK_SIZE = 3_500;
/** Bounds reading: a session never needs more than a handful of chunks. */
const MAX_CHUNKS = 10;

const encoder = new TextEncoder();

/**
 * Derives one AES-256-GCM key per secret and purpose with HKDF-SHA-256, so the session and the
 * login transaction never share a key and AUTH4_SECRET itself is never used directly.
 */
export async function deriveKeys(
  secrets: readonly string[],
  purpose: "session" | "transaction",
): Promise<Uint8Array[]> {
  return Promise.all(
    secrets.map(async (secret) => {
      const material = await crypto.subtle.importKey("raw", encoder.encode(secret), "HKDF", false, [
        "deriveBits",
      ]);
      const bits = await crypto.subtle.deriveBits(
        {
          name: "HKDF",
          hash: "SHA-256",
          salt: new Uint8Array(),
          info: encoder.encode(`auth4.dev nextjs ${purpose} v1`),
        },
        material,
        256,
      );
      return new Uint8Array(bits);
    }),
  );
}

/** Encrypts a payload as a compact JWE (dir, A256GCM) that also carries its own expiry. */
export async function seal(
  payload: Record<string, unknown>,
  key: Uint8Array,
  nowSeconds: number,
  expiresAt: number,
): Promise<string> {
  return new EncryptJWT(payload)
    .setProtectedHeader({ alg: "dir", enc: "A256GCM" })
    .setIssuedAt(nowSeconds)
    .setExpirationTime(expiresAt)
    .encrypt(key);
}

/**
 * Decrypts a sealed value with the first key that opens it (the first secret encrypts; older
 * secrets still decrypt during a rotation). Tampered, expired or foreign values give null.
 */
export async function unseal(
  value: string,
  keys: readonly Uint8Array[],
  nowSeconds: number,
): Promise<Record<string, unknown> | null> {
  for (const key of keys) {
    try {
      const { payload } = await jwtDecrypt(value, key, {
        keyManagementAlgorithms: ["dir"],
        contentEncryptionAlgorithms: ["A256GCM"],
        currentDate: new Date(nowSeconds * 1_000),
      });
      return payload as Record<string, unknown>;
    } catch {
      // Try the next secret.
    }
  }
  return null;
}

function chunkPattern(name: string): RegExp {
  return new RegExp(`^${name.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&")}\\.(\\d+)$`, "u");
}

/** The names of every cookie that currently holds part of `name`. */
function storedNames(reader: CookieReader, name: string): string[] {
  const pattern = chunkPattern(name);
  return reader
    .getAll()
    .map((cookie) => cookie.name)
    .filter((candidate) => candidate === name || pattern.test(candidate));
}

/** Reads a value written by writeChunked(), whole or from its numbered chunks. */
export function readChunked(reader: CookieReader, name: string): string | null {
  const all = reader.getAll();
  const whole = all.find((cookie) => cookie.name === name);
  if (whole) return whole.value;
  const parts: string[] = [];
  for (let index = 0; index < MAX_CHUNKS; index += 1) {
    const part = all.find((cookie) => cookie.name === `${name}.${index}`);
    if (!part) break;
    parts.push(part.value);
  }
  return parts.length > 0 ? parts.join("") : null;
}

/** Writes a value in as few chunks as fit, and deletes chunks left over from a longer value. */
export function writeChunked(
  reader: CookieReader,
  writer: CookieWriter,
  name: string,
  value: string,
  options: CookieOptions,
): void {
  const written = new Set<string>();
  if (value.length <= CHUNK_SIZE) {
    writer.set(name, value, options);
    written.add(name);
  } else {
    for (let index = 0; index * CHUNK_SIZE < value.length; index += 1) {
      const chunk = `${name}.${index}`;
      writer.set(chunk, value.slice(index * CHUNK_SIZE, (index + 1) * CHUNK_SIZE), options);
      written.add(chunk);
    }
  }
  for (const stale of storedNames(reader, name)) {
    if (!written.has(stale)) writer.set(stale, "", { ...options, maxAge: 0 });
  }
}

export function clearChunked(
  reader: CookieReader,
  writer: CookieWriter,
  name: string,
  options: CookieOptions,
): void {
  for (const stored of storedNames(reader, name)) {
    writer.set(stored, "", { ...options, maxAge: 0 });
  }
}

/**
 * The request's cookies plus every change made while handling it. Handlers read and write through
 * it, then the changes are copied to the response, and (in middleware) the updated values are
 * forwarded to the page so server components see a refreshed session on the same request.
 */
export class CookieChanges implements CookieReader, CookieWriter {
  readonly #values = new Map<string, string>();
  readonly #writes: [string, string, CookieOptions][] = [];

  constructor(initial: CookieReader) {
    for (const { name, value } of initial.getAll()) this.#values.set(name, value);
  }

  getAll(): { name: string; value: string }[] {
    return [...this.#values].map(([name, value]) => ({ name, value }));
  }

  set(name: string, value: string, options: CookieOptions): void {
    if (options.maxAge === 0) this.#values.delete(name);
    else this.#values.set(name, value);
    this.#writes.push([name, value, options]);
  }

  get changed(): boolean {
    return this.#writes.length > 0;
  }

  applyTo(writer: CookieWriter): void {
    for (const [name, value, options] of this.#writes) writer.set(name, value, options);
  }

  /**
   * The original Cookie request header with the cookies written here replaced. Other cookies are
   * kept byte for byte, so their encoding is never changed.
   */
  header(original: string | null): string {
    const touched = new Set(this.#writes.map(([name]) => name));
    const kept = (original ?? "")
      .split(";")
      .map((pair) => pair.trim())
      .filter((pair) => pair !== "" && !touched.has(pair.split("=", 1)[0]!.trim()));
    const current = [...touched]
      .filter((name) => this.#values.has(name))
      .map((name) => `${name}=${this.#values.get(name)!}`);
    return [...kept, ...current].join("; ");
  }
}
