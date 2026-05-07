/**
 * Ed25519 key handling.
 *
 * @noble/ed25519 v2 ships only the curve operations and requires a
 * SHA-512 implementation to be plugged in via `etc.sha512Sync`. We use
 * @noble/hashes/sha512 for that.
 */
// Polyfill MUST be imported BEFORE @noble/ed25519, which captures
// globalThis.crypto at module load time.
import "./_polyfill.js";

import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";

import type { KeyPair } from "./types.js";

// Plug SHA-512 into noble-ed25519 (required by v2 API).
ed.etc.sha512Sync = (...m: Uint8Array[]) => sha512(ed.etc.concatBytes(...m));

/**
 * Provide random bytes that work everywhere:
 *   - browsers and modern Node: globalThis.crypto.getRandomValues
 *   - older Node (18.x ESM): dynamic import of "node:crypto" (top-level await)
 *
 * We override `ed.etc.randomBytes` so noble-ed25519's own RNG path
 * works in older Node, plus expose `randomBytes()` for seal.ts.
 */
type RandFn = (n: number) => Uint8Array;

async function pickRandomBytes(): Promise<RandFn> {
  const g = globalThis as {
    crypto?: { getRandomValues?: (a: Uint8Array) => Uint8Array };
  };
  if (g.crypto && typeof g.crypto.getRandomValues === "function") {
    return (n: number) => g.crypto!.getRandomValues!(new Uint8Array(n));
  }
  // Node ESM fallback for environments where globalThis.crypto is missing
  // (Node 18.x without --experimental-global-webcrypto). The dynamic import
  // is a no-op in browsers because the branch above always wins there.
  try {
    const nc = (await import("node:crypto")) as unknown as {
      webcrypto?: { getRandomValues: (a: Uint8Array) => Uint8Array };
      randomBytes?: (n: number) => Uint8Array;
    };
    if (nc.webcrypto?.getRandomValues) {
      return (n: number) => nc.webcrypto!.getRandomValues(new Uint8Array(n));
    }
    if (typeof nc.randomBytes === "function") {
      return (n: number) => new Uint8Array(nc.randomBytes!(n));
    }
  } catch {
    // not in Node — fall through to throw
  }
  throw new Error(
    "no secure RNG available — need WebCrypto or Node 'crypto' module",
  );
}

const _randomBytes: RandFn = await pickRandomBytes();
// noble-ed25519's randomBytes signature takes (len?: number); default 32.
ed.etc.randomBytes = (len?: number) => _randomBytes(len ?? 32);

/** Cryptographically-secure random bytes (browser + Node). */
export function randomBytes(n: number): Uint8Array {
  return _randomBytes(n);
}

const HEX64_RE = /^[0-9a-f]{64}$/;

function bytesToHex(bytes: Uint8Array): string {
  let s = "";
  for (let i = 0; i < bytes.length; i++) {
    s += bytes[i]!.toString(16).padStart(2, "0");
  }
  return s;
}

function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0 || !/^[0-9a-f]*$/.test(hex)) {
    throw new Error(`invalid hex string of length ${hex.length}`);
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function hexToBytes32(hex: string): Uint8Array {
  if (!HEX64_RE.test(hex)) {
    throw new Error(`expected 64 lowercase hex chars, got ${hex.length} chars`);
  }
  return hexToBytes(hex);
}

/**
 * Generate a fresh Ed25519 key pair.
 * Uses crypto.getRandomValues — works in Node 18+ and modern browsers.
 */
export async function generateKey(): Promise<KeyPair> {
  const priv = ed.utils.randomPrivateKey();
  const pub = await ed.getPublicKeyAsync(priv);
  return {
    privateHex: bytesToHex(priv),
    publicHex: bytesToHex(pub),
  };
}

/**
 * Synchronous variant of generateKey() — usable when running with the
 * sha512Sync hook installed (Node, Deno, modern browsers).
 */
export function generateKeySync(): KeyPair {
  const priv = ed.utils.randomPrivateKey();
  const pub = ed.getPublicKey(priv);
  return {
    privateHex: bytesToHex(priv),
    publicHex: bytesToHex(pub),
  };
}

/** Derive the public hex from a private hex (does not mutate caller). */
export async function publicFromPrivate(privateHex: string): Promise<string> {
  const pub = await ed.getPublicKeyAsync(hexToBytes32(privateHex));
  return bytesToHex(pub);
}

/**
 * Sign raw bytes with an Ed25519 private key (hex).
 * Returns 64-byte signature as 128 lowercase hex chars.
 */
export async function signBytes(
  privateHex: string,
  message: Uint8Array,
): Promise<string> {
  const sig = await ed.signAsync(message, hexToBytes32(privateHex));
  return bytesToHex(sig);
}

/** Verify a signature against bytes and a public key (all hex / Uint8Array). */
export async function verifyBytes(
  publicHex: string,
  signatureHex: string,
  message: Uint8Array,
): Promise<boolean> {
  if (signatureHex.length !== 128 || !/^[0-9a-f]{128}$/.test(signatureHex)) {
    return false;
  }
  if (!HEX64_RE.test(publicHex)) return false;
  try {
    return await ed.verifyAsync(
      hexToBytes(signatureHex),
      message,
      hexToBytes32(publicHex),
    );
  } catch {
    return false;
  }
}

export { bytesToHex, hexToBytes };
