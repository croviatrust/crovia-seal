/**
 * Issuer key management.
 *
 * Wraps @noble/ed25519 to match the Python reference's IssuerKey API:
 *
 *   - `generateIssuerKey(id)` - fresh random 32-byte seed.
 *   - `loadIssuerKey(id, privateHex)` - deterministic from a 64-hex seed.
 *   - `loadPublicKey(publicHex)` - verify-only public key object.
 *
 * Ed25519 is set up in synchronous mode by injecting a pure-JS SHA-512 so
 * that callers never have to await signing/verification. This matters for
 * demo scripts and for the browser extension's fast inline path.
 */
import * as ed from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha512';

import { ISSUER_ID_REGEX } from './constants.js';
import { fromHex, toHex } from './util/hex.js';
import { randomBytes } from './util/random.js';

// --- Synchronous SHA-512 injection (done once, at module load) -------------
// Without this, ed.sign / ed.verify return Promises. We prefer a sync API.
// Upstream docs: https://github.com/paulmillr/noble-ed25519
// eslint-disable-next-line @typescript-eslint/no-explicit-any
(ed.etc as any).sha512Sync = (...m: Uint8Array[]) => sha512(ed.etc.concatBytes(...m));


export interface IssuerKey {
  readonly issuerId: string;
  readonly publicHex: string;

  /** Export the 32-byte private seed as lowercase hex. SECURITY-SENSITIVE. */
  privateHex(): string;

  /** Sign an arbitrary byte payload. Deterministic per RFC 8032. */
  sign(payload: Uint8Array): Uint8Array;

  /** Verify a signature against this key's public key. Returns bool. */
  verify(signature: Uint8Array, payload: Uint8Array): boolean;
}


function _validateIssuerId(issuerId: string): void {
  if (typeof issuerId !== 'string') {
    throw new TypeError('issuerId must be a string');
  }
  if (!ISSUER_ID_REGEX.test(issuerId)) {
    throw new Error(
      `invalid issuer_id: ${JSON.stringify(issuerId)}\n` +
      'expected: "urn:crovia:seal-issuer:<name>" where <name> ' +
      'is 1..64 chars of [a-z0-9._-] starting with alphanumeric.',
    );
  }
}


function _build(issuerId: string, privateSeed: Uint8Array): IssuerKey {
  if (privateSeed.length !== 32) {
    throw new Error(`private seed must be 32 bytes, got ${privateSeed.length}`);
  }
  // ed.getPublicKey is sync because we injected sha512Sync.
  const pubBytes = ed.getPublicKey(privateSeed);
  const publicHex = toHex(pubBytes);

  return {
    issuerId,
    publicHex,

    privateHex(): string {
      return toHex(privateSeed);
    },

    sign(payload: Uint8Array): Uint8Array {
      if (!(payload instanceof Uint8Array)) {
        throw new TypeError('payload must be Uint8Array');
      }
      return ed.sign(payload, privateSeed);
    },

    verify(signature: Uint8Array, payload: Uint8Array): boolean {
      if (!(signature instanceof Uint8Array)) {
        throw new TypeError('signature must be Uint8Array');
      }
      if (!(payload instanceof Uint8Array)) {
        throw new TypeError('payload must be Uint8Array');
      }
      try {
        return ed.verify(signature, payload, pubBytes);
      } catch {
        return false;
      }
    },
  };
}


export function generateIssuerKey(issuerId: string): IssuerKey {
  _validateIssuerId(issuerId);
  const seed = randomBytes(32);
  return _build(issuerId, seed);
}


export function loadIssuerKey(issuerId: string, privateHex: string): IssuerKey {
  _validateIssuerId(issuerId);
  if (typeof privateHex !== 'string') {
    throw new TypeError('privateHex must be a string');
  }
  const lower = privateHex.toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(lower)) {
    throw new Error('privateHex must be exactly 64 lowercase hex chars');
  }
  const seed = fromHex(lower);
  return _build(issuerId, seed);
}


export interface PublicKey {
  readonly publicHex: string;
  verify(signature: Uint8Array, payload: Uint8Array): boolean;
}


export function loadPublicKey(publicHex: string): PublicKey {
  if (typeof publicHex !== 'string') {
    throw new TypeError('publicHex must be a string');
  }
  const lower = publicHex.toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(lower)) {
    throw new Error('publicHex must be exactly 64 lowercase hex chars');
  }
  const pubBytes = fromHex(lower);
  return {
    publicHex: lower,
    verify(signature: Uint8Array, payload: Uint8Array): boolean {
      if (!(signature instanceof Uint8Array) || !(payload instanceof Uint8Array)) {
        throw new TypeError('signature and payload must be Uint8Array');
      }
      try {
        return ed.verify(signature, payload, pubBytes);
      } catch {
        return false;
      }
    },
  };
}
