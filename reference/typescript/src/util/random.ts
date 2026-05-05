/**
 * Cryptographically secure random bytes across Node and browser.
 *
 * We delegate to @noble/hashes' `randomBytes`, which already performs
 * cross-environment detection (Web Crypto in browsers and modern Node;
 * `node:crypto.webcrypto` on older Node; clear error otherwise). This
 * keeps our module ESM-pure (no `require`) and adds no transitive
 * dependency since @noble/hashes is already required by @noble/ed25519.
 *
 * Invariants:
 *   - Input: positive integer, up to 1 MiB.
 *   - Output: Uint8Array of exactly `n` bytes, uniformly distributed.
 */
import { randomBytes as nobleRandomBytes } from '@noble/hashes/utils';

export function randomBytes(n: number): Uint8Array {
  if (!Number.isInteger(n) || n <= 0 || n > 1024 * 1024) {
    throw new RangeError('randomBytes requires a positive int up to 1MiB');
  }
  return nobleRandomBytes(n);
}
