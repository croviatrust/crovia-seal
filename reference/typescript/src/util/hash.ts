/**
 * SHA-256 thin wrapper.
 *
 * We use @noble/hashes for portability: works in browser and Node with no
 * polyfills. The `cryptography.hazmat` library in Python is the analogue
 * on that side; both produce the same 32-byte digest for the same input.
 */
import { sha256 } from '@noble/hashes/sha256';
import { toHex } from './hex.js';

export function sha256Bytes(data: Uint8Array): Uint8Array {
  return sha256(data);
}

export function sha256Hex(data: Uint8Array): string {
  return toHex(sha256(data));
}

/**
 * Return the string "sha256:<lowercase hex>", matching the convention used
 * throughout the Seal schema (input_hash, output_hash, prev_seal_hash, ...).
 */
export function sha256Prefixed(data: Uint8Array): string {
  return 'sha256:' + sha256Hex(data);
}
