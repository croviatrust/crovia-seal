/**
 * Protocol constants for Crovia Seal v1.
 *
 * These are frozen by the specification. They must be byte-identical to
 * the Python reference (`crovia_seal.constants`). Any divergence would
 * produce non-conformant signatures.
 */

export const SEAL_VERSION = 'crovia.seal.v1' as const;

/**
 * Domain separator. Prepended (with LF) to every signing payload.
 * Length MUST be exactly 14 chars; including the LF the separator is 15 bytes.
 */
export const SIGNATURE_DOMAIN = 'CROVIA-SEAL-v1' as const;

/** UTF-8 bytes of SIGNATURE_DOMAIN + LF. Length MUST equal 15. */
export const SIGNATURE_DOMAIN_BYTES: Uint8Array = (() => {
  const text = SIGNATURE_DOMAIN + '\n';
  const bytes = new TextEncoder().encode(text);
  if (bytes.length !== 15) {
    throw new Error('domain separator length invariant violated');
  }
  return bytes;
})();

export const CANON_ID = 'csc-1' as const;
export const PAYLOAD_HASH_ALG = 'sha256' as const;
export const SIGNATURE_ALG = 'ed25519' as const;

/** Number of random bytes inside seal_id and timestamp.nonce. */
export const RANDOM_BYTES = 16 as const;
/** Base32 length (no pad) of 16 random bytes. */
export const RANDOM_B32_CHARS = 26 as const;

export const ALLOWED_MODALITIES = new Set<string>([
  'text', 'code', 'image', 'audio', 'multimodal',
]);

// JS-safe integer bounds (same as Python).
export const JS_SAFE_INT_MIN = -(2 ** 53) + 1;
export const JS_SAFE_INT_MAX = 2 ** 53 - 1;

// Regex patterns matching the spec.
export const SEAL_ID_REGEX = /^cs_[0-9]{4}_[A-Z2-7]{26}$/;
export const HEX64_REGEX = /^[0-9a-f]{64}$/;
export const HEX128_REGEX = /^[0-9a-f]{128}$/;
export const B32_26_REGEX = /^[A-Z2-7]{26}$/;
export const RFC3339_MS_REGEX = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
export const ISSUER_ID_REGEX = /^urn:crovia:seal-issuer:[a-z0-9][a-z0-9\-_.]{0,63}$/;

export const SHA256_PREFIX = 'sha256:' as const;
