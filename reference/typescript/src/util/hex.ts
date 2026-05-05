/**
 * Hex encoding/decoding helpers.
 *
 * We implement these explicitly rather than relying on Node's Buffer or
 * third-party libraries so the package runs unchanged in browsers.
 *
 * Invariants enforced:
 *   - `toHex()` always outputs lowercase (matches Python `.hex()`).
 *   - `fromHex()` accepts lowercase and uppercase; rejects any other char.
 *   - `fromHex()` requires an even number of hex digits.
 */

const HEX_CHARS = '0123456789abcdef';

export function toHex(bytes: Uint8Array): string {
  let out = '';
  for (const b of bytes) {
    out += HEX_CHARS[(b >> 4) & 0x0f];
    out += HEX_CHARS[b & 0x0f];
  }
  return out;
}

export function fromHex(hex: string): Uint8Array {
  if (typeof hex !== 'string') {
    throw new TypeError('fromHex requires a string');
  }
  if (hex.length % 2 !== 0) {
    throw new Error('hex string must have even length');
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    const hi = _hexVal(hex.charCodeAt(i));
    const lo = _hexVal(hex.charCodeAt(i + 1));
    out[i / 2] = (hi << 4) | lo;
  }
  return out;
}

function _hexVal(c: number): number {
  // '0'..'9' -> 0..9
  if (c >= 0x30 && c <= 0x39) return c - 0x30;
  // 'a'..'f' -> 10..15
  if (c >= 0x61 && c <= 0x66) return c - 0x61 + 10;
  // 'A'..'F' -> 10..15 (accepted but normalized via toHex output)
  if (c >= 0x41 && c <= 0x46) return c - 0x41 + 10;
  throw new Error(`invalid hex character code ${c}`);
}

/** Strict variant that ONLY accepts lowercase hex. */
export function fromHexLowercase(hex: string): Uint8Array {
  if (!/^[0-9a-f]*$/.test(hex)) {
    throw new Error('hex string must be lowercase [0-9a-f]');
  }
  return fromHex(hex);
}
