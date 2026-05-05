/**
 * RFC 4648 base32 encoder/decoder (uppercase A-Z, 2-7; no padding).
 *
 * This is the encoding used for `seal_id` and `timestamp.nonce`. We want:
 *   - Uppercase alphabet so it round-trips cleanly through URLs and headers.
 *   - No padding (the Python side uses `rstrip("=")`).
 *
 * Inputs are always multiples of 5 bytes in our usage (16-byte IDs produce
 * 26-char output after stripping padding), so we do not need to decode
 * padded forms.
 */

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function toBase32NoPad(bytes: Uint8Array): string {
  let out = '';
  let bits = 0;
  let value = 0;
  for (const b of bytes) {
    value = (value << 8) | b;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out += ALPHABET[(value >> bits) & 0x1f];
    }
  }
  if (bits > 0) {
    out += ALPHABET[(value << (5 - bits)) & 0x1f];
  }
  return out;
}
