/**
 * CSC-1 — Crovia Seal Canonicalization v1.
 *
 * Strict subset of RFC 8785 (JCS):
 *   - Object keys sorted by UTF-16 code-unit order
 *   - String escapes per RFC 8259 (mandatory short escapes only)
 *   - Integers only (floats forbidden in signed payloads)
 *   - No insignificant whitespace
 *
 * This implementation MUST produce byte-identical output to the Python
 * reference (`reference/python/crovia_seal/canonical.py`) for every shared
 * conformance vector. Any divergence is a bug.
 */

// JS-safe integer range — same as Python reference.
const JS_SAFE_INT_MIN = -(2 ** 53 - 1);
const JS_SAFE_INT_MAX = 2 ** 53 - 1;

const ESCAPE_MAP: Record<number, string> = {
  0x22: '\\"',   // "
  0x5c: "\\\\",  // \
  0x08: "\\b",
  0x0c: "\\f",
  0x0a: "\\n",
  0x0d: "\\r",
  0x09: "\\t",
};

export class CanonicalizationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CanonicalizationError";
  }
}

function serializeString(s: string): string {
  let out = '"';
  for (let i = 0; i < s.length; i++) {
    const cp = s.charCodeAt(i);
    if (cp < 0x20) {
      const esc = ESCAPE_MAP[cp];
      if (esc !== undefined) {
        out += esc;
      } else {
        out += "\\u" + cp.toString(16).padStart(4, "0");
      }
    } else if (cp === 0x22 || cp === 0x5c) {
      out += ESCAPE_MAP[cp];
    } else {
      out += s[i];
    }
  }
  out += '"';
  return out;
}

function serializeNumber(n: number): string {
  if (typeof n !== "number" || !Number.isFinite(n)) {
    throw new CanonicalizationError(
      `CSC-1 forbids non-finite numbers; got ${n}`,
    );
  }
  if (!Number.isInteger(n)) {
    throw new CanonicalizationError(
      "CSC-1 forbids float in signed payloads; " +
        'encode numeric parameters as strings (e.g. temperature="0.7")',
    );
  }
  if (n < JS_SAFE_INT_MIN || n > JS_SAFE_INT_MAX) {
    throw new CanonicalizationError(
      `integer ${n} outside JS-safe range [${JS_SAFE_INT_MIN}, ${JS_SAFE_INT_MAX}]; ` +
        "encode large integers as strings",
    );
  }
  // Number.prototype.toString() on integers produces the shortest decimal,
  // no leading zeros, leading "-" for negatives, "0" for zero. Matches
  // Python's str(int) byte-for-byte.
  return String(n);
}

function serializeArray(arr: unknown[]): string {
  const parts = arr.map((v) => serialize(v));
  return "[" + parts.join(",") + "]";
}

function utf16Compare(a: string, b: string): number {
  // RFC 8785 §3.2.3: keys sorted by UTF-16 code-unit value.
  // JavaScript strings ARE UTF-16, so direct < / > comparison works
  // for BMP keys. For supplementary-plane keys the surrogate halves
  // already sort correctly because we compare code units, not code points.
  const len = Math.min(a.length, b.length);
  for (let i = 0; i < len; i++) {
    const ac = a.charCodeAt(i);
    const bc = b.charCodeAt(i);
    if (ac !== bc) return ac - bc;
  }
  return a.length - b.length;
}

function serializeObject(obj: Record<string, unknown>): string {
  // Reject non-string keys via JS prototype. Object keys in JS are always
  // strings (Symbol keys are skipped by Object.keys), so this is ok by
  // construction. But we still defend against malformed input shapes.
  const keys = Object.keys(obj);
  for (const k of keys) {
    if (typeof k !== "string") {
      throw new CanonicalizationError(
        `object key must be string, got ${typeof k}`,
      );
    }
  }

  // Detect duplicates (impossible from a literal object, but possible
  // from manually-constructed values).
  const seen = new Set<string>();
  for (const k of keys) {
    if (seen.has(k)) {
      throw new CanonicalizationError(`duplicate object key: ${k}`);
    }
    seen.add(k);
  }

  const sorted = [...keys].sort(utf16Compare);
  const parts = sorted.map(
    (k) => serializeString(k) + ":" + serialize(obj[k]),
  );
  return "{" + parts.join(",") + "}";
}

function serialize(value: unknown): string {
  if (value === null) return "null";
  if (value === true) return "true";
  if (value === false) return "false";
  if (typeof value === "string") return serializeString(value);
  if (typeof value === "number") return serializeNumber(value);
  if (typeof value === "bigint") {
    if (value < BigInt(JS_SAFE_INT_MIN) || value > BigInt(JS_SAFE_INT_MAX)) {
      throw new CanonicalizationError(
        `bigint ${value} outside JS-safe range; encode as string`,
      );
    }
    return value.toString();
  }
  if (Array.isArray(value)) return serializeArray(value);
  if (typeof value === "object") {
    return serializeObject(value as Record<string, unknown>);
  }
  if (value === undefined) {
    throw new CanonicalizationError("CSC-1 cannot serialize undefined");
  }
  throw new CanonicalizationError(
    `CSC-1 cannot serialize value of type ${typeof value}`,
  );
}

/**
 * Canonicalize a JSON-compatible value to its UTF-8 byte representation.
 * Output is byte-identical to the Python reference implementation.
 */
export function canonicalize(value: unknown): Uint8Array {
  const str = serialize(value);
  return new TextEncoder().encode(str);
}

/**
 * Canonicalize and return the string form (UTF-8 will be identical).
 * Useful for debugging.
 */
export function canonicalizeString(value: unknown): string {
  return serialize(value);
}
