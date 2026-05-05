/**
 * CSC-1 - Crovia Seal Canonicalization v1.
 *
 * TypeScript port of `crovia_seal/canonical.py`. MUST produce byte-identical
 * output to the Python reference for all valid inputs. Divergence is a bug.
 *
 * Key correctness notes for JavaScript:
 *
 * - JS numbers are IEEE-754 doubles. CSC-1 forbids floats in signed
 *   payloads, so we accept ONLY `number` values satisfying
 *   `Number.isInteger(n) && Number.isSafeInteger(n)`. Anything else
 *   (fractional, NaN, +/-Infinity, out-of-range) is rejected.
 *
 * - BigInt: accepted IF within the JS-safe integer range (for cross-language
 *   compatibility with Python's int). Outside the range: rejected.
 *
 * - String iteration: JS `for..of` on a string iterates by Unicode scalar
 *   value (code point), which is what CSC-1 wants. Surrogate pairs in the
 *   source are presented as a single supplementary-plane code point.
 *
 * - Object key sorting: JS's default string comparison (`a < b`) operates
 *   on UTF-16 code units, which matches Python's `str.encode("utf-16-be")`
 *   byte comparison. For BMP-only keys this equals lexicographic sort; for
 *   supplementary-plane keys both sides agree on surrogate-pair ordering.
 */
import {
  DuplicateKey,
  NonCanonicalNumber,
  NonStringKey,
  UnsupportedType,
} from './errors.js';
import { JS_SAFE_INT_MAX, JS_SAFE_INT_MIN } from './constants.js';

/** JSON-like values we accept. */
export type JsonValue =
  | null
  | boolean
  | number
  | bigint
  | string
  | readonly JsonValue[]
  | { readonly [k: string]: JsonValue };


// --- String serialization --------------------------------------------------

const SHORT_ESCAPES: Record<number, string> = {
  0x08: '\\b',
  0x0c: '\\f',
  0x0a: '\\n',
  0x0d: '\\r',
  0x09: '\\t',
};

function _serializeString(s: string): string {
  let out = '"';
  // for..of iterates by Unicode code point, which is what we want.
  // This correctly handles supplementary-plane code points (emoji etc).
  for (const ch of s) {
    const cp = ch.codePointAt(0)!;
    if (cp < 0x20) {
      const esc = SHORT_ESCAPES[cp];
      if (esc !== undefined) {
        out += esc;
      } else {
        // \u00XX form, lowercase hex to match Python.
        out += '\\u' + cp.toString(16).padStart(4, '0');
      }
    } else if (cp === 0x22) {
      out += '\\"';
    } else if (cp === 0x5c) {
      out += '\\\\';
    } else {
      out += ch;
    }
  }
  out += '"';
  return out;
}


// --- Number serialization (CSC-1: integers only) ---------------------------

function _serializeNumber(n: number | bigint): string {
  if (typeof n === 'bigint') {
    if (n < BigInt(JS_SAFE_INT_MIN) || n > BigInt(JS_SAFE_INT_MAX)) {
      throw new NonCanonicalNumber(
        `bigint ${n} is outside the JS-safe range ` +
        `[${JS_SAFE_INT_MIN}, ${JS_SAFE_INT_MAX}]; ` +
        'encode large integers as strings',
      );
    }
    return n.toString(10);
  }

  if (!Number.isFinite(n)) {
    throw new NonCanonicalNumber(
      'CSC-1 forbids NaN and +/-Infinity',
    );
  }
  if (!Number.isInteger(n)) {
    throw new NonCanonicalNumber(
      'CSC-1 forbids float in signed payloads; ' +
      'encode numeric parameters as strings (e.g. temperature="0.7")',
    );
  }
  // Treat -0 as 0 (Python: str(0) == "0").
  if (Object.is(n, -0)) {
    return '0';
  }
  if (!Number.isSafeInteger(n)) {
    throw new NonCanonicalNumber(
      `integer ${n} is outside the JS-safe range ` +
      `[${JS_SAFE_INT_MIN}, ${JS_SAFE_INT_MAX}]; ` +
      'encode large integers as strings',
    );
  }
  // Number.prototype.toString(10) for a safe integer produces the shortest
  // decimal representation with no leading zeros and an explicit leading
  // minus sign for negatives. For 0 it produces "0".
  return n.toString(10);
}


// --- Array serialization ---------------------------------------------------

function _serializeArray(arr: readonly JsonValue[]): string {
  let out = '[';
  let first = true;
  for (const v of arr) {
    if (!first) out += ',';
    first = false;
    out += _serialize(v);
  }
  out += ']';
  return out;
}


// --- Object serialization --------------------------------------------------

/**
 * A "plain object" is one whose prototype is `Object.prototype` or `null`.
 * This deliberately excludes Uint8Array, Set, Map, Date, class instances,
 * and any other exotic object. Passing such objects to canonicalize() is
 * a type error, not a silent empty-object serialization.
 *
 * SECURITY: without this check, a Uint8Array serializes as
 * `{"0":n0,"1":n1,...}` and a Set serializes as `{}`. Both would produce
 * valid signatures over data the caller never intended to sign.
 */
function _isPlainObject(v: unknown): boolean {
  if (v === null || typeof v !== 'object') return false;
  const proto = Object.getPrototypeOf(v);
  return proto === Object.prototype || proto === null;
}

function _serializeObject(obj: { readonly [k: string]: JsonValue }): string {
  // Gather keys with JS semantics. `Object.keys` returns the own enumerable
  // string keys in definition order (ignoring Symbol keys).
  const keys = Object.keys(obj);

  // Duplicate-key detection: JS object literals cannot have duplicate keys
  // in the source (last wins). But if someone constructs a dict-like and
  // hands us an object with a collision that somehow survives, we still
  // want to flag it. In practice, once keys is an array of strings obtained
  // from Object.keys, duplicates cannot appear. We check defensively.
  const seen = new Set<string>();
  for (const k of keys) {
    if (typeof k !== 'string') {
      throw new NonStringKey(`object key must be string, got ${typeof k}`);
    }
    if (seen.has(k)) {
      throw new DuplicateKey(`duplicate object key: ${JSON.stringify(k)}`);
    }
    seen.add(k);
  }

  // Sort keys by UTF-16 code-unit sequence. JS string `<` already does this
  // natively (compares by UTF-16 code units). We use a stable sort.
  keys.sort();

  let out = '{';
  let first = true;
  for (const k of keys) {
    if (!first) out += ',';
    first = false;
    out += _serializeString(k) + ':' + _serialize(obj[k]!);
  }
  out += '}';
  return out;
}


// --- Dispatcher ------------------------------------------------------------

function _serialize(v: JsonValue): string {
  if (v === null) return 'null';
  if (v === true) return 'true';
  if (v === false) return 'false';
  const t = typeof v;
  if (t === 'string') return _serializeString(v as string);
  if (t === 'number' || t === 'bigint') return _serializeNumber(v as number | bigint);
  if (Array.isArray(v)) return _serializeArray(v);
  // `typeof` alone is insufficient: Uint8Array, Set, Map, Date etc. are all
  // `"object"` but must NOT be silently coerced. Require a plain object.
  if (t === 'object') {
    if (!_isPlainObject(v)) {
      const ctor = (v as { constructor?: { name?: string } }).constructor?.name ?? 'unknown';
      throw new UnsupportedType(
        `CSC-1 accepts only plain objects; got ${ctor}. ` +
        'Convert exotic values (Uint8Array, Set, Map, Date, ...) to a supported ' +
        'representation (array, string, integer) before canonicalizing.',
      );
    }
    return _serializeObject(v as { [k: string]: JsonValue });
  }
  throw new UnsupportedType(`CSC-1 cannot serialize value of type ${t}`);
}


// --- Public API ------------------------------------------------------------

/**
 * Produce the CSC-1 UTF-8 byte sequence for the given JSON-like value.
 *
 * Accepts nested structures of: null, boolean, number (integer only, JS-safe
 * range), bigint (JS-safe range), string, array, plain object (string keys).
 * Any other type - including float - throws a CanonicalizationError subclass.
 *
 * The output is deterministic: two values that are logically equal as JSON
 * will canonicalize to the same bytes. This is what makes signing meaningful.
 */
export function canonicalize(value: JsonValue): Uint8Array {
  const text = _serialize(value);
  return new TextEncoder().encode(text);
}
