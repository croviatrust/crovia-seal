/**
 * CSC-1 tests. Mirrors Python tests/test_canonical.py. Byte-identical
 * assertions where possible.
 */
import { describe, it, expect } from 'vitest';
import { canonicalize } from '../src/canonical.js';
import {
  DuplicateKey,
  NonCanonicalNumber,
  NonStringKey,
  UnsupportedType,
} from '../src/errors.js';

function bytesOf(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

describe('CSC-1 primitives', () => {
  it('null', () => {
    expect(canonicalize(null)).toEqual(bytesOf('null'));
  });
  it('true/false', () => {
    expect(canonicalize(true)).toEqual(bytesOf('true'));
    expect(canonicalize(false)).toEqual(bytesOf('false'));
  });
  it('empty string', () => {
    expect(canonicalize('')).toEqual(bytesOf('""'));
  });
  it('ascii string', () => {
    expect(canonicalize('hello')).toEqual(bytesOf('"hello"'));
  });
});

describe('CSC-1 string escapes', () => {
  it('required short escapes', () => {
    expect(canonicalize('"')).toEqual(bytesOf('"\\""'));
    expect(canonicalize('\\')).toEqual(bytesOf('"\\\\"'));
    expect(canonicalize('\b')).toEqual(bytesOf('"\\b"'));
    expect(canonicalize('\f')).toEqual(bytesOf('"\\f"'));
    expect(canonicalize('\n')).toEqual(bytesOf('"\\n"'));
    expect(canonicalize('\r')).toEqual(bytesOf('"\\r"'));
    expect(canonicalize('\t')).toEqual(bytesOf('"\\t"'));
  });
  it('other controls use \\u00XX lowercase', () => {
    expect(canonicalize('\x00')).toEqual(bytesOf('"\\u0000"'));
    expect(canonicalize('\x1f')).toEqual(bytesOf('"\\u001f"'));
    expect(canonicalize('\x01\x02')).toEqual(bytesOf('"\\u0001\\u0002"'));
  });
  it('non-ASCII emitted literally (UTF-8)', () => {
    expect(canonicalize('café')).toEqual(new Uint8Array([0x22, 0x63, 0x61, 0x66, 0xc3, 0xa9, 0x22]));
  });
  it('emoji supplementary plane emitted as UTF-8, not \\uXXXX\\uXXXX', () => {
    // U+1F600 -> UTF-8: F0 9F 98 80
    expect(canonicalize('\u{1F600}')).toEqual(new Uint8Array([0x22, 0xf0, 0x9f, 0x98, 0x80, 0x22]));
  });
});

describe('CSC-1 integers', () => {
  it('basic', () => {
    expect(canonicalize(0)).toEqual(bytesOf('0'));
    expect(canonicalize(1)).toEqual(bytesOf('1'));
    expect(canonicalize(-1)).toEqual(bytesOf('-1'));
    expect(canonicalize(1234567890)).toEqual(bytesOf('1234567890'));
    expect(canonicalize(-999)).toEqual(bytesOf('-999'));
  });
  it('js-safe bounds accepted', () => {
    expect(canonicalize(Number.MAX_SAFE_INTEGER)).toEqual(
      bytesOf(String(Number.MAX_SAFE_INTEGER)),
    );
    expect(canonicalize(Number.MIN_SAFE_INTEGER)).toEqual(
      bytesOf(String(Number.MIN_SAFE_INTEGER)),
    );
  });
  it('out-of-range integers rejected', () => {
    expect(() => canonicalize(2 ** 53)).toThrow(NonCanonicalNumber);
    expect(() => canonicalize(-(2 ** 53))).toThrow(NonCanonicalNumber);
  });
  it('floats rejected', () => {
    expect(() => canonicalize(0.1)).toThrow(NonCanonicalNumber);
    // Note: in JS `1.0 === 1` so Number.isInteger(1.0) is true.
    // That's fine: Python's int(1) and JS's 1 both canonicalize to "1".
    // We only need to reject NON-integer numbers.
    expect(() => canonicalize(0.5)).toThrow(NonCanonicalNumber);
  });
  it('NaN and Infinity rejected', () => {
    expect(() => canonicalize(Number.NaN)).toThrow(NonCanonicalNumber);
    expect(() => canonicalize(Number.POSITIVE_INFINITY)).toThrow(NonCanonicalNumber);
    expect(() => canonicalize(Number.NEGATIVE_INFINITY)).toThrow(NonCanonicalNumber);
  });
  it('negative zero serializes as 0', () => {
    // Python `str(0)` is "0"; `-0` is also "0". We match.
    expect(canonicalize(-0)).toEqual(bytesOf('0'));
  });
  it('bigint accepted within js-safe range', () => {
    expect(canonicalize(42n)).toEqual(bytesOf('42'));
    expect(canonicalize(-42n)).toEqual(bytesOf('-42'));
  });
  it('bigint out of range rejected', () => {
    expect(() => canonicalize((2n ** 53n))).toThrow(NonCanonicalNumber);
    expect(() => canonicalize(-(2n ** 53n))).toThrow(NonCanonicalNumber);
  });
});

describe('CSC-1 arrays', () => {
  it('empty array', () => {
    expect(canonicalize([])).toEqual(bytesOf('[]'));
  });
  it('array of primitives', () => {
    expect(canonicalize([1, 'a', null, true, false])).toEqual(
      bytesOf('[1,"a",null,true,false]'),
    );
  });
  it('array order preserved', () => {
    expect(canonicalize([3, 1, 2])).toEqual(bytesOf('[3,1,2]'));
  });
  it('nested arrays', () => {
    expect(canonicalize([[1, 2], [3, 4]])).toEqual(bytesOf('[[1,2],[3,4]]'));
  });
});

describe('CSC-1 objects', () => {
  it('empty object', () => {
    expect(canonicalize({})).toEqual(bytesOf('{}'));
  });
  it('keys sorted by UTF-16 code units', () => {
    expect(canonicalize({ b: 2, a: 1 })).toEqual(bytesOf('{"a":1,"b":2}'));
    expect(canonicalize({ z: 1, a: 2, m: 3 })).toEqual(bytesOf('{"a":2,"m":3,"z":1}'));
  });
  it('no whitespace', () => {
    const out = new TextDecoder().decode(canonicalize({ a: 1, b: 'two' }));
    expect(out).toBe('{"a":1,"b":"two"}');
    expect(out).not.toContain(' ');
  });
  it('supplementary-plane key sorts after BMP', () => {
    // "z" (U+007A) vs emoji (U+1F600 = surrogate D83D+DE00).
    // UTF-16 code-unit sort: 0x007A < 0xD83D => "z" first.
    const out = canonicalize({ '\u{1F600}': 1, z: 2 });
    // Expected: {"z":2,"<emoji>":1}
    const expected = new Uint8Array([
      0x7b, // {
      0x22, 0x7a, 0x22, 0x3a, 0x32, 0x2c, // "z":2,
      0x22, 0xf0, 0x9f, 0x98, 0x80, 0x22, 0x3a, 0x31, // "<emoji>":1
      0x7d, // }
    ]);
    expect(out).toEqual(expected);
  });
  it('nested objects', () => {
    expect(canonicalize({
      outer: { b: 1, a: 2 },
      also: [1, { y: 1, x: 2 }],
    })).toEqual(bytesOf('{"also":[1,{"x":2,"y":1}],"outer":{"a":2,"b":1}}'));
  });
});

describe('CSC-1 determinism', () => {
  it('same content, different insertion order -> identical bytes', () => {
    const a = canonicalize({ a: 1, b: 2, c: 3 });
    const b = canonicalize({ c: 3, a: 1, b: 2 });
    const d: Record<string, number> = {};
    d.b = 2; d.a = 1; d.c = 3;
    const c = canonicalize(d);
    expect(a).toEqual(b);
    expect(b).toEqual(c);
  });
});

describe('CSC-1 rejection of unsupported types', () => {
  it('Uint8Array rejected', () => {
    expect(() => canonicalize(new Uint8Array([1, 2, 3]) as unknown as never)).toThrow(UnsupportedType);
  });
  it('Set rejected', () => {
    expect(() => canonicalize(new Set([1, 2, 3]) as unknown as never)).toThrow(UnsupportedType);
  });
  it('Map rejected (not a plain object)', () => {
    // Map has its own prototype. The plain-object check in canonicalize
    // rejects it rather than silently serializing as empty `{}`.
    const m = new Map<string, number>([['a', 1]]);
    expect(() => canonicalize(m as unknown as never)).toThrow(UnsupportedType);
  });
  it('Date rejected (not a plain object)', () => {
    // Dates should be explicitly converted to ISO strings by the caller.
    expect(() => canonicalize(new Date() as unknown as never)).toThrow(UnsupportedType);
  });
  it('class instance rejected (not a plain object)', () => {
    class Foo { x = 1; }
    expect(() => canonicalize(new Foo() as unknown as never)).toThrow(UnsupportedType);
  });
  it('Object.create(null) is accepted (null prototype is plain enough)', () => {
    const o = Object.create(null);
    o.a = 1;
    o.b = 2;
    expect(canonicalize(o as unknown as never)).toEqual(bytesOf('{"a":1,"b":2}'));
  });
  it('function rejected', () => {
    expect(() => canonicalize((() => 1) as unknown as never)).toThrow(UnsupportedType);
  });
});
