/**
 * Crovia Invisible Mark - tests.
 *
 * Every property that the spec asserts must be tested:
 *   - round-trip: encode then decode recovers the same seal_id;
 *   - visual invisibility: embedded CIM does not change the visible text;
 *   - survivability: concatenation, prefixing, suffixing with arbitrary
 *     visible text preserves extraction;
 *   - tamper detection: single bit flip in payload invalidates CRC and
 *     extraction returns null (no silent acceptance);
 *   - truncation: cutting the mark mid-stream returns null;
 *   - multi-mark: multiple CIMs in one string are all extracted;
 *   - strip: all valid CIMs are removed, invalid partial marks untouched;
 *   - overhead: exactly CIM_TOTAL_LEN invisible chars added.
 */
import { describe, it, expect } from 'vitest';

import {
  BOM,
  CIM_END,
  CIM_START,
  CIM_TOTAL_LEN,
  ZWJ,
  ZW_BIT_0,
  ZW_BIT_1,
  containsCimMarker,
  embedCim,
  encodeCim,
  extractAllCims,
  extractCim,
  stripCim,
} from '../src/lib/stego';


const VALID_ID = 'cs_2026_ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const VALID_ID_2 = 'cs_2026_234567ABCDEFGHIJKLMNOPQRST';
const SAMPLE_TEXT =
  'Mr. and Mrs. Dursley, of number four, Privet Drive, were proud to ' +
  'say that they were perfectly normal, thank you very much.';


// ---------------------------------------------------------------------------
// Unit-level invariants
// ---------------------------------------------------------------------------

describe('CIM primitives', () => {
  it('constants have the expected lengths', () => {
    expect(CIM_START).toHaveLength(3);
    expect(CIM_END).toHaveLength(3);
    expect(CIM_TOTAL_LEN).toBe(3 + 130 + 16 + 3); // 152
  });
  it('start and end markers are distinct', () => {
    expect(CIM_START).not.toBe(CIM_END);
  });
});


describe('encodeCim', () => {
  it('produces exactly CIM_TOTAL_LEN invisible chars', () => {
    const mark = encodeCim(VALID_ID);
    expect(mark).toHaveLength(CIM_TOTAL_LEN);
  });

  it('starts with CIM_START and ends with CIM_END', () => {
    const mark = encodeCim(VALID_ID);
    expect(mark.startsWith(CIM_START)).toBe(true);
    expect(mark.endsWith(CIM_END)).toBe(true);
  });

  it('contains ONLY zero-width characters', () => {
    const mark = encodeCim(VALID_ID);
    const allowed = new Set([ZW_BIT_0, ZW_BIT_1, ZWJ, BOM]);
    for (const ch of mark) {
      expect(allowed.has(ch)).toBe(true);
    }
  });

  it('rejects malformed seal_id', () => {
    const bad = [
      'not-a-seal',
      'cs_ABC_DEFGHIJKLMNOPQRSTUVWXYZABCD',  // non-numeric year
      'cs_2026_abcdefghijklmnopqrstuvwxyz',  // lowercase
      'cs_2026_ABCDEFGHIJKLMNOPQRSTUVWXY0',  // 0 not in base32 alphabet
      'cs_2026_TOOSHORT',
    ];
    for (const b of bad) {
      expect(() => encodeCim(b)).toThrow();
    }
  });
});


// ---------------------------------------------------------------------------
// Round-trip
// ---------------------------------------------------------------------------

describe('CIM round-trip', () => {
  it('bare mark decodes to the original seal_id', () => {
    const mark = encodeCim(VALID_ID);
    const x = extractCim(mark);
    expect(x).not.toBeNull();
    expect(x!.sealId).toBe(VALID_ID);
    expect(x!.crcValid).toBe(true);
  });

  it('mark embedded mid-sentence survives extraction', () => {
    const text = 'hello ' + encodeCim(VALID_ID) + ' world';
    const x = extractCim(text);
    expect(x!.sealId).toBe(VALID_ID);
    expect(text.replace(/[\u200B-\u200D\uFEFF]/g, '')).toBe('hello  world');
  });

  it('embedCim preserves the visible characters exactly', () => {
    const combined = embedCim(SAMPLE_TEXT, VALID_ID);
    // Strip all zero-width chars
    const visible = combined.replace(/[\u200B-\u200D\uFEFF]/g, '');
    expect(visible).toBe(SAMPLE_TEXT);
  });

  it('embedCim produces round-trip extractable mark', () => {
    const combined = embedCim(SAMPLE_TEXT, VALID_ID);
    const x = extractCim(combined);
    expect(x!.sealId).toBe(VALID_ID);
  });

  it('embedCim in multi-line text places the mark before the last newline', () => {
    const text = 'line A\nline B\n';
    const combined = embedCim(text, VALID_ID);
    const visible = combined.replace(/[\u200B-\u200D\uFEFF]/g, '');
    expect(visible).toBe(text);
    const x = extractCim(combined);
    expect(x!.sealId).toBe(VALID_ID);
  });
});


// ---------------------------------------------------------------------------
// Tamper detection
// ---------------------------------------------------------------------------

describe('CIM tamper detection', () => {
  it('flipping ONE data bit invalidates CRC -> extractCim returns null', () => {
    const mark = encodeCim(VALID_ID);
    // Locate the first data bit (just after CIM_START)
    const arr = [...mark];
    const firstBitIdx = CIM_START.length;
    arr[firstBitIdx] = arr[firstBitIdx] === ZW_BIT_0 ? ZW_BIT_1 : ZW_BIT_0;
    const tampered = arr.join('');
    expect(extractCim(tampered)).toBeNull();
  });

  it('flipping ONE crc bit invalidates CRC -> extractCim returns null', () => {
    const mark = encodeCim(VALID_ID);
    const arr = [...mark];
    const firstCrcIdx = CIM_START.length + 130;
    arr[firstCrcIdx] = arr[firstCrcIdx] === ZW_BIT_0 ? ZW_BIT_1 : ZW_BIT_0;
    const tampered = arr.join('');
    expect(extractCim(tampered)).toBeNull();
  });

  it('stripping the END marker returns null (no partial acceptance)', () => {
    const mark = encodeCim(VALID_ID);
    const truncated = mark.slice(0, mark.length - 1);
    expect(extractCim(truncated)).toBeNull();
  });

  it('corrupting the START marker returns null', () => {
    const mark = encodeCim(VALID_ID);
    const bad = 'X' + mark.slice(1);
    expect(extractCim(bad)).toBeNull();
  });

  it('replacing a ZW bit with a non-ZW char returns null', () => {
    const mark = encodeCim(VALID_ID);
    const arr = [...mark];
    arr[CIM_START.length + 5] = 'A'; // visible letter inside bit-stream
    expect(extractCim(arr.join(''))).toBeNull();
  });
});


// ---------------------------------------------------------------------------
// Multi-mark scenarios
// ---------------------------------------------------------------------------

describe('CIM multi-mark scenarios', () => {
  it('two distinct CIMs in one text are both extracted', () => {
    const t = 'alpha ' + encodeCim(VALID_ID) + ' beta ' + encodeCim(VALID_ID_2) + ' gamma';
    const all = extractAllCims(t);
    expect(all).toHaveLength(2);
    expect(all[0]!.sealId).toBe(VALID_ID);
    expect(all[1]!.sealId).toBe(VALID_ID_2);
  });

  it('extractCim returns the first valid mark when others are corrupted', () => {
    const good = encodeCim(VALID_ID);
    const mark2 = encodeCim(VALID_ID_2);
    // Corrupt one crc bit of the SECOND mark.
    const arr2 = [...mark2];
    const firstCrcIdx = CIM_START.length + 130;
    arr2[firstCrcIdx] = arr2[firstCrcIdx] === ZW_BIT_0 ? ZW_BIT_1 : ZW_BIT_0;
    const text = good + ' separator ' + arr2.join('');
    const x = extractCim(text);
    expect(x!.sealId).toBe(VALID_ID);
    expect(extractAllCims(text)).toHaveLength(1);
  });

  it('containsCimMarker detects any CIM_START occurrence', () => {
    expect(containsCimMarker('no mark here')).toBe(false);
    expect(containsCimMarker('hello' + CIM_START + 'rest')).toBe(true);
  });
});


// ---------------------------------------------------------------------------
// Strip
// ---------------------------------------------------------------------------

describe('stripCim', () => {
  it('removes a single valid CIM cleanly', () => {
    const text = 'abc' + encodeCim(VALID_ID) + 'def';
    expect(stripCim(text)).toBe('abcdef');
  });

  it('removes multiple valid CIMs', () => {
    const text = 'a' + encodeCim(VALID_ID) + 'b' + encodeCim(VALID_ID_2) + 'c';
    expect(stripCim(text)).toBe('abc');
  });

  it('does not remove invalid (corrupted) CIMs', () => {
    const mark = encodeCim(VALID_ID);
    const arr = [...mark];
    arr[CIM_START.length] = arr[CIM_START.length] === ZW_BIT_0 ? ZW_BIT_1 : ZW_BIT_0;
    const corrupted = arr.join('');
    const text = 'a' + corrupted + 'b';
    // Strip leaves the bytes alone because CRC fails.
    expect(stripCim(text)).toBe(text);
  });
});


// ---------------------------------------------------------------------------
// Robustness against realistic AI output samples
// ---------------------------------------------------------------------------

describe('CIM realistic AI output', () => {
  it('1KB realistic AI response round-trips cleanly', () => {
    const longResponse = [
      'Here are the steps to solve the problem:',
      '',
      '1. First, parse the input and validate its format.',
      '2. Next, compute the SHA-256 hash of each chunk.',
      '3. Finally, append a CRC-16 checksum for integrity.',
      '',
      'The full algorithm runs in O(n) time and uses O(1) extra space.',
      '',
      'Key considerations: Unicode normalization, endian-ness, and the ',
      'specific edge cases around surrogate pairs in UTF-16.',
    ].join('\n');
    const embedded = embedCim(longResponse, VALID_ID);
    const visible = embedded.replace(/[\u200B-\u200D\uFEFF]/g, '');
    expect(visible).toBe(longResponse);
    const x = extractCim(embedded);
    expect(x!.sealId).toBe(VALID_ID);
  });

  it('CIM survives Unix-style paste (single blob copy)', () => {
    const embedded = embedCim(SAMPLE_TEXT, VALID_ID);
    // Simulate a paste that preserves zero-width chars verbatim.
    const pasted = 'Somebody wrote: "' + embedded + '" yesterday.';
    const x = extractCim(pasted);
    expect(x!.sealId).toBe(VALID_ID);
  });

  it('CIM is absent in plain AI text -> extractCim returns null', () => {
    expect(extractCim(SAMPLE_TEXT)).toBeNull();
  });
});
