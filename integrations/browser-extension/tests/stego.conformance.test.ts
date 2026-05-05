/**
 * Cross-language CIM conformance test.
 *
 * Loads the vectors emitted by `conformance/generate_cim_vectors.py` and
 * asserts that the TypeScript `encodeCim` produces the SAME code points for
 * the same `seal_id`, and that `extractCim` recovers the original id.
 *
 * If this test fails, Python and TypeScript have diverged. Do NOT relax the
 * assertions - fix whichever side drifted.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { encodeCim, extractCim, CIM_TOTAL_LEN } from '../src/lib/stego';

const HERE = dirname(fileURLToPath(import.meta.url));
const VECTORS_PATH = resolve(
  HERE,
  '..',
  '..',
  '..',
  'conformance',
  'vectors',
  'cim',
  'v1.json',
);

interface Vector {
  seal_id: string;
  issuance_year: number;
  note: string;
  mark_len: number;
  mark_codepoints: number[];
}

interface VectorFile {
  version: number;
  format: string;
  vectors: Vector[];
}

function codepointsOf(s: string): number[] {
  // Iterating the string directly yields UTF-16 code UNITS. Since every CIM
  // code point is in the BMP (all zero-width chars < U+FFFF), code units and
  // code points coincide for our fixtures. We assert this invariant.
  const out: number[] = [];
  for (let i = 0; i < s.length; i++) out.push(s.charCodeAt(i));
  return out;
}

describe('CIM cross-language conformance (Python <-> TypeScript)', () => {
  const payload = JSON.parse(readFileSync(VECTORS_PATH, 'utf-8')) as VectorFile;

  it('loaded at least one vector', () => {
    expect(payload.vectors.length).toBeGreaterThan(0);
    expect(payload.version).toBe(1);
    expect(payload.format).toBe('cim-codepoints');
  });

  for (const v of payload.vectors) {
    it(`encodes "${v.seal_id}" byte-identically`, () => {
      const mark = encodeCim(v.seal_id);
      expect(mark.length).toBe(CIM_TOTAL_LEN);
      expect(mark.length).toBe(v.mark_len);
      expect(codepointsOf(mark)).toEqual(v.mark_codepoints);
    });

    it(`extracts "${v.seal_id}" round-trip`, () => {
      const mark = String.fromCodePoint(...v.mark_codepoints);
      const text = `prefix ${mark} suffix`;
      const extracted = extractCim(text, v.issuance_year);
      expect(extracted).not.toBeNull();
      expect(extracted!.sealId).toBe(v.seal_id);
      expect(extracted!.crcValid).toBe(true);
    });
  }
});
