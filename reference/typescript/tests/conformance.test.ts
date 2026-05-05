/**
 * Cross-language conformance tests.
 *
 * These tests load the fixtures produced by the Python reference
 * (`conformance/generate_vectors.py`) and assert byte-identical output.
 *
 * Running these tests REQUIRES the fixture files. Generate them once:
 *
 *     cd crovia-seal/reference/python
 *     pip install -e .
 *     python ../../conformance/generate_vectors.py
 *
 * If the vectors directory is absent, these tests are skipped with a
 * clear message rather than failing spuriously.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync, existsSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { sha256 } from '@noble/hashes/sha256';

import {
  canonicalize,
  computePayload,
  computeSealHash,
  loadIssuerKey,
  loadPublicKey,
  verifySeal,
  type Seal,
} from '../src/index.js';
import { fromHex, toHex } from '../src/util/hex.js';

// Resolve paths relative to this file's directory.
const __dirname = dirname(fileURLToPath(import.meta.url));
const VECTOR_DIR = resolve(__dirname, '..', '..', '..', 'conformance', 'vectors', 'v1');

const vectorsAvailable = existsSync(resolve(VECTOR_DIR, 'seal_001_genesis.json'));

const runOrSkip = vectorsAvailable ? describe : describe.skip;

if (!vectorsAvailable) {
  // eslint-disable-next-line no-console
  console.warn(
    `\n  [conformance] vectors not found at ${VECTOR_DIR}\n` +
    '  Run: python ../../conformance/generate_vectors.py from the Python reference dir.\n',
  );
}


function readJson<T>(filename: string): T {
  const p = resolve(VECTOR_DIR, filename);
  return JSON.parse(readFileSync(p, 'utf-8')) as T;
}

function readHex(filename: string): string {
  return readFileSync(resolve(VECTOR_DIR, filename), 'utf-8').trim();
}


runOrSkip('CSC-1 canonicalization conformance', () => {
  interface CanonCase {
    name: string;
    input: unknown;
    expected_hex: string;
    expected_utf8: string;
  }
  interface CanonFile {
    version: string;
    cases: CanonCase[];
  }

  const file = readJson<CanonFile>('canonical_cases.json');

  it(`loaded ${file.cases.length} canonicalization cases`, () => {
    expect(file.cases.length).toBeGreaterThan(0);
    expect(file.version).toBe('v1');
  });

  // One parameterized test per case.
  for (const c of (vectorsAvailable ? file.cases : [])) {
    it(`canonical: ${c.name}`, () => {
      const bytes = canonicalize(c.input as Parameters<typeof canonicalize>[0]);
      expect(toHex(bytes)).toBe(c.expected_hex);
    });
  }
});


runOrSkip('Signed seal conformance', () => {
  const issuerId = readFileSync(resolve(VECTOR_DIR, 'issuer.id.txt'), 'utf-8').trim();
  const publicHexExpected = readHex('issuer.public.hex');
  const privateHex = readHex('issuer.private.hex');

  it('loaded issuer matches expected public key', () => {
    const key = loadIssuerKey(issuerId, privateHex);
    expect(key.publicHex).toBe(publicHexExpected);
  });

  for (const name of ['seal_001_genesis', 'seal_002_chained']) {
    describe(name, () => {
      const seal = readJson<Seal>(`${name}.json`);
      const expectedPayloadHex = readHex(`${name}.payload.hex`);
      const expectedSignatureHex = readHex(`${name}.signature.hex`);

      it('verifies with pinned issuer public key', () => {
        const r = verifySeal(seal, { issuerPubkeyHex: publicHexExpected });
        expect(r.ok, `errors: ${r.errors.join('; ')}`).toBe(true);
      });

      it('payload bytes match Python reference', () => {
        const payload = computePayload(seal);
        expect(toHex(payload)).toBe(expectedPayloadHex);
      });

      it('signature matches Python reference (Ed25519 is deterministic)', () => {
        const key = loadIssuerKey(issuerId, privateHex);
        const payload = computePayload(seal);
        const sig = key.sign(payload);
        expect(toHex(sig)).toBe(expectedSignatureHex);
      });

      it('independent verify of the stored signature', () => {
        const pub = loadPublicKey(publicHexExpected);
        const payload = computePayload(seal);
        const sigBytes = fromHex(seal.signature.sig_hex);
        expect(pub.verify(sigBytes, payload)).toBe(true);
      });

      it('computeSealHash == sha256: + sha256(payload)', () => {
        const payload = computePayload(seal);
        const expected = 'sha256:' + toHex(sha256(payload));
        expect(computeSealHash(seal)).toBe(expected);
      });
    });
  }

  it('seal_002 chains to seal_001', () => {
    const s1 = readJson<Seal>('seal_001_genesis.json');
    const s2 = readJson<Seal>('seal_002_chained.json');
    expect(s2.chain.sequence).toBe(1);
    expect(s2.chain.prev_seal_hash).toBe(computeSealHash(s1));
  });
});
