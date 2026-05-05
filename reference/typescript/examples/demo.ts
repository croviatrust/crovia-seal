/**
 * TypeScript mirror of examples/demo_hp.py.
 *
 * Reproduces the same end-to-end flow in TS:
 *   1. Deterministic issuer (same seed as Python demo).
 *   2. Genesis Seal over the Harry Potter fixture.
 *   3. Self-verify.
 *   4. Tamper with output_hash -> verify fails.
 *   5. Chained Seal.
 *   6. Chain verify.
 *
 * Because the Python demo uses random seal_id / nonce / timestamp, the
 * exact seal_id and signature bytes differ from the Python run. For
 * byte-identical cross-language comparison see `tests/conformance.test.ts`
 * which uses fixed seal_id/nonce/timestamp vectors.
 *
 * Run:
 *   cd crovia-seal/reference/typescript
 *   npm install
 *   npm run demo
 */
import {
  computeSealHash,
  emitSeal,
  loadIssuerKey,
  verifySeal,
  type Seal,
} from '../src/index.js';

// Same seed as examples/demo_hp.py.
const DEMO_SEED_HEX = 'deadbeef'.repeat(8);
const DEMO_ISSUER_ID = 'urn:crovia:seal-issuer:demo';

const HP_PASSAGE =
  'Mr. and Mrs. Dursley, of number four, Privet Drive, were proud to ' +
  'say that they were perfectly normal, thank you very much. They ' +
  "were the last people you'd expect to be involved in anything " +
  "strange or mysterious, because they just didn't hold with such " +
  'nonsense.';

const INPUT_PROMPT =
  "Continue this passage: 'Mr. and Mrs. Dursley, of number four,'";

const HR = '-'.repeat(72);

/** Recursively sort object keys so the output mirrors Python's json.dumps(sort_keys=True). */
function sortKeysDeep(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(sortKeysDeep);
  if (v !== null && typeof v === 'object' && Object.getPrototypeOf(v) === Object.prototype) {
    const o = v as Record<string, unknown>;
    const sorted: Record<string, unknown> = {};
    for (const k of Object.keys(o).sort()) sorted[k] = sortKeysDeep(o[k]);
    return sorted;
  }
  return v;
}

function printSeal(label: string, s: Seal): void {
  console.log(HR);
  console.log(`${label}:`);
  console.log(HR);
  console.log(JSON.stringify(sortKeysDeep(s), null, 2));
  console.log();
}

function printResult(label: string, r: { ok: boolean; errors: string[] }): void {
  const status = r.ok ? 'OK' : 'REJECTED';
  console.log(`${label}: ${status}`);
  for (const e of r.errors) {
    console.log(`    error: ${e}`);
  }
  console.log();
}

function main(): number {
  console.log('Crovia Seal TypeScript demo');
  console.log('='.repeat(72));
  console.log();

  const issuer = loadIssuerKey(DEMO_ISSUER_ID, DEMO_SEED_HEX);
  console.log(`Issuer id:         ${issuer.issuerId}`);
  console.log(`Issuer public key: ${issuer.publicHex}`);
  console.log();

  const seal = emitSeal({
    issuerKey: issuer,
    inputBytes: new TextEncoder().encode(INPUT_PROMPT),
    outputBytes: new TextEncoder().encode(HP_PASSAGE),
    modality: 'text',
    generatorId: 'openai/gpt-4o',
    generatorVersion: '2024-08-06',
    generatorParams: { temperature: '0.7', top_p: '1.0' },
    checks: {
      memorization: {
        db_version: 'crovia-memdb-2026-04-15',
        method: 'ngram-lsh-v1',
        matches: 1,
        max_conf: '0.94',
        work: "Harry Potter and the Philosopher's Stone (1997)",
      },
    },
  });
  printSeal('Genesis Seal', seal);

  const rOk = verifySeal(seal, { issuerPubkeyHex: issuer.publicHex });
  printResult('Self-verify (honest)', rOk);
  if (!rOk.ok) return 1;

  // Tamper
  const tampered: Seal = JSON.parse(JSON.stringify(seal));
  const h = tampered.subject.output_hash;
  const flipped = h.slice(0, -1) + (h.slice(-1) === '0' ? '1' : '0');
  tampered.subject.output_hash = flipped;
  console.log(`Tampering: subject.output_hash last char ${h.slice(-1)} -> ${flipped.slice(-1)}`);
  const rBad = verifySeal(tampered, { issuerPubkeyHex: issuer.publicHex });
  printResult('Verify (tampered)', rBad);
  if (rBad.ok) {
    console.log('FAIL: tampered Seal should have been rejected.');
    return 1;
  }

  // Chained
  const seal2 = emitSeal({
    issuerKey: issuer,
    inputBytes: new TextEncoder().encode('Now write a one-sentence summary.'),
    outputBytes: new TextEncoder().encode('The Dursleys are proud to be perfectly normal.'),
    modality: 'text',
    generatorId: 'openai/gpt-4o',
    generatorVersion: '2024-08-06',
    sequence: 1,
    prevSealHash: computeSealHash(seal),
  });
  printSeal('Chained Seal (sequence=1)', seal2);

  const rChain = verifySeal(seal2, { issuerPubkeyHex: issuer.publicHex });
  printResult('Chain verify', rChain);
  if (seal2.chain.prev_seal_hash !== computeSealHash(seal)) {
    console.log('FAIL: prev_seal_hash does not match previous seal.');
    return 1;
  }
  console.log('Chain link: prev_seal_hash matches hash of genesis Seal.');
  console.log();

  console.log('Demo complete.');
  return 0;
}

process.exit(main());
