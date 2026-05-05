/**
 * Seal happy-path tests. Mirrors Python tests/test_seal.py.
 */
import { describe, it, expect } from 'vitest';
import { sha256 } from '@noble/hashes/sha256';

import {
  SEAL_VERSION,
  SIGNATURE_DOMAIN,
  computePayload,
  computeSealHash,
  emitSeal,
  generateIssuerKey,
  loadIssuerKey,
  verifySeal,
} from '../src/index.js';

const ISSUER_ID = 'urn:crovia:seal-issuer:test';

function basicIssuer() {
  return generateIssuerKey(ISSUER_ID);
}

function basicSeal(issuer = basicIssuer()) {
  return {
    issuer,
    seal: emitSeal({
      issuerKey: issuer,
      inputBytes: new TextEncoder().encode('What is the capital of France?'),
      outputBytes: new TextEncoder().encode('The capital of France is Paris.'),
      modality: 'text',
      generatorId: 'openai/gpt-4o',
      generatorVersion: '2024-08-06',
      generatorParams: { temperature: '0.7', top_p: '1.0' },
    }),
  };
}


describe('Seal structure', () => {
  it('has all required top-level fields', () => {
    const { seal } = basicSeal();
    for (const k of ['seal_version', 'seal_id', 'issuer', 'subject',
                     'generator', 'timestamp', 'chain', 'signature']) {
      expect(seal).toHaveProperty(k);
    }
  });

  it('seal_version is v1', () => {
    const { seal } = basicSeal();
    expect(seal.seal_version).toBe(SEAL_VERSION);
  });

  it('seal_id format cs_YYYY_<26 base32>', () => {
    const { seal } = basicSeal();
    expect(seal.seal_id).toMatch(/^cs_[0-9]{4}_[A-Z2-7]{26}$/);
  });

  it('subject hashes are SHA-256 of the inputs', () => {
    const input = new TextEncoder().encode('test-input');
    const output = new TextEncoder().encode('test-output');
    const issuer = basicIssuer();
    const seal = emitSeal({
      issuerKey: issuer,
      inputBytes: input,
      outputBytes: output,
      modality: 'text',
      generatorId: 'm/x',
    });
    const expectIn = 'sha256:' + Buffer.from(sha256(input)).toString('hex');
    const expectOut = 'sha256:' + Buffer.from(sha256(output)).toString('hex');
    expect(seal.subject.input_hash).toBe(expectIn);
    expect(seal.subject.output_hash).toBe(expectOut);
    expect(seal.subject.input_len).toBe(input.length);
    expect(seal.subject.output_len).toBe(output.length);
  });

  it('signature fields correct', () => {
    const { seal } = basicSeal();
    expect(seal.signature.alg).toBe('ed25519');
    expect(seal.signature.canon).toBe('csc-1');
    expect(seal.signature.domain).toBe(SIGNATURE_DOMAIN);
    expect(seal.signature.payload_hash_alg).toBe('sha256');
    expect(seal.signature.sig_hex).toMatch(/^[0-9a-f]{128}$/);
  });

  it('genesis chain has sequence 0 and null prev_seal_hash', () => {
    const { seal } = basicSeal();
    expect(seal.chain.sequence).toBe(0);
    expect(seal.chain.prev_seal_hash).toBeNull();
  });
});


describe('Seal verification', () => {
  it('round-trip: self-verify OK', () => {
    const { seal } = basicSeal();
    const r = verifySeal(seal);
    expect(r.ok).toBe(true);
    expect(r.errors).toHaveLength(0);
  });

  it('verify with pinned correct public key', () => {
    const { issuer, seal } = basicSeal();
    const r = verifySeal(seal, { issuerPubkeyHex: issuer.publicHex });
    expect(r.ok).toBe(true);
  });

  it('verify fails with wrong pinned key', () => {
    const { seal } = basicSeal();
    const other = generateIssuerKey('urn:crovia:seal-issuer:other');
    const r = verifySeal(seal, { issuerPubkeyHex: other.publicHex });
    expect(r.ok).toBe(false);
    expect(r.errors.some(e => e.includes('issuer public key mismatch'))).toBe(true);
  });
});


describe('Payload construction', () => {
  it('payload starts with domain separator', () => {
    const { seal } = basicSeal();
    const payload = computePayload(seal);
    const prefix = new TextEncoder().encode('CROVIA-SEAL-v1\n');
    for (let i = 0; i < prefix.length; i++) {
      expect(payload[i]).toBe(prefix[i]);
    }
  });

  it('payload excludes signature and witnesses', () => {
    const { seal } = basicSeal();
    const p1 = computePayload(seal);
    const withFakeWitness = {
      ...seal,
      witnesses: [{
        id: 'fake',
        pubkey: { alg: 'ed25519' as const, key_hex: '0'.repeat(64) },
        sig_hex: '0'.repeat(128),
      }],
    };
    const p2 = computePayload(withFakeWitness);
    expect(p1).toEqual(p2);
  });

  it('computeSealHash == sha256: + sha256(payload)', () => {
    const { seal } = basicSeal();
    const payload = computePayload(seal);
    const expected = 'sha256:' + Buffer.from(sha256(payload)).toString('hex');
    expect(computeSealHash(seal)).toBe(expected);
  });
});


describe('Deterministic load', () => {
  it('loadIssuerKey produces identical public key for identical seed', () => {
    const priv = 'a'.repeat(64);
    const k1 = loadIssuerKey('urn:crovia:seal-issuer:det', priv);
    const k2 = loadIssuerKey('urn:crovia:seal-issuer:det', priv);
    expect(k1.publicHex).toBe(k2.publicHex);
  });

  it('issuer id validation', () => {
    const badIds = [
      'not-a-urn',
      'urn:wrong:seal-issuer:test',
      'urn:crovia:seal-issuer:',
      'urn:crovia:seal-issuer:UPPER',
      'urn:crovia:seal-issuer:with space',
      'urn:crovia:seal-issuer:' + 'a'.repeat(65),
    ];
    for (const bad of badIds) {
      expect(() => generateIssuerKey(bad)).toThrow();
    }
  });
});


describe('Chain composition', () => {
  it('chained seal with correct prev_seal_hash verifies', () => {
    const issuer = basicIssuer();
    const s1 = emitSeal({
      issuerKey: issuer,
      inputBytes: new TextEncoder().encode('first prompt'),
      outputBytes: new TextEncoder().encode('first response'),
      modality: 'text',
      generatorId: 'test/model',
    });
    const s2 = emitSeal({
      issuerKey: issuer,
      inputBytes: new TextEncoder().encode('second prompt'),
      outputBytes: new TextEncoder().encode('second response'),
      modality: 'text',
      generatorId: 'test/model',
      sequence: 1,
      prevSealHash: computeSealHash(s1),
    });
    expect(s2.chain.sequence).toBe(1);
    expect(s2.chain.prev_seal_hash).toBe(computeSealHash(s1));
    expect(verifySeal(s1).ok).toBe(true);
    expect(verifySeal(s2).ok).toBe(true);
  });

  it('genesis with prevSealHash throws', () => {
    const iss = generateIssuerKey('urn:crovia:seal-issuer:chain');
    expect(() => emitSeal({
      issuerKey: iss,
      inputBytes: new Uint8Array([1]),
      outputBytes: new Uint8Array([2]),
      modality: 'text',
      generatorId: 'm',
      sequence: 0,
      prevSealHash: 'sha256:' + 'f'.repeat(64),
    })).toThrow();
  });

  it('non-genesis without prevSealHash throws', () => {
    const iss = generateIssuerKey('urn:crovia:seal-issuer:chain');
    expect(() => emitSeal({
      issuerKey: iss,
      inputBytes: new Uint8Array([1]),
      outputBytes: new Uint8Array([2]),
      modality: 'text',
      generatorId: 'm',
      sequence: 1,
      prevSealHash: null,
    })).toThrow();
  });
});


describe('Optional fields', () => {
  it('checks field round-trips', () => {
    const issuer = basicIssuer();
    const seal = emitSeal({
      issuerKey: issuer,
      inputBytes: new TextEncoder().encode('probe'),
      outputBytes: new TextEncoder().encode('answer'),
      modality: 'text',
      generatorId: 'model',
      checks: {
        memorization: {
          db_version: 'crovia-memdb-2026-04-15',
          method: 'ngram-lsh-v1',
          matches: 0,
          max_conf: '0.03',
        },
      },
    });
    expect(seal.checks).toBeDefined();
    expect(verifySeal(seal).ok).toBe(true);
  });

  it('anchor field round-trips', () => {
    const issuer = basicIssuer();
    const seal = emitSeal({
      issuerKey: issuer,
      inputBytes: new Uint8Array([1]),
      outputBytes: new Uint8Array([2]),
      modality: 'text',
      generatorId: 'm',
      anchor: {
        log_url: 'https://log.example/seal',
        merkle_root: 'sha256:' + 'a'.repeat(64),
        merkle_proof: ['sha256:' + 'b'.repeat(64), 'sha256:' + 'c'.repeat(64)],
        log_index: 42,
        root_signed_at: '2026-04-15T00:00:00.000Z',
      },
    });
    expect(verifySeal(seal).ok).toBe(true);
  });
});
