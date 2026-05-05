/**
 * Tamper detection tests. Mirrors Python tests/test_tamper.py.
 * Every adversarial vector MUST be rejected.
 */
import { describe, it, expect } from 'vitest';

import {
  computePayload,
  computeSealHash,
  emitSeal,
  generateIssuerKey,
  loadPublicKey,
  verifySeal,
  type Seal,
} from '../src/index.js';
import { fromHex, toHex } from '../src/util/hex.js';
import { canonicalize } from '../src/canonical.js';


const ISSUER_ID = 'urn:crovia:seal-issuer:adv';


function cloneSeal(s: Seal): Seal {
  return JSON.parse(JSON.stringify(s)) as Seal;
}

function basic(): Seal {
  const issuer = generateIssuerKey(ISSUER_ID);
  return emitSeal({
    issuerKey: issuer,
    inputBytes: new TextEncoder().encode('prompt'),
    outputBytes: new TextEncoder().encode('response'),
    modality: 'text',
    generatorId: 'model/x',
    generatorParams: { temperature: '0.5' },
  });
}


function flipLastChar(hex: string): string {
  const last = hex[hex.length - 1];
  return hex.slice(0, -1) + (last === '0' ? '1' : '0');
}


function expectRejects(seal: unknown): void {
  const r = verifySeal(seal);
  expect(r.ok, `expected rejection; errors=${JSON.stringify(r.errors)}`).toBe(false);
}


describe('Subject tampering', () => {
  it('input_hash flip', () => {
    const s = cloneSeal(basic());
    s.subject.input_hash = s.subject.input_hash.slice(0, -1) +
      (s.subject.input_hash.slice(-1) === '0' ? '1' : '0');
    expectRejects(s);
  });

  it('output_hash flip', () => {
    const s = cloneSeal(basic());
    s.subject.output_hash = s.subject.output_hash.slice(0, -1) +
      (s.subject.output_hash.slice(-1) === '0' ? '1' : '0');
    expectRejects(s);
  });

  it('input_len changed', () => {
    const s = cloneSeal(basic());
    s.subject.input_len += 1;
    expectRejects(s);
  });

  it('modality changed', () => {
    const s = cloneSeal(basic());
    s.subject.modality = 'code' as Seal['subject']['modality'];
    expectRejects(s);
  });
});


describe('Generator tampering', () => {
  it('generator.id changed', () => {
    const s = cloneSeal(basic());
    s.generator.id = 'attacker/model';
    expectRejects(s);
  });

  it('generator.params value changed', () => {
    const s = cloneSeal(basic());
    s.generator.params.temperature = '0.0';
    expectRejects(s);
  });

  it('injected parameter', () => {
    const s = cloneSeal(basic());
    s.generator.params.injected = 'yes';
    expectRejects(s);
  });
});


describe('Chain tampering', () => {
  it('chain sequence changed', () => {
    const s = cloneSeal(basic());
    s.chain.sequence = 1;
    // prev_seal_hash still null -> schema fails. Any failure mode OK.
    expectRejects(s);
  });

  it('chain prev_seal_hash flipped on a chained seal', () => {
    const issuer = generateIssuerKey('urn:crovia:seal-issuer:chain-tamper');
    const s1 = emitSeal({
      issuerKey: issuer,
      inputBytes: new TextEncoder().encode('a'),
      outputBytes: new TextEncoder().encode('b'),
      modality: 'text',
      generatorId: 'm',
    });
    const s2 = emitSeal({
      issuerKey: issuer,
      inputBytes: new TextEncoder().encode('c'),
      outputBytes: new TextEncoder().encode('d'),
      modality: 'text',
      generatorId: 'm',
      sequence: 1,
      prevSealHash: computeSealHash(s1),
    });
    const tampered = cloneSeal(s2);
    tampered.chain.prev_seal_hash = tampered.chain.prev_seal_hash!.slice(0, -1) +
      (tampered.chain.prev_seal_hash!.slice(-1) === '0' ? '1' : '0');
    expectRejects(tampered);
  });
});


describe('Version / downgrade', () => {
  it('seal_version changed', () => {
    const s = cloneSeal(basic());
    (s as unknown as Record<string, unknown>).seal_version = 'crovia.seal.v2';
    expectRejects(s);
  });

  it('signature.alg changed', () => {
    const s = cloneSeal(basic());
    (s.signature as unknown as Record<string, string>).alg = 'rsa-2048';
    expectRejects(s);
  });

  it('signature.domain changed', () => {
    const s = cloneSeal(basic());
    (s.signature as unknown as Record<string, string>).domain = 'ATTACKER-DOMAIN';
    expectRejects(s);
  });

  it('signature.canon changed', () => {
    const s = cloneSeal(basic());
    (s.signature as unknown as Record<string, string>).canon = 'jcs-rfc8785';
    expectRejects(s);
  });
});


describe('Signature tampering', () => {
  it('signature hex bit-flipped', () => {
    const s = cloneSeal(basic());
    s.signature.sig_hex = flipLastChar(s.signature.sig_hex);
    expectRejects(s);
  });

  it('signature from different key rejected', () => {
    const s = cloneSeal(basic());
    const other = generateIssuerKey('urn:crovia:seal-issuer:other');
    const payload = computePayload(s);
    s.signature.sig_hex = toHex(other.sign(payload));
    // issuer.pubkey still points to original -> sig won't validate.
    expectRejects(s);
  });
});


describe('Key substitution', () => {
  it('swap pubkey + re-sign: unpinned passes, pinned fails', () => {
    const s = cloneSeal(basic());
    const originalPubkey = s.issuer.pubkey.key_hex;
    const attacker = generateIssuerKey('urn:crovia:seal-issuer:attacker');
    s.issuer.pubkey.key_hex = attacker.publicHex;
    const payload = computePayload(s);
    s.signature.sig_hex = toHex(attacker.sign(payload));

    // Unpinned: self-consistent, passes.
    expect(verifySeal(s).ok).toBe(true);

    // Pinned to original issuer: fails.
    const r = verifySeal(s, { issuerPubkeyHex: originalPubkey });
    expect(r.ok).toBe(false);
    expect(r.errors.some(e => e.includes('issuer public key mismatch'))).toBe(true);
  });
});


describe('Structural tampering', () => {
  it('unknown top-level field rejected', () => {
    const s = cloneSeal(basic()) as unknown as Record<string, unknown>;
    s.secret_backdoor = 1;
    expectRejects(s);
  });

  it('removed required field rejected', () => {
    const s = cloneSeal(basic()) as unknown as Record<string, unknown>;
    delete s.timestamp;
    expectRejects(s);
  });
});


describe('Cross-protocol replay', () => {
  it('signature on DOMAIN||canonical does NOT validate on canonical alone', () => {
    const issuer = generateIssuerKey('urn:crovia:seal-issuer:replay');
    const s = emitSeal({
      issuerKey: issuer,
      inputBytes: new TextEncoder().encode('x'),
      outputBytes: new TextEncoder().encode('y'),
      modality: 'text',
      generatorId: 'm',
    });
    const sig = fromHex(s.signature.sig_hex);

    // Canonical WITHOUT the domain prefix:
    const stripped: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(s)) {
      if (k === 'signature' || k === 'witnesses') continue;
      stripped[k] = v;
    }
    const naked = canonicalize(stripped as Record<string, never>);
    const pub = loadPublicKey(issuer.publicHex);
    // Without domain prefix, signature must NOT validate.
    expect(pub.verify(sig, naked)).toBe(false);
  });
});
