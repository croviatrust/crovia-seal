/**
 * Seal issuance and verification.
 *
 * TypeScript port of `crovia_seal/seal.py`. Byte-identical output required
 * for cross-language conformance.
 */
import {
  ALLOWED_MODALITIES,
  B32_26_REGEX,
  CANON_ID,
  HEX128_REGEX,
  HEX64_REGEX,
  PAYLOAD_HASH_ALG,
  RANDOM_BYTES,
  RFC3339_MS_REGEX,
  SEAL_ID_REGEX,
  SEAL_VERSION,
  SHA256_PREFIX,
  SIGNATURE_ALG,
  SIGNATURE_DOMAIN,
  SIGNATURE_DOMAIN_BYTES,
} from './constants.js';
import { SchemaError } from './errors.js';
import { canonicalize, type JsonValue } from './canonical.js';
import {
  type IssuerKey,
  loadPublicKey,
} from './keys.js';
import { fromHex, toHex } from './util/hex.js';
import { sha256Hex, sha256Prefixed } from './util/hash.js';
import { toBase32NoPad } from './util/base32.js';
import { randomBytes } from './util/random.js';


// --- Types -----------------------------------------------------------------

export type Modality = 'text' | 'code' | 'image' | 'audio' | 'multimodal';

export interface Seal {
  seal_version: typeof SEAL_VERSION;
  seal_id: string;
  issuer: { id: string; pubkey: { alg: typeof SIGNATURE_ALG; key_hex: string } };
  subject: {
    input_hash: string;
    output_hash: string;
    input_len: number;
    output_len: number;
    modality: Modality;
  };
  generator: {
    id: string;
    version: string | null;
    weights_hash: string | null;
    params: Record<string, string>;
  };
  timestamp: { emitted_at: string; nonce: string };
  chain: { prev_seal_hash: string | null; sequence: number };
  checks?: Record<string, unknown>;
  anchor?: {
    log_url: string;
    merkle_root: string;
    merkle_proof: string[];
    log_index: number;
    root_signed_at: string;
  };
  signature: {
    alg: typeof SIGNATURE_ALG;
    canon: typeof CANON_ID;
    domain: typeof SIGNATURE_DOMAIN;
    payload_hash_alg: typeof PAYLOAD_HASH_ALG;
    sig_hex: string;
  };
  witnesses?: Array<{
    id: string;
    pubkey: { alg: typeof SIGNATURE_ALG; key_hex: string };
    sig_hex: string;
  }>;
}


export interface EmitSealOptions {
  issuerKey: IssuerKey;
  inputBytes: Uint8Array;
  outputBytes: Uint8Array;
  modality: Modality;
  generatorId: string;
  generatorVersion?: string | null;
  generatorWeightsHash?: string | null;
  generatorParams?: Record<string, string>;
  sequence?: number;
  prevSealHash?: string | null;
  checks?: Record<string, unknown>;
  anchor?: Seal['anchor'];
}


// --- Helpers ---------------------------------------------------------------

function _randomB32(n: number = RANDOM_BYTES): string {
  const b32 = toBase32NoPad(randomBytes(n));
  if (!B32_26_REGEX.test(b32)) {
    throw new Error('base32 alphabet invariant violated');
  }
  return b32;
}

function _newSealId(): string {
  const year = new Date().getUTCFullYear();
  return `cs_${year}_${_randomB32()}`;
}

function _nowRfc3339Ms(): string {
  const d = new Date();
  // Build string manually to guarantee exact "YYYY-MM-DDTHH:MM:SS.sssZ" form.
  const pad = (n: number, w: number) => n.toString().padStart(w, '0');
  return (
    `${pad(d.getUTCFullYear(), 4)}-${pad(d.getUTCMonth() + 1, 2)}-${pad(d.getUTCDate(), 2)}` +
    `T${pad(d.getUTCHours(), 2)}:${pad(d.getUTCMinutes(), 2)}:${pad(d.getUTCSeconds(), 2)}` +
    `.${pad(d.getUTCMilliseconds(), 3)}Z`
  );
}


// --- Payload ---------------------------------------------------------------

/**
 * Return the exact byte sequence that is signed.
 *   payload = DOMAIN || "\n" || CSC1(seal \ {signature, witnesses})
 */
export function computePayload(seal: Partial<Seal>): Uint8Array {
  if (typeof seal !== 'object' || seal === null) {
    throw new TypeError('seal must be an object');
  }
  const stripped: Record<string, JsonValue> = {};
  for (const [k, v] of Object.entries(seal)) {
    if (k === 'signature' || k === 'witnesses') continue;
    stripped[k] = v as JsonValue;
  }
  const canonical = canonicalize(stripped);
  const out = new Uint8Array(SIGNATURE_DOMAIN_BYTES.length + canonical.length);
  out.set(SIGNATURE_DOMAIN_BYTES, 0);
  out.set(canonical, SIGNATURE_DOMAIN_BYTES.length);
  return out;
}


/** Return 'sha256:<hex>' of the signing payload. */
export function computeSealHash(seal: Seal): string {
  return sha256Prefixed(computePayload(seal));
}


// --- Schema validation -----------------------------------------------------

const REQUIRED_TOP = [
  'seal_version', 'seal_id', 'issuer', 'subject',
  'generator', 'timestamp', 'chain', 'signature',
] as const;
const OPTIONAL_TOP = ['checks', 'anchor', 'witnesses'] as const;
const ALLOWED_TOP = new Set<string>([...REQUIRED_TOP, ...OPTIONAL_TOP]);


function _require(cond: boolean, msg: string): void {
  if (!cond) throw new SchemaError(msg);
}

function _isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function _isNonNegativeInt(v: unknown): v is number {
  return typeof v === 'number' && Number.isInteger(v) && v >= 0;
}

function _isSha256Prefixed(v: unknown): v is string {
  if (typeof v !== 'string') return false;
  if (!v.startsWith(SHA256_PREFIX)) return false;
  return HEX64_REGEX.test(v.slice(SHA256_PREFIX.length));
}


export function validateStructure(seal: unknown): asserts seal is Seal {
  _require(_isPlainObject(seal), 'seal must be a JSON object');
  const s = seal as Record<string, unknown>;

  // Unknown top-level fields -> reject (fail-closed).
  for (const k of Object.keys(s)) {
    _require(ALLOWED_TOP.has(k), `unknown top-level field: ${k}`);
  }
  for (const k of REQUIRED_TOP) {
    _require(k in s, `missing required top-level field: ${k}`);
  }

  // seal_version
  _require(s.seal_version === SEAL_VERSION,
    `seal_version must be "${SEAL_VERSION}"`);

  // seal_id
  _require(typeof s.seal_id === 'string' && SEAL_ID_REGEX.test(s.seal_id as string),
    'seal_id must match cs_YYYY_<26 base32 chars>');

  // issuer
  _require(_isPlainObject(s.issuer), 'issuer must be object');
  const iss = s.issuer as Record<string, unknown>;
  _require(Object.keys(iss).sort().join(',') === 'id,pubkey',
    'issuer must have exactly {id, pubkey}');
  _require(typeof iss.id === 'string' && (iss.id as string).length > 0,
    'issuer.id must be non-empty string');
  _require(_isPlainObject(iss.pubkey), 'issuer.pubkey must be object');
  const pk = iss.pubkey as Record<string, unknown>;
  _require(Object.keys(pk).sort().join(',') === 'alg,key_hex',
    'issuer.pubkey must have exactly {alg, key_hex}');
  _require(pk.alg === SIGNATURE_ALG, `issuer.pubkey.alg must be "${SIGNATURE_ALG}"`);
  _require(typeof pk.key_hex === 'string' && HEX64_REGEX.test(pk.key_hex as string),
    'issuer.pubkey.key_hex must be 64 lowercase hex chars');

  // subject
  _require(_isPlainObject(s.subject), 'subject must be object');
  const sub = s.subject as Record<string, unknown>;
  _require(Object.keys(sub).sort().join(',') === 'input_hash,input_len,modality,output_hash,output_len',
    'subject must have exactly {input_hash, output_hash, input_len, output_len, modality}');
  _require(_isSha256Prefixed(sub.input_hash), "subject.input_hash must be 'sha256:<64 hex>'");
  _require(_isSha256Prefixed(sub.output_hash), "subject.output_hash must be 'sha256:<64 hex>'");
  _require(_isNonNegativeInt(sub.input_len), 'subject.input_len must be non-negative integer');
  _require(_isNonNegativeInt(sub.output_len), 'subject.output_len must be non-negative integer');
  _require(typeof sub.modality === 'string' && ALLOWED_MODALITIES.has(sub.modality as string),
    `subject.modality must be one of ${[...ALLOWED_MODALITIES].sort().join(', ')}`);

  // generator
  _require(_isPlainObject(s.generator), 'generator must be object');
  const gen = s.generator as Record<string, unknown>;
  _require(Object.keys(gen).sort().join(',') === 'id,params,version,weights_hash',
    'generator must have exactly {id, version, weights_hash, params}');
  _require(typeof gen.id === 'string' && (gen.id as string).length > 0,
    'generator.id must be non-empty string');
  _require(gen.version === null || typeof gen.version === 'string',
    'generator.version must be string or null');
  _require(gen.weights_hash === null || _isSha256Prefixed(gen.weights_hash),
    "generator.weights_hash must be 'sha256:<64 hex>' or null");
  _require(_isPlainObject(gen.params), 'generator.params must be object');
  for (const [k, v] of Object.entries(gen.params as object)) {
    _require(typeof k === 'string', 'generator.params keys must be strings');
    _require(typeof v === 'string',
      `generator.params[${JSON.stringify(k)}] must be string ` +
      '(encode numeric params as strings per SPEC 4.6)');
  }

  // timestamp
  _require(_isPlainObject(s.timestamp), 'timestamp must be object');
  const ts = s.timestamp as Record<string, unknown>;
  _require(Object.keys(ts).sort().join(',') === 'emitted_at,nonce',
    'timestamp must have exactly {emitted_at, nonce}');
  _require(typeof ts.emitted_at === 'string' && RFC3339_MS_REGEX.test(ts.emitted_at as string),
    'timestamp.emitted_at must be RFC 3339 UTC with ms precision');
  _require(typeof ts.nonce === 'string' && B32_26_REGEX.test(ts.nonce as string),
    'timestamp.nonce must be 26 RFC 4648 base32 chars');

  // chain
  _require(_isPlainObject(s.chain), 'chain must be object');
  const ch = s.chain as Record<string, unknown>;
  _require(Object.keys(ch).sort().join(',') === 'prev_seal_hash,sequence',
    'chain must have exactly {prev_seal_hash, sequence}');
  _require(_isNonNegativeInt(ch.sequence), 'chain.sequence must be non-negative integer');
  if (ch.sequence === 0) {
    _require(ch.prev_seal_hash === null,
      'chain.prev_seal_hash must be null for sequence==0 (genesis)');
  } else {
    _require(_isSha256Prefixed(ch.prev_seal_hash),
      "chain.prev_seal_hash must be 'sha256:<64 hex>' for sequence>=1");
  }

  // checks (optional)
  if ('checks' in s) {
    _require(_isPlainObject(s.checks), 'checks must be object if present');
  }

  // anchor (optional)
  if ('anchor' in s) {
    _require(_isPlainObject(s.anchor), 'anchor must be object if present');
    const an = s.anchor as Record<string, unknown>;
    _require(Object.keys(an).sort().join(',') === 'log_index,log_url,merkle_proof,merkle_root,root_signed_at',
      'anchor must have exactly the 5 specified keys');
    _require(typeof an.log_url === 'string' && (an.log_url as string).length > 0,
      'anchor.log_url must be non-empty string');
    _require(_isSha256Prefixed(an.merkle_root), "anchor.merkle_root must be 'sha256:<64 hex>'");
    _require(Array.isArray(an.merkle_proof), 'anchor.merkle_proof must be array');
    for (const item of an.merkle_proof as unknown[]) {
      _require(_isSha256Prefixed(item), "each merkle_proof element must be 'sha256:<64 hex>'");
    }
    _require(_isNonNegativeInt(an.log_index), 'anchor.log_index must be non-negative integer');
    _require(typeof an.root_signed_at === 'string', 'anchor.root_signed_at must be string');
  }

  // signature
  _require(_isPlainObject(s.signature), 'signature must be object');
  const sig = s.signature as Record<string, unknown>;
  _require(Object.keys(sig).sort().join(',') === 'alg,canon,domain,payload_hash_alg,sig_hex',
    'signature must have exactly the 5 specified keys');
  _require(sig.alg === SIGNATURE_ALG, `signature.alg must be "${SIGNATURE_ALG}"`);
  _require(sig.canon === CANON_ID, `signature.canon must be "${CANON_ID}"`);
  _require(sig.domain === SIGNATURE_DOMAIN, `signature.domain must be "${SIGNATURE_DOMAIN}"`);
  _require(sig.payload_hash_alg === PAYLOAD_HASH_ALG,
    `signature.payload_hash_alg must be "${PAYLOAD_HASH_ALG}"`);
  _require(typeof sig.sig_hex === 'string' && HEX128_REGEX.test(sig.sig_hex as string),
    'signature.sig_hex must be 128 lowercase hex chars');

  // witnesses (optional)
  if ('witnesses' in s) {
    _require(Array.isArray(s.witnesses), 'witnesses must be array if present');
    const wl = s.witnesses as unknown[];
    for (let i = 0; i < wl.length; i++) {
      const w = wl[i];
      _require(_isPlainObject(w), `witnesses[${i}] must be object`);
      const wr = w as Record<string, unknown>;
      _require(Object.keys(wr).sort().join(',') === 'id,pubkey,sig_hex',
        `witnesses[${i}] must have exactly {id, pubkey, sig_hex}`);
      _require(typeof wr.id === 'string' && (wr.id as string).length > 0,
        `witnesses[${i}].id must be non-empty string`);
      _require(_isPlainObject(wr.pubkey), `witnesses[${i}].pubkey must be object`);
      const wpk = wr.pubkey as Record<string, unknown>;
      _require(Object.keys(wpk).sort().join(',') === 'alg,key_hex',
        `witnesses[${i}].pubkey must have exactly {alg, key_hex}`);
      _require(wpk.alg === SIGNATURE_ALG,
        `witnesses[${i}].pubkey.alg must be "${SIGNATURE_ALG}"`);
      _require(typeof wpk.key_hex === 'string' && HEX64_REGEX.test(wpk.key_hex as string),
        `witnesses[${i}].pubkey.key_hex must be 64 hex chars`);
      _require(typeof wr.sig_hex === 'string' && HEX128_REGEX.test(wr.sig_hex as string),
        `witnesses[${i}].sig_hex must be 128 hex chars`);
    }
  }
}


// --- Issuance --------------------------------------------------------------

export function emitSeal(opts: EmitSealOptions): Seal {
  const {
    issuerKey,
    inputBytes,
    outputBytes,
    modality,
    generatorId,
    generatorVersion = null,
    generatorWeightsHash = null,
    generatorParams,
    sequence = 0,
    prevSealHash = null,
    checks,
    anchor,
  } = opts;

  if (!(inputBytes instanceof Uint8Array)) throw new TypeError('inputBytes must be Uint8Array');
  if (!(outputBytes instanceof Uint8Array)) throw new TypeError('outputBytes must be Uint8Array');
  if (!ALLOWED_MODALITIES.has(modality)) {
    throw new Error(`modality must be one of ${[...ALLOWED_MODALITIES].join(', ')}`);
  }
  if (!Number.isInteger(sequence) || sequence < 0) {
    throw new Error('sequence must be non-negative integer');
  }
  if (sequence === 0 && prevSealHash !== null) {
    throw new Error('genesis Seal (sequence==0) must have prevSealHash=null');
  }
  if (sequence > 0 && prevSealHash === null) {
    throw new Error('non-genesis Seal (sequence>=1) requires prevSealHash');
  }

  const params: Record<string, string> = {};
  if (generatorParams) {
    for (const [k, v] of Object.entries(generatorParams)) {
      if (typeof k !== 'string' || typeof v !== 'string') {
        throw new TypeError('generatorParams must be Record<string, string>');
      }
      params[k] = v;
    }
  }

  const unsigned: Partial<Seal> = {
    seal_version: SEAL_VERSION,
    seal_id: _newSealId(),
    issuer: {
      id: issuerKey.issuerId,
      pubkey: { alg: SIGNATURE_ALG, key_hex: issuerKey.publicHex },
    },
    subject: {
      input_hash: SHA256_PREFIX + sha256Hex(inputBytes),
      output_hash: SHA256_PREFIX + sha256Hex(outputBytes),
      input_len: inputBytes.length,
      output_len: outputBytes.length,
      modality,
    },
    generator: {
      id: generatorId,
      version: generatorVersion,
      weights_hash: generatorWeightsHash,
      params,
    },
    timestamp: {
      emitted_at: _nowRfc3339Ms(),
      nonce: _randomB32(),
    },
    chain: {
      prev_seal_hash: prevSealHash,
      sequence,
    },
  };
  if (checks !== undefined) unsigned.checks = checks;
  if (anchor !== undefined) unsigned.anchor = anchor;

  const payload = computePayload(unsigned);
  const sig = issuerKey.sign(payload);
  const signed: Seal = {
    ...(unsigned as Seal),
    signature: {
      alg: SIGNATURE_ALG,
      canon: CANON_ID,
      domain: SIGNATURE_DOMAIN,
      payload_hash_alg: PAYLOAD_HASH_ALG,
      sig_hex: toHex(sig),
    },
  };

  // Defence in depth.
  validateStructure(signed);
  return signed;
}


// --- Verification ----------------------------------------------------------

export interface VerifyResult {
  ok: boolean;
  sealId: string | null;
  issuerId: string | null;
  issuerPubkeyHex: string | null;
  witnessCount: number;
  errors: string[];
}


export interface VerifyOptions {
  issuerPubkeyHex?: string;
  requireWitnesses?: number;
}


export function verifySeal(seal: unknown, opts: VerifyOptions = {}): VerifyResult {
  const result: VerifyResult = {
    ok: false,
    sealId: null,
    issuerId: null,
    issuerPubkeyHex: null,
    witnessCount: 0,
    errors: [],
  };

  try {
    validateStructure(seal);
  } catch (e) {
    result.errors.push(`schema: ${(e as Error).message}`);
    return result;
  }

  const s = seal as Seal;
  result.sealId = s.seal_id;
  result.issuerId = s.issuer.id;
  result.issuerPubkeyHex = s.issuer.pubkey.key_hex;

  if (opts.issuerPubkeyHex !== undefined) {
    if (opts.issuerPubkeyHex.toLowerCase() !== result.issuerPubkeyHex) {
      result.errors.push(
        `issuer public key mismatch: seal claims ${result.issuerPubkeyHex}, ` +
        `caller pinned ${opts.issuerPubkeyHex.toLowerCase()}`,
      );
      return result;
    }
  }

  let payload: Uint8Array;
  try {
    payload = computePayload(s);
  } catch (e) {
    result.errors.push(`payload-construction: ${(e as Error).message}`);
    return result;
  }

  try {
    const pub = loadPublicKey(result.issuerPubkeyHex!);
    const sigBytes = fromHex(s.signature.sig_hex);
    if (!pub.verify(sigBytes, payload)) {
      result.errors.push('signature: invalid');
      return result;
    }
  } catch (e) {
    result.errors.push(`signature-verification: ${(e as Error).message}`);
    return result;
  }

  // Witnesses
  const witnesses = s.witnesses ?? [];
  let validWitnesses = 0;
  for (let i = 0; i < witnesses.length; i++) {
    const w = witnesses[i]!;
    try {
      const wpub = loadPublicKey(w.pubkey.key_hex);
      const wsig = fromHex(w.sig_hex);
      if (!wpub.verify(wsig, payload)) {
        result.errors.push(`witness[${i}] signature: invalid`);
        return result;
      }
      validWitnesses++;
    } catch (e) {
      result.errors.push(`witness[${i}] verification: ${(e as Error).message}`);
      return result;
    }
  }
  result.witnessCount = validWitnesses;

  const required = opts.requireWitnesses ?? 0;
  if (validWitnesses < required) {
    result.errors.push(
      `requireWitnesses=${required} but only ${validWitnesses} valid witnesses present`,
    );
    return result;
  }

  result.ok = true;
  return result;
}
