/**
 * `seal()` — produce a continuity receipt over an arbitrary JSON payload.
 *
 * Receipt format: `crovia.receipt.v1`. See types.ts for the schema.
 *
 * Wire format guarantees:
 *   - Canonical JSON via CSC-1 (byte-identical with Python reference)
 *   - Ed25519 signatures over `b"CROVIA-RECEIPT-v1\n" || csc1(receipt without sig)`
 *   - Domain separator `CROVIA-RECEIPT-v1` distinct from `CROVIA-SEAL-v1`,
 *     so a receipt signature cannot be replayed as a Seal v1 signature.
 *   - SHA-256 over canonical bytes of `payload` for `payload_hash`.
 */
import { sha256 } from "@noble/hashes/sha256";

import { canonicalize } from "./canonical.js";
import {
  bytesToHex,
  generateKeySync,
  hexToBytes,
  randomBytes,
  signBytes,
} from "./keys.js";
import type { KeyPair, Receipt, SealOptions } from "./types.js";

const RECEIPT_VERSION = "crovia.receipt.v1" as const;
const DOMAIN_STRING = "CROVIA-RECEIPT-v1" as const;
const DOMAIN_BYTES = new TextEncoder().encode(DOMAIN_STRING + "\n");
const CANON_ID = "csc-1" as const;
const SIG_ALG = "ed25519" as const;
const PAYLOAD_ALG = "sha256" as const;
const RECEIPT_ID_RE = /^cr_[0-9]{4}_[A-Z2-7]{26}$/;

// 16 random bytes encoded as base32 (no padding) gives 26 chars.
function randomB32(nBytes = 16): string {
  const buf = randomBytes(nBytes);
  // RFC 4648 base32 alphabet, uppercase.
  const ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let out = "";
  let bits = 0;
  let acc = 0;
  for (let i = 0; i < buf.length; i++) {
    acc = (acc << 8) | buf[i]!;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out += ALPHA[(acc >>> bits) & 0x1f];
    }
  }
  if (bits > 0) {
    out += ALPHA[(acc << (5 - bits)) & 0x1f];
  }
  return out.slice(0, 26);
}

function newReceiptId(): string {
  const year = new Date().getUTCFullYear();
  return `cr_${year}_${randomB32()}`;
}

function nowRfc3339Ms(): string {
  const d = new Date();
  // toISOString gives e.g. "2026-05-07T15:43:57.123Z" — exactly the shape
  // the Python reference uses for its emitted_at field.
  return d.toISOString();
}

function sha256Prefixed(data: Uint8Array): string {
  return "sha256:" + bytesToHex(sha256(data));
}

/**
 * Compute the exact bytes that are signed.
 * `payload` here is the receipt object minus its `sig` field.
 */
export function computePayload(
  receiptWithoutSig: Omit<Receipt, "sig">,
): Uint8Array {
  const canonical = canonicalize(receiptWithoutSig);
  const out = new Uint8Array(DOMAIN_BYTES.length + canonical.length);
  out.set(DOMAIN_BYTES, 0);
  out.set(canonical, DOMAIN_BYTES.length);
  return out;
}

/**
 * Validate the structural shape of a receipt object.
 * Returns `null` on success or an error string on failure.
 */
export function validateReceiptShape(r: unknown): string | null {
  if (!r || typeof r !== "object") return "receipt must be an object";
  const o = r as Record<string, unknown>;
  if (o["v"] !== RECEIPT_VERSION) return `v must be "${RECEIPT_VERSION}"`;
  if (typeof o["id"] !== "string" || !RECEIPT_ID_RE.test(o["id"] as string)) {
    return "id must match cr_YYYY_<26 base32 chars>";
  }
  if (
    typeof o["issued_at"] !== "string" ||
    !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(
      o["issued_at"] as string,
    )
  ) {
    return "issued_at must be RFC 3339 UTC with ms precision";
  }
  if (
    typeof o["payload_hash"] !== "string" ||
    !/^sha256:[0-9a-f]{64}$/.test(o["payload_hash"] as string)
  ) {
    return "payload_hash must be 'sha256:<64 hex>'";
  }
  if (o["payload_alg"] !== PAYLOAD_ALG) {
    return `payload_alg must be "${PAYLOAD_ALG}"`;
  }
  if (
    o["payload_type"] !== undefined &&
    typeof o["payload_type"] !== "string"
  ) {
    return "payload_type must be string when present";
  }
  if (o["prev"] !== null) {
    if (
      typeof o["prev"] !== "string" ||
      !RECEIPT_ID_RE.test(o["prev"] as string)
    ) {
      return "prev must be null or a valid receipt id";
    }
  }
  if (
    typeof o["seq"] !== "number" ||
    !Number.isInteger(o["seq"] as number) ||
    (o["seq"] as number) < 0
  ) {
    return "seq must be a non-negative integer";
  }
  if (
    (o["seq"] as number) === 0 &&
    o["prev"] !== null
  ) {
    return "seq=0 (genesis) requires prev=null";
  }
  if ((o["seq"] as number) > 0 && o["prev"] === null) {
    return "seq>0 requires prev to be a receipt id";
  }
  if (
    typeof o["signer"] !== "string" ||
    !/^[0-9a-f]{64}$/.test(o["signer"] as string)
  ) {
    return "signer must be 64 lowercase hex chars";
  }
  if (o["sig_alg"] !== SIG_ALG) return `sig_alg must be "${SIG_ALG}"`;
  if (o["canon"] !== CANON_ID) return `canon must be "${CANON_ID}"`;
  if (o["domain"] !== DOMAIN_STRING) {
    return `domain must be "${DOMAIN_STRING}"`;
  }
  if (
    typeof o["sig"] !== "string" ||
    !/^[0-9a-f]{128}$/.test(o["sig"] as string)
  ) {
    return "sig must be 128 lowercase hex chars";
  }
  return null;
}

/**
 * Produce a continuity receipt over an arbitrary JSON payload.
 *
 * Default behaviour: generates a fresh ephemeral key for this call.
 * Pass `opts.key` to use your own key (recommended for chains).
 */
export async function seal(
  payload: unknown,
  opts: SealOptions = {},
): Promise<Receipt> {
  const key: KeyPair = opts.key ?? generateKeySync();

  // Hash the canonical bytes of the user's payload. This is what makes
  // the receipt verifiable WITHOUT carrying the payload itself: anyone
  // with the original bytes can recompute the hash and check it against
  // payload_hash.
  const payloadCanonical = canonicalize(payload);
  const payloadHash = sha256Prefixed(payloadCanonical);

  const prev: string | null = opts.prevReceipt?.id ?? null;
  const seq: number = opts.prevReceipt
    ? opts.prevReceipt.seq + 1
    : 0;

  const issuedAt =
    opts.issuedAt ??
    nowRfc3339Ms();

  const unsignedShape: Omit<Receipt, "sig"> = {
    v: RECEIPT_VERSION,
    id: newReceiptId(),
    issued_at: issuedAt,
    payload_hash: payloadHash,
    payload_alg: PAYLOAD_ALG,
    ...(opts.payloadType !== undefined && {
      payload_type: opts.payloadType,
    }),
    prev,
    seq,
    signer: key.publicHex,
    sig_alg: SIG_ALG,
    canon: CANON_ID,
    domain: DOMAIN_STRING,
  };

  const signingPayload = computePayload(unsignedShape);
  const sigHex = await signBytes(key.privateHex, signingPayload);

  const receipt: Receipt = {
    ...unsignedShape,
    sig: sigHex,
  };

  // Defense in depth: ensure what we return validates.
  const err = validateReceiptShape(receipt);
  if (err !== null) {
    throw new Error(`internal: produced invalid receipt — ${err}`);
  }

  return receipt;
}

export {
  bytesToHex,
  hexToBytes,
  RECEIPT_VERSION,
  DOMAIN_STRING,
  DOMAIN_BYTES,
};
