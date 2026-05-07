/**
 * `verify()` — check the structure and signature of a receipt.
 *
 * If you also have the original payload, pass it as the second argument
 * to additionally verify the payload_hash. Without the payload, only
 * the signature and structure are checked.
 */
import { sha256 } from "@noble/hashes/sha256";

import { canonicalize } from "./canonical.js";
import { bytesToHex, verifyBytes } from "./keys.js";
import {
  computePayload,
  validateReceiptShape,
} from "./seal.js";
import type { Receipt, VerifyResult } from "./types.js";

function sha256Prefixed(data: Uint8Array): string {
  return "sha256:" + bytesToHex(sha256(data));
}

/**
 * Verify a continuity receipt.
 *
 * @param receipt The receipt object (or any value to be type-checked).
 * @param payload Optional original payload to verify payload_hash against.
 *                If omitted, only the signature and structure are checked.
 * @returns A VerifyResult — never throws.
 */
export async function verify(
  receipt: unknown,
  payload?: unknown,
): Promise<VerifyResult> {
  const errors: string[] = [];

  // Step 1: structural validation.
  const shapeErr = validateReceiptShape(receipt);
  if (shapeErr !== null) {
    errors.push(`schema: ${shapeErr}`);
    return { valid: false, errors };
  }

  const r = receipt as Receipt;

  // Step 2: signature.
  const { sig, ...withoutSig } = r;
  const signingPayload = computePayload(withoutSig);

  let sigOk = false;
  try {
    sigOk = await verifyBytes(r.signer, sig, signingPayload);
  } catch (e) {
    errors.push(
      `signature-verify: ${e instanceof Error ? e.message : String(e)}`,
    );
    return { valid: false, errors };
  }

  if (!sigOk) {
    errors.push("signature: invalid");
    return {
      valid: false,
      errors,
      id: r.id,
      signer: r.signer,
      payloadHash: r.payload_hash,
      prev: r.prev,
      seq: r.seq,
      issuedAt: r.issued_at,
    };
  }

  // Step 3: payload-hash check (only if caller provided the payload).
  if (payload !== undefined) {
    let computed: string;
    try {
      computed = sha256Prefixed(canonicalize(payload));
    } catch (e) {
      errors.push(
        `payload-canonicalize: ${e instanceof Error ? e.message : String(e)}`,
      );
      return { valid: false, errors };
    }
    if (computed !== r.payload_hash) {
      errors.push(
        `payload_hash mismatch: receipt=${r.payload_hash} computed=${computed}`,
      );
      return {
        valid: false,
        errors,
        id: r.id,
        signer: r.signer,
        payloadHash: r.payload_hash,
        prev: r.prev,
        seq: r.seq,
        issuedAt: r.issued_at,
      };
    }
  }

  return {
    valid: true,
    errors: [],
    id: r.id,
    signer: r.signer,
    payloadHash: r.payload_hash,
    prev: r.prev,
    seq: r.seq,
    issuedAt: r.issued_at,
  };
}

/**
 * Verify a chain of receipts in order: each receipt[i].prev must equal
 * receipt[i-1].id, sequence must increment by 1, and signer must remain
 * the same. All signatures must verify.
 *
 * @returns true iff the chain is internally consistent and all sigs valid.
 */
export async function verifyChain(receipts: Receipt[]): Promise<VerifyResult> {
  if (receipts.length === 0) {
    return { valid: false, errors: ["empty chain"] };
  }
  let prevId: string | null = null;
  let prevSeq = -1;
  let signer: string | null = null;
  for (let i = 0; i < receipts.length; i++) {
    const r = receipts[i]!;
    const single = await verify(r);
    if (!single.valid) {
      return {
        valid: false,
        errors: [`chain[${i}] invalid: ${single.errors.join("; ")}`],
      };
    }
    if (signer === null) signer = r.signer;
    else if (signer !== r.signer) {
      return {
        valid: false,
        errors: [`chain[${i}] signer changed from ${signer} to ${r.signer}`],
      };
    }
    if (r.seq !== prevSeq + 1) {
      return {
        valid: false,
        errors: [
          `chain[${i}] seq=${r.seq} but expected ${prevSeq + 1}`,
        ],
      };
    }
    if (r.prev !== prevId) {
      return {
        valid: false,
        errors: [`chain[${i}] prev=${r.prev} but expected ${prevId}`],
      };
    }
    prevId = r.id;
    prevSeq = r.seq;
  }
  return {
    valid: true,
    errors: [],
    id: receipts[receipts.length - 1]!.id,
    signer: signer!,
  };
}
