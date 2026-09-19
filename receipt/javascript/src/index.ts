/**
 * @crovia/seal — Immutable continuity receipts for evolving AI systems.
 *
 * Public API:
 *   seal(payload, opts?)            → Receipt
 *   verify(receipt, payload?)       → VerifyResult
 *   verifyChain(receipts)           → VerifyResult
 *   register(receipt, opts?)        → RegisterResult   (optional)
 *   generateKey() / generateKeySync() → KeyPair
 *   canonicalize(value)             → Uint8Array
 *
 * Wire format: crovia.receipt.v1 (Ed25519 + CSC-1 canonical JSON).
 * Cross-language byte-identity with the Python reference is part of
 * the conformance contract.
 */
export { seal, computePayload, validateReceiptShape } from "./seal.js";
export { verify, verifyChain } from "./verify.js";
export { register } from "./register.js";
export {
  generateKey,
  generateKeySync,
  publicFromPrivate,
  signBytes,
  verifyBytes,
} from "./keys.js";
export { canonicalize, canonicalizeString, CanonicalizationError } from "./canonical.js";

export type {
  Receipt,
  KeyPair,
  SealOptions,
  VerifyResult,
  RegisterOptions,
  RegisterResult,
} from "./types.js";
