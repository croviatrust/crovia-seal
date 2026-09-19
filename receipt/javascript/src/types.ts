/**
 * Core types for @crovia/seal.
 */

/** A signed continuity receipt over an arbitrary JSON payload. */
export interface Receipt {
  /** Format identifier. Always "crovia.receipt.v1" for this version. */
  v: "crovia.receipt.v1";
  /** Receipt identifier: "cr_YYYY_<26 base32 chars>". */
  id: string;
  /** RFC 3339 UTC timestamp with millisecond precision. */
  issued_at: string;
  /** "sha256:<64 lowercase hex>" of the canonical UTF-8 bytes of payload. */
  payload_hash: string;
  /** Hash algorithm used for payload_hash. Currently always "sha256". */
  payload_alg: "sha256";
  /** Optional content-type hint for the payload (free-form, not signed semantics). */
  payload_type?: string;
  /** Previous receipt id from the same signer, or null for genesis. */
  prev: string | null;
  /** Monotonic sequence per signer, 0 for genesis. */
  seq: number;
  /** Signer's Ed25519 public key as 64 lowercase hex chars. */
  signer: string;
  /** Signature algorithm: always "ed25519". */
  sig_alg: "ed25519";
  /** Canonicalization scheme: always "csc-1". */
  canon: "csc-1";
  /** Domain separator string baked into the signed payload. */
  domain: "CROVIA-RECEIPT-v1";
  /** Detached signature over compute_payload(receipt) — 128 lowercase hex. */
  sig: string;
}

/** Options for `seal()`. */
export interface SealOptions {
  /** Bring-your-own Ed25519 key. If omitted, a fresh key is generated for this call. */
  key?: KeyPair;
  /** Previous receipt to chain against (provides prev + seq). */
  prevReceipt?: Receipt;
  /** Optional content-type hint (e.g., "text/plain", "application/json", "model-card"). */
  payloadType?: string;
  /** Override timestamp (testing only — must be RFC 3339 with ms precision). */
  issuedAt?: string;
}

/** Ed25519 key pair, raw 32-byte private + 32-byte public. */
export interface KeyPair {
  /** 64 lowercase hex chars (32 bytes). */
  privateHex: string;
  /** 64 lowercase hex chars (32 bytes). */
  publicHex: string;
}

/** Outcome of `verify()`. */
export interface VerifyResult {
  /** True iff structure, signature, and self-consistency all check out. */
  valid: boolean;
  /** Errors encountered (empty when valid=true). */
  errors: string[];
  /** Receipt id (echoed for convenience). */
  id?: string;
  /** Signer pubkey hex. */
  signer?: string;
  /** payload_hash echoed for the caller to compare against their payload. */
  payloadHash?: string;
  /** prev id, for chain walks. */
  prev?: string | null;
  /** sequence, for chain walks. */
  seq?: number;
  /** issued_at echoed for time-range checks. */
  issuedAt?: string;
}

/** Options for `register()`. */
export interface RegisterOptions {
  /** Substrate URL. Defaults to https://croviatrust.com */
  endpoint?: string;
  /** Optional fetch override (for testing or custom transports). */
  fetch?: typeof globalThis.fetch;
  /** Request timeout in ms. Defaults to 10_000. */
  timeoutMs?: number;
}

/** Outcome of `register()`. */
export interface RegisterResult {
  /** Whether the substrate accepted the receipt. */
  accepted: boolean;
  /** Substrate-assigned anchor id, if any. */
  anchorId?: string;
  /** HTTP status code returned by the substrate. */
  status: number;
  /** Error message if not accepted. */
  error?: string;
}
