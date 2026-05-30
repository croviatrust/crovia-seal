/**
 * Typed message protocol between content scripts, popup, and service worker.
 *
 * Server-backed mode: the extension calls seal.croviatrust.com for signing.
 * No local private keys. CIM format matches production check.html.
 */

/** Seal object as returned by the Crovia Seal Service (sl_ format). */
export interface ServerSeal {
  seal_version: string;
  seal_id: string;
  issuer: { id: string; pubkey_alg: string; pubkey: string };
  generator: { vendor: string; model: string };
  subject: { input_hash: string; output_hash: string; output_length: number };
  issued_at: string;
  signature: string;
  [key: string]: unknown;
}

export type RequestType =
  | 'seal_output'
  | 'verify_seal'
  | 'get_public_identity'
  | 'list_recent_seals';

export interface SealOutputRequest {
  type: 'seal_output';
  inputText: string;
  outputText: string;
  generatorId: string;
  generatorVersion?: string;
  site: string;
}
export interface SealOutputResponse {
  ok: boolean;
  seal?: ServerSeal;
  cim?: string;          // the zero-width mark ready to append
  error?: string;
}

export interface VerifySealRequest {
  type: 'verify_seal';
  sealId: string;
}
export interface VerifySealResponse {
  ok: boolean;
  seal?: ServerSeal;
  errors?: string[];
  sealId?: string | null;
}

export interface GetPublicIdentityRequest { type: 'get_public_identity'; }
export interface GetPublicIdentityResponse {
  ok: boolean;
  issuerId?: string;
  publicHex?: string;
  createdAt?: string;
  error?: string;
}

export interface ListRecentSealsRequest { type: 'list_recent_seals'; limit?: number; }
export interface ListRecentSealsResponse {
  ok: boolean;
  seals?: Array<{ sealId: string; emittedAt: string; site: string; excerpt: string }>;
  error?: string;
}

export type AnyRequest =
  | SealOutputRequest
  | VerifySealRequest
  | GetPublicIdentityRequest
  | ListRecentSealsRequest;

export type AnyResponse =
  | SealOutputResponse
  | VerifySealResponse
  | GetPublicIdentityResponse
  | ListRecentSealsResponse;
