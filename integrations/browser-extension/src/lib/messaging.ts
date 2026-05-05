/**
 * Typed message protocol between content scripts, popup, and service worker.
 */
import type { Seal } from '@crovia/seal';

export type RequestType =
  | 'seal_output'
  | 'verify_seal'
  | 'get_public_identity'
  | 'reset_identity'
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
  seal?: Seal;
  cim?: string;          // the zero-width mark ready to append
  error?: string;
}

export interface VerifySealRequest {
  type: 'verify_seal';
  seal: unknown;
  pinnedPubkeyHex?: string;
}
export interface VerifySealResponse {
  ok: boolean;
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

export interface ResetIdentityRequest { type: 'reset_identity'; }
export interface ResetIdentityResponse { ok: boolean; publicHex?: string; error?: string; }

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
  | ResetIdentityRequest
  | ListRecentSealsRequest;

export type AnyResponse =
  | SealOutputResponse
  | VerifySealResponse
  | GetPublicIdentityResponse
  | ResetIdentityResponse
  | ListRecentSealsResponse;
