/**
 * Public API of @crovia/seal.
 */
export {
  SEAL_VERSION,
  SIGNATURE_DOMAIN,
  CANON_ID,
  PAYLOAD_HASH_ALG,
  SIGNATURE_ALG,
  ALLOWED_MODALITIES,
} from './constants.js';

export {
  CroviaSealError,
  CanonicalizationError,
  NonCanonicalNumber,
  DuplicateKey,
  NonStringKey,
  UnsupportedType,
  SchemaError,
  VerificationError,
  ChainError,
} from './errors.js';

export {
  canonicalize,
  type JsonValue,
} from './canonical.js';

export {
  generateIssuerKey,
  loadIssuerKey,
  loadPublicKey,
  type IssuerKey,
  type PublicKey,
} from './keys.js';

export {
  emitSeal,
  verifySeal,
  computePayload,
  computeSealHash,
  validateStructure,
  type Seal,
  type VerifyResult,
  type VerifyOptions,
  type EmitSealOptions,
  type Modality,
} from './seal.js';
