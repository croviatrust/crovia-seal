/**
 * Exception hierarchy mirroring Python.
 */

export class CroviaSealError extends Error {
  constructor(message: string) {
    super(message);
    this.name = new.target.name;
    // Preserve V8 stack traces.
    if (typeof (Error as unknown as { captureStackTrace?: Function }).captureStackTrace === 'function') {
      (Error as unknown as { captureStackTrace: Function }).captureStackTrace(this, new.target);
    }
  }
}

// --- Canonicalization ------------------------------------------------------

export class CanonicalizationError extends CroviaSealError {}
export class NonCanonicalNumber extends CanonicalizationError {}
export class DuplicateKey extends CanonicalizationError {}
export class NonStringKey extends CanonicalizationError {}
export class UnsupportedType extends CanonicalizationError {}

// --- Schema ----------------------------------------------------------------

export class SchemaError extends CroviaSealError {}

// --- Verification ----------------------------------------------------------

export class VerificationError extends CroviaSealError {}
export class ChainError extends CroviaSealError {}
