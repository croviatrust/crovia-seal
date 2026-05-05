"""
Exception hierarchy for Crovia Seal.

All errors raised by this package are subclasses of CroviaSealError, so
callers can catch a single base class to reject any Seal-related failure.
The specific subclasses exist to support defensive code paths (e.g., a
verifier that wants to log canonicalization errors differently from
signature errors).
"""
from __future__ import annotations


class CroviaSealError(Exception):
    """Base class for all Crovia Seal errors."""


# --- Canonicalization errors ------------------------------------------------

class CanonicalizationError(CroviaSealError):
    """Base class for CSC-1 canonicalization failures."""


class NonCanonicalNumber(CanonicalizationError):
    """A JSON value contains a number that is not a CSC-1 integer.

    CSC-1 forbids floating-point, NaN, Infinity, negative zero, and
    integers outside the JavaScript-safe range [-2^53+1, 2^53-1].
    """


class DuplicateKey(CanonicalizationError):
    """An object contains the same key more than once."""


class NonStringKey(CanonicalizationError):
    """An object has a non-string key (not representable in JSON)."""


class UnsupportedType(CanonicalizationError):
    """A value of a type not covered by CSC-1 was encountered."""


# --- Schema errors ----------------------------------------------------------

class SchemaError(CroviaSealError):
    """The Seal does not conform to the structural schema."""


# --- Verification errors ----------------------------------------------------

class VerificationError(CroviaSealError):
    """A Seal failed verification.

    The message contains a precise description of which check failed
    (signature, version, format, witness, anchor).
    """


class ChainError(CroviaSealError):
    """Issuer hash chain integrity error (gap, fork, or wrong link)."""
