"""
crovia-seal — Immutable continuity receipts for evolving AI systems.

Public API:
    seal(payload, *, key=None, prev_receipt=None, payload_type=None) -> dict
    verify(receipt, payload=...)                                      -> VerifyResult
    verify_chain(receipts)                                            -> VerifyResult
    register(receipt, *, endpoint=..., timeout_sec=10.0)              -> RegisterResult
    generate_key()                                                    -> KeyPair
    canonicalize(value)                                               -> bytes

Wire format: crovia.receipt.v1 (Ed25519 + CSC-1 canonical JSON).
Cross-language byte identity with the @crovia/seal JavaScript SDK is
part of the conformance contract.
"""
from crovia_seal.canonical import (
    CanonicalizationError,
    canonicalize,
)
from crovia_seal.keys import (
    KeyPair,
    generate_key,
    public_from_private,
    sign_bytes,
    verify_bytes,
)
from crovia_seal.seal import (
    DOMAIN_BYTES,
    DOMAIN_STRING,
    PAYLOAD_ALG,
    RECEIPT_VERSION,
    Receipt,
    compute_payload,
    seal,
    validate_receipt_shape,
)
from crovia_seal.verify import (
    VerifyResult,
    verify,
    verify_chain,
)
from crovia_seal.register import (
    RegisterResult,
    register,
)

__version__ = "0.1.0"

__all__ = [
    "__version__",
    # canonical
    "canonicalize",
    "CanonicalizationError",
    # keys
    "KeyPair",
    "generate_key",
    "public_from_private",
    "sign_bytes",
    "verify_bytes",
    # seal
    "seal",
    "Receipt",
    "compute_payload",
    "validate_receipt_shape",
    "RECEIPT_VERSION",
    "DOMAIN_STRING",
    "DOMAIN_BYTES",
    "PAYLOAD_ALG",
    # verify
    "verify",
    "verify_chain",
    "VerifyResult",
    # register
    "register",
    "RegisterResult",
]
