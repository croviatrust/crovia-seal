"""
crovia-receipt — Crovia Receipt (crovia.receipt.v1): lightweight continuity receipts for AI outputs.

A Receipt is NOT a Crovia Seal (crovia.seal.v1). For Seals use the `crovia-seal` package.

Public API:
    seal(payload, *, key=None, prev_receipt=None, payload_type=None) -> dict
    verify(receipt, payload=...)                                      -> VerifyResult
    verify_chain(receipts)                                            -> VerifyResult
    register(receipt, *, endpoint=..., timeout_sec=10.0)              -> RegisterResult
    generate_key()                                                    -> KeyPair
    canonicalize(value)                                               -> bytes

Wire format: crovia.receipt.v1 (Ed25519 + CSC-1 canonical JSON).
Cross-language byte identity with the @crovia/receipt JavaScript SDK is
part of the conformance contract.
"""
from crovia_receipt.canonical import (
    CanonicalizationError,
    canonicalize,
)
from crovia_receipt.keys import (
    KeyPair,
    generate_key,
    public_from_private,
    sign_bytes,
    verify_bytes,
)
from crovia_receipt.seal import (
    DOMAIN_BYTES,
    DOMAIN_STRING,
    PAYLOAD_ALG,
    RECEIPT_VERSION,
    Receipt,
    compute_payload,
    seal,
    validate_receipt_shape,
)
from crovia_receipt.verify import (
    VerifyResult,
    verify,
    verify_chain,
)
from crovia_receipt.register import (
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
