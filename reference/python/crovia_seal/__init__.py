"""
Crovia Seal v1 - Reference implementation.

Public API:
    generate_issuer_key()   -> IssuerKey
    load_issuer_key(...)    -> IssuerKey
    emit_seal(...)          -> dict (Seal object)
    verify_seal(seal, ...)  -> VerifyResult
    canonicalize(obj)       -> bytes  (CSC-1 serialization)
    compute_payload(seal)   -> bytes  (domain-separated signing payload)
"""
from crovia_seal.constants import (
    SEAL_VERSION,
    SIGNATURE_DOMAIN,
    CANON_ID,
    PAYLOAD_HASH_ALG,
    SIGNATURE_ALG,
)
from crovia_seal.errors import (
    CroviaSealError,
    CanonicalizationError,
    NonCanonicalNumber,
    DuplicateKey,
    NonStringKey,
    SchemaError,
    VerificationError,
    ChainError,
)
from crovia_seal.canonical import canonicalize
from crovia_seal.keys import (
    IssuerKey,
    generate_issuer_key,
    load_issuer_key,
    load_public_key,
)
from crovia_seal.seal import (
    emit_seal,
    verify_seal,
    compute_payload,
    compute_seal_hash,
    VerifyResult,
)
from crovia_seal.stego import (
    ExtractedCim,
    encode_cim,
    embed_cim,
    extract_cim,
    extract_all_cims,
    strip_cim,
    contains_cim_marker,
    CIM_START,
    CIM_END,
    CIM_TOTAL_LEN,
)
from crovia_seal.beacon import (
    BeaconAnchor,
    BeaconChainInfo,
    quicknet_chain_info,
    wrap_as_seal_anchor,
    fetch_latest as fetch_latest_beacon,
    fetch_round as fetch_beacon_round,
    fetch_chain_info,
    verify_round_online,
)

__version__ = "0.5.0"

__all__ = [
    "SEAL_VERSION",
    "SIGNATURE_DOMAIN",
    "CANON_ID",
    "PAYLOAD_HASH_ALG",
    "SIGNATURE_ALG",
    "CroviaSealError",
    "CanonicalizationError",
    "NonCanonicalNumber",
    "DuplicateKey",
    "NonStringKey",
    "SchemaError",
    "VerificationError",
    "ChainError",
    "canonicalize",
    "IssuerKey",
    "generate_issuer_key",
    "load_issuer_key",
    "load_public_key",
    "emit_seal",
    "verify_seal",
    "compute_payload",
    "compute_seal_hash",
    "VerifyResult",
    "__version__",
]
