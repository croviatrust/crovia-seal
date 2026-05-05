"""
Protocol constants for Crovia Seal v1.

These values are frozen by the specification and MUST NOT be changed by
implementers. Changing any of these constants would produce non-conformant
signatures that no other implementation can verify.
"""
from __future__ import annotations

# --- Protocol identifiers ---------------------------------------------------

#: The literal string that identifies this version of the Seal format.
#: Present in the signed payload, cannot be downgraded by an attacker.
SEAL_VERSION: str = "crovia.seal.v1"

#: Domain separator prepended to every signing payload. Prevents signatures
#: from being replayed as valid in any other protocol that does not use the
#: exact same 14-byte prefix followed by a newline (0x0A).
SIGNATURE_DOMAIN: str = "CROVIA-SEAL-v1"

#: Byte representation of the domain separator, including the trailing LF.
#: Length MUST be exactly 15 bytes.
SIGNATURE_DOMAIN_BYTES: bytes = SIGNATURE_DOMAIN.encode("ascii") + b"\n"
assert len(SIGNATURE_DOMAIN_BYTES) == 15, "domain separator length invariant"

#: Identifier of the canonicalization scheme (Section 3 of the specification).
CANON_ID: str = "csc-1"

#: Hash algorithm used for digests embedded in the Seal (content hashes,
#: chain links). Note: this is NOT the signature hash; Ed25519 uses SHA-512
#: internally per RFC 8032.
PAYLOAD_HASH_ALG: str = "sha256"

#: Signature algorithm.
SIGNATURE_ALG: str = "ed25519"

# --- Format specifications --------------------------------------------------

#: Regex for seal_id: cs_<4-digit year>_<26 base32 chars>.
SEAL_ID_REGEX: str = r"^cs_[0-9]{4}_[A-Z2-7]{26}$"

#: Length in bytes of the random component of seal_id and timestamp.nonce.
RANDOM_BYTES: int = 16

#: Length in base32 chars of the encoded 16-byte random value (no padding).
RANDOM_B32_CHARS: int = 26

#: Allowed values for subject.modality.
ALLOWED_MODALITIES: frozenset = frozenset({
    "text", "code", "image", "audio", "multimodal",
})

#: Safe integer range (JSON numbers that can be round-tripped via JavaScript).
#: Inherited from RFC 8785 to maximize interoperability.
JS_SAFE_INT_MIN: int = -(2 ** 53) + 1
JS_SAFE_INT_MAX: int = (2 ** 53) - 1
