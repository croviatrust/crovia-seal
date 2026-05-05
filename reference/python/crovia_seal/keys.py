"""
Issuer key management for Crovia Seal.

An IssuerKey wraps an Ed25519 private key, its public key, and a stable
issuer identifier. Two creation paths are supported:

1. `generate_issuer_key(issuer_id)` — fresh random key from `os.urandom`.
   This is the recommended production path.
2. `load_issuer_key(issuer_id, private_hex=...)` — load an existing key
   from its hex-encoded 32-byte seed. For deployment continuity and for
   deterministic testing.

A separate `load_public_key(...)` is exposed for verification-only contexts
where the private key is not available.

Private material NEVER leaves IssuerKey in plaintext except via the explicit
`private_hex()` method, which is labelled loudly for reviewers.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.exceptions import InvalidSignature


# urn:crovia:seal-issuer:<name> with <name> = 1..64 chars from a
# restricted alphabet. Matches the convention in SPEC.md Section 4.4.
_ISSUER_ID_REGEX = re.compile(
    r"^urn:crovia:seal-issuer:[a-z0-9][a-z0-9\-_.]{0,63}$"
)


def _validate_issuer_id(issuer_id: str) -> None:
    if not isinstance(issuer_id, str):
        raise TypeError("issuer_id must be str")
    if not _ISSUER_ID_REGEX.match(issuer_id):
        raise ValueError(
            f"invalid issuer_id: {issuer_id!r}\n"
            "expected: 'urn:crovia:seal-issuer:<name>' where <name> "
            "is 1..64 chars of [a-z0-9._-] starting with alphanumeric."
        )


@dataclass
class IssuerKey:
    """A signing identity.

    The Ed25519PrivateKey object is held in memory; the raw 32-byte seed is
    NOT kept around after initialization unless explicitly re-exported.
    """

    issuer_id: str
    _private: Ed25519PrivateKey = field(repr=False)
    _public_hex: str = field(repr=False)

    # --- Public key helpers -------------------------------------------------

    @property
    def public_hex(self) -> str:
        """Lowercase 64-char hex encoding of the 32-byte Ed25519 public key."""
        return self._public_hex

    @property
    def public_key(self) -> Ed25519PublicKey:
        """The underlying cryptography Ed25519PublicKey object."""
        return self._private.public_key()

    # --- Private key export (flagged) --------------------------------------

    def private_hex(self) -> str:
        """Export the 32-byte private seed as hex.

        SECURITY: This is intentionally verbose. Call sites exporting private
        material should be obviously reviewable in code review. Do not log.
        Do not commit. Do not transmit over unencrypted channels.
        """
        raw = self._private.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        return raw.hex()

    # --- Cryptographic operations ------------------------------------------

    def sign(self, payload: bytes) -> bytes:
        """Sign `payload` with Ed25519. Returns 64 raw signature bytes.

        Ed25519 is deterministic (RFC 8032): the same key + same payload
        produces the same signature.
        """
        if not isinstance(payload, (bytes, bytearray)):
            raise TypeError("payload must be bytes")
        return self._private.sign(bytes(payload))

    def verify(self, signature: bytes, payload: bytes) -> bool:
        """Verify a signature against this key. Returns True on success.

        Constant-time via the cryptography library. Never raises on mismatch;
        returns False instead so that callers can keep error paths uniform.
        Invalid-type arguments still raise TypeError.
        """
        if not isinstance(signature, (bytes, bytearray)):
            raise TypeError("signature must be bytes")
        if not isinstance(payload, (bytes, bytearray)):
            raise TypeError("payload must be bytes")
        try:
            self._private.public_key().verify(bytes(signature), bytes(payload))
            return True
        except InvalidSignature:
            return False


# --- Constructors -----------------------------------------------------------

def _build(issuer_id: str, priv: Ed25519PrivateKey) -> IssuerKey:
    pub_bytes = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return IssuerKey(issuer_id=issuer_id, _private=priv, _public_hex=pub_bytes.hex())


def generate_issuer_key(issuer_id: str) -> IssuerKey:
    """Create a fresh IssuerKey from 32 bytes of `os.urandom`.

    This is the recommended production path. The resulting private key is
    uniformly random and cannot be predicted without access to the OS CSPRNG.
    """
    _validate_issuer_id(issuer_id)
    seed = os.urandom(32)
    priv = Ed25519PrivateKey.from_private_bytes(seed)
    return _build(issuer_id, priv)


def load_issuer_key(issuer_id: str, private_hex: str) -> IssuerKey:
    """Load an IssuerKey from a 64-char hex-encoded 32-byte Ed25519 seed.

    For deployment continuity (loading the same key across restarts) and
    for deterministic testing. In production, the seed SHOULD be read from
    a secrets manager, never from a file in the repo.
    """
    _validate_issuer_id(issuer_id)
    if not isinstance(private_hex, str):
        raise TypeError("private_hex must be str")
    private_hex = private_hex.lower()
    if not re.fullmatch(r"[0-9a-f]{64}", private_hex):
        raise ValueError("private_hex must be exactly 64 lowercase hex chars")
    seed = bytes.fromhex(private_hex)
    priv = Ed25519PrivateKey.from_private_bytes(seed)
    return _build(issuer_id, priv)


def load_public_key(public_hex: str) -> Ed25519PublicKey:
    """Load a bare Ed25519 public key from its 64-char hex encoding.

    Used by verifiers that have no access to a private key.
    """
    if not isinstance(public_hex, str):
        raise TypeError("public_hex must be str")
    public_hex = public_hex.lower()
    if not re.fullmatch(r"[0-9a-f]{64}", public_hex):
        raise ValueError("public_hex must be exactly 64 lowercase hex chars")
    return Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_hex))
