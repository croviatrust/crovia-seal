"""Ed25519 key handling — wraps the `cryptography` library."""
from __future__ import annotations

import os
import secrets
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


@dataclass(frozen=True)
class KeyPair:
    """Ed25519 key pair, raw 32-byte private + 32-byte public, hex-encoded."""

    private_hex: str  # 64 lowercase hex chars
    public_hex: str  # 64 lowercase hex chars


def _bytes_to_hex(b: bytes) -> str:
    return b.hex()


def _hex_to_bytes(h: str, expected_len: int) -> bytes:
    if len(h) != expected_len * 2 or not all(c in "0123456789abcdef" for c in h):
        raise ValueError(
            f"expected {expected_len * 2} lowercase hex chars, got {len(h)}"
        )
    return bytes.fromhex(h)


def generate_key() -> KeyPair:
    """Generate a fresh Ed25519 key pair using a cryptographically-secure RNG."""
    # Cryptography's Ed25519PrivateKey.generate() uses os.urandom under the hood,
    # but we generate the seed explicitly to match the JS SDK's flow and to make
    # the source of randomness explicit.
    seed = secrets.token_bytes(32)
    priv = Ed25519PrivateKey.from_private_bytes(seed)
    pub_bytes = priv.public_key().public_bytes_raw()
    return KeyPair(
        private_hex=_bytes_to_hex(seed),
        public_hex=_bytes_to_hex(pub_bytes),
    )


def public_from_private(private_hex: str) -> str:
    """Derive the public hex from a 32-byte private hex (no mutation of caller)."""
    seed = _hex_to_bytes(private_hex, 32)
    priv = Ed25519PrivateKey.from_private_bytes(seed)
    return _bytes_to_hex(priv.public_key().public_bytes_raw())


def sign_bytes(private_hex: str, message: bytes) -> str:
    """Sign raw bytes with an Ed25519 private key (hex). Returns 128 lowercase hex chars."""
    seed = _hex_to_bytes(private_hex, 32)
    priv = Ed25519PrivateKey.from_private_bytes(seed)
    sig = priv.sign(message)
    return _bytes_to_hex(sig)


def verify_bytes(public_hex: str, signature_hex: str, message: bytes) -> bool:
    """Verify an Ed25519 signature. Returns False on any failure (never raises)."""
    if (
        not isinstance(public_hex, str)
        or not isinstance(signature_hex, str)
        or len(public_hex) != 64
        or len(signature_hex) != 128
    ):
        return False
    try:
        pub_bytes = bytes.fromhex(public_hex)
        sig_bytes = bytes.fromhex(signature_hex)
    except ValueError:
        return False
    try:
        pub = Ed25519PublicKey.from_public_bytes(pub_bytes)
        pub.verify(sig_bytes, message)
        return True
    except (InvalidSignature, ValueError):
        return False
