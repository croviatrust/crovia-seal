"""
Minimal Ed25519 key wrapper for the TLog operator.

We intentionally do NOT reuse `crovia_seal.keys.IssuerKey` because that
class validates its URN against the `urn:crovia:seal-issuer:...` namespace,
whereas the TLog operator lives under `urn:crovia:tlog:...`. Mixing the two
would either force a permissive URN grammar (weakening seal checks) or
introduce a dual-purpose class whose audit surface is larger than needed.

A Crovia TLog key is therefore a plain Ed25519 keypair (from the
`cryptography` package) wrapped for ergonomic use by the STH module.
"""
from __future__ import annotations

from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PrivateFormat,
    PublicFormat,
    NoEncryption,
)
from cryptography.exceptions import InvalidSignature


@dataclass
class TlogKey:
    """An Ed25519 key owned by a TLog operator. Signs Signed Tree Heads."""
    private: Ed25519PrivateKey
    public: Ed25519PublicKey

    @classmethod
    def from_hex(cls, private_hex: str) -> "TlogKey":
        raw = bytes.fromhex(private_hex)
        if len(raw) != 32:
            raise ValueError("TLog private key must be 32 bytes (64 hex chars)")
        priv = Ed25519PrivateKey.from_private_bytes(raw)
        return cls(private=priv, public=priv.public_key())

    @property
    def public_hex(self) -> str:
        return self.public.public_bytes(
            encoding=Encoding.Raw, format=PublicFormat.Raw
        ).hex()

    def sign(self, data: bytes) -> bytes:
        return self.private.sign(data)

    @staticmethod
    def verify_raw(public_hex: str, data: bytes, sig: bytes) -> bool:
        try:
            pk = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_hex))
            pk.verify(sig, data)
            return True
        except (InvalidSignature, ValueError):
            return False
