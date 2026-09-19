"""
seal() — produce a continuity receipt over an arbitrary JSON payload.

Receipt format: `crovia.receipt.v1`. Byte-identical with the @crovia/seal
JavaScript SDK: a receipt produced by either implementation verifies
identically in both.

Wire format:
  - Canonical JSON via CSC-1
  - Ed25519 signatures over `b"CROVIA-RECEIPT-v1\\n" || csc1(receipt without sig)`
  - Domain separator distinct from any other Crovia signed object
"""
from __future__ import annotations

import base64
import hashlib
import re
import secrets
from datetime import datetime, timezone
from typing import Any, Dict, Optional, TypedDict

from crovia_seal.canonical import canonicalize
from crovia_seal.keys import KeyPair, generate_key, sign_bytes

RECEIPT_VERSION = "crovia.receipt.v1"
DOMAIN_STRING = "CROVIA-RECEIPT-v1"
DOMAIN_BYTES = (DOMAIN_STRING + "\n").encode("utf-8")
CANON_ID = "csc-1"
SIG_ALG = "ed25519"
PAYLOAD_ALG = "sha256"
RECEIPT_ID_RE = re.compile(r"^cr_[0-9]{4}_[A-Z2-7]{26}$")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
HEX128_RE = re.compile(r"^[0-9a-f]{128}$")
SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
ISO_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")

_BASE32_ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"


class Receipt(TypedDict, total=False):
    """A signed continuity receipt over an arbitrary JSON payload."""

    v: str
    id: str
    issued_at: str
    payload_hash: str
    payload_alg: str
    payload_type: str  # optional
    prev: Optional[str]
    seq: int
    signer: str
    sig_alg: str
    canon: str
    domain: str
    sig: str


def _random_b32(n_bytes: int = 16) -> str:
    """Crockford-style RFC 4648 base32 of `n_bytes` random bytes, no padding.

    16 bytes → 26 base32 chars (we strip any padding).
    """
    raw = secrets.token_bytes(n_bytes)
    bits = 0
    acc = 0
    out = []
    for b in raw:
        acc = (acc << 8) | b
        bits += 8
        while bits >= 5:
            bits -= 5
            out.append(_BASE32_ALPHA[(acc >> bits) & 0x1F])
    if bits > 0:
        out.append(_BASE32_ALPHA[(acc << (5 - bits)) & 0x1F])
    return "".join(out)[:26]


def _new_receipt_id() -> str:
    year = datetime.now(timezone.utc).year
    return f"cr_{year}_{_random_b32()}"


def _now_rfc3339_ms() -> str:
    """Return current UTC time as 'YYYY-MM-DDTHH:MM:SS.mmmZ' (millisecond precision)."""
    dt = datetime.now(timezone.utc)
    ms = dt.microsecond // 1000
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{ms:03d}Z"


def _sha256_prefixed(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def compute_payload(receipt_without_sig: Dict[str, Any]) -> bytes:
    """Compute the exact bytes that are signed.

    Equivalent to the JS `computePayload` — concatenates the domain prefix
    with CSC-1 canonical bytes of the receipt minus its `sig` field.
    """
    return DOMAIN_BYTES + canonicalize(receipt_without_sig)


def validate_receipt_shape(r: Any) -> Optional[str]:
    """Validate the structural shape of a receipt object.

    Returns None on success, or a string describing the first failure.
    """
    if not isinstance(r, dict):
        return "receipt must be a dict"
    if r.get("v") != RECEIPT_VERSION:
        return f"v must be {RECEIPT_VERSION!r}"
    rid = r.get("id")
    if not isinstance(rid, str) or not RECEIPT_ID_RE.match(rid):
        return "id must match cr_YYYY_<26 base32 chars>"
    iss = r.get("issued_at")
    if not isinstance(iss, str) or not ISO_RE.match(iss):
        return "issued_at must be RFC 3339 UTC with ms precision"
    ph = r.get("payload_hash")
    if not isinstance(ph, str) or not SHA256_RE.match(ph):
        return "payload_hash must be 'sha256:<64 hex>'"
    if r.get("payload_alg") != PAYLOAD_ALG:
        return f"payload_alg must be {PAYLOAD_ALG!r}"
    pt = r.get("payload_type")
    if pt is not None and not isinstance(pt, str):
        return "payload_type must be string when present"
    prev = r.get("prev")
    if prev is not None:
        if not isinstance(prev, str) or not RECEIPT_ID_RE.match(prev):
            return "prev must be null or a valid receipt id"
    seq = r.get("seq")
    if not isinstance(seq, int) or isinstance(seq, bool) or seq < 0:
        return "seq must be a non-negative integer"
    if seq == 0 and prev is not None:
        return "seq=0 (genesis) requires prev=null"
    if seq > 0 and prev is None:
        return "seq>0 requires prev to be a receipt id"
    signer = r.get("signer")
    if not isinstance(signer, str) or not HEX64_RE.match(signer):
        return "signer must be 64 lowercase hex chars"
    if r.get("sig_alg") != SIG_ALG:
        return f"sig_alg must be {SIG_ALG!r}"
    if r.get("canon") != CANON_ID:
        return f"canon must be {CANON_ID!r}"
    if r.get("domain") != DOMAIN_STRING:
        return f"domain must be {DOMAIN_STRING!r}"
    sig = r.get("sig")
    if not isinstance(sig, str) or not HEX128_RE.match(sig):
        return "sig must be 128 lowercase hex chars"
    return None


def seal(
    payload: Any,
    *,
    key: Optional[KeyPair] = None,
    prev_receipt: Optional[Dict[str, Any]] = None,
    payload_type: Optional[str] = None,
    issued_at: Optional[str] = None,
) -> Dict[str, Any]:
    """Produce a continuity receipt over an arbitrary JSON payload.

    Args:
        payload: Any JSON-compatible value. Will be canonicalized via CSC-1
                 (so floats are forbidden — encode numerics as strings).
        key:     Bring-your-own Ed25519 key. If omitted, a fresh ephemeral
                 key is generated for this call.
        prev_receipt: Previous receipt to chain against (provides prev + seq+1
                 and forces signer continuity).
        payload_type: Optional content-type hint stored alongside the receipt.
        issued_at: Override timestamp (testing only; must be RFC 3339 UTC ms).

    Returns:
        A dict-shaped receipt (compatible with JSON serialization). Identical
        in structure to what `@crovia/seal` produces in JavaScript.
    """
    if key is None:
        key = generate_key()

    payload_canonical = canonicalize(payload)
    payload_hash = _sha256_prefixed(payload_canonical)

    if prev_receipt is not None:
        prev_id = prev_receipt["id"]
        seq = int(prev_receipt["seq"]) + 1
    else:
        prev_id = None
        seq = 0

    iss = issued_at if issued_at is not None else _now_rfc3339_ms()

    unsigned: Dict[str, Any] = {
        "v": RECEIPT_VERSION,
        "id": _new_receipt_id(),
        "issued_at": iss,
        "payload_hash": payload_hash,
        "payload_alg": PAYLOAD_ALG,
    }
    if payload_type is not None:
        unsigned["payload_type"] = payload_type
    unsigned.update({
        "prev": prev_id,
        "seq": seq,
        "signer": key.public_hex,
        "sig_alg": SIG_ALG,
        "canon": CANON_ID,
        "domain": DOMAIN_STRING,
    })

    signing_payload = compute_payload(unsigned)
    sig_hex = sign_bytes(key.private_hex, signing_payload)

    receipt = dict(unsigned)
    receipt["sig"] = sig_hex

    err = validate_receipt_shape(receipt)
    if err is not None:
        raise RuntimeError(f"internal: produced invalid receipt — {err}")

    return receipt
