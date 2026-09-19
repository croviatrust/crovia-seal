"""
Cross-SDK interoperability — receipts produced by either Python or JS
must verify in both. This test is the load-bearing piece of the
"byte-identity" promise.

Two checks:
  1. Verify a known receipt produced offline by `@crovia/seal` (JS).
  2. Round-trip: seal in Python, signing payload bytes must match what
     the JS SDK would produce for the same unsigned receipt.
"""
import json

import pytest

from crovia_seal import (
    canonicalize,
    compute_payload,
    seal,
    validate_receipt_shape,
    verify,
)


# A receipt produced by the JavaScript SDK in `examples/register-live.mjs`.
# Captured from a real run, anchored to position 0 in production.
JS_RECEIPT = {
    "v": "crovia.receipt.v1",
    "id": "cr_2026_TLK2RRZH5QFWALAY45IT7RF6YQ",
    "issued_at": "2026-05-07T16:02:09.349Z",
    "payload_hash": "sha256:1a4162ee75e4cebf534c0966ed180ff361e9e88438187b11e0930bd62f696a85",
    "payload_alg": "sha256",
    "payload_type": "test/live",
    "prev": None,
    "seq": 0,
    "signer": "d1afa36d1bf0c891102865f9147b49c670ba1f5bdc30a1b6938885ab07d16a92",
    "sig_alg": "ed25519",
    "canon": "csc-1",
    "domain": "CROVIA-RECEIPT-v1",
    "sig": "64b2fe814f06f40bbb5785fdb5606662e2b95a1b74dd5d3b4d93836a893bff9175af008db43cd7073b6696616e06106a1a9fe1f6bb377fb2fea0800c2c082e02",
}


def test_python_verifies_js_produced_receipt_shape():
    """The receipt produced by @crovia/seal passes our schema check."""
    assert validate_receipt_shape(JS_RECEIPT) is None


def test_python_verifies_js_produced_receipt_signature():
    """Signature produced by JS SDK verifies in Python — the load-bearing test."""
    result = verify(JS_RECEIPT)
    assert result.valid, f"JS receipt failed Python verify: {result.errors}"
    assert result.id == JS_RECEIPT["id"]
    assert result.signer == JS_RECEIPT["signer"]


def test_signing_payload_canonical_form():
    """The signing payload bytes for a JS-shaped receipt are reproducible."""
    without_sig = {k: v for k, v in JS_RECEIPT.items() if k != "sig"}
    payload = compute_payload(without_sig)
    # Sanity: domain prefix
    assert payload.startswith(b"CROVIA-RECEIPT-v1\n")
    # Sanity: rest is canonical JSON of the unsigned receipt
    canonical = canonicalize(without_sig)
    assert payload == b"CROVIA-RECEIPT-v1\n" + canonical


def test_python_seal_and_verify_roundtrip():
    """Python-produced receipt verifies in Python."""
    payload = {"interop": "test", "n": 42}
    r = seal(payload, payload_type="interop/test")
    assert verify(r, payload).valid
