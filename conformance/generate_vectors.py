"""
Generate cross-language conformance fixtures.

This script is the single source of truth for testing that a non-Python
implementation (TypeScript, Go, Rust) produces bit-identical output to
the Python reference.

It emits:

    vectors/v1/
      canonical_cases.json      (input -> expected canonical bytes, hex)
      seal_001_genesis.json     (a signed Seal with fixed seal_id/nonce/time)
      seal_001.payload.hex      (domain-separated payload, hex)
      seal_001.signature.hex    (Ed25519 signature bytes, hex)
      seal_002_chained.json     (a chained Seal, sequence=1)
      seal_002.payload.hex
      seal_002.signature.hex
      issuer.public.hex         (the deterministic public key, published)
      issuer.private.hex        (the deterministic private seed; DEMO ONLY)

Run from the reference/python directory after `pip install -e .`:

    python ../../conformance/generate_vectors.py

Vectors are committed to the repository. Any implementation whose output
differs from these bytes is non-conformant.
"""
from __future__ import annotations

import json
import sys
import hashlib
from pathlib import Path

# Make the reference package importable whether or not it's been installed.
_HERE = Path(__file__).resolve().parent
_REPO = _HERE.parent
_PKG_ROOT = _REPO / "reference" / "python"
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

from crovia_seal.canonical import canonicalize
from crovia_seal.constants import (
    CANON_ID,
    PAYLOAD_HASH_ALG,
    SEAL_VERSION,
    SIGNATURE_ALG,
    SIGNATURE_DOMAIN,
    SIGNATURE_DOMAIN_BYTES,
)
from crovia_seal.keys import load_issuer_key
from crovia_seal.seal import compute_payload, _validate_structure  # private but useful


# ---------------------------------------------------------------------------
# Deterministic demo issuer (MUST NEVER be used in production)
# ---------------------------------------------------------------------------

ISSUER_ID = "urn:crovia:seal-issuer:conformance"
ISSUER_SEED_HEX = "deadbeef" * 8   # 64 hex chars = 32 bytes


# ---------------------------------------------------------------------------
# Canonicalization cases (input -> expected canonical bytes)
# ---------------------------------------------------------------------------
# Each case is chosen to exercise one CSC-1 rule. Non-Python implementations
# MUST produce the exact `expected_hex` bytes for each `input`.

CANON_CASES = [
    {"name": "null",            "input": None,                    "expected": b"null"},
    {"name": "true",            "input": True,                    "expected": b"true"},
    {"name": "false",           "input": False,                   "expected": b"false"},
    {"name": "empty_string",    "input": "",                      "expected": b'""'},
    {"name": "ascii",           "input": "hello",                 "expected": b'"hello"'},
    {"name": "escape_quote",    "input": '"',                     "expected": b'"\\""'},
    {"name": "escape_bslash",   "input": "\\",                    "expected": b'"\\\\"'},
    {"name": "escape_newline",  "input": "\n",                    "expected": b'"\\n"'},
    {"name": "escape_tab",      "input": "\t",                    "expected": b'"\\t"'},
    {"name": "control_00",      "input": "\x00",                  "expected": b'"\\u0000"'},
    {"name": "control_1f",      "input": "\x1f",                  "expected": b'"\\u001f"'},
    {"name": "non_ascii_latin", "input": "café",                  "expected": b'"caf\xc3\xa9"'},
    {"name": "emoji_supp",      "input": "\U0001F600",            "expected": '"\U0001F600"'.encode("utf-8")},
    {"name": "int_zero",        "input": 0,                       "expected": b"0"},
    {"name": "int_one",         "input": 1,                       "expected": b"1"},
    {"name": "int_neg",         "input": -1,                      "expected": b"-1"},
    {"name": "int_large",       "input": 2**53 - 1,               "expected": str(2**53 - 1).encode()},
    {"name": "int_neg_large",   "input": -(2**53) + 1,            "expected": str(-(2**53) + 1).encode()},
    {"name": "empty_array",     "input": [],                      "expected": b"[]"},
    {"name": "array_mixed",     "input": [1, "a", None, True, False], "expected": b'[1,"a",null,true,false]'},
    {"name": "array_order",     "input": [3, 1, 2],               "expected": b"[3,1,2]"},
    {"name": "empty_object",    "input": {},                      "expected": b"{}"},
    {"name": "object_sorted",   "input": {"b": 2, "a": 1},        "expected": b'{"a":1,"b":2}'},
    {"name": "object_three",    "input": {"z": 1, "a": 2, "m": 3}, "expected": b'{"a":2,"m":3,"z":1}'},
    {"name": "nested",          "input": {"outer": {"b": 1, "a": 2}, "also": [1, {"y": 1, "x": 2}]},
                                  "expected": b'{"also":[1,{"x":2,"y":1}],"outer":{"a":2,"b":1}}'},
    {"name": "object_utf16",    "input": {"\U0001F600": 1, "z": 2},
                                  "expected": b'{"z":2,' + '"\U0001F600":1'.encode("utf-8") + b"}"},
]


def write_canonical_cases(out_dir: Path) -> None:
    rows = []
    for c in CANON_CASES:
        canonical = canonicalize(c["input"])
        assert canonical == c["expected"], (
            f"Case {c['name']!r}: generator disagrees with its own expected. "
            f"This is a bug in conformance generation."
        )
        rows.append({
            "name": c["name"],
            "input": c["input"],
            "expected_hex": canonical.hex(),
            "expected_utf8": canonical.decode("utf-8"),
        })
    path = out_dir / "canonical_cases.json"
    with open(path, "w", encoding="utf-8") as f:
        # Pretty-print for human review (NOT canonical, this is metadata).
        json.dump({"version": "v1", "cases": rows}, f, indent=2, ensure_ascii=False)
    print(f"  wrote {path} ({len(rows)} cases)")


# ---------------------------------------------------------------------------
# Deterministic Seal construction
# ---------------------------------------------------------------------------
# We bypass the randomness in emit_seal() by composing the Seal dict manually
# with fixed seal_id/nonce/timestamp, then compute the signature through the
# same code path (compute_payload + Ed25519 sign).

def _build_unsigned(
    issuer,
    *,
    seal_id: str,
    nonce: str,
    emitted_at: str,
    input_bytes: bytes,
    output_bytes: bytes,
    modality: str,
    generator_id: str,
    generator_version=None,
    generator_weights_hash=None,
    generator_params=None,
    sequence: int = 0,
    prev_seal_hash=None,
    checks=None,
    anchor=None,
):
    sub = {
        "input_hash": "sha256:" + hashlib.sha256(input_bytes).hexdigest(),
        "output_hash": "sha256:" + hashlib.sha256(output_bytes).hexdigest(),
        "input_len": len(input_bytes),
        "output_len": len(output_bytes),
        "modality": modality,
    }
    unsigned = {
        "seal_version": SEAL_VERSION,
        "seal_id": seal_id,
        "issuer": {
            "id": issuer.issuer_id,
            "pubkey": {"alg": SIGNATURE_ALG, "key_hex": issuer.public_hex},
        },
        "subject": sub,
        "generator": {
            "id": generator_id,
            "version": generator_version,
            "weights_hash": generator_weights_hash,
            "params": dict(generator_params or {}),
        },
        "timestamp": {"emitted_at": emitted_at, "nonce": nonce},
        "chain": {"prev_seal_hash": prev_seal_hash, "sequence": sequence},
    }
    if checks is not None:
        unsigned["checks"] = checks
    if anchor is not None:
        unsigned["anchor"] = anchor
    return unsigned


def _sign(issuer, unsigned: dict) -> dict:
    payload = compute_payload(unsigned)
    sig_bytes = issuer.sign(payload)
    signed = dict(unsigned)
    signed["signature"] = {
        "alg": SIGNATURE_ALG,
        "canon": CANON_ID,
        "domain": SIGNATURE_DOMAIN,
        "payload_hash_alg": PAYLOAD_HASH_ALG,
        "sig_hex": sig_bytes.hex(),
    }
    _validate_structure(signed)  # defence in depth
    return signed, payload, sig_bytes


# Fixed demo values. These exact strings MUST be used by any implementation
# attempting to reproduce the fixtures.
SEAL_001 = {
    "seal_id": "cs_2026_AAAAAAAAAAAAAAAAAAAAAAAAAA",     # 26 base32 chars
    "nonce":   "BBBBBBBBBBBBBBBBBBBBBBBBBB",
    "emitted_at": "2026-04-15T00:00:00.000Z",
}
SEAL_002 = {
    "seal_id": "cs_2026_CCCCCCCCCCCCCCCCCCCCCCCCCC",
    "nonce":   "DDDDDDDDDDDDDDDDDDDDDDDDDD",
    "emitted_at": "2026-04-15T00:00:01.000Z",
}


def write_seal_vectors(out_dir: Path) -> None:
    issuer = load_issuer_key(ISSUER_ID, ISSUER_SEED_HEX)

    # --- Seal 001: genesis ---
    unsigned_1 = _build_unsigned(
        issuer,
        seal_id=SEAL_001["seal_id"],
        nonce=SEAL_001["nonce"],
        emitted_at=SEAL_001["emitted_at"],
        input_bytes=b"What is the capital of France?",
        output_bytes=b"The capital of France is Paris.",
        modality="text",
        generator_id="openai/gpt-4o",
        generator_version="2024-08-06",
        generator_params={"temperature": "0.7", "top_p": "1.0"},
    )
    signed_1, payload_1, sig_1 = _sign(issuer, unsigned_1)

    # --- Seal 002: chained ---
    prev_hash = "sha256:" + hashlib.sha256(payload_1).hexdigest()
    unsigned_2 = _build_unsigned(
        issuer,
        seal_id=SEAL_002["seal_id"],
        nonce=SEAL_002["nonce"],
        emitted_at=SEAL_002["emitted_at"],
        input_bytes=b"Now summarize in one sentence.",
        output_bytes=b"France's capital is Paris.",
        modality="text",
        generator_id="openai/gpt-4o",
        generator_version="2024-08-06",
        sequence=1,
        prev_seal_hash=prev_hash,
    )
    signed_2, payload_2, sig_2 = _sign(issuer, unsigned_2)

    # --- Write ---
    # Issuer key material (public + demo-only private).
    (out_dir / "issuer.public.hex").write_text(issuer.public_hex + "\n", encoding="utf-8")
    (out_dir / "issuer.private.hex").write_text(ISSUER_SEED_HEX + "\n", encoding="utf-8")
    (out_dir / "issuer.id.txt").write_text(ISSUER_ID + "\n", encoding="utf-8")
    print(f"  issuer public key: {issuer.public_hex}")

    for name, seal, payload, sig in [
        ("seal_001_genesis", signed_1, payload_1, sig_1),
        ("seal_002_chained", signed_2, payload_2, sig_2),
    ]:
        # Seal JSON: write in pretty form for human review AND in minified
        # form used in spec. The canonical bytes are payload.hex, not the
        # pretty JSON; the pretty JSON is for documentation only.
        pretty = out_dir / f"{name}.json"
        with open(pretty, "w", encoding="utf-8") as f:
            json.dump(seal, f, indent=2, ensure_ascii=False)
            f.write("\n")
        (out_dir / f"{name}.payload.hex").write_text(payload.hex() + "\n", encoding="utf-8")
        (out_dir / f"{name}.signature.hex").write_text(sig.hex() + "\n", encoding="utf-8")
        print(f"  wrote {pretty.name} + payload + signature ({len(payload)} payload bytes)")


# ---------------------------------------------------------------------------

def main() -> int:
    out_dir = _REPO / "conformance" / "vectors" / "v1"
    out_dir.mkdir(parents=True, exist_ok=True)
    print(f"Writing conformance vectors to: {out_dir}")
    print()

    print("Canonicalization cases:")
    write_canonical_cases(out_dir)
    print()

    print("Signed seal vectors:")
    write_seal_vectors(out_dir)
    print()

    print("Conformance vector generation complete.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
