"""
Tests for Seal issuance and verification — happy paths.

Attack-resistance tests live in test_tamper.py.
"""
from __future__ import annotations

import hashlib
import pytest

from crovia_seal import (
    SEAL_VERSION,
    SIGNATURE_DOMAIN,
    compute_payload,
    compute_seal_hash,
    emit_seal,
    generate_issuer_key,
    load_issuer_key,
    verify_seal,
)


# --- Fixtures ---------------------------------------------------------------

@pytest.fixture
def issuer():
    return generate_issuer_key("urn:crovia:seal-issuer:test")


@pytest.fixture
def basic_seal(issuer):
    return emit_seal(
        issuer_key=issuer,
        input_bytes=b"What is the capital of France?",
        output_bytes=b"The capital of France is Paris.",
        modality="text",
        generator_id="openai/gpt-4o",
        generator_version="2024-08-06",
        generator_params={"temperature": "0.7", "top_p": "1.0"},
    )


# --- Structural shape -------------------------------------------------------

def test_seal_has_all_required_fields(basic_seal):
    for k in ("seal_version", "seal_id", "issuer", "subject",
              "generator", "timestamp", "chain", "signature"):
        assert k in basic_seal


def test_seal_version(basic_seal):
    assert basic_seal["seal_version"] == SEAL_VERSION


def test_seal_id_format(basic_seal):
    sid = basic_seal["seal_id"]
    assert sid.startswith("cs_")
    parts = sid.split("_")
    assert len(parts) == 3
    assert len(parts[1]) == 4  # YYYY
    assert len(parts[2]) == 26  # 26 base32 chars


def test_subject_hashes(basic_seal):
    inp = b"What is the capital of France?"
    out = b"The capital of France is Paris."
    expected_in = "sha256:" + hashlib.sha256(inp).hexdigest()
    expected_out = "sha256:" + hashlib.sha256(out).hexdigest()
    assert basic_seal["subject"]["input_hash"] == expected_in
    assert basic_seal["subject"]["output_hash"] == expected_out
    assert basic_seal["subject"]["input_len"] == len(inp)
    assert basic_seal["subject"]["output_len"] == len(out)


def test_signature_fields(basic_seal):
    sig = basic_seal["signature"]
    assert sig["alg"] == "ed25519"
    assert sig["canon"] == "csc-1"
    assert sig["domain"] == SIGNATURE_DOMAIN
    assert sig["payload_hash_alg"] == "sha256"
    assert len(sig["sig_hex"]) == 128


def test_chain_genesis_defaults(basic_seal):
    assert basic_seal["chain"]["sequence"] == 0
    assert basic_seal["chain"]["prev_seal_hash"] is None


# --- Round-trip -------------------------------------------------------------

def test_roundtrip_verifies(basic_seal):
    r = verify_seal(basic_seal)
    assert r.ok, r.errors
    assert r.seal_id == basic_seal["seal_id"]
    assert r.issuer_id == basic_seal["issuer"]["id"]


def test_verify_with_pinned_issuer_key(issuer, basic_seal):
    r = verify_seal(basic_seal, issuer_pubkey_hex=issuer.public_hex)
    assert r.ok, r.errors


def test_verify_fails_wrong_pinned_key(basic_seal):
    # Generate a different key and pin it; verification MUST fail.
    other = generate_issuer_key("urn:crovia:seal-issuer:other")
    r = verify_seal(basic_seal, issuer_pubkey_hex=other.public_hex)
    assert not r.ok
    assert any("issuer public key mismatch" in e for e in r.errors)


# --- Payload construction --------------------------------------------------

def test_payload_starts_with_domain(basic_seal):
    payload = compute_payload(basic_seal)
    assert payload.startswith(b"CROVIA-SEAL-v1\n")


def test_payload_excludes_signature_and_witnesses(issuer, basic_seal):
    # Add a fake witnesses field, verify payload unchanged.
    p1 = compute_payload(basic_seal)
    tampered = dict(basic_seal)
    tampered["witnesses"] = [{"id": "fake", "pubkey": {"alg": "ed25519", "key_hex": "0" * 64}, "sig_hex": "0" * 128}]
    p2 = compute_payload(tampered)
    assert p1 == p2


def test_seal_hash_is_sha256_of_payload(basic_seal):
    expected = "sha256:" + hashlib.sha256(compute_payload(basic_seal)).hexdigest()
    assert compute_seal_hash(basic_seal) == expected


# --- Deterministic load -----------------------------------------------------

def test_load_issuer_key_deterministic():
    priv_hex = "a" * 64  # any valid hex seed
    k1 = load_issuer_key("urn:crovia:seal-issuer:det", priv_hex)
    k2 = load_issuer_key("urn:crovia:seal-issuer:det", priv_hex)
    assert k1.public_hex == k2.public_hex


def test_issuer_id_validation():
    # Bad schemes, bad alphabets, too long — all must fail.
    bad_ids = [
        "not-a-urn",
        "urn:wrong:seal-issuer:test",
        "urn:crovia:seal-issuer:",               # empty name
        "urn:crovia:seal-issuer:UPPER",          # uppercase not allowed
        "urn:crovia:seal-issuer:with space",     # space not allowed
        "urn:crovia:seal-issuer:" + "a" * 65,    # too long
    ]
    for bad in bad_ids:
        with pytest.raises(ValueError):
            generate_issuer_key(bad)


# --- Chain composition -----------------------------------------------------

def test_chained_seal(issuer):
    s1 = emit_seal(
        issuer_key=issuer,
        input_bytes=b"first prompt",
        output_bytes=b"first response",
        modality="text",
        generator_id="test/model",
    )
    s2 = emit_seal(
        issuer_key=issuer,
        input_bytes=b"second prompt",
        output_bytes=b"second response",
        modality="text",
        generator_id="test/model",
        sequence=1,
        prev_seal_hash=compute_seal_hash(s1),
    )
    assert s2["chain"]["sequence"] == 1
    assert s2["chain"]["prev_seal_hash"] == compute_seal_hash(s1)
    r1 = verify_seal(s1); assert r1.ok, r1.errors
    r2 = verify_seal(s2); assert r2.ok, r2.errors


def test_chain_mismatch_raises():
    iss = generate_issuer_key("urn:crovia:seal-issuer:chain")
    # Genesis with prev_seal_hash set: invalid.
    with pytest.raises(ValueError):
        emit_seal(
            issuer_key=iss,
            input_bytes=b"x", output_bytes=b"y",
            modality="text", generator_id="m",
            sequence=0,
            prev_seal_hash="sha256:" + "f" * 64,
        )
    # Non-genesis with prev_seal_hash=None: invalid.
    with pytest.raises(ValueError):
        emit_seal(
            issuer_key=iss,
            input_bytes=b"x", output_bytes=b"y",
            modality="text", generator_id="m",
            sequence=1,
            prev_seal_hash=None,
        )


# --- Optional fields -------------------------------------------------------

def test_checks_field(issuer):
    s = emit_seal(
        issuer_key=issuer,
        input_bytes=b"probe",
        output_bytes=b"answer",
        modality="text",
        generator_id="model",
        checks={"memorization": {
            "db_version": "crovia-memdb-2026-04-15",
            "method": "ngram-lsh-v1",
            "matches": 0,
            "max_conf": "0.03",
        }},
    )
    assert s["checks"]["memorization"]["matches"] == 0
    r = verify_seal(s)
    assert r.ok, r.errors


def test_anchor_field(issuer):
    s = emit_seal(
        issuer_key=issuer,
        input_bytes=b"x",
        output_bytes=b"y",
        modality="text",
        generator_id="m",
        anchor={
            "log_url": "https://log.example/seal",
            "merkle_root": "sha256:" + "a" * 64,
            "merkle_proof": ["sha256:" + "b" * 64, "sha256:" + "c" * 64],
            "log_index": 42,
            "root_signed_at": "2026-04-15T00:00:00.000Z",
        },
    )
    r = verify_seal(s)
    assert r.ok, r.errors
