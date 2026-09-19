"""End-to-end tests for seal/verify (Python SDK)."""
import pytest

from crovia_seal import (
    generate_key,
    seal,
    validate_receipt_shape,
    verify,
    verify_chain,
)


def test_seal_produces_structurally_valid_receipt():
    key = generate_key()
    r = seal({"hello": "world"}, key=key)
    assert validate_receipt_shape(r) is None
    assert r["v"] == "crovia.receipt.v1"
    assert r["signer"] == key.public_hex
    assert r["prev"] is None
    assert r["seq"] == 0


def test_genesis_invariants():
    r = seal({"x": 1})
    assert r["prev"] is None
    assert r["seq"] == 0


def test_chain_increments_seq_and_links_prev():
    key = generate_key()
    r1 = seal({"v": 1}, key=key)
    r2 = seal({"v": 2}, key=key, prev_receipt=r1)
    assert r2["prev"] == r1["id"]
    assert r2["seq"] == 1
    assert r2["signer"] == r1["signer"]


def test_payload_type_is_attached():
    r = seal({"x": 1}, payload_type="model-card")
    assert r["payload_type"] == "model-card"


def test_two_seals_have_distinct_ids():
    key = generate_key()
    r1 = seal({"x": 1}, key=key)
    r2 = seal({"x": 1}, key=key)
    assert r1["id"] != r2["id"]


def test_verify_accepts_fresh_seal():
    r = seal({"msg": "hi"})
    result = verify(r)
    assert result.valid
    assert result.errors == []


def test_verify_with_payload_full_check():
    payload = {"a": 1, "b": "x"}
    r = seal(payload)
    result = verify(r, payload)
    assert result.valid


def test_verify_rejects_mismatched_payload():
    r = seal({"a": 1})
    result = verify(r, {"a": 2})
    assert not result.valid
    assert any("payload_hash mismatch" in e for e in result.errors)


def test_verify_rejects_tampered_signature():
    r = seal({"x": 1})
    tampered = dict(r)
    # Flip one hex digit
    s = r["sig"]
    tampered["sig"] = ("1" if s[0] == "0" else "0") + s[1:]
    result = verify(tampered)
    assert not result.valid
    assert "signature: invalid" in result.errors


def test_verify_rejects_tampered_field():
    r = seal({"x": 1})
    tampered = dict(r)
    tampered["issued_at"] = "2099-01-01T00:00:00.000Z"
    result = verify(tampered)
    assert not result.valid


def test_verify_rejects_malformed_receipt():
    result = verify({"not": "a receipt"})
    assert not result.valid
    assert any(e.startswith("schema:") for e in result.errors)


def test_verify_chain_three():
    key = generate_key()
    r1 = seal({"v": 1}, key=key)
    r2 = seal({"v": 2}, key=key, prev_receipt=r1)
    r3 = seal({"v": 3}, key=key, prev_receipt=r2)
    assert verify_chain([r1, r2, r3]).valid


def test_verify_chain_rejects_seq_gap():
    key = generate_key()
    r1 = seal({"v": 1}, key=key)
    r2 = seal({"v": 2}, key=key, prev_receipt=r1)
    fake = dict(r2)
    fake["seq"] = 5
    assert not verify_chain([r1, fake]).valid


def test_verify_chain_rejects_prev_mismatch():
    key = generate_key()
    r1 = seal({"v": 1}, key=key)
    r2 = seal({"v": 2}, key=key, prev_receipt=r1)
    fake = dict(r2)
    fake["prev"] = "cr_2026_FAKEFAKEFAKEFAKEFAKEFAKEFA"
    assert not verify_chain([r1, fake]).valid


def test_verify_chain_rejects_signer_change():
    k1 = generate_key()
    k2 = generate_key()
    r1 = seal({"v": 1}, key=k1)
    r2 = seal({"v": 2}, key=k2, prev_receipt=r1)
    assert not verify_chain([r1, r2]).valid


def test_canonicalize_rejects_float_in_payload():
    # CSC-1 fail-closed: floats must not slip through.
    with pytest.raises(Exception):
        seal({"temp": 0.7})
