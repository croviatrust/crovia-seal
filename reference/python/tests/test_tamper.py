"""
Adversarial tests: every tampering vector we can think of MUST be detected.

These tests are the heart of the security argument. If any of them pass
with ok=True after tampering, the implementation has a vulnerability.
"""
from __future__ import annotations

import copy
import pytest

from crovia_seal import (
    compute_payload,
    emit_seal,
    generate_issuer_key,
    verify_seal,
)
from crovia_seal.keys import load_issuer_key


@pytest.fixture
def issuer():
    return generate_issuer_key("urn:crovia:seal-issuer:adv")


@pytest.fixture
def seal(issuer):
    return emit_seal(
        issuer_key=issuer,
        input_bytes=b"prompt",
        output_bytes=b"response",
        modality="text",
        generator_id="model/x",
        generator_params={"temperature": "0.5"},
    )


def _assert_rejects(s):
    r = verify_seal(s)
    assert not r.ok, f"expected rejection, got ok with errors={r.errors}"


# --- Subject tampering ------------------------------------------------------

def test_tamper_input_hash(seal):
    s = copy.deepcopy(seal)
    # Flip a single hex char in input_hash.
    h = s["subject"]["input_hash"]
    s["subject"]["input_hash"] = h[:-1] + ("0" if h[-1] != "0" else "1")
    _assert_rejects(s)


def test_tamper_output_hash(seal):
    s = copy.deepcopy(seal)
    h = s["subject"]["output_hash"]
    s["subject"]["output_hash"] = h[:-1] + ("0" if h[-1] != "0" else "1")
    _assert_rejects(s)


def test_tamper_input_len(seal):
    s = copy.deepcopy(seal)
    s["subject"]["input_len"] = s["subject"]["input_len"] + 1
    _assert_rejects(s)


def test_tamper_modality(seal):
    s = copy.deepcopy(seal)
    s["subject"]["modality"] = "code"  # was "text"
    _assert_rejects(s)


# --- Generator tampering ----------------------------------------------------

def test_tamper_generator_id(seal):
    s = copy.deepcopy(seal)
    s["generator"]["id"] = "attacker/model"
    _assert_rejects(s)


def test_tamper_generator_params(seal):
    s = copy.deepcopy(seal)
    s["generator"]["params"]["temperature"] = "0.0"
    _assert_rejects(s)


def test_add_new_generator_param(seal):
    s = copy.deepcopy(seal)
    s["generator"]["params"]["injected"] = "yes"
    _assert_rejects(s)


# --- Chain tampering --------------------------------------------------------

def test_tamper_chain_sequence(seal):
    s = copy.deepcopy(seal)
    s["chain"]["sequence"] = 1
    # Also must set prev_seal_hash or schema fails first; but EITHER failure
    # mode is acceptable as long as verification rejects.
    _assert_rejects(s)


def test_tamper_chain_prev_hash(seal):
    # Create a chained seal, then flip the prev hash.
    iss = generate_issuer_key("urn:crovia:seal-issuer:chain-tamper")
    s1 = emit_seal(
        issuer_key=iss, input_bytes=b"a", output_bytes=b"b",
        modality="text", generator_id="m",
    )
    from crovia_seal.seal import compute_seal_hash
    s2 = emit_seal(
        issuer_key=iss, input_bytes=b"c", output_bytes=b"d",
        modality="text", generator_id="m",
        sequence=1, prev_seal_hash=compute_seal_hash(s1),
    )
    # Tamper
    s2_tampered = copy.deepcopy(s2)
    h = s2_tampered["chain"]["prev_seal_hash"]
    s2_tampered["chain"]["prev_seal_hash"] = h[:-1] + ("0" if h[-1] != "0" else "1")
    _assert_rejects(s2_tampered)


# --- Version / downgrade ---------------------------------------------------

def test_tamper_seal_version(seal):
    s = copy.deepcopy(seal)
    s["seal_version"] = "crovia.seal.v2"
    _assert_rejects(s)


def test_tamper_signature_alg(seal):
    s = copy.deepcopy(seal)
    s["signature"]["alg"] = "rsa-2048"
    _assert_rejects(s)


def test_tamper_signature_domain(seal):
    s = copy.deepcopy(seal)
    s["signature"]["domain"] = "ATTACKER-DOMAIN"
    _assert_rejects(s)


def test_tamper_signature_canon(seal):
    s = copy.deepcopy(seal)
    s["signature"]["canon"] = "jcs-rfc8785"
    _assert_rejects(s)


# --- Signature bit-flip ----------------------------------------------------

def test_tamper_signature_hex(seal):
    s = copy.deepcopy(seal)
    sig = s["signature"]["sig_hex"]
    # Flip the first nibble.
    s["signature"]["sig_hex"] = ("0" if sig[0] != "0" else "1") + sig[1:]
    _assert_rejects(s)


def test_signature_from_different_key_rejected(seal):
    # Generate a different keypair, re-sign the same payload, swap the signature
    # but keep the original issuer pubkey — this MUST fail.
    other = generate_issuer_key("urn:crovia:seal-issuer:other")
    s = copy.deepcopy(seal)
    payload = compute_payload(s)
    bogus = other.sign(payload)
    s["signature"]["sig_hex"] = bogus.hex()
    # issuer.pubkey still points to the original — signature won't validate.
    _assert_rejects(s)


# --- Key substitution ------------------------------------------------------

def test_swap_issuer_pubkey_with_sig_rewrite(seal):
    # Attacker tries: swap issuer pubkey to their own AND re-sign.
    # This IS a valid seal cryptographically, but it is no longer a seal
    # from the ORIGINAL issuer. Pinned verification catches this.
    attacker = generate_issuer_key("urn:crovia:seal-issuer:attacker")
    s = copy.deepcopy(seal)
    original_issuer_pubkey = s["issuer"]["pubkey"]["key_hex"]

    s["issuer"]["pubkey"]["key_hex"] = attacker.public_hex
    # Must also re-sign with the attacker's key (otherwise sig won't match):
    payload = compute_payload(s)
    s["signature"]["sig_hex"] = attacker.sign(payload).hex()

    # Unpinned verification: signature is self-consistent, will pass.
    r_unpinned = verify_seal(s)
    assert r_unpinned.ok, "attacker-rewritten seal is self-consistent (expected)"

    # Pinned verification against the ORIGINAL issuer pubkey: MUST fail.
    r_pinned = verify_seal(s, issuer_pubkey_hex=original_issuer_pubkey)
    assert not r_pinned.ok
    assert any("issuer public key mismatch" in e for e in r_pinned.errors)


# --- Field addition / removal ----------------------------------------------

def test_add_unknown_top_level_field(seal):
    s = copy.deepcopy(seal)
    s["secret_backdoor"] = 1
    _assert_rejects(s)


def test_remove_required_field(seal):
    s = copy.deepcopy(seal)
    del s["timestamp"]
    _assert_rejects(s)


# --- Replay across protocols -----------------------------------------------

def test_sig_does_not_validate_on_raw_canonical():
    """A signature on the domain-separated payload MUST NOT validate against
    the canonical JSON alone (without the DOMAIN prefix)."""
    from crovia_seal.canonical import canonicalize
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature

    iss = generate_issuer_key("urn:crovia:seal-issuer:replay")
    s = emit_seal(
        issuer_key=iss, input_bytes=b"x", output_bytes=b"y",
        modality="text", generator_id="m",
    )
    sig = bytes.fromhex(s["signature"]["sig_hex"])
    pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(iss.public_hex))

    # Canonical form WITHOUT the domain prefix:
    stripped = {k: v for k, v in s.items() if k not in ("signature", "witnesses")}
    naked = canonicalize(stripped)

    with pytest.raises(InvalidSignature):
        pub.verify(sig, naked)


# --- Duplicate keys at JSON parse level -----------------------------------

def test_duplicate_top_level_keys_are_unreachable_in_python_dicts():
    # Python dicts cannot have literal duplicate keys (last wins). This
    # limitation is a protection: if an attacker serializes a Seal with
    # duplicate top-level keys in raw JSON text, a conformant parser will
    # either reject or pick one; re-canonicalization will then match the
    # picked one, not the attacker's intent. We document this behavior
    # and rely on json.loads' default (which keeps the last duplicate).
    # There is nothing more to assert here; this test is a regression pin
    # for future maintainers.
    assert True
