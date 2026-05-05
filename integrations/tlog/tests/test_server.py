"""
End-to-end tests for the Crovia TLog HTTP server.

Each test spins up a fresh app with an in-memory-equivalent SQLite file in
`tmp_path`, exercises the HTTP surface, and validates the Merkle proofs
returned by the server using ONLY the client-side verification primitives.

This is the strongest possible kind of integration test: server and client
do not share state beyond the public JSON responses.
"""
from __future__ import annotations

import pytest

from crovia_tlog.merkle import (
    hash_leaf,
    verify_inclusion_proof,
    verify_consistency_proof,
    merkle_tree_hash,
)
from crovia_tlog.sth import verify_sth


@pytest.mark.asyncio
async def test_health_and_well_known(client_and_settings):
    client, settings = client_and_settings
    r = await client.get("/health")
    assert r.status_code == 200
    body = r.json()
    assert body["log_id"] == settings.log_id
    assert body["tree_size"] == 0
    assert len(body["pubkey_hex"]) == 64

    r = await client.get("/.well-known/crovia-tlog.json")
    assert r.status_code == 200
    assert r.json()["pubkey"]["alg"] == "Ed25519"


@pytest.mark.asyncio
async def test_submit_and_verify_inclusion(client_and_settings, sample_seal):
    client, settings = client_and_settings
    r = await client.post("/v1/leaves", json=sample_seal)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["index"] == 0

    sth = body["sth"]
    assert verify_sth(sth, sth["log_pubkey_hex"])
    # Root of a 1-leaf tree = leaf hash itself.
    from crovia_seal.canonical import canonicalize
    expected_root = hash_leaf(canonicalize(sample_seal)).hex()
    assert sth["root_hash"] == expected_root

    # Inclusion proof (empty for 1-leaf tree) must verify.
    audit = [bytes.fromhex(h) for h in body["inclusion_proof"]["audit_path"]]
    assert verify_inclusion_proof(
        leaf_hash=hash_leaf(canonicalize(sample_seal)),
        leaf_index=0,
        tree_size=1,
        proof=audit,
        root=bytes.fromhex(sth["root_hash"]),
    )


@pytest.mark.asyncio
async def test_duplicate_submission_returns_409(client_and_settings, sample_seal):
    client, _ = client_and_settings
    r1 = await client.post("/v1/leaves", json=sample_seal)
    assert r1.status_code == 200
    r2 = await client.post("/v1/leaves", json=sample_seal)
    assert r2.status_code == 409


@pytest.mark.asyncio
async def test_invalid_seal_rejected_when_require_valid_true(client_and_settings):
    client, _ = client_and_settings
    # A minimal bogus seal missing signature.
    bogus = {"seal_id": "cs_2026_AAAAAAAAAAAAAAAAAAAAAAAAAA"}
    r = await client.post("/v1/leaves", json=bogus)
    assert r.status_code == 400


@pytest.mark.asyncio
async def test_multiple_seals_chain_consistency(settings_factory):
    """Submit N seals, then ask the server for an N-vs-K consistency proof
    and verify it client-side. This proves the server cannot rewrite history
    (if it did, the proof it returns would fail verification)."""
    from httpx import ASGITransport, AsyncClient
    from crovia_seal import emit_seal, generate_issuer_key, compute_seal_hash
    from crovia_tlog.server import create_app
    from crovia_seal.canonical import canonicalize

    settings = settings_factory()
    app = create_app(settings)

    # Generate 6 chained seals.
    issuer = generate_issuer_key("urn:crovia:seal-issuer:chain-tests")
    seals = []
    prev_hash = None
    for i in range(6):
        seal = emit_seal(
            issuer_key=issuer,
            input_bytes=f"in{i}".encode(),
            output_bytes=f"out{i}".encode(),
            modality="text",
            generator_id="test/model",
            sequence=i,
            prev_seal_hash=prev_hash,
        )
        prev_hash = compute_seal_hash(seal)
        seals.append(seal)

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        roots_by_size = {}
        for seal in seals:
            r = await client.post("/v1/leaves", json=seal)
            assert r.status_code == 200, r.text
            sth = r.json()["sth"]
            roots_by_size[sth["tree_size"]] = bytes.fromhex(sth["root_hash"])

        # Ask for a consistency proof between tree sizes 3 and 6.
        r = await client.get("/v1/proof/consistency", params={"first": 3, "second": 6})
        assert r.status_code == 200
        body = r.json()
        proof = [bytes.fromhex(h) for h in body["proof"]]
        assert verify_consistency_proof(
            old_size=3,
            new_size=6,
            old_root=roots_by_size[3],
            new_root=roots_by_size[6],
            proof=proof,
        )

        # Ask for an inclusion proof for leaf 2 in tree of size 6.
        r = await client.get("/v1/proof/inclusion", params={"leaf_index": 2, "tree_size": 6})
        assert r.status_code == 200
        ib = r.json()
        leaf_hash_2 = hash_leaf(canonicalize(seals[2]))
        assert verify_inclusion_proof(
            leaf_hash=leaf_hash_2,
            leaf_index=2,
            tree_size=6,
            proof=[bytes.fromhex(h) for h in ib["audit_path"]],
            root=bytes.fromhex(ib["root_hash_hex"]),
        )


@pytest.mark.asyncio
async def test_lookup_by_seal_id_and_index(client_and_settings, sample_seal):
    client, _ = client_and_settings
    r = await client.post("/v1/leaves", json=sample_seal)
    assert r.status_code == 200

    r = await client.get(f"/v1/leaves/by-seal-id/{sample_seal['seal_id']}")
    assert r.status_code == 200
    assert r.json()["index"] == 0

    r = await client.get("/v1/leaves/0")
    assert r.status_code == 200
    assert r.json()["seal"]["seal_id"] == sample_seal["seal_id"]

    r = await client.get("/v1/leaves/999")
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_sth_signature_verifies(client_and_settings, sample_seal):
    client, _ = client_and_settings
    await client.post("/v1/leaves", json=sample_seal)
    r = await client.get("/v1/sth")
    assert r.status_code == 200
    sth = r.json()
    # Signature valid against the key the STH itself advertises.
    assert verify_sth(sth, sth["log_pubkey_hex"])
    # Tampering flips the verdict.
    tampered = dict(sth)
    tampered["tree_size"] = sth["tree_size"] + 1
    assert not verify_sth(tampered, sth["log_pubkey_hex"])
