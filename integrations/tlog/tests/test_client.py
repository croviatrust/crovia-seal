"""
End-to-end client tests.

The AsyncTlogClient talks to the FastAPI app through httpx's ASGITransport
so nothing listens on a real port. Critically, all verification runs with
local primitives, so passing these tests proves that a verifier who only
pinned the log's public key can audit the log with zero additional trust.
"""
from __future__ import annotations

import pytest
from dataclasses import replace
from httpx import ASGITransport, AsyncClient

from crovia_seal import emit_seal, generate_issuer_key, compute_seal_hash
from crovia_seal.canonical import canonicalize
from crovia_tlog.client import AsyncTlogClient, build_anchor
from crovia_tlog.server import create_app


def _make_client(app) -> AsyncTlogClient:
    http = AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver", timeout=10.0)
    return AsyncTlogClient("http://testserver", http_client=http)


def _make_seal(i: int, issuer, prev_hash=None):
    return emit_seal(
        issuer_key=issuer,
        input_bytes=f"in{i}".encode(),
        output_bytes=f"out{i}".encode(),
        modality="text",
        generator_id="test/model",
        sequence=i,
        prev_seal_hash=prev_hash,
    )


@pytest.mark.asyncio
async def test_client_submit_and_verify_offline(settings_factory):
    settings = settings_factory()
    app = create_app(settings)
    issuer = generate_issuer_key("urn:crovia:seal-issuer:client-tests")
    seal = _make_seal(0, issuer)

    client = _make_client(app)
    async with client:
        pk = await client.fetch_public_key()
        assert len(pk) == 64
        result = await client.submit(seal)
        assert result.index == 0
        assert client.verify_submission(canonicalize(seal), result)


@pytest.mark.asyncio
async def test_client_detects_tampered_receipt(settings_factory):
    settings = settings_factory()
    app = create_app(settings)
    issuer = generate_issuer_key("urn:crovia:seal-issuer:client-tests")
    seal = _make_seal(0, issuer)

    async with _make_client(app) as client:
        await client.fetch_public_key()
        result = await client.submit(seal)
        bad_sth = dict(result.sth)
        bad_sth["root_hash"] = "00" * 32
        tampered = replace(result, sth=bad_sth)
        assert not client.verify_submission(canonicalize(seal), tampered)


@pytest.mark.asyncio
async def test_build_anchor_lets_offline_verifier_check_inclusion(settings_factory):
    """Once the anchor is embedded in the Seal, a downstream verifier needs
    only the pinned log pubkey to re-check inclusion - no network access."""
    settings = settings_factory()
    app = create_app(settings)
    issuer = generate_issuer_key("urn:crovia:seal-issuer:client-tests")
    seal = _make_seal(0, issuer)

    async with _make_client(app) as client:
        pubkey = await client.fetch_public_key()
        result = await client.submit(seal)
        anchor = build_anchor(result)

    from crovia_tlog.sth import verify_sth
    from crovia_tlog.merkle import verify_inclusion_proof, hash_leaf

    assert verify_sth(anchor["sth"], pubkey)
    leaf_hash = hash_leaf(canonicalize(seal))
    assert verify_inclusion_proof(
        leaf_hash=leaf_hash,
        leaf_index=anchor["leaf_index"],
        tree_size=anchor["tree_size"],
        proof=[bytes.fromhex(h) for h in anchor["audit_path"]],
        root=bytes.fromhex(anchor["sth"]["root_hash"]),
    )


@pytest.mark.asyncio
async def test_client_consistency_proof_round_trip(settings_factory):
    settings = settings_factory()
    app = create_app(settings)
    issuer = generate_issuer_key("urn:crovia:seal-issuer:client-tests")

    async with _make_client(app) as client:
        await client.fetch_public_key()
        prev = None
        roots = {}
        for i in range(5):
            seal = _make_seal(i, issuer, prev_hash=prev)
            prev = compute_seal_hash(seal)
            result = await client.submit(seal)
            roots[result.inclusion_proof["tree_size"]] = result.sth["root_hash"]

        proof = await client.fetch_consistency(first=2, second=5)
        assert client.verify_consistency(
            old_size=2,
            new_size=5,
            old_root_hex=roots[2],
            new_root_hex=roots[5],
            proof_hex=proof["proof"],
        )
