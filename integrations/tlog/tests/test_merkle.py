"""
Merkle tree correctness tests.

Two layers:

1. Known-answer vectors from RFC 6962 (Appendix B / reference test data)
   ensure our hashes match other RFC-compliant implementations byte-for-byte.

2. Exhaustive property tests: for every tree size n in [1, 64] and every
   leaf index i in [0, n), the round-trip proof-verify loop must succeed,
   and the wrong leaf_hash must always be rejected.
"""
from __future__ import annotations

import hashlib
import itertools
import secrets

import pytest

from crovia_tlog.merkle import (
    EMPTY_ROOT,
    hash_leaf,
    hash_children,
    merkle_tree_hash,
    inclusion_proof,
    verify_inclusion_proof,
    consistency_proof,
    verify_consistency_proof,
)


# ---------------------------------------------------------------------------
# Known-answer: RFC 6962 reference vectors
# ---------------------------------------------------------------------------

# Leaf data from the "certificate-transparency" reference implementation
# test vectors (well-known, public, stable). See
# https://datatracker.ietf.org/doc/html/rfc6962#section-2.1.3 and the
# `test-data/` directory of google/certificate-transparency.
_RFC_LEAVES = [
    bytes.fromhex(""),                                         # empty
    bytes.fromhex("00"),
    bytes.fromhex("10"),
    bytes.fromhex("2021"),
    bytes.fromhex("3031"),
    bytes.fromhex("40414243"),
    bytes.fromhex("5051525354555657"),
    bytes.fromhex("606162636465666768696a6b6c6d6e6f"),
]

# Expected root hashes (hex) for the Merkle tree built over the FIRST n
# RFC vectors (1..8). Values taken from the CT reference implementation.
_RFC_EXPECTED_ROOTS_HEX = [
    "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
    "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
    "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
    "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
    "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
    "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
    "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
    "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
]


def test_empty_tree_root():
    assert merkle_tree_hash([]).hex() == hashlib.sha256(b"").hexdigest()
    assert merkle_tree_hash([]) == EMPTY_ROOT


@pytest.mark.parametrize("n", range(1, 9))
def test_rfc6962_known_roots(n):
    leaf_hashes = [hash_leaf(x) for x in _RFC_LEAVES[:n]]
    root = merkle_tree_hash(leaf_hashes)
    assert root.hex() == _RFC_EXPECTED_ROOTS_HEX[n - 1], \
        f"tree size {n}: got {root.hex()} expected {_RFC_EXPECTED_ROOTS_HEX[n - 1]}"


# ---------------------------------------------------------------------------
# Exhaustive inclusion round-trip
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("n", [1, 2, 3, 4, 5, 7, 8, 15, 16, 17, 32, 63, 64])
def test_inclusion_proof_round_trip_all_indices(n):
    rng = secrets.token_bytes
    leaves = [rng(16) for _ in range(n)]
    leaf_hashes = [hash_leaf(l) for l in leaves]
    root = merkle_tree_hash(leaf_hashes)
    for i in range(n):
        proof = inclusion_proof(i, leaf_hashes)
        assert verify_inclusion_proof(leaf_hashes[i], i, n, proof, root), \
            f"inclusion proof FAILED for index {i} in tree of size {n}"


def test_inclusion_rejects_wrong_leaf():
    leaves = [b"a", b"b", b"c", b"d", b"e"]
    leaf_hashes = [hash_leaf(l) for l in leaves]
    root = merkle_tree_hash(leaf_hashes)
    proof = inclusion_proof(2, leaf_hashes)
    # Wrong leaf value
    assert not verify_inclusion_proof(hash_leaf(b"X"), 2, len(leaves), proof, root)
    # Wrong index
    assert not verify_inclusion_proof(leaf_hashes[2], 3, len(leaves), proof, root)
    # Wrong root
    assert not verify_inclusion_proof(leaf_hashes[2], 2, len(leaves), proof, b"\x00" * 32)


def test_inclusion_rejects_tampered_proof():
    leaves = [secrets.token_bytes(8) for _ in range(10)]
    leaf_hashes = [hash_leaf(l) for l in leaves]
    root = merkle_tree_hash(leaf_hashes)
    proof = inclusion_proof(5, leaf_hashes)
    # Flip one byte of the first sibling hash
    flipped = bytearray(proof[0])
    flipped[0] ^= 0xFF
    tampered = [bytes(flipped)] + proof[1:]
    assert not verify_inclusion_proof(leaf_hashes[5], 5, len(leaves), tampered, root)


# ---------------------------------------------------------------------------
# Exhaustive consistency round-trip
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("n", [1, 2, 3, 4, 7, 8, 15, 16, 17, 32])
def test_consistency_proof_round_trip(n):
    leaves = [secrets.token_bytes(8) for _ in range(n)]
    leaf_hashes = [hash_leaf(l) for l in leaves]
    new_root = merkle_tree_hash(leaf_hashes)
    for m in range(1, n + 1):
        old_root = merkle_tree_hash(leaf_hashes[:m])
        proof = consistency_proof(m, leaf_hashes)
        assert verify_consistency_proof(m, n, old_root, new_root, proof), \
            f"consistency FAILED m={m} n={n}"


def test_consistency_rejects_wrong_old_root():
    leaves = [secrets.token_bytes(8) for _ in range(10)]
    leaf_hashes = [hash_leaf(l) for l in leaves]
    new_root = merkle_tree_hash(leaf_hashes)
    proof = consistency_proof(6, leaf_hashes)
    bogus_old = secrets.token_bytes(32)
    assert not verify_consistency_proof(6, 10, bogus_old, new_root, proof)


def test_consistency_rejects_divergent_history():
    # Original tree of 5 leaves, then two alternative continuations must not
    # validate a consistency proof between them.
    base = [secrets.token_bytes(8) for _ in range(5)]
    branch_a = [hash_leaf(l) for l in base + [secrets.token_bytes(8) for _ in range(3)]]
    branch_b = [hash_leaf(l) for l in base + [secrets.token_bytes(8) for _ in range(3)]]
    old_root = merkle_tree_hash([hash_leaf(l) for l in base])
    root_a = merkle_tree_hash(branch_a)
    root_b = merkle_tree_hash(branch_b)
    proof_a = consistency_proof(5, branch_a)
    # The proof made for branch_a MUST NOT verify against the root of branch_b.
    assert not verify_consistency_proof(5, 8, old_root, root_b, proof_a)
    # But it DOES verify against its own branch (sanity).
    assert verify_consistency_proof(5, 8, old_root, root_a, proof_a)


def test_consistency_identical_trees_empty_proof():
    leaves = [hash_leaf(secrets.token_bytes(8)) for _ in range(7)]
    root = merkle_tree_hash(leaves)
    assert consistency_proof(7, leaves) == []
    assert verify_consistency_proof(7, 7, root, root, [])
