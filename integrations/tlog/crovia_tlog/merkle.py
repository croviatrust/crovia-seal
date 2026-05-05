"""
RFC 6962-style Merkle tree utilities.

The Crovia Transparency Log (CTLog) is append-only. Every submitted Seal is
hashed into a leaf, and a balanced-as-possible Merkle tree is computed over
the leaf sequence. The tree exposes two crucial primitives:

    inclusion_proof(i, N)  - evidence that leaf `i` is contained in the tree
                             of size `N` (lets a verifier who trusts the root
                             conclude membership from O(log N) hashes).

    consistency_proof(M, N) - evidence that the tree of size `N` is an
                              APPEND-ONLY continuation of the tree of size
                              `M` (M <= N). This is what makes the log
                              auditable: an operator who tries to rewrite
                              history can never produce a valid consistency
                              proof.

Hashing (RFC 6962 Section 2.1):
    HASH_LEAF(d)     = SHA-256(0x00 || d)
    HASH_CHILDREN(L,R) = SHA-256(0x01 || L || R)
    MTH({})          = SHA-256(empty)

All functions are pure and deterministic.
"""
from __future__ import annotations

import hashlib
from typing import List, Sequence


EMPTY_ROOT: bytes = hashlib.sha256(b"").digest()


# ---------------------------------------------------------------------------
# Hashes
# ---------------------------------------------------------------------------

def hash_leaf(data: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + data).digest()


def hash_children(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


# ---------------------------------------------------------------------------
# Merkle tree root
# ---------------------------------------------------------------------------

def merkle_tree_hash(leaf_hashes: Sequence[bytes]) -> bytes:
    """Compute the Merkle Tree Hash (MTH) over a list of pre-hashed leaves.

    Leaves MUST already be in HASH_LEAF(d) form; this function never applies
    the leaf prefix itself. The input is consumed read-only.
    """
    n = len(leaf_hashes)
    if n == 0:
        return EMPTY_ROOT
    if n == 1:
        return leaf_hashes[0]
    # Split at the largest power-of-two < n (RFC 6962, k = largest 2^x < n)
    k = _largest_power_of_two_less_than(n)
    left = merkle_tree_hash(leaf_hashes[:k])
    right = merkle_tree_hash(leaf_hashes[k:])
    return hash_children(left, right)


def _largest_power_of_two_less_than(n: int) -> int:
    if n <= 1:
        raise ValueError("n must be >= 2 for split")
    k = 1
    while (k << 1) < n:
        k <<= 1
    return k


# ---------------------------------------------------------------------------
# Inclusion proof (RFC 6962 Section 2.1.1)
# ---------------------------------------------------------------------------

def inclusion_proof(leaf_index: int, leaf_hashes: Sequence[bytes]) -> List[bytes]:
    """Produce a Merkle audit path that proves `leaf_hashes[leaf_index]` is
    included in the tree built over `leaf_hashes`.

    The result is a list of sibling hashes, ORDERED BOTTOM-UP. To verify the
    proof, call `verify_inclusion_proof(...)`.
    """
    n = len(leaf_hashes)
    if not 0 <= leaf_index < n:
        raise IndexError(f"leaf_index {leaf_index} out of range for tree size {n}")
    return _subproof(leaf_index, leaf_hashes, starting=True)


def _subproof(m: int, leaves: Sequence[bytes], *, starting: bool) -> List[bytes]:
    """Recursive helper used by both inclusion and consistency proofs.

    See RFC 6962 Section 2.1.1 / 2.1.2 for the pseudo-code this mirrors.
    """
    n = len(leaves)
    if n == 1:
        return []
    k = _largest_power_of_two_less_than(n)
    if m < k:
        return _subproof(m, leaves[:k], starting=starting) + [merkle_tree_hash(leaves[k:])]
    else:
        return _subproof(m - k, leaves[k:], starting=False) + [merkle_tree_hash(leaves[:k])]


def verify_inclusion_proof(
    leaf_hash: bytes,
    leaf_index: int,
    tree_size: int,
    proof: Sequence[bytes],
    root: bytes,
) -> bool:
    """Return True iff `proof` proves that `leaf_hash` is at `leaf_index`
    within a tree of size `tree_size` whose root is `root`.

    Algorithm: RFC 6962 Section 2.1.1, adapted for the common case.
    """
    if not 0 <= leaf_index < tree_size:
        return False
    fn = leaf_index
    sn = tree_size - 1
    r = leaf_hash
    for sibling in proof:
        if sn == 0:
            return False
        if (fn & 1) or (fn == sn):
            r = hash_children(sibling, r)
            if not (fn & 1):
                while not (fn & 1) and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            r = hash_children(r, sibling)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == root


# ---------------------------------------------------------------------------
# Consistency proof (RFC 6962 Section 2.1.2)
# ---------------------------------------------------------------------------

def consistency_proof(m: int, leaf_hashes: Sequence[bytes]) -> List[bytes]:
    """Produce evidence that the tree of the first `m` leaves is a prefix of
    the current tree of size len(leaf_hashes)."""
    n = len(leaf_hashes)
    if m == 0 or m > n:
        raise ValueError(f"consistency proof requires 0 < m <= n (got m={m}, n={n})")
    if m == n:
        return []  # identical trees
    return _consistency(m, leaf_hashes, starting=True)


def _consistency(m: int, leaves: Sequence[bytes], *, starting: bool) -> List[bytes]:
    n = len(leaves)
    if m == n:
        return [merkle_tree_hash(leaves)] if not starting else []
    k = _largest_power_of_two_less_than(n)
    if m <= k:
        return _consistency(m, leaves[:k], starting=starting) + [merkle_tree_hash(leaves[k:])]
    else:
        return _consistency(m - k, leaves[k:], starting=False) + [merkle_tree_hash(leaves[:k])]


def verify_consistency_proof(
    old_size: int,
    new_size: int,
    old_root: bytes,
    new_root: bytes,
    proof: Sequence[bytes],
) -> bool:
    """Verify an RFC 6962 consistency proof between two tree sizes."""
    if old_size < 0 or new_size < old_size:
        return False
    if old_size == new_size:
        return len(proof) == 0 and old_root == new_root
    if old_size == 0:
        # By convention, an empty old tree trivially extends into any tree.
        return len(proof) == 0

    # If old_size is a power of two, the caller didn't include old_root in
    # the proof. Prepend it (RFC 6962 Section 2.1.2).
    proof_list = list(proof)
    if (old_size & (old_size - 1)) == 0:
        proof_list = [old_root] + proof_list

    fn, sn = old_size - 1, new_size - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1

    if not proof_list:
        return False

    # The first hash is fr = fs = proof[0]
    fr = fs = proof_list[0]
    for sibling in proof_list[1:]:
        if sn == 0:
            return False
        if (fn & 1) or (fn == sn):
            fr = hash_children(sibling, fr)
            fs = hash_children(sibling, fs)
            if not (fn & 1):
                while not (fn & 1) and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            fs = hash_children(fs, sibling)
        fn >>= 1
        sn >>= 1

    return sn == 0 and fr == old_root and fs == new_root


__all__ = [
    "EMPTY_ROOT",
    "hash_leaf",
    "hash_children",
    "merkle_tree_hash",
    "inclusion_proof",
    "verify_inclusion_proof",
    "consistency_proof",
    "verify_consistency_proof",
]
