"""
HTTP client for a Crovia Transparency Log.

Designed to be dependency-minimal for embedders: the only hard dep is httpx.
All verification is done LOCALLY using the pure-Python `merkle.py` and
`sth.py` helpers so a verifier who has pinned the log's public key never
has to trust the log's responses beyond their signatures.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import httpx

from crovia_tlog.merkle import (
    hash_leaf,
    verify_inclusion_proof,
    verify_consistency_proof,
)
from crovia_tlog.sth import verify_sth


@dataclass(frozen=True)
class SubmissionResult:
    index: int
    leaf_hash_hex: str
    inserted_at: str
    sth: Dict[str, Any]
    inclusion_proof: Dict[str, Any]


class TlogClient:
    """Tiny synchronous client (httpx.Client) - one call per method."""

    def __init__(
        self,
        base_url: str,
        *,
        log_pubkey_hex: Optional[str] = None,
        timeout: float = 10.0,
    ) -> None:
        self._base = base_url.rstrip("/")
        self._client = httpx.Client(timeout=timeout)
        self._pubkey_hex = log_pubkey_hex

    # -------------------------------------------------------------

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "TlogClient":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # -------------------------------------------------------------
    # Metadata
    # -------------------------------------------------------------

    def fetch_public_key(self) -> str:
        r = self._client.get(f"{self._base}/.well-known/crovia-tlog.json")
        r.raise_for_status()
        pk = r.json()["pubkey"]["key_hex"]
        self._pubkey_hex = pk
        return pk

    def sth(self) -> Dict[str, Any]:
        r = self._client.get(f"{self._base}/v1/sth")
        r.raise_for_status()
        return r.json()

    # -------------------------------------------------------------
    # Submission
    # -------------------------------------------------------------

    def submit(self, seal: Dict[str, Any]) -> SubmissionResult:
        r = self._client.post(f"{self._base}/v1/leaves", json=seal)
        r.raise_for_status()
        body = r.json()
        return SubmissionResult(
            index=body["index"],
            leaf_hash_hex=body["leaf_hash_hex"],
            inserted_at=body["inserted_at"],
            sth=body["sth"],
            inclusion_proof=body["inclusion_proof"],
        )

    # -------------------------------------------------------------
    # Proofs
    # -------------------------------------------------------------

    def fetch_inclusion(self, leaf_index: int, tree_size: int) -> Dict[str, Any]:
        r = self._client.get(
            f"{self._base}/v1/proof/inclusion",
            params={"leaf_index": leaf_index, "tree_size": tree_size},
        )
        r.raise_for_status()
        return r.json()

    def fetch_consistency(self, first: int, second: int) -> Dict[str, Any]:
        r = self._client.get(
            f"{self._base}/v1/proof/consistency",
            params={"first": first, "second": second},
        )
        r.raise_for_status()
        return r.json()

    # -------------------------------------------------------------
    # Local verification (no trust in the server)
    # -------------------------------------------------------------

    def verify_sth(self, sth: Dict[str, Any]) -> bool:
        if self._pubkey_hex is None:
            raise RuntimeError("log_pubkey_hex not known; call fetch_public_key() first")
        return verify_sth(sth, self._pubkey_hex)

    def verify_submission(self, seal_canonical_bytes: bytes, result: SubmissionResult) -> bool:
        """Verify the submission receipt offline.

        1. STH signature must verify against the pinned log pubkey.
        2. Leaf hash recomputed from `seal_canonical_bytes` must match.
        3. Inclusion proof must produce the STH root.
        """
        if not self.verify_sth(result.sth):
            return False
        leaf_hash = hash_leaf(seal_canonical_bytes)
        if leaf_hash.hex() != result.leaf_hash_hex:
            return False
        audit = [bytes.fromhex(h) for h in result.inclusion_proof["audit_path"]]
        return verify_inclusion_proof(
            leaf_hash=leaf_hash,
            leaf_index=result.index,
            tree_size=result.inclusion_proof["tree_size"],
            proof=audit,
            root=bytes.fromhex(result.sth["root_hash"]),
        )

    def verify_consistency(
        self,
        old_size: int,
        new_size: int,
        old_root_hex: str,
        new_root_hex: str,
        proof_hex: List[str],
    ) -> bool:
        return verify_consistency_proof(
            old_size=old_size,
            new_size=new_size,
            old_root=bytes.fromhex(old_root_hex),
            new_root=bytes.fromhex(new_root_hex),
            proof=[bytes.fromhex(h) for h in proof_hex],
        )


# ---------------------------------------------------------------------------
# Async variant (same API). Useful inside FastAPI services and tests.
# ---------------------------------------------------------------------------

class AsyncTlogClient:
    """Async twin of TlogClient. The client may be constructed with a
    caller-provided AsyncClient (e.g. backed by httpx.ASGITransport for tests
    or by an authenticated client in production)."""

    def __init__(
        self,
        base_url: str,
        *,
        http_client: Optional[httpx.AsyncClient] = None,
        log_pubkey_hex: Optional[str] = None,
        timeout: float = 10.0,
    ) -> None:
        self._base = base_url.rstrip("/")
        self._owns_client = http_client is None
        self._client = http_client or httpx.AsyncClient(timeout=timeout)
        self._pubkey_hex = log_pubkey_hex

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    async def __aenter__(self) -> "AsyncTlogClient":
        return self

    async def __aexit__(self, *exc) -> None:
        await self.aclose()

    async def fetch_public_key(self) -> str:
        r = await self._client.get(f"{self._base}/.well-known/crovia-tlog.json")
        r.raise_for_status()
        pk = r.json()["pubkey"]["key_hex"]
        self._pubkey_hex = pk
        return pk

    async def sth(self) -> Dict[str, Any]:
        r = await self._client.get(f"{self._base}/v1/sth")
        r.raise_for_status()
        return r.json()

    async def submit(self, seal: Dict[str, Any]) -> SubmissionResult:
        r = await self._client.post(f"{self._base}/v1/leaves", json=seal)
        r.raise_for_status()
        body = r.json()
        return SubmissionResult(
            index=body["index"],
            leaf_hash_hex=body["leaf_hash_hex"],
            inserted_at=body["inserted_at"],
            sth=body["sth"],
            inclusion_proof=body["inclusion_proof"],
        )

    async def fetch_inclusion(self, leaf_index: int, tree_size: int) -> Dict[str, Any]:
        r = await self._client.get(
            f"{self._base}/v1/proof/inclusion",
            params={"leaf_index": leaf_index, "tree_size": tree_size},
        )
        r.raise_for_status()
        return r.json()

    async def fetch_consistency(self, first: int, second: int) -> Dict[str, Any]:
        r = await self._client.get(
            f"{self._base}/v1/proof/consistency",
            params={"first": first, "second": second},
        )
        r.raise_for_status()
        return r.json()

    def verify_sth(self, sth: Dict[str, Any]) -> bool:
        if self._pubkey_hex is None:
            raise RuntimeError("log_pubkey_hex not known; call fetch_public_key() first")
        return verify_sth(sth, self._pubkey_hex)

    def verify_submission(self, seal_canonical_bytes: bytes, result: SubmissionResult) -> bool:
        if not self.verify_sth(result.sth):
            return False
        leaf_hash = hash_leaf(seal_canonical_bytes)
        if leaf_hash.hex() != result.leaf_hash_hex:
            return False
        audit = [bytes.fromhex(h) for h in result.inclusion_proof["audit_path"]]
        return verify_inclusion_proof(
            leaf_hash=leaf_hash,
            leaf_index=result.index,
            tree_size=result.inclusion_proof["tree_size"],
            proof=audit,
            root=bytes.fromhex(result.sth["root_hash"]),
        )

    def verify_consistency(
        self,
        old_size: int,
        new_size: int,
        old_root_hex: str,
        new_root_hex: str,
        proof_hex: List[str],
    ) -> bool:
        return verify_consistency_proof(
            old_size=old_size,
            new_size=new_size,
            old_root=bytes.fromhex(old_root_hex),
            new_root=bytes.fromhex(new_root_hex),
            proof=[bytes.fromhex(h) for h in proof_hex],
        )


# ---------------------------------------------------------------------------
# Anchor helper: attach the inclusion proof into the Seal's `anchor` field
# ---------------------------------------------------------------------------

def build_anchor(result: SubmissionResult) -> Dict[str, Any]:
    """Render a SubmissionResult as a Seal-spec-compatible `anchor` object.

    Storing this inside the Seal's `anchor` field lets downstream verifiers
    re-check inclusion without contacting the log at all - only the pinned
    pubkey is needed. This is what turns Crovia into "trust the math, not
    the server".
    """
    return {
        "kind": "crovia-tlog",
        "log_id": result.sth["log_id"],
        "leaf_index": result.index,
        "tree_size": result.inclusion_proof["tree_size"],
        "audit_path": result.inclusion_proof["audit_path"],
        "sth": result.sth,
    }
