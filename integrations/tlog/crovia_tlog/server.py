"""
FastAPI app implementing the Crovia Transparency Log HTTP API.

Endpoints:

    GET  /health                           -> liveness + identity
    GET  /.well-known/crovia-tlog.json     -> public log metadata (pubkey, log_id)
    POST /v1/leaves                        -> append a seal, returns {index, sth, proof}
    GET  /v1/leaves/{index}                -> raw leaf data
    GET  /v1/leaves/by-seal-id/{seal_id}   -> lookup by seal_id
    GET  /v1/sth                           -> latest Signed Tree Head
    GET  /v1/proof/inclusion
         ?leaf_index=N&tree_size=M         -> RFC 6962 inclusion proof
    GET  /v1/proof/consistency
         ?first=M&second=N                 -> RFC 6962 consistency proof

All hashes are transported as lowercase hex.
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import JSONResponse

from crovia_seal import verify_seal

from crovia_tlog.config import Settings
from crovia_tlog.keys import TlogKey
from crovia_tlog.merkle import (
    consistency_proof,
    inclusion_proof,
    merkle_tree_hash,
)
from crovia_tlog.storage import DuplicateSealError, LogStorage
from crovia_tlog.sth import sign_sth


def _hex_list(hashes: List[bytes]) -> List[str]:
    return [h.hex() for h in hashes]


def create_app(settings: Optional[Settings] = None) -> FastAPI:
    settings = settings or Settings()
    storage = LogStorage(settings.db_path)
    log_key = TlogKey.from_hex(settings.resolve_private_hex())

    app = FastAPI(
        title="Crovia Transparency Log",
        version="0.5.0",
        description="Append-only Merkle log (RFC 6962 style) for Crovia Seal v1 receipts.",
    )

    # -----------------------------------------------------------------
    # Public metadata
    # -----------------------------------------------------------------

    @app.get("/health")
    def health() -> Dict[str, Any]:
        return {
            "ok": True,
            "log_id": settings.log_id,
            "tree_size": storage.tree_size(),
            "pubkey_hex": log_key.public_hex,
        }

    @app.get("/.well-known/crovia-tlog.json")
    def well_known() -> Dict[str, Any]:
        return {
            "log_id": settings.log_id,
            "pubkey": {"alg": "Ed25519", "key_hex": log_key.public_hex},
            "version": "0.5.0",
        }

    # -----------------------------------------------------------------
    # STH
    # -----------------------------------------------------------------

    @app.get("/v1/sth")
    def current_sth() -> Dict[str, Any]:
        size = storage.tree_size()
        leaf_hashes = storage.all_leaf_hashes()
        root = merkle_tree_hash(leaf_hashes)
        return sign_sth(
            log_id=settings.log_id,
            tree_size=size,
            root_hash=root,
            log_key=log_key,
        )

    # -----------------------------------------------------------------
    # Append leaf
    # -----------------------------------------------------------------

    @app.post("/v1/leaves")
    async def submit_leaf(request: Request) -> Dict[str, Any]:
        raw = await request.body()
        try:
            seal = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise HTTPException(status_code=400, detail="body must be JSON")
        if not isinstance(seal, dict):
            raise HTTPException(status_code=400, detail="body must be a JSON object (a Seal)")

        seal_id = seal.get("seal_id")
        if not isinstance(seal_id, str) or not seal_id:
            raise HTTPException(status_code=400, detail="Seal missing seal_id")

        if settings.require_valid_seal:
            vr = verify_seal(seal)
            if not vr.ok:
                raise HTTPException(status_code=400, detail={"error": "invalid seal", "reasons": vr.errors})

        # Canonicalize the submission bytes so byte-identical seals submitted
        # twice (with just key reordering) are deduplicated consistently.
        # We rely on the same canon the core library uses (`canonicalize`),
        # imported lazily to keep server import surface minimal.
        from crovia_seal.canonical import canonicalize
        canonical_bytes = canonicalize(seal)

        try:
            record = storage.append(seal_id=seal_id, seal_bytes=canonical_bytes)
        except DuplicateSealError as e:
            raise HTTPException(status_code=409, detail=str(e))

        # Produce the fresh STH + inclusion proof for the just-appended leaf.
        leaf_hashes = storage.all_leaf_hashes()
        root = merkle_tree_hash(leaf_hashes)
        proof = inclusion_proof(record.index, leaf_hashes)
        sth = sign_sth(
            log_id=settings.log_id,
            tree_size=len(leaf_hashes),
            root_hash=root,
            log_key=log_key,
        )

        return {
            "index": record.index,
            "leaf_hash_hex": record.leaf_hash.hex(),
            "inserted_at": record.inserted_at,
            "inclusion_proof": {
                "leaf_index": record.index,
                "tree_size": len(leaf_hashes),
                "audit_path": _hex_list(proof),
            },
            "sth": sth,
        }

    # -----------------------------------------------------------------
    # Lookups
    # -----------------------------------------------------------------

    @app.get("/v1/leaves/by-seal-id/{seal_id}")
    def leaf_by_seal_id(seal_id: str) -> Dict[str, Any]:
        record = storage.get_leaf_by_seal_id(seal_id)
        if record is None:
            raise HTTPException(status_code=404, detail="not found")
        return {
            "index": record.index,
            "leaf_hash_hex": record.leaf_hash.hex(),
            "seal_id": record.seal_id,
            "inserted_at": record.inserted_at,
            "leaf_data_len": len(record.leaf_data),
        }

    @app.get("/v1/leaves/{index}")
    def get_leaf(index: int) -> Any:
        record = storage.get_leaf(index)
        if record is None:
            raise HTTPException(status_code=404, detail="not found")
        try:
            seal = json.loads(record.leaf_data.decode("utf-8"))
        except Exception:
            seal = None
        return {
            "index": record.index,
            "leaf_hash_hex": record.leaf_hash.hex(),
            "seal_id": record.seal_id,
            "inserted_at": record.inserted_at,
            "seal": seal,
        }

    # -----------------------------------------------------------------
    # Proofs on demand
    # -----------------------------------------------------------------

    @app.get("/v1/proof/inclusion")
    def proof_inclusion(
        leaf_index: int = Query(..., ge=0),
        tree_size: int = Query(..., ge=1),
    ) -> Dict[str, Any]:
        current_size = storage.tree_size()
        if tree_size > current_size:
            raise HTTPException(status_code=400, detail="requested tree_size exceeds current size")
        if leaf_index >= tree_size:
            raise HTTPException(status_code=400, detail="leaf_index must be < tree_size")
        leaf_hashes = storage.all_leaf_hashes(up_to=tree_size)
        proof = inclusion_proof(leaf_index, leaf_hashes)
        root = merkle_tree_hash(leaf_hashes)
        return {
            "leaf_index": leaf_index,
            "tree_size": tree_size,
            "audit_path": _hex_list(proof),
            "root_hash_hex": root.hex(),
        }

    @app.get("/v1/proof/consistency")
    def proof_consistency(
        first: int = Query(..., ge=1),
        second: int = Query(..., ge=1),
    ) -> Dict[str, Any]:
        if first > second:
            raise HTTPException(status_code=400, detail="first must be <= second")
        current_size = storage.tree_size()
        if second > current_size:
            raise HTTPException(status_code=400, detail="second exceeds current tree size")
        leaf_hashes = storage.all_leaf_hashes(up_to=second)
        proof = consistency_proof(first, leaf_hashes)
        return {
            "first": first,
            "second": second,
            "proof": _hex_list(proof),
            "first_root_hex": merkle_tree_hash(leaf_hashes[:first]).hex(),
            "second_root_hex": merkle_tree_hash(leaf_hashes).hex(),
        }

    return app
