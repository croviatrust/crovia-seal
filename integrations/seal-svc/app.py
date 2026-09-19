"""
Crovia Seal Service v1 — public sealing + retrieval endpoint.

POST /v1/sign      -> sign an AI output, return a conformant crovia.seal.v1 Seal
GET  /v1/seal/{id} -> retrieve a previously-issued Seal by its seal_id
GET  /v1/stats     -> public counters (total seals, last seal time, chain head)
GET  /health       -> 200 if running

Every Seal issued here is a `crovia.seal.v1` object produced by the reference
implementation (`crovia_seal.emit_seal`), so it verifies with `verify_seal`,
with the web verifier at croviatrust.com/registry/seal/verify/ and with any
conformant third-party verifier. Seals form one hash chain per issuer key
(SPEC §4.8): `chain.prev_seal_hash` is the SHA-256 of the previous Seal's
signed payload.

Free, no auth. Rate-limit via a simple in-memory token bucket per IP.
Persists Seals to a JSON-Lines append-only log; reload-resilient.

Deployment:
    - expects /opt/crovia/keys/seal/private.hex (+ public.hex, informational)
    - listens on 127.0.0.1:8090
    - fronted by nginx at seal.croviatrust.com/v1/* and /health
    - requires the reference package: pip install -e reference/python

Seals issued by the previous, non-conformant version of this service
(`seal_version: "crovia-seal-v1"`) stay retrievable by id but are marked
`legacy: true` in /v1/seal/{id} responses and are not counted in the chain.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from collections import defaultdict, deque
from pathlib import Path
from typing import Any, Dict, Optional

from fastapi import FastAPI, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, Field

from crovia_seal import emit_seal, verify_seal
from crovia_seal.constants import ALLOWED_MODALITIES, SEAL_VERSION
from crovia_seal.keys import load_issuer_key
from crovia_seal.seal import compute_seal_hash

# ----------------------------- KEY LOAD --------------------------------
KEY_PATH = os.environ.get("CROVIA_SEAL_KEY", "/opt/crovia/keys/seal/private.hex")
ISSUER = os.environ.get("CROVIA_SEAL_ISSUER", "urn:crovia:seal-issuer:crovia-trust")

with open(KEY_PATH) as f:
    ISSUER_KEY = load_issuer_key(ISSUER, f.read().strip())
PUB_HEX = ISSUER_KEY.public_hex

# ----------------------------- STORAGE ---------------------------------
DATA_DIR = Path(os.environ.get("CROVIA_SEAL_DATA", "/opt/crovia/seal-svc/data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)
LOG_PATH = DATA_DIR / "seals.jsonl"
INDEX: Dict[str, dict] = {}
CHAIN_HEAD: Optional[dict] = None   # last conformant Seal issued by this key


def _is_conformant(s: dict) -> bool:
    return s.get("seal_version") == SEAL_VERSION


def _load_index() -> None:
    global CHAIN_HEAD
    if not LOG_PATH.exists():
        return
    for line in LOG_PATH.open():
        line = line.strip()
        if not line:
            continue
        try:
            s = json.loads(line)
        except json.JSONDecodeError:
            continue
        sid = s.get("seal_id")
        if not sid:
            continue
        INDEX[sid] = s
        if _is_conformant(s) and s.get("issuer", {}).get("pubkey", {}).get("key_hex") == PUB_HEX:
            if CHAIN_HEAD is None or s["chain"]["sequence"] > CHAIN_HEAD["chain"]["sequence"]:
                CHAIN_HEAD = s


_load_index()

# ----------------------------- RATE LIMIT ------------------------------
RATE_WINDOW_S = 3600
RATE_LIMIT = 1000
_buckets: Dict[str, deque] = defaultdict(deque)


def rate_check(ip: str) -> bool:
    now = time.time()
    q = _buckets[ip]
    while q and now - q[0] > RATE_WINDOW_S:
        q.popleft()
    if len(q) >= RATE_LIMIT:
        return False
    q.append(now)
    return True


# ----------------------------- API -------------------------------------
class Generator(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str = Field(min_length=1, max_length=200)
    version: Optional[str] = Field(default=None, max_length=200)
    weights_hash: Optional[str] = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")
    params: Dict[str, str] = Field(default_factory=dict)


class SignRequest(BaseModel):
    """Either `input_text` (preferred) or `input_hash` + `input_len` must be given."""
    model_config = ConfigDict(extra="forbid")
    output_text: str = Field(min_length=1, max_length=200_000)
    input_text: Optional[str] = Field(default=None, max_length=200_000)
    input_hash: Optional[str] = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")
    input_len: Optional[int] = Field(default=None, ge=0)
    generator: Generator
    modality: str = "text"
    issuer_app: Optional[str] = Field(default=None, max_length=200)


class SignResponse(BaseModel):
    seal_id: str
    seal: dict
    seal_hash: str
    verify_url: str


app = FastAPI(title="Crovia Seal Service", version="0.6.0")


@app.middleware("http")
async def cors_mw(request: Request, call_next):
    if request.method == "OPTIONS":
        return Response(status_code=204, headers={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type",
            "Access-Control-Max-Age": "3600",
        })
    resp = await call_next(request)
    resp.headers["Access-Control-Allow-Origin"] = "*"
    return resp


@app.get("/health")
def health():
    return {"status": "ok", "issuer": ISSUER, "seal_version": SEAL_VERSION,
            "total_seals": sum(1 for s in INDEX.values() if _is_conformant(s))}


@app.get("/v1/stats")
def stats():
    conformant = [s for s in INDEX.values() if _is_conformant(s)]
    legacy = len(INDEX) - len(conformant)
    last = max((s["timestamp"]["emitted_at"] for s in conformant), default=None)
    return {
        "seal_version": SEAL_VERSION,
        "issuer": ISSUER,
        "issuer_pubkey_hex": PUB_HEX,
        "total_seals": len(conformant),
        "legacy_seals": legacy,
        "last_seal_at": last,
        "chain": {"sequence": CHAIN_HEAD["chain"]["sequence"] if CHAIN_HEAD else None,
                  "head_hash": compute_seal_hash(CHAIN_HEAD) if CHAIN_HEAD else None},
        "trust_root": "https://seal.croviatrust.com/trust-root.json",
        "rate_limit": {"per_ip_per_hour": RATE_LIMIT},
    }


@app.post("/v1/sign", response_model=SignResponse)
def sign(req: SignRequest, request: Request):
    global CHAIN_HEAD
    ip = request.client.host if request.client else "0.0.0.0"
    if not rate_check(ip):
        raise HTTPException(status_code=429, detail="rate limit: 1000/hour per IP")
    if req.modality not in ALLOWED_MODALITIES:
        raise HTTPException(status_code=422, detail=f"modality must be one of {sorted(ALLOWED_MODALITIES)}")

    output_bytes = req.output_text.encode("utf-8")
    if req.input_text is not None:
        input_bytes = req.input_text.encode("utf-8")
        input_hash_override = None
    elif req.input_hash is not None and req.input_len is not None:
        input_bytes = b""
        input_hash_override = (req.input_hash, req.input_len)
    else:
        raise HTTPException(status_code=422, detail="provide input_text, or input_hash together with input_len")

    checks: Dict[str, Any] = {}
    if req.issuer_app:
        checks["issuer_app"] = req.issuer_app

    prev_hash = compute_seal_hash(CHAIN_HEAD) if CHAIN_HEAD else None
    sequence = CHAIN_HEAD["chain"]["sequence"] + 1 if CHAIN_HEAD else 0

    seal = emit_seal(
        issuer_key=ISSUER_KEY,
        input_bytes=input_bytes,
        output_bytes=output_bytes,
        modality=req.modality,
        generator_id=req.generator.id,
        generator_version=req.generator.version,
        generator_weights_hash=req.generator.weights_hash,
        generator_params=req.generator.params,
        sequence=sequence,
        prev_seal_hash=prev_hash,
        checks=checks or None,
    )
    if input_hash_override is not None:
        # The client supplied a pre-computed input digest: re-emit with it so the
        # signature covers the client's values (emit_seal hashes bytes itself).
        seal = _reemit_with_input_digest(seal, *input_hash_override, sequence, prev_hash, checks or None,
                                         req, output_bytes)

    result = verify_seal(seal)
    if not result.ok:  # defence in depth: never persist a Seal we cannot verify
        raise HTTPException(status_code=500, detail=f"issued Seal failed self-verification: {result.errors}")

    with LOG_PATH.open("a") as f:
        f.write(json.dumps(seal, ensure_ascii=False) + "\n")
    INDEX[seal["seal_id"]] = seal
    CHAIN_HEAD = seal
    return SignResponse(seal_id=seal["seal_id"], seal=seal, seal_hash=compute_seal_hash(seal),
                        verify_url="https://croviatrust.com/registry/seal/verify/")


def _reemit_with_input_digest(seal: dict, input_hash: str, input_len: int, sequence: int,
                              prev_hash: Optional[str], checks: Optional[dict], req: SignRequest,
                              output_bytes: bytes) -> dict:
    """Sign a Seal whose subject.input_* come from the client (hash-only inputs)."""
    from crovia_seal.constants import CANON_ID, PAYLOAD_HASH_ALG, SIGNATURE_ALG, SIGNATURE_DOMAIN
    from crovia_seal.seal import _validate_structure, compute_payload
    unsigned = {k: v for k, v in seal.items() if k != "signature"}
    unsigned["subject"] = {
        "input_hash": input_hash,
        "output_hash": "sha256:" + hashlib.sha256(output_bytes).hexdigest(),
        "input_len": input_len,
        "output_len": len(output_bytes),
        "modality": req.modality,
    }
    sig = ISSUER_KEY.sign(compute_payload(unsigned))
    unsigned["signature"] = {"alg": SIGNATURE_ALG, "canon": CANON_ID, "domain": SIGNATURE_DOMAIN,
                             "payload_hash_alg": PAYLOAD_HASH_ALG, "sig_hex": sig.hex()}
    _validate_structure(unsigned)
    return unsigned


@app.get("/v1/seal/{seal_id}")
def get_seal(seal_id: str):
    s = INDEX.get(seal_id)
    if s is None:
        raise HTTPException(status_code=404, detail="not found")
    if not _is_conformant(s):
        return {"legacy": True, "note": "issued by the pre-0.6 service; not a crovia.seal.v1 object", "seal": s}
    return s
