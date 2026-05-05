"""
Crovia Seal Service v1 — public sealing + retrieval endpoint.

POST /v1/sign      -> sign an AI output, return canonical seal
GET  /v1/seal/{id} -> retrieve a previously-signed seal by its seal_id
GET  /v1/stats     -> public counters (total seals, last seal time)
GET  /health       -> 200 if running

Free, no auth. Rate-limit via a simple in-memory token bucket per IP.
Persists seals to JSON-Lines append-only log; reload-resilient.

Deployment (see ../../STATUS.md session 2026-05-04 part 3):
    - expects /opt/crovia/keys/seal/private.hex + public.hex
    - listens on 127.0.0.1:8090
    - fronted by nginx at seal.croviatrust.com/v1/* and /health
"""
from __future__ import annotations
import hashlib, json, os, secrets, time
from collections import defaultdict, deque
from pathlib import Path
from typing import Any, Dict, Optional

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, ConfigDict
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

# ----------------------------- KEY LOAD --------------------------------
KEY_PATH = "/opt/crovia/keys/seal/private.hex"
PUB_PATH = "/opt/crovia/keys/seal/public.hex"
ISSUER   = "urn:crovia:seal-issuer:crovia-trust"

with open(KEY_PATH) as f:
    _SEED = bytes.fromhex(f.read().strip())
PRIV = Ed25519PrivateKey.from_private_bytes(_SEED)
PUB_HEX = open(PUB_PATH).read().strip()

# ----------------------------- STORAGE ---------------------------------
DATA_DIR = Path("/opt/crovia/seal-svc/data")
DATA_DIR.mkdir(parents=True, exist_ok=True)
LOG_PATH = DATA_DIR / "seals.jsonl"
INDEX: Dict[str, dict] = {}

def _load_index():
    if not LOG_PATH.exists(): return
    for line in LOG_PATH.open():
        line = line.strip()
        if not line: continue
        try:
            s = json.loads(line)
            INDEX[s["seal_id"]] = s
        except Exception: pass

_load_index()

# ----------------------------- CSC-1 -----------------------------------
def csc1_canonicalize(obj: Any) -> bytes:
    """Strict subset of RFC 8785 (no floats; UTF-16 sorted keys)."""
    if obj is None: return b"null"
    if obj is True: return b"true"
    if obj is False: return b"false"
    if isinstance(obj, int):
        if not -(2**53 - 1) <= obj <= 2**53 - 1:
            raise ValueError("integer out of safe range")
        return str(obj).encode()
    if isinstance(obj, float):
        raise ValueError("CSC-1 forbids floats in signed payload")
    if isinstance(obj, str):
        return json.dumps(obj, ensure_ascii=False).encode("utf-8")
    if isinstance(obj, list):
        return b"[" + b",".join(csc1_canonicalize(x) for x in obj) + b"]"
    if isinstance(obj, dict):
        keys = sorted(obj.keys())
        if any(not isinstance(k, str) for k in keys):
            raise ValueError("non-string key")
        items = [csc1_canonicalize(k) + b":" + csc1_canonicalize(obj[k]) for k in keys]
        return b"{" + b",".join(items) + b"}"
    raise ValueError(f"unsupported type {type(obj)}")

def sign_seal(payload: dict) -> dict:
    domain = b"CROVIA-SEAL-v1\n"
    canon = csc1_canonicalize(payload)
    sig = PRIV.sign(domain + canon)
    payload["signature"] = "Ed25519:" + sig.hex()
    return payload

# ----------------------------- RATE LIMIT ------------------------------
RATE_WINDOW_S = 3600
RATE_LIMIT    = 1000
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
class SignRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    output_text: str = Field(min_length=1, max_length=200_000)
    input_hash: str  = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    generator: dict
    issuer_app: Optional[str] = None

class SignResponse(BaseModel):
    seal_id: str
    seal: dict

app = FastAPI(title="Crovia Seal Service", version="0.5.0")

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
def health(): return {"status": "ok", "issuer": ISSUER, "total_seals": len(INDEX)}

@app.get("/v1/stats")
def stats():
    last = max(INDEX.values(), key=lambda s: s.get("issued_at",""))["issued_at"] if INDEX else None
    return {
        "total_seals": len(INDEX),
        "issuer": ISSUER,
        "last_seal_at": last,
        "rate_limit": {"per_ip_per_hour": RATE_LIMIT},
    }

@app.post("/v1/sign", response_model=SignResponse)
def sign(req: SignRequest, request: Request):
    ip = request.client.host if request.client else "0.0.0.0"
    if not rate_check(ip):
        raise HTTPException(status_code=429, detail="rate limit: 1000/hour per IP")

    output_hash = "sha256:" + hashlib.sha256(req.output_text.encode("utf-8")).hexdigest()
    seal_id = "sl_" + secrets.token_hex(20)

    payload = {
        "seal_version": "crovia-seal-v1",
        "seal_id": seal_id,
        "issuer": {
            "id": ISSUER,
            "pubkey_alg": "Ed25519",
            "pubkey": PUB_HEX,
        },
        "generator": req.generator,
        "subject": {
            "input_hash":    req.input_hash,
            "output_hash":   output_hash,
            "output_length": len(req.output_text),
        },
        "issued_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    if req.issuer_app:
        payload["issuer_app"] = req.issuer_app

    seal = sign_seal(payload)
    with LOG_PATH.open("a") as f:
        f.write(json.dumps(seal) + "\n")
    INDEX[seal_id] = seal
    return SignResponse(seal_id=seal_id, seal=seal)

@app.get("/v1/seal/{seal_id}")
def get_seal(seal_id: str):
    if seal_id not in INDEX:
        raise HTTPException(status_code=404, detail="not found")
    return INDEX[seal_id]
