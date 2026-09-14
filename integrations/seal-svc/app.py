"""Crovia Seal public service.

Historical v1 records remain readable byte-for-byte. New issuance is available
only through /v2/sign and emits the draft-crovia-seal-01 profile implemented by
the repository reference package.
"""
from __future__ import annotations

import json
import os
import threading
import time
from collections import defaultdict, deque
from pathlib import Path
from typing import Dict, Optional

from fastapi import FastAPI, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, Field

from crovia_seal.keys import load_issuer_key
from crovia_seal.seal import compute_seal_hash, emit_seal, verify_seal
from protocol_profiles import Profile, classify_profile


KEY_PATH = Path("/opt/crovia/keys/seal/private.hex")
PUB_PATH = Path("/opt/crovia/keys/seal/public.hex")
ISSUER = "urn:crovia:seal-issuer:crovia-trust"
DATA_DIR = Path("/opt/crovia/seal-svc/data")
LOG_PATH = DATA_DIR / "seals.jsonl"
RATE_WINDOW_S = 3600
RATE_LIMIT = 1000

DATA_DIR.mkdir(parents=True, exist_ok=True)
ISSUER_KEY = load_issuer_key(ISSUER, KEY_PATH.read_text().strip())
EXPECTED_PUBLIC_HEX = PUB_PATH.read_text().strip().lower()
if ISSUER_KEY.public_hex != EXPECTED_PUBLIC_HEX:
    raise RuntimeError("seal public key does not match the configured private key")

INDEX: Dict[str, dict] = {}
_ISSUE_LOCK = threading.Lock()
_buckets: Dict[str, deque] = defaultdict(deque)


def _load_index() -> None:
    if not LOG_PATH.exists():
        return
    with LOG_PATH.open(encoding="utf-8") as stream:
        for line in stream:
            try:
                seal = json.loads(line)
                if isinstance(seal, dict) and isinstance(seal.get("seal_id"), str):
                    INDEX[seal["seal_id"]] = seal
            except (json.JSONDecodeError, UnicodeDecodeError):
                # The append-only source remains untouched. Invalid records are
                # not indexed and must be handled by offline recovery tooling.
                continue


def _latest_draft() -> Optional[dict]:
    drafts = [
        seal for seal in INDEX.values()
        if classify_profile(seal) is Profile.DRAFT_01
    ]
    if not drafts:
        return None
    return max(drafts, key=lambda item: item["chain"]["sequence"])


def _append(seal: dict) -> None:
    encoded = json.dumps(
        seal, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    )
    with LOG_PATH.open("a", encoding="utf-8") as stream:
        stream.write(encoded + "\n")
        stream.flush()
        os.fsync(stream.fileno())
    INDEX[seal["seal_id"]] = seal


def _emitted_at(seal: dict) -> Optional[str]:
    profile = classify_profile(seal)
    if profile is Profile.DRAFT_01:
        return seal["timestamp"]["emitted_at"]
    if profile is Profile.LEGACY_V1:
        return seal.get("issued_at")
    return None


def rate_check(ip: str) -> bool:
    now = time.time()
    queue = _buckets[ip]
    while queue and now - queue[0] > RATE_WINDOW_S:
        queue.popleft()
    if len(queue) >= RATE_LIMIT:
        return False
    queue.append(now)
    return True


_load_index()


class Generator(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str = Field(min_length=1, max_length=256)
    version: Optional[str] = Field(default=None, max_length=256)
    weights_hash: Optional[str] = Field(
        default=None, pattern=r"^sha256:[0-9a-f]{64}$"
    )
    params: Dict[str, str] = Field(default_factory=dict)


class DraftSignRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    input_text: str = Field(max_length=200_000)
    output_text: str = Field(min_length=1, max_length=200_000)
    modality: str = Field(default="text")
    generator: Generator
    checks: Optional[dict] = None


class SignResponse(BaseModel):
    seal_id: str
    profile: str
    seal: dict


app = FastAPI(title="Crovia Seal Service", version="1.0.0-draft01")


@app.middleware("http")
async def cors_mw(request: Request, call_next):
    if request.method == "OPTIONS":
        return Response(status_code=204, headers={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type",
            "Access-Control-Max-Age": "3600",
        })
    response = await call_next(request)
    response.headers["Access-Control-Allow-Origin"] = "*"
    return response


@app.get("/health")
def health():
    return {
        "status": "ok",
        "issuer": ISSUER,
        "issuance_profile": Profile.DRAFT_01.value,
        "total_seals": len(INDEX),
    }


@app.get("/v1/stats")
def stats():
    timestamps = [stamp for seal in INDEX.values() if (stamp := _emitted_at(seal))]
    counts = {profile.value: 0 for profile in Profile}
    for seal in INDEX.values():
        counts[classify_profile(seal).value] += 1
    return {
        "total_seals": len(INDEX),
        "profiles": counts,
        "issuer": ISSUER,
        "last_seal_at": max(timestamps) if timestamps else None,
        "new_issuance_profile": Profile.DRAFT_01.value,
        "rate_limit": {"per_ip_per_hour": RATE_LIMIT},
    }


@app.post("/v1/sign")
def retired_legacy_sign():
    raise HTTPException(
        status_code=410,
        detail={
            "code": "LEGACY_ISSUANCE_RETIRED",
            "message": "Use /v2/sign; historical /v1 seals remain retrievable.",
        },
    )


@app.post("/v2/sign", response_model=SignResponse)
def sign_draft(req: DraftSignRequest, request: Request):
    ip = request.client.host if request.client else "0.0.0.0"
    if not rate_check(ip):
        raise HTTPException(status_code=429, detail="rate limit: 1000/hour per IP")

    with _ISSUE_LOCK:
        previous = _latest_draft()
        sequence = 0 if previous is None else previous["chain"]["sequence"] + 1
        prev_hash = None if previous is None else compute_seal_hash(previous)
        seal = emit_seal(
            issuer_key=ISSUER_KEY,
            input_bytes=req.input_text.encode("utf-8"),
            output_bytes=req.output_text.encode("utf-8"),
            modality=req.modality,
            generator_id=req.generator.id,
            generator_version=req.generator.version,
            generator_weights_hash=req.generator.weights_hash,
            generator_params=req.generator.params,
            sequence=sequence,
            prev_seal_hash=prev_hash,
            checks=req.checks,
        )
        result = verify_seal(seal, issuer_pubkey_hex=EXPECTED_PUBLIC_HEX)
        if not result.ok:
            raise HTTPException(status_code=500, detail="self-verification failed")
        _append(seal)

    return SignResponse(
        seal_id=seal["seal_id"],
        profile=Profile.DRAFT_01.value,
        seal=seal,
    )


@app.get("/v1/seal/{seal_id}")
def get_seal(seal_id: str):
    seal = INDEX.get(seal_id)
    if seal is None:
        raise HTTPException(status_code=404, detail="not found")
    return {
        "profile": classify_profile(seal).value,
        "seal": seal,
    }
