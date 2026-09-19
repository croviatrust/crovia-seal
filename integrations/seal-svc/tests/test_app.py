"""seal-svc issues conformant crovia.seal.v1 Seals, chained per issuer key."""
import importlib
import json
import os
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from crovia_seal import verify_seal
from crovia_seal.seal import compute_seal_hash

HERE = Path(__file__).resolve().parent


@pytest.fixture()
def svc(tmp_path, monkeypatch):
    key = Ed25519PrivateKey.generate().private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
    ).hex()
    (tmp_path / "private.hex").write_text(key)
    monkeypatch.setenv("CROVIA_SEAL_KEY", str(tmp_path / "private.hex"))
    monkeypatch.setenv("CROVIA_SEAL_DATA", str(tmp_path / "data"))
    sys.path.insert(0, str(HERE.parent))
    sys.modules.pop("app", None)
    mod = importlib.import_module("app")
    yield mod
    sys.modules.pop("app", None)
    sys.path.remove(str(HERE.parent))


GEN = {"id": "openai/gpt-4o", "version": "2024-08-06"}


def test_sign_emits_verifiable_seal(svc):
    c = TestClient(svc.app)
    r = c.post("/v1/sign", json={"output_text": "hello", "input_text": "say hi", "generator": GEN})
    assert r.status_code == 200, r.text
    body = r.json()
    seal = body["seal"]
    assert seal["seal_version"] == "crovia.seal.v1"
    assert seal["seal_id"].startswith("cs_")
    assert verify_seal(seal).ok
    assert body["seal_hash"] == compute_seal_hash(seal)
    assert seal["chain"] == {"prev_seal_hash": None, "sequence": 0}
    assert seal["subject"]["input_len"] == len(b"say hi")
    assert c.get(f"/v1/seal/{seal['seal_id']}").json() == seal


def test_chain_links_consecutive_seals(svc):
    c = TestClient(svc.app)
    s1 = c.post("/v1/sign", json={"output_text": "a", "input_text": "q", "generator": GEN}).json()["seal"]
    s2 = c.post("/v1/sign", json={"output_text": "b", "input_text": "q", "generator": GEN}).json()["seal"]
    assert s2["chain"]["sequence"] == 1
    assert s2["chain"]["prev_seal_hash"] == compute_seal_hash(s1)
    assert verify_seal(s2).ok
    stats = c.get("/v1/stats").json()
    assert stats["total_seals"] == 2 and stats["chain"]["sequence"] == 1
    assert stats["chain"]["head_hash"] == compute_seal_hash(s2)


def test_hash_only_input_is_signed_as_given(svc):
    c = TestClient(svc.app)
    h = "sha256:" + "ab" * 32
    r = c.post("/v1/sign", json={"output_text": "x", "input_hash": h, "input_len": 12,
                                 "generator": {"id": "meta-llama/Llama-3.1-8B", "params": {"temperature": "0.7"}},
                                 "issuer_app": "pytest"})
    assert r.status_code == 200, r.text
    seal = r.json()["seal"]
    assert seal["subject"]["input_hash"] == h and seal["subject"]["input_len"] == 12
    assert seal["checks"]["issuer_app"] == "pytest"
    assert verify_seal(seal).ok


def test_rejects_missing_input_and_bad_modality(svc):
    c = TestClient(svc.app)
    assert c.post("/v1/sign", json={"output_text": "x", "generator": GEN}).status_code == 422
    assert c.post("/v1/sign", json={"output_text": "x", "input_text": "q", "generator": GEN,
                                    "modality": "hologram"}).status_code == 422
    assert c.get("/v1/seal/cs_2026_NOPE").status_code == 404


def test_reload_restores_chain_head_and_flags_legacy(svc):
    c = TestClient(svc.app)
    c.post("/v1/sign", json={"output_text": "a", "input_text": "q", "generator": GEN})
    legacy = {"seal_version": "crovia-seal-v1", "seal_id": "sl_" + "0" * 40, "signature": "Ed25519:00"}
    with svc.LOG_PATH.open("a") as f:
        f.write(json.dumps(legacy) + "\n")
    svc.INDEX.clear()
    svc.CHAIN_HEAD = None
    svc._load_index()
    assert svc.CHAIN_HEAD["chain"]["sequence"] == 0
    r = c.get("/v1/seal/" + legacy["seal_id"]).json()
    assert r["legacy"] is True
    stats = c.get("/v1/stats").json()
    assert stats["legacy_seals"] == 1 and stats["total_seals"] == 1
    assert os.path.exists(svc.LOG_PATH)
