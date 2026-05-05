"""Unit tests for the Sealer (no FastAPI involved)."""
from __future__ import annotations

import json

import pytest

from crovia_seal import verify_seal, extract_cim
from crovia_proxy.sealer import Sealer


@pytest.mark.asyncio
async def test_seal_roundtrip(settings_factory):
    s = Sealer(settings_factory())
    result = await s.seal(
        input_text="Say hi.",
        output_text="Hi there!",
        generator_id="openai/gpt-4o",
        generator_version="2026-01-01",
    )
    assert result.seal_id.startswith("cs_")
    vr = verify_seal(result.seal)
    assert vr.ok, vr.errors
    # CIM should be embedded and decodable from the modified output.
    assert result.cim_embedded
    extracted = extract_cim(result.modified_output_text, issuance_year=int(result.seal_id.split("_")[1]))
    assert extracted is not None
    assert extracted.seal_id == result.seal_id


@pytest.mark.asyncio
async def test_cim_disabled(settings_factory):
    s = Sealer(settings_factory(inject_cim=False))
    r = await s.seal(input_text="x", output_text="y", generator_id="g")
    assert r.cim_embedded is False
    assert r.modified_output_text == "y"


@pytest.mark.asyncio
async def test_chain_increments_sequence(settings_factory):
    s = Sealer(settings_factory())
    r1 = await s.seal(input_text="a", output_text="b", generator_id="g")
    r2 = await s.seal(input_text="c", output_text="d", generator_id="g")
    assert r1.seal["chain"]["sequence"] == 0
    assert r1.seal["chain"]["prev_seal_hash"] is None
    assert r2.seal["chain"]["sequence"] == 1
    assert r2.seal["chain"]["prev_seal_hash"] is not None
    assert r2.seal["chain"]["prev_seal_hash"].startswith("sha256:")


@pytest.mark.asyncio
async def test_chain_disabled_stays_at_genesis(settings_factory):
    s = Sealer(settings_factory(chain_seals=False))
    r1 = await s.seal(input_text="a", output_text="b", generator_id="g")
    r2 = await s.seal(input_text="c", output_text="d", generator_id="g")
    for r in (r1, r2):
        assert r.seal["chain"]["sequence"] == 0
        assert r.seal["chain"]["prev_seal_hash"] is None


@pytest.mark.asyncio
async def test_audit_log_appends_jsonl(tmp_path, settings_factory):
    log = tmp_path / "mylog.jsonl"
    s = Sealer(settings_factory(log_file=log))
    await s.seal(input_text="a", output_text="b", generator_id="g")
    await s.seal(input_text="c", output_text="d", generator_id="g")
    lines = log.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    for line in lines:
        obj = json.loads(line)
        assert obj["seal_version"].startswith("crovia.seal.v")


@pytest.mark.asyncio
async def test_seal_base64_round_trips_to_same_json(settings_factory):
    import base64
    s = Sealer(settings_factory())
    r = await s.seal(input_text="hello", output_text="world", generator_id="g")
    decoded = json.loads(base64.b64decode(r.seal_base64))
    assert decoded == r.seal

