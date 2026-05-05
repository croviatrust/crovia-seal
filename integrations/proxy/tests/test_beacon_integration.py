"""
Verify the Crovia Beacon Anchor integration path.

The drand upstream is mocked so tests remain offline. Two properties are
asserted:

    1. When `beacon_anchor=True`, every emitted seal embeds a valid
       `anchor.kind == "crovia-beacon"` structure and the seal still
       self-verifies after signing.

    2. When the drand relay is unreachable, the sealer either serves a
       cached round (warm path) or emits the seal with no anchor (cold
       path). In no case does a beacon failure prevent sealing.
"""
from __future__ import annotations

import io
import json
from contextlib import contextmanager
from unittest.mock import patch

import pytest

from crovia_seal import verify_seal
from crovia_proxy.sealer import Sealer


class _FakeResp(io.BytesIO):
    def __enter__(self):
        return self
    def __exit__(self, *exc):
        self.close()


@contextmanager
def _mock_drand(body):
    def responder(req, timeout=None):
        return _FakeResp(json.dumps(body).encode("utf-8"))
    # Patch INSIDE crovia_seal.beacon since that's what fetch_latest uses.
    with patch("crovia_seal.beacon.urlopen", side_effect=responder):
        yield


BEACON_BODY = {
    "round": 7_777_777,
    "randomness": "ab" * 32,
    "signature": "cd" * 48,
}


@pytest.mark.asyncio
async def test_seal_includes_beacon_anchor(settings_factory):
    s = Sealer(settings_factory(beacon_anchor=True))
    with _mock_drand(BEACON_BODY):
        r = await s.seal(input_text="hi", output_text="there", generator_id="g")

    assert r.seal["anchor"]["kind"] == "crovia-beacon"
    assert r.seal["anchor"]["beacon"]["round"] == 7_777_777
    # not_emitted_before is present because chain metadata is inlined for quicknet.
    assert "not_emitted_before" in r.seal["anchor"]
    vr = verify_seal(r.seal)
    assert vr.ok, vr.errors


@pytest.mark.asyncio
async def test_beacon_cache_skips_refetch(settings_factory):
    s = Sealer(settings_factory(beacon_anchor=True, beacon_cache_seconds=10.0))
    call_count = {"n": 0}
    def responder(req, timeout=None):
        call_count["n"] += 1
        return _FakeResp(json.dumps(BEACON_BODY).encode("utf-8"))
    with patch("crovia_seal.beacon.urlopen", side_effect=responder):
        await s.seal(input_text="a", output_text="b", generator_id="g")
        await s.seal(input_text="c", output_text="d", generator_id="g")
        await s.seal(input_text="e", output_text="f", generator_id="g")
    # 3 seals, 1 network fetch.
    assert call_count["n"] == 1


@pytest.mark.asyncio
async def test_beacon_network_failure_does_not_block_sealing(settings_factory):
    s = Sealer(settings_factory(beacon_anchor=True))
    def responder(req, timeout=None):
        raise OSError("upstream unreachable")
    with patch("crovia_seal.beacon.urlopen", side_effect=responder):
        r = await s.seal(input_text="a", output_text="b", generator_id="g")
    # Seal is still emitted, just without a beacon anchor.
    assert "anchor" not in r.seal or r.seal.get("anchor") is None
    vr = verify_seal(r.seal)
    assert vr.ok


@pytest.mark.asyncio
async def test_beacon_disabled_by_default(settings_factory):
    s = Sealer(settings_factory())   # beacon_anchor default = False
    # No urlopen patch -> if anchoring triggered, this would raise URLError.
    r = await s.seal(input_text="a", output_text="b", generator_id="g")
    assert "anchor" not in r.seal
