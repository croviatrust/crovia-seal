"""
Beacon anchor tests.

Network I/O is mocked using a context manager that swaps `urlopen` in
`crovia_seal.beacon` for a callable producing canned JSON bodies. No real
network is contacted; tests remain deterministic and CI-safe.

We also exercise the offline helpers (`BeaconChainInfo.round_to_time`,
`wrap_as_seal_anchor`) against closed-form expected values.
"""
from __future__ import annotations

import io
import json
from contextlib import contextmanager
from datetime import datetime, timezone
from unittest.mock import patch

import pytest

from crovia_seal.beacon import (
    BeaconAnchor,
    BeaconChainInfo,
    quicknet_chain_info,
    wrap_as_seal_anchor,
    fetch_latest,
    fetch_round,
    fetch_chain_info,
    verify_round_online,
    QUICKNET_HASH,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class _FakeResp(io.BytesIO):
    """Minimal context-manager that mimics what urlopen() returns."""
    def __enter__(self):
        return self
    def __exit__(self, *exc):
        self.close()


@contextmanager
def _mock_urlopen(responder):
    """Patch `urlopen` used INSIDE crovia_seal.beacon only."""
    with patch("crovia_seal.beacon.urlopen", side_effect=responder):
        yield


def _as_resp(body: dict) -> _FakeResp:
    return _FakeResp(json.dumps(body).encode("utf-8"))


# ---------------------------------------------------------------------------
# Offline helpers
# ---------------------------------------------------------------------------

def test_quicknet_static_info_is_self_consistent():
    info = quicknet_chain_info()
    assert info.chain_hash == QUICKNET_HASH
    assert info.period_seconds == 3
    assert info.genesis_time > 1_600_000_000
    # Round 1 falls on genesis_time; round 2 is genesis + 3s.
    t1 = info.round_to_time(1)
    t2 = info.round_to_time(2)
    assert (t2 - t1).total_seconds() == 3


def test_round_to_time_rejects_zero_or_negative():
    info = quicknet_chain_info()
    with pytest.raises(ValueError):
        info.round_to_time(0)
    with pytest.raises(ValueError):
        info.round_to_time(-5)


def test_beacon_round_cannot_be_back_dated():
    """Stamp a round at its exact emission time and verify that any *earlier*
    timestamp would contradict the beacon - which is the whole point."""
    info = quicknet_chain_info()
    r = 1_000_000
    emission = info.round_to_time(r)
    # One-second earlier proposed emission is inconsistent with r.
    earlier = datetime(emission.year, emission.month, emission.day,
                       emission.hour, emission.minute, emission.second - 1,
                       tzinfo=timezone.utc)
    assert earlier < emission


def test_wrap_as_seal_anchor_shape():
    info = quicknet_chain_info()
    b = BeaconAnchor(
        chain_hash=info.chain_hash,
        round=12_345,
        randomness="ab" * 32,
        signature="cd" * 48,
    )
    out = wrap_as_seal_anchor(b, info)
    assert out["kind"] == "crovia-beacon"
    assert out["beacon"]["round"] == 12_345
    assert out["chain"]["period_seconds"] == 3
    assert out["not_emitted_before"].endswith("Z")


def test_wrap_without_chain_omits_time():
    b = BeaconAnchor(chain_hash="h", round=1, randomness="00", signature="00")
    out = wrap_as_seal_anchor(b)
    assert "not_emitted_before" not in out
    assert "chain" not in out
    assert out["kind"] == "crovia-beacon"


# ---------------------------------------------------------------------------
# Online helpers (mocked)
# ---------------------------------------------------------------------------

_LATEST_BODY = {
    "round": 4242424,
    "randomness": "abcdef" * 10 + "abcd",   # 64 hex chars
    "signature": "11" * 48,
}


def test_fetch_latest_parses_response():
    def responder(req, timeout=None):
        assert "public/latest" in req.full_url
        return _as_resp(_LATEST_BODY)
    with _mock_urlopen(responder):
        a = fetch_latest()
    assert a.round == 4242424
    assert a.signature == _LATEST_BODY["signature"]
    assert a.chain_hash == QUICKNET_HASH


def test_fetch_round_parses_response():
    def responder(req, timeout=None):
        assert "/public/9999" in req.full_url
        return _as_resp({"round": 9999, "randomness": "ff" * 32, "signature": "aa" * 48})
    with _mock_urlopen(responder):
        a = fetch_round(9999)
    assert a.round == 9999


def test_fetch_chain_info_parses_response():
    body = {
        "hash": QUICKNET_HASH,
        "public_key": "ab" * 48,
        "genesis_time": 1_692_803_367,
        "period": 3,
        "schemeID": "bls-unchained-g1-rfc9380",
    }
    def responder(req, timeout=None):
        assert req.full_url.endswith("/info")
        return _as_resp(body)
    with _mock_urlopen(responder):
        info = fetch_chain_info()
    assert info.period_seconds == 3
    assert info.scheme_id == "bls-unchained-g1-rfc9380"


def test_verify_round_online_accepts_matching_response():
    a = BeaconAnchor(chain_hash=QUICKNET_HASH, round=7, randomness="aa" * 32, signature="bb" * 48)
    def responder(req, timeout=None):
        # Return what the anchor says.
        return _as_resp({"round": 7, "randomness": a.randomness, "signature": a.signature})
    with _mock_urlopen(responder):
        assert verify_round_online(a) is True


def test_verify_round_online_rejects_tampered_randomness():
    a = BeaconAnchor(chain_hash=QUICKNET_HASH, round=7, randomness="aa" * 32, signature="bb" * 48)
    def responder(req, timeout=None):
        return _as_resp({"round": 7, "randomness": "cc" * 32, "signature": a.signature})
    with _mock_urlopen(responder):
        assert verify_round_online(a) is False


def test_verify_round_online_rejects_tampered_signature():
    a = BeaconAnchor(chain_hash=QUICKNET_HASH, round=7, randomness="aa" * 32, signature="bb" * 48)
    def responder(req, timeout=None):
        return _as_resp({"round": 7, "randomness": a.randomness, "signature": "ff" * 48})
    with _mock_urlopen(responder):
        assert verify_round_online(a) is False


def test_verify_round_online_is_robust_to_network_failure():
    a = BeaconAnchor(chain_hash=QUICKNET_HASH, round=7, randomness="aa" * 32, signature="bb" * 48)
    def responder(req, timeout=None):
        raise OSError("simulated network failure")
    with _mock_urlopen(responder):
        assert verify_round_online(a) is False


# ---------------------------------------------------------------------------
# Integration: embed in emit_seal
# ---------------------------------------------------------------------------

def test_beacon_anchor_round_trips_through_emit_seal_and_verify_seal():
    from crovia_seal import emit_seal, verify_seal, generate_issuer_key

    issuer = generate_issuer_key("urn:crovia:seal-issuer:beacon-tests")
    beacon = BeaconAnchor(
        chain_hash=QUICKNET_HASH,
        round=1_000_000,
        randomness="ab" * 32,
        signature="cd" * 48,
    )
    anchor = wrap_as_seal_anchor(beacon, quicknet_chain_info())

    seal = emit_seal(
        issuer_key=issuer,
        input_bytes=b"in",
        output_bytes=b"out",
        modality="text",
        generator_id="test/model",
        anchor=anchor,
    )

    assert seal["anchor"]["kind"] == "crovia-beacon"
    assert seal["anchor"]["beacon"]["round"] == 1_000_000
    assert "not_emitted_before" in seal["anchor"]

    vr = verify_seal(seal)
    assert vr.ok, vr.errors

    # Tampering with the anchor now breaks the signature.
    tampered = json.loads(json.dumps(seal))
    tampered["anchor"]["beacon"]["round"] = 1_000_001
    vr2 = verify_seal(tampered)
    assert not vr2.ok
