"""
Crovia Beacon Anchor - proof of *earliest possible* emission time.

=============================================================================
                                WHY THIS EXISTS
=============================================================================

A Crovia Seal already carries a timestamp and an Ed25519 signature, but:

    - the timestamp is asserted BY THE ISSUER, not proven;
    - the signature proves "this issuer signed this content", not "this
      content existed no earlier than time T".

Nothing stops a compromised or malicious issuer from later signing a seal
with a past timestamp (back-dating). This weakness is devastating for any
adoption scenario where the *order of events* matters (a journalist claiming
a scoop, a student submitting homework, a lawyer producing evidence).

The drand network (https://drand.love) is a publicly observable distributed
randomness beacon operated by a diverse threshold of independent
organizations. Every 3 seconds it produces a new round `(round_number,
randomness, signature)` that is:

    - UNPREDICTABLE before it is published (thanks to a BLS threshold
      signature over the round data);
    - IMMUTABLE after publication (the round is broadcast to many relays);
    - PUBLICLY VERIFIABLE (anyone can fetch it and check the signature
      against the chain's public key).

If a Seal embeds `{chain_hash, round, randomness, signature}`, anyone can:

    1. Compute the exact UTC instant `T_round = genesis_time + round*period`.
    2. Conclude: this seal CANNOT have been emitted before `T_round`.

This is a forward-shift-proof timestamp without any trusted third party.

=============================================================================
                            INTEGRATION MODES
=============================================================================

Two modes, both supported:

    OFFLINE pinning (MVP, this module): emit_seal() accepts a prefetched
        BeaconAnchor and stores it in seal.anchor.beacon. Verification can
        later re-fetch the round from drand and check equality.

    INLINE verification (future): ship a tiny BLS verifier so the check
        can be done with zero network access. `verify_anchor_signature()`
        is a stub today and raises NotImplementedError; it will become
        truthy when `py_ecc` is bundled as an optional dependency.

This module has ZERO new hard dependencies - it uses stdlib `urllib.request`
and `json` for the optional network fetch. Consumers that never call
`fetch_latest()` can use the data-class and the offline helpers with no I/O.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from urllib.request import Request, urlopen


# ---------------------------------------------------------------------------
# Known drand chains (public, League of Entropy)
# ---------------------------------------------------------------------------

# Quicknet (unchained, 3s period) - the recommended chain for new integrations
# as of 2024+. See https://drand.love/docs/ and `api.drand.sh/chains`.
QUICKNET_HASH = "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971"
QUICKNET_PUBKEY_BLS = (
    "83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c"
    "8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb"
    "5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a"
)

#: Default relay. Any drand relay returns the same rounds for a given chain.
DEFAULT_RELAY = "https://api.drand.sh"


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class BeaconChainInfo:
    """Static metadata about a drand chain needed to convert rounds to times."""
    chain_hash: str          # hex of the chain's own hash
    public_key_hex: str      # BLS public key (hex)
    genesis_time: int        # UNIX seconds of round 1
    period_seconds: int      # seconds between rounds
    scheme_id: str           # e.g. "bls-unchained-g1-rfc9380" (quicknet)

    def round_to_time(self, round_number: int) -> datetime:
        """Deterministic mapping round -> UTC datetime of its emission."""
        if round_number < 1:
            raise ValueError("drand rounds start at 1")
        ts = self.genesis_time + (round_number - 1) * self.period_seconds
        return datetime.fromtimestamp(ts, tz=timezone.utc)


@dataclass(frozen=True)
class BeaconAnchor:
    """A single beacon round, stored inside a Seal's anchor field.

    Serialization: `to_dict()` returns a plain JSON-safe dict. CSC-1
    canonicalization (used by the Seal signature) handles this dict exactly
    like any other nested object; there is no new canonicalization rule.
    """
    chain_hash: str
    round: int
    randomness: str             # hex
    signature: str              # hex (BLS)
    previous_signature: Optional[str] = None  # only present on chained beacons

    def to_dict(self) -> Dict[str, Any]:
        d = {
            "chain_hash": self.chain_hash,
            "round": self.round,
            "randomness": self.randomness,
            "signature": self.signature,
        }
        if self.previous_signature is not None:
            d["previous_signature"] = self.previous_signature
        return d

    @classmethod
    def from_api_response(cls, chain_hash: str, body: Dict[str, Any]) -> "BeaconAnchor":
        return cls(
            chain_hash=chain_hash,
            round=int(body["round"]),
            randomness=str(body["randomness"]),
            signature=str(body["signature"]),
            previous_signature=body.get("previous_signature"),
        )


# ---------------------------------------------------------------------------
# Offline helpers (no I/O)
# ---------------------------------------------------------------------------

def wrap_as_seal_anchor(beacon: BeaconAnchor, chain: Optional[BeaconChainInfo] = None) -> Dict[str, Any]:
    """Render a BeaconAnchor as the `anchor` field of a Crovia Seal.

    If `chain` is provided, we also compute the deterministic
    `not_emitted_before` timestamp, which is the ENTIRE POINT of this anchor
    (it's what turns a beacon round into a proof-of-earliest-emission).
    """
    out: Dict[str, Any] = {
        "kind": "crovia-beacon",
        "beacon": beacon.to_dict(),
    }
    if chain is not None:
        out["chain"] = {
            "chain_hash": chain.chain_hash,
            "public_key_hex": chain.public_key_hex,
            "genesis_time": chain.genesis_time,
            "period_seconds": chain.period_seconds,
            "scheme_id": chain.scheme_id,
        }
        out["not_emitted_before"] = chain.round_to_time(beacon.round).isoformat().replace(
            "+00:00", "Z"
        )
    return out


def quicknet_chain_info() -> BeaconChainInfo:
    """Static, well-known metadata for drand's quicknet chain.

    Inlined so offline usage (tests, air-gapped deployments) never needs to
    query a relay. Values from drand's public `/info` endpoint as of 2024.
    """
    return BeaconChainInfo(
        chain_hash=QUICKNET_HASH,
        public_key_hex=QUICKNET_PUBKEY_BLS,
        genesis_time=1692803367,       # UTC: 2023-08-23T15:49:27Z
        period_seconds=3,
        scheme_id="bls-unchained-g1-rfc9380",
    )


# ---------------------------------------------------------------------------
# Online helpers (stdlib urllib only)
# ---------------------------------------------------------------------------

def fetch_chain_info(chain_hash: str = QUICKNET_HASH, relay: str = DEFAULT_RELAY,
                     timeout_seconds: float = 5.0) -> BeaconChainInfo:
    url = f"{relay.rstrip('/')}/{chain_hash}/info"
    body = _http_get_json(url, timeout_seconds)
    return BeaconChainInfo(
        chain_hash=str(body.get("hash", chain_hash)),
        public_key_hex=str(body["public_key"]),
        genesis_time=int(body["genesis_time"]),
        period_seconds=int(body["period"]),
        scheme_id=str(body.get("schemeID", "unknown")),
    )


def fetch_latest(chain_hash: str = QUICKNET_HASH, relay: str = DEFAULT_RELAY,
                 timeout_seconds: float = 5.0) -> BeaconAnchor:
    url = f"{relay.rstrip('/')}/{chain_hash}/public/latest"
    body = _http_get_json(url, timeout_seconds)
    return BeaconAnchor.from_api_response(chain_hash, body)


def fetch_round(round_number: int, chain_hash: str = QUICKNET_HASH,
                relay: str = DEFAULT_RELAY, timeout_seconds: float = 5.0) -> BeaconAnchor:
    url = f"{relay.rstrip('/')}/{chain_hash}/public/{round_number}"
    body = _http_get_json(url, timeout_seconds)
    return BeaconAnchor.from_api_response(chain_hash, body)


def verify_round_online(anchor: BeaconAnchor, relay: str = DEFAULT_RELAY,
                        timeout_seconds: float = 5.0) -> bool:
    """Check that the beacon round stored in `anchor` still matches the
    authoritative value served by the drand network.

    This relies on the trustworthiness of the relay. For truly offline
    verification (and for protection against a compromised single relay),
    callers should use `verify_anchor_signature()` instead, which verifies
    the BLS signature against the chain's public key (future work).
    """
    try:
        ground_truth = fetch_round(anchor.round, anchor.chain_hash, relay, timeout_seconds)
    except Exception:
        return False
    return (
        ground_truth.randomness == anchor.randomness
        and ground_truth.signature == anchor.signature
    )


def verify_anchor_signature(anchor: BeaconAnchor, chain: BeaconChainInfo) -> bool:
    """Verify the BLS signature inside a BeaconAnchor locally.

    Not implemented in the stdlib-only MVP - this would require bundling a
    BLS12-381 library such as `py_ecc` or `blspy`. Shipped as an explicit
    raise so downstream code that depends on offline verification fails
    loudly rather than silently accepting unverified data.
    """
    raise NotImplementedError(
        "offline BLS verification will be added in a future release; "
        "use verify_round_online() for now"
    )


# ---------------------------------------------------------------------------
# Private
# ---------------------------------------------------------------------------

def _http_get_json(url: str, timeout_seconds: float) -> Dict[str, Any]:
    req = Request(url, headers={"User-Agent": "crovia-seal/0.5.0 (+beacon)"})
    with urlopen(req, timeout=timeout_seconds) as resp:  # noqa: S310 - constant scheme
        raw = resp.read()
    return json.loads(raw.decode("utf-8"))


__all__ = [
    "QUICKNET_HASH",
    "QUICKNET_PUBKEY_BLS",
    "DEFAULT_RELAY",
    "BeaconChainInfo",
    "BeaconAnchor",
    "quicknet_chain_info",
    "wrap_as_seal_anchor",
    "fetch_chain_info",
    "fetch_latest",
    "fetch_round",
    "verify_round_online",
    "verify_anchor_signature",
]
