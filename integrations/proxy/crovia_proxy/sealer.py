"""
Stateless sealing service for the Crovia Proxy.

The Sealer owns a single IssuerKey and emits Crovia Seal v1 receipts over
request/response pairs flowing through the proxy. It optionally:

    - embeds a CIM zero-width mark into the response text
    - chains every new seal to the previous one (hash chain -> append-only)
    - writes a JSONL audit line per emission (configurable)

The Sealer is *thread-safe on POSIX async loops* thanks to an asyncio.Lock
around chain-state mutation. Two concurrent seals never share a sequence
number, and the hash chain never forks (see `_ChainState`).
"""
from __future__ import annotations

import asyncio
import base64
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional

from crovia_seal import (
    IssuerKey,
    emit_seal,
    compute_seal_hash,
    embed_cim,
    verify_seal,
)
from crovia_seal.keys import load_issuer_key
from crovia_seal.beacon import (
    BeaconAnchor,
    BeaconChainInfo,
    fetch_latest as _fetch_latest_beacon,
    wrap_as_seal_anchor,
    quicknet_chain_info,
    QUICKNET_HASH,
)

from crovia_proxy.config import Settings


# ---------------------------------------------------------------------------
# Chain state
# ---------------------------------------------------------------------------

@dataclass
class _ChainState:
    """Mutable sequence/prev-hash pair guarded by an asyncio.Lock."""
    sequence: int = 0
    prev_hash: Optional[str] = None


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class SealedResponse:
    """Result of sealing a request/response pair."""
    seal: Dict[str, Any]                # full Seal v1 object
    seal_id: str
    seal_base64: str                    # canonical JSON, base64-encoded
    modified_output_text: str           # input with CIM appended (or original if inject_cim=False)
    cim_embedded: bool                  # True if output_text was rewritten


# ---------------------------------------------------------------------------
# Sealer
# ---------------------------------------------------------------------------

class Sealer:
    """Encapsulates the IssuerKey and chain-state of the proxy."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        private_hex = settings.resolve_private_hex()
        self._key: IssuerKey = load_issuer_key(settings.issuer_id, private_hex)
        self._chain = _ChainState()
        self._lock = asyncio.Lock()
        # The proxy's public key hex is useful in logs and /health endpoints.
        self.public_hex: str = self._key.public_hex
        # Beacon anchor caching (opt-in, skipped if disabled in settings).
        self._beacon_cache: Optional[BeaconAnchor] = None
        self._beacon_cache_ts: float = 0.0
        self._beacon_chain_info: Optional[BeaconChainInfo] = None
        if settings.beacon_anchor and settings.beacon_chain_hash == QUICKNET_HASH:
            # Inline well-known chain metadata so we never need to hit /info.
            self._beacon_chain_info = quicknet_chain_info()

    # ---------------------------------------------------------------

    async def seal(
        self,
        *,
        input_text: str,
        output_text: str,
        generator_id: str,
        generator_version: Optional[str] = None,
        modality: str = "text",
        extra_params: Optional[Dict[str, str]] = None,
    ) -> SealedResponse:
        """Emit a Seal for `(input_text, output_text)` and optionally embed a CIM.

        The function is synchronous in its computation but async in its API so
        callers can `await sealer.seal(...)` safely inside FastAPI handlers.
        """
        input_bytes = input_text.encode("utf-8")
        output_bytes = output_text.encode("utf-8")

        # Fetch the beacon OUTSIDE the lock: network I/O does not need
        # serialization and must not starve other concurrent seal operations.
        beacon_anchor_dict = await self._get_beacon_anchor()

        async with self._lock:
            if self._settings.chain_seals and self._chain.sequence > 0:
                sequence = self._chain.sequence
                prev_hash: Optional[str] = self._chain.prev_hash
            else:
                sequence = 0
                prev_hash = None

            seal = emit_seal(
                issuer_key=self._key,
                input_bytes=input_bytes,
                output_bytes=output_bytes,
                modality=modality,
                generator_id=generator_id,
                generator_version=generator_version,
                generator_params=extra_params or None,
                sequence=sequence,
                prev_seal_hash=prev_hash,
                anchor=beacon_anchor_dict,
            )

            if self._settings.chain_seals:
                self._chain.prev_hash = compute_seal_hash(seal)
                self._chain.sequence = sequence + 1

        # CIM injection happens AFTER signing because the seal certifies the
        # SEMANTIC output (what the model produced), not the CIM-augmented
        # text. Extracting the CIM from a received message yields only the
        # seal_id which is then used to fetch the full seal and re-verify
        # against the output_hash computed from the text WITH the mark
        # stripped.
        final_output = output_text
        cim_embedded = False
        if self._settings.inject_cim:
            final_output = embed_cim(output_text, seal["seal_id"])
            cim_embedded = True

        seal_json = json.dumps(seal, ensure_ascii=False, separators=(",", ":"))
        seal_b64 = base64.b64encode(seal_json.encode("utf-8")).decode("ascii")

        await self._append_audit(seal)

        # Defense in depth: verify what we just signed.
        vr = verify_seal(seal)
        if not vr.ok:
            raise RuntimeError(
                f"Sealer produced a seal that fails self-verification: {vr.errors!r}"
            )

        return SealedResponse(
            seal=seal,
            seal_id=seal["seal_id"],
            seal_base64=seal_b64,
            modified_output_text=final_output,
            cim_embedded=cim_embedded,
        )

    # ---------------------------------------------------------------

    async def _get_beacon_anchor(self) -> Optional[Dict[str, Any]]:
        """Return a Seal-anchor dict for the current drand round, cached.

        Returns None when:
          - beacon anchoring is disabled via settings, or
          - the upstream drand relay is unreachable AND no cached round is
            fresh enough to use.

        Network fetch is performed in a worker thread via asyncio.to_thread
        so the FastAPI event loop is not blocked by urllib.
        """
        if not self._settings.beacon_anchor:
            return None
        import time
        now = time.time()
        if (
            self._beacon_cache is not None
            and now - self._beacon_cache_ts < self._settings.beacon_cache_seconds
        ):
            return wrap_as_seal_anchor(self._beacon_cache, self._beacon_chain_info)
        try:
            beacon = await asyncio.to_thread(
                _fetch_latest_beacon,
                self._settings.beacon_chain_hash,
                self._settings.beacon_relay,
                5.0,
            )
        except Exception:
            # Network failure: fall back to the stale cache if we have one;
            # otherwise skip anchoring rather than block the response.
            if self._beacon_cache is not None:
                return wrap_as_seal_anchor(self._beacon_cache, self._beacon_chain_info)
            return None
        self._beacon_cache = beacon
        self._beacon_cache_ts = now
        return wrap_as_seal_anchor(beacon, self._beacon_chain_info)

    async def _append_audit(self, seal: Dict[str, Any]) -> None:
        """Append one compact JSON line per seal to `settings.log_file`."""
        log_file: Optional[Path] = self._settings.log_file
        if log_file is None:
            return
        log_file.parent.mkdir(parents=True, exist_ok=True)
        line = json.dumps(seal, ensure_ascii=False, separators=(",", ":"))
        # Synchronous write is acceptable: one short line, bounded latency.
        # If throughput ever matters, switch to aiofiles + batching.
        with log_file.open("a", encoding="utf-8") as f:
            f.write(line + "\n")
