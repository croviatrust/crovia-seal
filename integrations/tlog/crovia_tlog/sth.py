"""
Signed Tree Head (STH).

An STH is the log operator's attestation of a specific tree state:

    {
      "log_id":      "urn:crovia:tlog:<operator>",
      "tree_size":   <int>,
      "root_hash":   "<hex sha256>",
      "timestamp":   "<RFC 3339>",
      "signature": {
         "alg":     "Ed25519",
         "sig_hex": "<128 hex>"
      }
    }

The signature is computed over the DOMAIN-SEPARATED canonical byte string:

    b"CROVIA-TLOG-STH-v1\\n" + UTF-8(json.dumps({
        "log_id":    ...,
        "tree_size": ...,
        "root_hash": ...,
        "timestamp": ...
    }, sort_keys=True, separators=(",",":")))

Verifiers reconstruct that byte string and check it against the operator's
published public key. The log serves its key at
`/.well-known/crovia-tlog.json` so clients can trust-on-first-use or pin it.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict

from crovia_tlog.keys import TlogKey


STH_DOMAIN = b"CROVIA-TLOG-STH-v1\n"


def _now() -> str:
    now = datetime.now(tz=timezone.utc)
    ms = now.microsecond // 1000
    return now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{ms:03d}Z"


def sign_sth(
    *,
    log_id: str,
    tree_size: int,
    root_hash: bytes,
    log_key: TlogKey,
    timestamp: str | None = None,
) -> Dict[str, Any]:
    ts = timestamp or _now()
    body = {
        "log_id": log_id,
        "tree_size": tree_size,
        "root_hash": root_hash.hex(),
        "timestamp": ts,
    }
    message = STH_DOMAIN + _canon_json(body).encode("utf-8")
    sig = log_key.sign(message)
    return {
        **body,
        "signature": {
            "alg": "Ed25519",
            "sig_hex": sig.hex(),
        },
        "log_pubkey_hex": log_key.public_hex,
    }


def verify_sth(sth: Dict[str, Any], log_pubkey_hex: str) -> bool:
    """Verify a Signed Tree Head against a known log public key.

    Returns True on successful verification, False otherwise. Never raises
    on malformed input.
    """
    try:
        sig_hex = sth["signature"]["sig_hex"]
        body = {
            "log_id": sth["log_id"],
            "tree_size": sth["tree_size"],
            "root_hash": sth["root_hash"],
            "timestamp": sth["timestamp"],
        }
        message = STH_DOMAIN + _canon_json(body).encode("utf-8")
        return TlogKey.verify_raw(log_pubkey_hex, message, bytes.fromhex(sig_hex))
    except Exception:
        return False


def _canon_json(obj: Dict[str, Any]) -> str:
    """Minimal deterministic JSON (sorted keys, no whitespace).

    Not a full CSC-1 canonicalization: STH body is a tiny fixed schema with
    only string/int values, so sorted-keys + compact separators is
    sufficient and stable across languages (Python, JS, Go implementations
    all agree on this output).
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
