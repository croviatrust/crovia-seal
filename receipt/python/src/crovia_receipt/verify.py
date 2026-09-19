"""verify() — check the structure and signature of a receipt."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from crovia_seal.canonical import CanonicalizationError, canonicalize
from crovia_seal.keys import verify_bytes
from crovia_seal.seal import compute_payload, validate_receipt_shape


def _sha256_prefixed(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


@dataclass
class VerifyResult:
    """Outcome of verify() / verify_chain(). Never throws — all failures are returned."""

    valid: bool
    errors: List[str] = field(default_factory=list)
    id: Optional[str] = None
    signer: Optional[str] = None
    payload_hash: Optional[str] = None
    prev: Optional[str] = None
    seq: Optional[int] = None
    issued_at: Optional[str] = None

    def __bool__(self) -> bool:
        return self.valid


def verify(receipt: Any, payload: Any = ...) -> VerifyResult:
    """Verify a continuity receipt.

    Args:
        receipt: The receipt dict.
        payload: Optional original payload to verify payload_hash against.
                 Pass the sentinel default (omit) to skip the payload check.

    Returns:
        VerifyResult — never raises.
    """
    errors: List[str] = []

    shape_err = validate_receipt_shape(receipt)
    if shape_err is not None:
        return VerifyResult(valid=False, errors=[f"schema: {shape_err}"])

    r: Dict[str, Any] = receipt  # type: ignore[assignment]

    sig_hex = r["sig"]
    without_sig = {k: v for k, v in r.items() if k != "sig"}
    signing_payload = compute_payload(without_sig)

    if not verify_bytes(r["signer"], sig_hex, signing_payload):
        return VerifyResult(
            valid=False,
            errors=["signature: invalid"],
            id=r["id"],
            signer=r["signer"],
            payload_hash=r["payload_hash"],
            prev=r["prev"],
            seq=r["seq"],
            issued_at=r["issued_at"],
        )

    # Sentinel handling: ... means caller did not supply a payload.
    if payload is not ...:
        try:
            computed = _sha256_prefixed(canonicalize(payload))
        except CanonicalizationError as e:
            return VerifyResult(
                valid=False,
                errors=[f"payload-canonicalize: {e}"],
            )
        if computed != r["payload_hash"]:
            return VerifyResult(
                valid=False,
                errors=[
                    f"payload_hash mismatch: receipt={r['payload_hash']} computed={computed}"
                ],
                id=r["id"],
                signer=r["signer"],
                payload_hash=r["payload_hash"],
                prev=r["prev"],
                seq=r["seq"],
                issued_at=r["issued_at"],
            )

    return VerifyResult(
        valid=True,
        errors=[],
        id=r["id"],
        signer=r["signer"],
        payload_hash=r["payload_hash"],
        prev=r["prev"],
        seq=r["seq"],
        issued_at=r["issued_at"],
    )


def verify_chain(receipts: List[Dict[str, Any]]) -> VerifyResult:
    """Verify a chain of receipts in order.

    Each receipt[i].prev must equal receipt[i-1].id, sequence must increment
    by 1, and signer must remain stable. All signatures must verify.
    """
    if not receipts:
        return VerifyResult(valid=False, errors=["empty chain"])

    prev_id: Optional[str] = None
    prev_seq = -1
    signer: Optional[str] = None

    for i, r in enumerate(receipts):
        single = verify(r)
        if not single.valid:
            return VerifyResult(
                valid=False,
                errors=[f"chain[{i}] invalid: {'; '.join(single.errors)}"],
            )
        if signer is None:
            signer = r["signer"]
        elif signer != r["signer"]:
            return VerifyResult(
                valid=False,
                errors=[f"chain[{i}] signer changed from {signer} to {r['signer']}"],
            )
        if r["seq"] != prev_seq + 1:
            return VerifyResult(
                valid=False,
                errors=[f"chain[{i}] seq={r['seq']} but expected {prev_seq + 1}"],
            )
        if r["prev"] != prev_id:
            return VerifyResult(
                valid=False,
                errors=[f"chain[{i}] prev={r['prev']} but expected {prev_id}"],
            )
        prev_id = r["id"]
        prev_seq = r["seq"]

    return VerifyResult(
        valid=True,
        errors=[],
        id=receipts[-1]["id"],
        signer=signer,
    )
