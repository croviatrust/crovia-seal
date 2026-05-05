"""
Run the full Crovia Seal v1 conformance test suite against the Python
reference implementation.

Exits 0 on success, non-zero on any failure.

This script is the canonical oracle for implementations: a non-Python
implementation MUST be able to reproduce every byte in vectors/v1/ and
MUST reject every file under vectors/v1/invalid/.
"""
from __future__ import annotations

import json
import sys
import hashlib
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_REPO = _HERE.parent
_PKG_ROOT = _REPO / "reference" / "python"
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

from crovia_seal.canonical import canonicalize
from crovia_seal.seal import verify_seal, compute_payload


VECTORS = _REPO / "conformance" / "vectors" / "v1"


def _green(s: str) -> str:
    return f"\033[92m{s}\033[0m"


def _red(s: str) -> str:
    return f"\033[91m{s}\033[0m"


def _bold(s: str) -> str:
    return f"\033[1m{s}\033[0m"


def run_canonical_cases() -> tuple[int, int]:
    path = VECTORS / "canonical_cases.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    passed = failed = 0
    for case in data["cases"]:
        got = canonicalize(case["input"])
        want_hex = case["expected_hex"]
        if got.hex() == want_hex:
            passed += 1
        else:
            failed += 1
            print(_red(f"  FAIL canonical {case['name']!r}"))
            print(f"       want: {want_hex}")
            print(f"       got:  {got.hex()}")
    return passed, failed


def run_valid_seals() -> tuple[int, int]:
    passed = failed = 0
    for seal_path in sorted(VECTORS.glob("seal_*.json")):
        name = seal_path.stem
        seal = json.loads(seal_path.read_text(encoding="utf-8"))

        # 1) Re-derive the canonical payload and cross-check the companion .payload.hex file
        payload_file = VECTORS / f"{name}.payload.hex"
        if payload_file.exists():
            want_payload = bytes.fromhex(payload_file.read_text().strip())
            got_payload = compute_payload({k: v for k, v in seal.items()
                                           if k not in ("signature", "witnesses")})
            if got_payload != want_payload:
                failed += 1
                print(_red(f"  FAIL {name}: canonical payload mismatch"))
                continue

        # 2) Cross-check the companion .signature.hex file
        sig_file = VECTORS / f"{name}.signature.hex"
        if sig_file.exists():
            want_sig = bytes.fromhex(sig_file.read_text().strip())
            got_sig = bytes.fromhex(seal["signature"]["sig_hex"])
            if got_sig != want_sig:
                failed += 1
                print(_red(f"  FAIL {name}: signature in .json differs from .signature.hex"))
                continue

        # 3) End-to-end verification via the public API.
        # verify_seal returns a VerifyResult; .ok must be True for a valid seal.
        result = verify_seal(seal)
        if not result.ok:
            failed += 1
            print(_red(f"  FAIL {name}: verify_seal returned ok=False"))
            for err in result.errors:
                print(f"       reason: {err}")
            continue

        passed += 1
    return passed, failed


def run_invalid_seals() -> tuple[int, int]:
    inv_dir = VECTORS / "invalid"
    if not inv_dir.exists():
        return 0, 0

    idx_path = inv_dir / "index.json"
    index = json.loads(idx_path.read_text(encoding="utf-8"))["invalid_cases"]
    passed = failed = 0
    for case in index:
        name = case["file"]
        expected_err = case["expected_error"]
        seal_path = inv_dir / name
        seal = json.loads(seal_path.read_text(encoding="utf-8"))
        # The Python reference returns a VerifyResult.  An invalid seal MUST
        # produce ok=False.  Some implementations may raise instead of return;
        # we accept either rejection mode here.
        try:
            result = verify_seal(seal)
            rejected = (not result.ok)
        except Exception:
            rejected = True
        if rejected:
            passed += 1
            continue
        failed += 1
        print(_red(f"  FAIL {name}: verifier accepted an INVALID seal "
                   f"(expected to reject with {expected_err})"))
    return passed, failed


def main() -> int:
    print(_bold("Crovia Seal v1 conformance"))
    print(f"Vectors: {VECTORS}")
    print()

    p1, f1 = run_canonical_cases()
    print(f"  canonicalization cases: {_green(str(p1))} pass / {_red(str(f1)) if f1 else '0'} fail")

    p2, f2 = run_valid_seals()
    print(f"  valid seal vectors:     {_green(str(p2))} pass / {_red(str(f2)) if f2 else '0'} fail")

    p3, f3 = run_invalid_seals()
    print(f"  invalid (fail-closed):  {_green(str(p3))} pass / {_red(str(f3)) if f3 else '0'} fail")

    total_failed = f1 + f2 + f3
    total_passed = p1 + p2 + p3
    print()
    if total_failed == 0:
        print(_green(_bold(f"ALL {total_passed} TESTS PASSED")))
        return 0
    print(_red(_bold(f"{total_failed} TESTS FAILED ({total_passed} passed)")))
    return 1


if __name__ == "__main__":
    sys.exit(main())
