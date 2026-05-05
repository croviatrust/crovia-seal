"""
Crovia Seal — end-to-end demonstration.

What this script does (ASCII-only output for Windows terminal compatibility):

    1. Generates a deterministic issuer keypair (so the demo is reproducible).
    2. Emits a genesis Seal over a known copyrighted passage used as a
       research fixture: the opening of Harry Potter 1, bundled in
       capsules/copyright_probe_texts.json.
    3. Verifies the Seal against itself.
    4. Tampers with a single byte of the output and re-verifies.
       The tampered Seal MUST be rejected with a precise error.
    5. Emits a second, chained Seal referencing the first.
    6. Verifies the chain link.

Run:
    cd crovia-seal/reference/python
    pip install -e .
    python examples/demo_hp.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

# Make the package importable when running the script directly from source,
# without requiring a prior `pip install -e .`.
_HERE = Path(__file__).resolve().parent
_PKG_ROOT = _HERE.parent
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

from crovia_seal import (  # noqa: E402
    compute_seal_hash,
    emit_seal,
    load_issuer_key,
    verify_seal,
)


# --- Deterministic issuer ---------------------------------------------------

# A fixed seed so the demo is reproducible across machines.
# NEVER use this seed in production.
DEMO_SEED_HEX = "deadbeef" * 8  # 64 hex chars = 32 bytes
DEMO_ISSUER_ID = "urn:crovia:seal-issuer:demo"


# --- Research fixture -------------------------------------------------------

# Opening of "Harry Potter and the Philosopher's Stone" (J.K. Rowling, 1997).
# Used strictly as a test fixture for memorization research (fair use).
HP_PASSAGE = (
    "Mr. and Mrs. Dursley, of number four, Privet Drive, were proud to "
    "say that they were perfectly normal, thank you very much. They "
    "were the last people you'd expect to be involved in anything "
    "strange or mysterious, because they just didn't hold with such "
    "nonsense."
)
INPUT_PROMPT = "Continue this passage: 'Mr. and Mrs. Dursley, of number four,'"


# --- Pretty-print helpers ---------------------------------------------------

HR = "-" * 72


def _print_seal(label: str, s: dict) -> None:
    print(HR)
    print(f"{label}:")
    print(HR)
    print(json.dumps(s, indent=2, sort_keys=True))
    print()


def _print_result(label: str, r) -> None:
    status = "OK" if r.ok else "REJECTED"
    print(f"{label}: {status}")
    if r.errors:
        for e in r.errors:
            print(f"    error: {e}")
    print()


# --- Main -------------------------------------------------------------------

def main() -> int:
    print("Crovia Seal demo")
    print("=" * 72)
    print()

    # Step 1: deterministic issuer.
    issuer = load_issuer_key(DEMO_ISSUER_ID, DEMO_SEED_HEX)
    print(f"Issuer id:         {issuer.issuer_id}")
    print(f"Issuer public key: {issuer.public_hex}")
    print()

    # Step 2: emit genesis Seal over the HP passage.
    seal = emit_seal(
        issuer_key=issuer,
        input_bytes=INPUT_PROMPT.encode("utf-8"),
        output_bytes=HP_PASSAGE.encode("utf-8"),
        modality="text",
        generator_id="openai/gpt-4o",
        generator_version="2024-08-06",
        generator_params={"temperature": "0.7", "top_p": "1.0"},
        checks={
            "memorization": {
                "db_version": "crovia-memdb-2026-04-15",
                "method": "ngram-lsh-v1",
                "matches": 1,
                "max_conf": "0.94",
                "work": "Harry Potter and the Philosopher's Stone (1997)",
            }
        },
    )
    _print_seal("Genesis Seal", seal)

    # Step 3: self-verify.
    r_ok = verify_seal(seal, issuer_pubkey_hex=issuer.public_hex)
    _print_result("Self-verify (honest)", r_ok)
    if not r_ok.ok:
        return 1

    # Step 4: tamper with output_hash (single hex digit flip) and re-verify.
    import copy
    tampered = copy.deepcopy(seal)
    h = tampered["subject"]["output_hash"]
    flipped = h[:-1] + ("0" if h[-1] != "0" else "1")
    tampered["subject"]["output_hash"] = flipped
    print(f"Tampering: subject.output_hash last char {h[-1]} -> {flipped[-1]}")
    r_bad = verify_seal(tampered, issuer_pubkey_hex=issuer.public_hex)
    _print_result("Verify (tampered)", r_bad)
    if r_bad.ok:
        print("FAIL: tampered Seal should have been rejected.")
        return 1

    # Step 5: chained Seal.
    seal2 = emit_seal(
        issuer_key=issuer,
        input_bytes=b"Now write a one-sentence summary.",
        output_bytes=b"The Dursleys are proud to be perfectly normal.",
        modality="text",
        generator_id="openai/gpt-4o",
        generator_version="2024-08-06",
        sequence=1,
        prev_seal_hash=compute_seal_hash(seal),
    )
    _print_seal("Chained Seal (sequence=1)", seal2)

    # Step 6: verify chain link.
    r_chain = verify_seal(seal2, issuer_pubkey_hex=issuer.public_hex)
    _print_result("Chain verify", r_chain)
    if seal2["chain"]["prev_seal_hash"] != compute_seal_hash(seal):
        print("FAIL: prev_seal_hash does not match previous seal.")
        return 1
    print("Chain link: prev_seal_hash matches hash of genesis Seal.")
    print()

    print("Demo complete.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
