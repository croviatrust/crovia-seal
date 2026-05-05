"""
Extended conformance vectors for Crovia Seal v1.

Runs AFTER generate_vectors.py and adds:

    vectors/v1/
      seal_003_image.json            (+ .payload.hex, .signature.hex)
      seal_004_audio.json
      seal_005_multimodal.json
      seal_006_with_checks.json
      seal_007_with_anchor.json
      seal_008_empty_params.json
      seal_009_long_chain.json
      seal_010_utf8_content.json

      invalid/
        invalid_01_bad_signature.json         (valid seal, signature byte flipped)
        invalid_02_wrong_domain.json          (domain prefix altered in signature.domain)
        invalid_03_tampered_field.json        (output_hash changed post-signing)
        invalid_04_bad_seal_version.json      (seal_version = crovia.seal.v2)
        invalid_05_unknown_toplevel.json      (unknown top-level field "foo")

Any conformant verifier MUST accept all `seal_00X_*.json` files in `vectors/v1/`
and MUST REJECT every file under `vectors/v1/invalid/`. The tests/run_conformance.py
script exercises this end-to-end.
"""
from __future__ import annotations

import json
import sys
import copy
import hashlib
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_REPO = _HERE.parent
_PKG_ROOT = _REPO / "reference" / "python"
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

from crovia_seal.canonical import canonicalize  # noqa: F401
from crovia_seal.constants import (
    CANON_ID,
    PAYLOAD_HASH_ALG,
    SEAL_VERSION,
    SIGNATURE_ALG,
    SIGNATURE_DOMAIN,
)
from crovia_seal.keys import load_issuer_key
from crovia_seal.seal import compute_payload, _validate_structure

# Re-use the same deterministic issuer as generate_vectors.py
from generate_vectors import (
    ISSUER_ID,
    ISSUER_SEED_HEX,
    _build_unsigned,
    _sign,
)


# ---------------------------------------------------------------------------
# Eight additional valid seals (003..010)
# ---------------------------------------------------------------------------
# Fixed seal_id/nonce/time per vector so results are bit-identical across runs.

EXTRA_SEAL_DEFS = [
    {
        "name": "seal_003_image",
        "seal_id": "cs_2026_EEEEEEEEEEEEEEEEEEEEEEEEEE",
        "nonce":   "FFFFFFFFFFFFFFFFFFFFFFFFFF",
        "emitted_at": "2026-04-15T00:00:02.000Z",
        "input_bytes":  b"A photograph of a red door.",
        "output_bytes": b"\x89PNG\r\n\x1a\n" + b"\x00" * 128,  # fake PNG header + padding
        "modality": "image",
        "generator_id": "openai/dall-e-3",
        "generator_version": "2024-10-01",
        "generator_params": {"size": "1024x1024", "quality": "hd"},
        "sequence": 2,
    },
    {
        "name": "seal_004_audio",
        "seal_id": "cs_2026_GGGGGGGGGGGGGGGGGGGGGGGGGG",
        "nonce":   "HHHHHHHHHHHHHHHHHHHHHHHHHH",
        "emitted_at": "2026-04-15T00:00:03.000Z",
        "input_bytes":  b"Synthesize the sentence 'welcome to Crovia'.",
        "output_bytes": b"ID3\x03\x00\x00\x00" + b"\x00" * 256,  # fake MP3 header
        "modality": "audio",
        "generator_id": "elevenlabs/multilingual-v2",
        "generator_version": None,
        "generator_params": {"voice_id": "Rachel", "stability": "0.45"},
        "sequence": 3,
    },
    {
        "name": "seal_005_multimodal",
        "seal_id": "cs_2026_IIIIIIIIIIIIIIIIIIIIIIIIII",
        "nonce":   "JJJJJJJJJJJJJJJJJJJJJJJJJJ",
        "emitted_at": "2026-04-15T00:00:04.000Z",
        "input_bytes":  b"Describe this image and reply with 3 bullet points.",
        "output_bytes": b"- a red door\n- sunlit texture\n- cobblestones\n",
        "modality": "multimodal",
        "generator_id": "anthropic/claude-3-5-sonnet",
        "generator_version": "20241022",
        "generator_params": {"temperature": "0.3", "max_tokens": "512"},
        "sequence": 4,
    },
    {
        "name": "seal_006_with_checks",
        "seal_id": "cs_2026_KKKKKKKKKKKKKKKKKKKKKKKKKK",
        "nonce":   "LLLLLLLLLLLLLLLLLLLLLLLLLL",
        "emitted_at": "2026-04-15T00:00:05.000Z",
        "input_bytes":  b"Write a 50-word essay on liberty.",
        "output_bytes": b"Liberty is the capacity to act according to one's own will "
                        b"within the limits of equal liberty for others.",
        "modality": "text",
        "generator_id": "openai/gpt-4o",
        "generator_version": "2024-08-06",
        "generator_params": {"temperature": "0.7"},
        "sequence": 5,
        "checks": {
            "memorization": {
                "db_version": "crovia-memdb-2026-04-15",
                "method": "ngram-lsh-v1",
                "matches": 0,
                "max_conf": "0.03",
            },
            "toxicity": {
                "model": "openai-moderation-latest",
                "flagged": False,
                "score_hex": "0x02",
            },
        },
    },
    {
        "name": "seal_007_with_anchor",
        "seal_id": "cs_2026_MMMMMMMMMMMMMMMMMMMMMMMMMM",
        "nonce":   "NNNNNNNNNNNNNNNNNNNNNNNNNN",
        "emitted_at": "2026-04-15T00:00:06.000Z",
        "input_bytes":  b"Translate 'hello world' to French.",
        "output_bytes": b"bonjour le monde",
        "modality": "text",
        "generator_id": "google/gemini-1.5-pro",
        "generator_version": None,
        "generator_params": {},
        "sequence": 6,
        "anchor": {
            "log_url": "https://log.croviatrust.com/v1/entries",
            "merkle_root": "sha256:" + ("a" * 64),
            "merkle_proof": [
                "sha256:" + ("b" * 64),
                "sha256:" + ("c" * 64),
                "sha256:" + ("d" * 64),
            ],
            "log_index": 12345,
            "root_signed_at": "2026-04-15T00:05:00.000Z",
        },
    },
    {
        "name": "seal_008_empty_params",
        "seal_id": "cs_2026_OOOOOOOOOOOOOOOOOOOOOOOOOO",
        "nonce":   "PPPPPPPPPPPPPPPPPPPPPPPPPP",
        "emitted_at": "2026-04-15T00:00:07.000Z",
        "input_bytes":  b"ping",
        "output_bytes": b"pong",
        "modality": "text",
        "generator_id": "local/echo-v1",
        "generator_version": None,
        "generator_params": {},  # completely empty — tests canonicalization of {} inside signed payload
        "sequence": 7,
    },
    {
        "name": "seal_009_long_chain",
        "seal_id": "cs_2026_QQQQQQQQQQQQQQQQQQQQQQQQQQ",
        "nonce":   "RRRRRRRRRRRRRRRRRRRRRRRRRR",
        "emitted_at": "2026-04-15T00:00:08.000Z",
        "input_bytes":  b"Continue a conversation that has been going for a while.",
        "output_bytes": b"Of course, let's continue.",
        "modality": "text",
        "generator_id": "openai/gpt-4o",
        "generator_version": "2024-08-06",
        "generator_params": {"temperature": "0.9"},
        "sequence": 42,  # mid-chain; tests that large sequence numbers canonicalize correctly
        "prev_seal_hash_override": "sha256:" + ("e" * 64),  # simulated upstream hash
    },
    {
        "name": "seal_010_utf8_content",
        "seal_id": "cs_2026_SSSSSSSSSSSSSSSSSSSSSSSSSS",
        "nonce":   "TTTTTTTTTTTTTTTTTTTTTTTTTT",
        "emitted_at": "2026-04-15T00:00:09.000Z",
        "input_bytes":  "Traduis: 《café au lait》 en emoji 🙂☕".encode("utf-8"),
        "output_bytes": "☕ 🥛 \U0001F60A".encode("utf-8"),
        "modality": "text",
        "generator_id": "mistralai/mistral-large",
        "generator_version": "2411",
        "generator_params": {"temperature": "0.5"},
        "sequence": 8,
    },
]


def write_extra_valid(out_dir: Path) -> None:
    issuer = load_issuer_key(ISSUER_ID, ISSUER_SEED_HEX)

    # For seals with sequence > 0, we need a prev_seal_hash. Use the previous
    # signed seal in this list (or a test override for seal_009).
    prev_payload_hash = None
    last_payload_bytes = None

    # Try to read seal_002's payload (produced by generate_vectors.py) to chain
    # from it for seal_003. This makes the conformance set genuinely chained.
    prev_file = out_dir / "seal_002_chained.payload.hex"
    if prev_file.exists():
        prev_payload_bytes = bytes.fromhex(prev_file.read_text().strip())
        prev_payload_hash = "sha256:" + hashlib.sha256(prev_payload_bytes).hexdigest()
        last_payload_bytes = prev_payload_bytes
    else:
        prev_payload_hash = None

    for d in EXTRA_SEAL_DEFS:
        if d.get("prev_seal_hash_override"):
            ph = d["prev_seal_hash_override"]
        else:
            ph = prev_payload_hash

        unsigned = _build_unsigned(
            issuer,
            seal_id=d["seal_id"],
            nonce=d["nonce"],
            emitted_at=d["emitted_at"],
            input_bytes=d["input_bytes"],
            output_bytes=d["output_bytes"],
            modality=d["modality"],
            generator_id=d["generator_id"],
            generator_version=d.get("generator_version"),
            generator_weights_hash=None,
            generator_params=d.get("generator_params", {}),
            sequence=d["sequence"],
            prev_seal_hash=ph,
            checks=d.get("checks"),
            anchor=d.get("anchor"),
        )
        signed, payload, sig = _sign(issuer, unsigned)

        name = d["name"]
        (out_dir / f"{name}.json").write_text(
            json.dumps(signed, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
        (out_dir / f"{name}.payload.hex").write_text(payload.hex() + "\n", encoding="utf-8")
        (out_dir / f"{name}.signature.hex").write_text(sig.hex() + "\n", encoding="utf-8")
        print(f"  wrote {name}.json + payload + signature "
              f"({len(payload)} payload bytes, seq={d['sequence']})")

        # Rolling prev hash for subsequent valid seals (unless overridden)
        if not d.get("prev_seal_hash_override"):
            prev_payload_hash = "sha256:" + hashlib.sha256(payload).hexdigest()


# ---------------------------------------------------------------------------
# Five INVALID seals (negative tests for fail-closed verification)
# ---------------------------------------------------------------------------
# Each is derived from seal_001_genesis and corrupted in exactly one way.
# A conformant verifier MUST reject all of these with the documented error code.

def write_invalid(out_dir: Path) -> None:
    inv_dir = out_dir / "invalid"
    inv_dir.mkdir(exist_ok=True)

    base_path = out_dir / "seal_001_genesis.json"
    base = json.loads(base_path.read_text(encoding="utf-8"))

    # ---- invalid_01: flip one byte in signature.sig_hex ----
    s1 = copy.deepcopy(base)
    orig = s1["signature"]["sig_hex"]
    # flip the first hex nibble (0 -> 1 or similar)
    first = "0" if orig[0] != "0" else "f"
    s1["signature"]["sig_hex"] = first + orig[1:]
    _write_invalid(inv_dir, "invalid_01_bad_signature", s1,
                   "Signature byte 0 flipped; Ed25519 verify MUST fail.",
                   "BadSignature")

    # ---- invalid_02: wrong domain in signature.domain (downgrade attempt) ----
    s2 = copy.deepcopy(base)
    s2["signature"]["domain"] = "CROVIA-SEAL-v0"   # plausible-looking but wrong
    _write_invalid(inv_dir, "invalid_02_wrong_domain", s2,
                   "signature.domain does not match the canonical domain prefix. "
                   "Verifier MUST refuse to recompute the payload with a different prefix.",
                   "WrongDomain")

    # ---- invalid_03: subject.output_hash changed post-signing ----
    s3 = copy.deepcopy(base)
    # flip one hex character of output_hash (keep the prefix "sha256:")
    oh = s3["subject"]["output_hash"]
    prefix, rest = oh.split(":", 1)
    rest = ("0" if rest[0] != "0" else "f") + rest[1:]
    s3["subject"]["output_hash"] = f"{prefix}:{rest}"
    _write_invalid(inv_dir, "invalid_03_tampered_field", s3,
                   "output_hash tampered after signing; canonical payload hash differs, "
                   "Ed25519 verify MUST fail.",
                   "SignatureMismatch")

    # ---- invalid_04: unknown seal_version ----
    s4 = copy.deepcopy(base)
    s4["seal_version"] = "crovia.seal.v2"   # future version, unknown to v1 verifiers
    _write_invalid(inv_dir, "invalid_04_bad_seal_version", s4,
                   "seal_version is not 'crovia.seal.v1'. v1 verifier MUST fail closed "
                   "and refuse to interpret the document.",
                   "UnknownSealVersion")

    # ---- invalid_05: unknown top-level field (fail-closed on extra keys) ----
    s5 = copy.deepcopy(base)
    s5["foo"] = "bar"  # unknown top-level field
    _write_invalid(inv_dir, "invalid_05_unknown_toplevel", s5,
                   "An unknown top-level field was injected. "
                   "Per SPEC 4.1, unknown top-level fields MUST cause verification to fail.",
                   "UnknownTopLevelField")

    # Index file for easy machine-readable discovery by test runners.
    idx = {
        "version": "v1",
        "invalid_cases": [
            {"file": "invalid_01_bad_signature.json",   "expected_error": "BadSignature"},
            {"file": "invalid_02_wrong_domain.json",    "expected_error": "WrongDomain"},
            {"file": "invalid_03_tampered_field.json",  "expected_error": "SignatureMismatch"},
            {"file": "invalid_04_bad_seal_version.json","expected_error": "UnknownSealVersion"},
            {"file": "invalid_05_unknown_toplevel.json","expected_error": "UnknownTopLevelField"},
        ],
    }
    (inv_dir / "index.json").write_text(
        json.dumps(idx, indent=2) + "\n", encoding="utf-8"
    )
    print(f"  wrote 5 invalid vectors + index.json")


def _write_invalid(inv_dir: Path, name: str, seal: dict, desc: str, err: str) -> None:
    """Emit one invalid vector + a .note.md with human-readable reasoning."""
    (inv_dir / f"{name}.json").write_text(
        json.dumps(seal, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    note = (
        f"# {name}\n\n"
        f"**Expected verifier error:** `{err}`\n\n"
        f"## Description\n\n{desc}\n\n"
        f"## Derivation\n\nBase: `seal_001_genesis.json`\n\n"
        f"A single, deliberate corruption has been applied. All other bytes are identical.\n"
    )
    (inv_dir / f"{name}.note.md").write_text(note, encoding="utf-8")


# ---------------------------------------------------------------------------

def main() -> int:
    out_dir = _REPO / "conformance" / "vectors" / "v1"
    out_dir.mkdir(parents=True, exist_ok=True)
    print(f"Extending conformance vectors in: {out_dir}")
    print()
    print("Additional valid seals (003..010):")
    write_extra_valid(out_dir)
    print()
    print("Invalid seals (5 negative tests):")
    write_invalid(out_dir)
    print()
    print("Extended conformance vectors complete.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
