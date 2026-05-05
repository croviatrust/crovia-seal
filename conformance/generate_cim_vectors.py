"""
Generate cross-language CIM conformance vectors.

Produces `conformance/vectors/cim/v1.json` — consumed by:
  - Python tests to assert self-consistency
  - TypeScript tests (`tests/stego.conformance.test.ts`) to assert the TS
    encoder produces byte-identical output for the same seal_id inputs

Each vector stores:
    seal_id          : canonical "cs_YYYY_<26 base32>" id
    issuance_year    : required to reconstruct the full seal_id on extract
    mark_codepoints  : list[int] of every code point of encode_cim(seal_id)

We store code points (not raw UTF-8) because the CIM is defined in terms of
Unicode code points and serialization to UTF-8 is a separate concern.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

# Make `reference/python` importable when run from anywhere.
HERE = Path(__file__).resolve().parent
REPO = HERE.parent
sys.path.insert(0, str(REPO / "reference" / "python"))

from crovia_seal.stego import encode_cim, CIM_TOTAL_LEN  # noqa: E402

VECTORS = [
    # (seal_id, note)
    ("cs_2026_AAAAAAAAAAAAAAAAAAAAAAAAAA", "all-zero base32 (A = 0b00000)"),
    ("cs_2026_77777777777777777777777777", "all-one base32 (7 = 0b11111)"),
    ("cs_2026_ABCDEFGHIJKLMNOPQRSTUVWXYZ", "alphabet sweep A..Z"),
    ("cs_1999_23456723456723456723456723",  "all digit chars, year edge"),
    ("cs_2100_HGHHH64OQMB3EC55F5QDCS7YVE", "mixed realistic id"),
    ("cs_2026_ABCDEFGHIJKLMNOP2345672ABC", "letters + digits mixed"),
]


def make_vector(seal_id: str, note: str) -> dict:
    mark = encode_cim(seal_id)
    assert len(mark) == CIM_TOTAL_LEN
    return {
        "seal_id": seal_id,
        "issuance_year": int(seal_id.split("_")[1]),
        "note": note,
        "mark_len": CIM_TOTAL_LEN,
        "mark_codepoints": [ord(c) for c in mark],
    }


def main() -> None:
    out_dir = REPO / "conformance" / "vectors" / "cim"
    out_dir.mkdir(parents=True, exist_ok=True)
    payload = {
        "version": 1,
        "format": "cim-codepoints",
        "algorithm": {
            "cim_total_len": CIM_TOTAL_LEN,
            "data_bits": 130,
            "crc_bits": 16,
            "crc": "CRC-16/CCITT poly=0x1021 init=0xFFFF no_final_xor",
            "start_mark": [0x200D, 0xFEFF, 0x200D],
            "end_mark":   [0xFEFF, 0x200D, 0xFEFF],
            "bit_0": 0x200B,
            "bit_1": 0x200C,
        },
        "vectors": [make_vector(sid, note) for sid, note in VECTORS],
    }
    out = out_dir / "v1.json"
    out.write_text(json.dumps(payload, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
    print(f"wrote {len(payload['vectors'])} vectors -> {out}")


if __name__ == "__main__":
    main()
