"""
Crovia Invisible Mark (CIM) v1 — Python reference implementation.

This module is the authoritative Python twin of the TypeScript
`integrations/browser-extension/src/lib/stego.ts`. Every function is
deliberately kept algorithmically identical so that a CIM produced by one
language is verified by the other with ZERO tolerance (byte-identical test
vectors live in `conformance/vectors/cim/`).

WIRE FORMAT (must match stego.ts):

    START_MARK (3 cp)  +  DATA_BITS (130 cp)  +  CRC_BITS (16 cp)  +  END_MARK (3 cp)

    START_MARK = U+200D U+FEFF U+200D
    END_MARK   = U+FEFF U+200D U+FEFF
    bit 0      = U+200B
    bit 1      = U+200C
    CRC        = CRC-16/CCITT (poly 0x1021, init 0xFFFF, no final xor), MSB first

The suffix of a `seal_id` (26 RFC-4648 base32 chars) is encoded in DATA_BITS.
The `cs_YYYY_` prefix is reconstructed at extraction time using the
caller-provided `issuance_year` (default: current UTC year).

THIS FILE MUST NEVER DIVERGE FROM stego.ts. Changes here require mirrored
changes + re-generated conformance vectors in the TS twin.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import List, Optional

# ---------------------------------------------------------------------------
# Unicode constants (MUST equal stego.ts)
# ---------------------------------------------------------------------------

ZW_BIT_0 = "\u200B"  # ZERO WIDTH SPACE
ZW_BIT_1 = "\u200C"  # ZERO WIDTH NON-JOINER
ZWJ = "\u200D"
BOM = "\uFEFF"

CIM_START = ZWJ + BOM + ZWJ
CIM_END = BOM + ZWJ + BOM
CIM_BITS_DATA = 130
CIM_BITS_CRC = 16
CIM_TOTAL_LEN = len(CIM_START) + CIM_BITS_DATA + CIM_BITS_CRC + len(CIM_END)

_BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
_BASE32_INDEX = {c: i for i, c in enumerate(_BASE32_ALPHABET)}
_SEAL_ID_RE = re.compile(r"^cs_([0-9]{4})_([A-Z2-7]{26})$")
_BASE32_26_RE = re.compile(r"^[A-Z2-7]{26}$")


# ---------------------------------------------------------------------------
# Bit packing helpers
# ---------------------------------------------------------------------------

def _base32_to_bits(base32: str) -> List[int]:
    if not _BASE32_26_RE.match(base32):
        raise ValueError("invalid base32 suffix: need 26 upper-case RFC 4648 chars")
    bits: List[int] = [0] * CIM_BITS_DATA
    for i in range(26):
        value = _BASE32_INDEX[base32[i]]
        for b in range(4, -1, -1):  # MSB first
            bits[i * 5 + (4 - b)] = (value >> b) & 1
    return bits


def _bits_to_base32(bits: List[int]) -> str:
    if len(bits) != CIM_BITS_DATA:
        raise ValueError(f"expected {CIM_BITS_DATA} bits, got {len(bits)}")
    out_chars: List[str] = []
    for i in range(26):
        v = 0
        for b in range(5):
            v = (v << 1) | (bits[i * 5 + b] & 1)
        out_chars.append(_BASE32_ALPHABET[v])
    return "".join(out_chars)


# ---------------------------------------------------------------------------
# CRC-16/CCITT (bitwise; MUST equal stego.ts `crc16Bits`)
# ---------------------------------------------------------------------------

def _crc16_bits(bits: List[int]) -> int:
    crc = 0xFFFF
    for bit in bits:
        top = (crc & 0x8000) != 0
        crc = (crc << 1) & 0xFFFF
        if top != (bit == 1):
            crc ^= 0x1021
    return crc & 0xFFFF


# ---------------------------------------------------------------------------
# Zero-width encoder / decoder
# ---------------------------------------------------------------------------

def _bits_to_zw(bits: List[int]) -> str:
    return "".join(ZW_BIT_1 if b else ZW_BIT_0 for b in bits)


def _zw_to_bits(zw: str) -> List[int]:
    bits: List[int] = []
    for i, c in enumerate(zw):
        if c == ZW_BIT_0:
            bits.append(0)
        elif c == ZW_BIT_1:
            bits.append(1)
        else:
            raise ValueError(f"unexpected char in CIM bit stream at index {i}")
    return bits


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ExtractedCim:
    """Result of a successful CIM extraction.

    Mirrors the `ExtractedCim` interface in stego.ts. Instances of this class
    are only ever returned for marks whose CRC matched; a `crc_valid=False`
    mark is NEVER surfaced (mismatches are silently skipped so a single bad
    bit cannot shadow a subsequent valid mark).
    """
    seal_id: str
    base32: str
    crc_valid: bool
    start_index: int
    end_index: int
    year: int


def encode_cim(seal_id: str) -> str:
    """Encode a seal_id into a 152-code-point CIM string (all invisible)."""
    m = _SEAL_ID_RE.match(seal_id)
    if not m:
        raise ValueError(f"invalid seal_id: {seal_id!r}")
    base32 = m.group(2)
    data_bits = _base32_to_bits(base32)
    crc = _crc16_bits(data_bits)
    crc_bits = [(crc >> (CIM_BITS_CRC - 1 - i)) & 1 for i in range(CIM_BITS_CRC)]
    return CIM_START + _bits_to_zw(data_bits) + _bits_to_zw(crc_bits) + CIM_END


def embed_cim(visible_text: str, seal_id: str) -> str:
    """Inject a CIM into visible text.

    Placement policy (identical to stego.ts):
      - if the text contains a newline in the last 200 chars, insert the mark
        immediately BEFORE that newline (survives "first paragraph" crops);
      - otherwise append to the end.
    """
    mark = encode_cim(seal_id)
    last_nl = visible_text.rfind("\n")
    if last_nl >= 0 and last_nl > len(visible_text) - 200:
        return visible_text[:last_nl] + mark + visible_text[last_nl:]
    return visible_text + mark


def extract_all_cims(text: str, issuance_year: Optional[int] = None) -> List[ExtractedCim]:
    """Scan `text` for ALL valid CIM marks and return them in order.

    An invalid CIM (wrong CRC, bad bit alphabet, truncated end marker) is
    skipped over and NEVER returned: silent failures are safer than spoofing.
    """
    year = issuance_year if issuance_year is not None else datetime.now(timezone.utc).year
    out: List[ExtractedCim] = []
    cursor = 0
    while cursor < len(text):
        start = text.find(CIM_START, cursor)
        if start < 0:
            break
        payload_start = start + len(CIM_START)
        end_candidate = payload_start + CIM_BITS_DATA + CIM_BITS_CRC
        if end_candidate + len(CIM_END) > len(text):
            break
        if text[end_candidate:end_candidate + len(CIM_END)] != CIM_END:
            cursor = start + 1
            continue
        bit_stream = text[payload_start:end_candidate]
        if any(c not in (ZW_BIT_0, ZW_BIT_1) for c in bit_stream):
            cursor = start + 1
            continue
        try:
            data_bits = _zw_to_bits(bit_stream[:CIM_BITS_DATA])
            crc_bits = _zw_to_bits(bit_stream[CIM_BITS_DATA:])
            crc_from = 0
            for i in range(CIM_BITS_CRC):
                crc_from = (crc_from << 1) | crc_bits[i]
            crc_computed = _crc16_bits(data_bits)
            if crc_computed != crc_from:
                cursor = start + 1
                continue
            base32 = _bits_to_base32(data_bits)
            out.append(ExtractedCim(
                seal_id=f"cs_{year}_{base32}",
                base32=base32,
                crc_valid=True,
                start_index=start,
                end_index=end_candidate + len(CIM_END),
                year=year,
            ))
            cursor = end_candidate + len(CIM_END)
        except ValueError:
            cursor = start + 1
    return out


def extract_cim(text: str, issuance_year: Optional[int] = None) -> Optional[ExtractedCim]:
    """Return the FIRST valid CIM in `text`, or None."""
    all_marks = extract_all_cims(text, issuance_year)
    return all_marks[0] if all_marks else None


def strip_cim(text: str) -> str:
    """Return `text` with all valid CIMs removed; invalid partials kept."""
    all_marks = extract_all_cims(text)
    if not all_marks:
        return text
    out = text
    for m in reversed(all_marks):
        out = out[:m.start_index] + out[m.end_index:]
    return out


def contains_cim_marker(text: str) -> bool:
    """Heuristic: does this text contain at least a CIM start sequence?"""
    return CIM_START in text


__all__ = [
    "ZW_BIT_0", "ZW_BIT_1", "ZWJ", "BOM",
    "CIM_START", "CIM_END",
    "CIM_BITS_DATA", "CIM_BITS_CRC", "CIM_TOTAL_LEN",
    "ExtractedCim",
    "encode_cim", "embed_cim",
    "extract_cim", "extract_all_cims",
    "strip_cim", "contains_cim_marker",
]
