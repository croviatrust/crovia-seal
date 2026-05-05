"""
Tests for the Python CIM (Crovia Invisible Mark) implementation.

These tests mirror the TypeScript test file `integrations/browser-extension/
tests/stego.test.ts`. They also assert byte-level properties that any future
drift from the TS twin would immediately break.
"""
from __future__ import annotations

import pytest

from crovia_seal.stego import (
    CIM_START,
    CIM_END,
    CIM_TOTAL_LEN,
    encode_cim,
    embed_cim,
    extract_cim,
    extract_all_cims,
    strip_cim,
    contains_cim_marker,
    ExtractedCim,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

VALID = "cs_2026_ABCDEFGHIJKLMNOPQRSTUVWXYZ"
VALID_2 = "cs_2026_HGHHH64OQMB3EC55F5QDCS7YVE"  # real seal_id observed in live test
VALID_3 = "cs_1999_23456723456723456723456723"  # edge: all-digit suffix (26 chars)


# ---------------------------------------------------------------------------
# Basic encode / length invariants
# ---------------------------------------------------------------------------

def test_encode_produces_fixed_length():
    mark = encode_cim(VALID)
    assert len(mark) == CIM_TOTAL_LEN == 152


def test_encode_starts_and_ends_with_markers():
    mark = encode_cim(VALID)
    assert mark.startswith(CIM_START)
    assert mark.endswith(CIM_END)


def test_encode_contains_only_zero_width_chars():
    mark = encode_cim(VALID)
    allowed = {"\u200B", "\u200C", "\u200D", "\uFEFF"}
    assert all(c in allowed for c in mark)


def test_encode_is_deterministic():
    assert encode_cim(VALID) == encode_cim(VALID)


def test_encode_rejects_invalid_seal_id():
    for bad in ["", "cs_abc_XYZ", "cs_2026_", "cs_2026_abcdefghijklmnopqrstuvwxyz", "notaseal"]:
        with pytest.raises(ValueError):
            encode_cim(bad)


# ---------------------------------------------------------------------------
# Round-trip
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("seal_id", [VALID, VALID_2, VALID_3])
def test_round_trip_extracts_same_seal_id(seal_id):
    mark = encode_cim(seal_id)
    text = f"Hello world.{mark} How are you?"
    result = extract_cim(text, issuance_year=int(seal_id.split("_")[1]))
    assert result is not None
    assert result.seal_id == seal_id
    assert result.crc_valid is True


def test_extract_returns_none_on_plain_text():
    assert extract_cim("nothing here") is None
    assert extract_cim("") is None


def test_extract_returns_none_on_only_marker_start():
    # start marker present but no payload -> must not crash, must return None
    assert extract_cim(CIM_START + "oops") is None


# ---------------------------------------------------------------------------
# Tamper resistance (CRC)
# ---------------------------------------------------------------------------

def test_flipping_single_data_bit_fails_crc():
    mark = encode_cim(VALID)
    # Flip one data bit (index 10 -> right after CIM_START)
    data_pos = len(CIM_START) + 10
    orig = mark[data_pos]
    flipped = "\u200B" if orig == "\u200C" else "\u200C"
    tampered = mark[:data_pos] + flipped + mark[data_pos + 1:]
    assert extract_cim(tampered) is None


def test_flipping_single_crc_bit_fails_crc():
    mark = encode_cim(VALID)
    crc_pos = len(CIM_START) + 130 + 4  # inside CRC region
    orig = mark[crc_pos]
    flipped = "\u200B" if orig == "\u200C" else "\u200C"
    tampered = mark[:crc_pos] + flipped + mark[crc_pos + 1:]
    assert extract_cim(tampered) is None


def test_truncated_mark_returns_none():
    mark = encode_cim(VALID)
    truncated = mark[:-1]
    assert extract_cim(truncated) is None


def test_garbage_char_inside_bit_stream_returns_none():
    mark = encode_cim(VALID)
    # Replace a bit char with a regular letter
    pos = len(CIM_START) + 20
    bad = mark[:pos] + "X" + mark[pos + 1:]
    assert extract_cim(bad) is None


# ---------------------------------------------------------------------------
# Multi-mark handling
# ---------------------------------------------------------------------------

def test_two_marks_are_both_extracted():
    m1 = encode_cim(VALID)
    m2 = encode_cim(VALID_2)
    text = f"A{m1}B{m2}C"
    all_marks = extract_all_cims(text, issuance_year=2026)
    assert len(all_marks) == 2
    assert all_marks[0].seal_id == VALID
    assert all_marks[1].seal_id == VALID_2
    # Indices should be monotonic
    assert all_marks[0].end_index <= all_marks[1].start_index


def test_extract_skips_garbage_between_marks():
    m1 = encode_cim(VALID)
    m2 = encode_cim(VALID_2)
    # Introduce a fake partial start that is NOT followed by valid data
    text = f"x{m1}garbage{CIM_START}junk{m2}end"
    results = extract_all_cims(text, issuance_year=2026)
    assert len(results) == 2
    assert results[0].seal_id == VALID
    assert results[1].seal_id == VALID_2


# ---------------------------------------------------------------------------
# embed_cim placement policy
# ---------------------------------------------------------------------------

def test_embed_appends_when_no_trailing_newline():
    text = "Hello"
    out = embed_cim(text, VALID)
    assert out.startswith("Hello")
    assert len(out) == len(text) + CIM_TOTAL_LEN


def test_embed_inserts_before_final_newline():
    text = "Para one.\n\nPara two.\n"
    out = embed_cim(text, VALID)
    # Last visible char remains the newline
    assert out.endswith("\n")
    # The mark is adjacent to the last newline
    result = extract_cim(out, issuance_year=2026)
    assert result is not None and result.seal_id == VALID


# ---------------------------------------------------------------------------
# strip_cim
# ---------------------------------------------------------------------------

def test_strip_removes_valid_mark_only():
    mark = encode_cim(VALID)
    body = "Hello.\nWorld."
    text = body + mark
    assert strip_cim(text) == body


def test_strip_is_noop_on_plain_text():
    assert strip_cim("nothing") == "nothing"


def test_contains_cim_marker_detects_start():
    assert contains_cim_marker(encode_cim(VALID) + "x") is True
    assert contains_cim_marker("hello world") is False


# ---------------------------------------------------------------------------
# Known-vector regression (prevents algorithmic drift vs TS)
# ---------------------------------------------------------------------------

def test_known_vector_stability():
    """If this test breaks, CIM has drifted. Fix, then regenerate TS fixtures."""
    # This is the exact mark produced for VALID by the frozen algorithm.
    mark = encode_cim(VALID)
    # The data bits encode "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    # First 5 data chars after CIM_START encode "A" -> 00000 -> all ZW_BIT_0
    payload_start = len(CIM_START)
    assert mark[payload_start:payload_start + 5] == "\u200B" * 5
    # Next 5 chars encode "B" -> 00001 -> 0,0,0,0,1
    assert mark[payload_start + 5:payload_start + 10] == "\u200B\u200B\u200B\u200B\u200C"
