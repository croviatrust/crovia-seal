"""
Tests for CSC-1 canonicalization.

These tests pin the exact byte output for every nontrivial case. Any change
to canonical.py that alters the bytes for a case covered here will trip a
test — which is precisely the guarantee we need, because "the bytes that
are signed" MUST remain stable across releases to preserve signature
compatibility.
"""
from __future__ import annotations

import pytest

from crovia_seal.canonical import canonicalize
from crovia_seal.errors import (
    CanonicalizationError,
    DuplicateKey,
    NonCanonicalNumber,
    NonStringKey,
    UnsupportedType,
)


# --- Primitives -------------------------------------------------------------

def test_null():
    assert canonicalize(None) == b"null"


def test_true_false():
    assert canonicalize(True) == b"true"
    assert canonicalize(False) == b"false"


def test_empty_string():
    assert canonicalize("") == b'""'


def test_ascii_string():
    assert canonicalize("hello") == b'"hello"'


def test_string_with_required_escapes():
    # \" \\ \b \f \n \r \t are mandatory short escapes.
    # We also verify other controls use \u00XX.
    assert canonicalize('"') == b'"\\""'
    assert canonicalize("\\") == b'"\\\\"'
    assert canonicalize("\b") == b'"\\b"'
    assert canonicalize("\f") == b'"\\f"'
    assert canonicalize("\n") == b'"\\n"'
    assert canonicalize("\r") == b'"\\r"'
    assert canonicalize("\t") == b'"\\t"'


def test_string_control_u00xx():
    # Controls other than the seven short ones use \u00XX (lowercase per our impl).
    assert canonicalize("\x00") == b'"\\u0000"'
    assert canonicalize("\x1f") == b'"\\u001f"'
    assert canonicalize("\x01\x02") == b'"\\u0001\\u0002"'


def test_string_non_ascii_literal():
    # Non-ASCII at or above 0x20 is emitted literally (UTF-8 encoded).
    # This differs from ensure_ascii=True in Python's json module.
    out = canonicalize("café")
    assert out == "café".encode("utf-8").replace(
        b"caf\xc3\xa9", b'"caf\xc3\xa9"'
    )
    # Equivalent direct check:
    assert out == b'"caf\xc3\xa9"'


def test_string_emoji():
    # Emoji is a supplementary-plane code point; must be emitted as literal UTF-8,
    # not \uD83D\uDE00.
    assert canonicalize("\U0001F600") == '"\U0001F600"'.encode("utf-8")


# --- Integers ---------------------------------------------------------------

def test_integer_basic():
    assert canonicalize(0) == b"0"
    assert canonicalize(1) == b"1"
    assert canonicalize(-1) == b"-1"
    assert canonicalize(1234567890) == b"1234567890"
    assert canonicalize(-999) == b"-999"


def test_integer_js_safe_bounds():
    assert canonicalize(2 ** 53 - 1) == str(2 ** 53 - 1).encode()
    assert canonicalize(-(2 ** 53) + 1) == str(-(2 ** 53) + 1).encode()


def test_integer_out_of_range():
    with pytest.raises(NonCanonicalNumber):
        canonicalize(2 ** 53)
    with pytest.raises(NonCanonicalNumber):
        canonicalize(-(2 ** 53))


def test_float_forbidden():
    with pytest.raises(NonCanonicalNumber):
        canonicalize(0.1)
    with pytest.raises(NonCanonicalNumber):
        canonicalize(1.0)
    with pytest.raises(NonCanonicalNumber):
        canonicalize(-0.0)


def test_nan_and_inf_forbidden():
    with pytest.raises(NonCanonicalNumber):
        canonicalize(float("nan"))
    with pytest.raises(NonCanonicalNumber):
        canonicalize(float("inf"))
    with pytest.raises(NonCanonicalNumber):
        canonicalize(float("-inf"))


# --- Arrays -----------------------------------------------------------------

def test_empty_array():
    assert canonicalize([]) == b"[]"


def test_array_of_primitives():
    assert canonicalize([1, "a", None, True, False]) == b'[1,"a",null,true,false]'


def test_array_order_preserved():
    # Unlike objects, array order is semantic and MUST NOT be sorted.
    assert canonicalize([3, 1, 2]) == b"[3,1,2]"


def test_nested_arrays():
    assert canonicalize([[1, 2], [3, 4]]) == b"[[1,2],[3,4]]"


def test_tuple_treated_as_array():
    # Python tuples are accepted as arrays.
    assert canonicalize((1, 2, 3)) == b"[1,2,3]"


# --- Objects ----------------------------------------------------------------

def test_empty_object():
    assert canonicalize({}) == b"{}"


def test_object_key_sorting():
    # Keys MUST be sorted ascending by UTF-16 code unit order.
    assert canonicalize({"b": 2, "a": 1}) == b'{"a":1,"b":2}'
    assert canonicalize({"z": 1, "a": 2, "m": 3}) == b'{"a":2,"m":3,"z":1}'


def test_object_no_whitespace():
    # No spaces around ':' or ','.
    out = canonicalize({"a": 1, "b": "two"})
    assert b" " not in out
    assert out == b'{"a":1,"b":"two"}'


def test_object_utf16_sort_order():
    # UTF-16 code-unit sort: BMP code points sort by their scalar value,
    # which matches lexicographic str sort for BMP-only keys. We verify
    # supplementary-plane code points sort AFTER all BMP keys.
    bmp_key = "z"         # U+007A
    supp_key = "\U0001F600"  # U+1F600, encodes as surrogate pair D83D DE00
    # U+D83D > U+007A, so supplementary key sorts AFTER 'z' in UTF-16 order.
    out = canonicalize({supp_key: 1, bmp_key: 2})
    # Expected key order: "z", then "\U0001F600"
    expected = (
        b'{'
        + b'"z":2,'
        + '"\U0001F600":1'.encode("utf-8")
        + b'}'
    )
    assert out == expected


def test_nested_objects():
    out = canonicalize({"outer": {"b": 1, "a": 2}, "also": [1, {"y": 1, "x": 2}]})
    assert out == b'{"also":[1,{"x":2,"y":1}],"outer":{"a":2,"b":1}}'


def test_non_string_key_rejected():
    with pytest.raises(NonStringKey):
        canonicalize({1: "a"})
    with pytest.raises(NonStringKey):
        canonicalize({None: "a"})


# --- Determinism property ---------------------------------------------------

def test_deterministic_object_any_insertion_order():
    # Same dict content with different insertion orders MUST canonicalize
    # to identical bytes. This is the property that makes signing meaningful.
    d1 = {"a": 1, "b": 2, "c": 3}
    d2 = {"c": 3, "a": 1, "b": 2}
    d3 = {}
    d3["b"] = 2
    d3["a"] = 1
    d3["c"] = 3
    assert canonicalize(d1) == canonicalize(d2) == canonicalize(d3)


# --- Unsupported types ------------------------------------------------------

def test_bytes_rejected():
    with pytest.raises(CanonicalizationError):
        canonicalize(b"raw bytes")


def test_set_rejected():
    with pytest.raises(CanonicalizationError):
        canonicalize({1, 2, 3})


def test_custom_class_rejected():
    class Foo:
        pass
    with pytest.raises(UnsupportedType):
        canonicalize(Foo())
