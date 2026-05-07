"""
Canonicalization byte-identity vs the @crovia/seal JavaScript SDK.

These fixtures are the SAME ones used in JS at
`sdk/javascript/test/cross-language.test.ts`. If a fixture's expected
bytes change here, they MUST change there too.
"""
import pytest

from crovia_seal.canonical import CanonicalizationError, canonicalize


# (name, value, expected utf-8 bytes as decoded string)
FIXTURES = [
    ("null", None, "null"),
    ("true", True, "true"),
    ("false", False, "false"),
    ("zero", 0, "0"),
    ("positive int", 42, "42"),
    ("negative int", -1, "-1"),
    ("max safe int", 2**53 - 1, "9007199254740991"),
    ("empty string", "", '""'),
    ("ascii string", "hi", '"hi"'),
    ("newline escape", "a\nb", '"a\\nb"'),
    ("tab escape", "a\tb", '"a\\tb"'),
    ("quote escape", 'a"b', '"a\\"b"'),
    ("backslash escape", "a\\b", '"a\\\\b"'),
    ("control char", "\u0001", '"\\u0001"'),
    ("non-ASCII passes through", "café", '"café"'),
    ("Japanese", "日本", '"日本"'),
    ("empty array", [], "[]"),
    ("array preserves order", [3, 1, 2], "[3,1,2]"),
    ("empty object", {}, "{}"),
    ("object keys sorted", {"b": 1, "a": 2}, '{"a":2,"b":1}'),
    (
        "nested keys sorted recursively",
        {"z": {"y": 1, "x": 2}, "a": [{"d": 4, "c": 3}]},
        '{"a":[{"c":3,"d":4}],"z":{"x":2,"y":1}}',
    ),
    ("ASCII before non-ASCII", {"ä": 1, "a": 2}, '{"a":2,"ä":1}'),
    (
        "realistic AI output payload",
        {
            "model": "gpt-4o",
            "output": "Hello, world.",
            "params": {"temperature": "0.7", "top_p": "1.0"},
        },
        '{"model":"gpt-4o","output":"Hello, world.","params":{"temperature":"0.7","top_p":"1.0"}}',
    ),
]


@pytest.mark.parametrize("name,value,expected", FIXTURES)
def test_byte_identity(name, value, expected):
    actual = canonicalize(value).decode("utf-8")
    assert actual == expected, f"{name}: expected={expected!r} got={actual!r}"


def test_rejects_float():
    with pytest.raises(CanonicalizationError):
        canonicalize(1.5)


def test_rejects_out_of_range_int():
    with pytest.raises(CanonicalizationError):
        canonicalize(2**53)
    with pytest.raises(CanonicalizationError):
        canonicalize(-(2**53))


def test_rejects_non_string_key():
    with pytest.raises(CanonicalizationError):
        canonicalize({1: "a"})


def test_unsupported_type():
    with pytest.raises(CanonicalizationError):
        canonicalize(object())
