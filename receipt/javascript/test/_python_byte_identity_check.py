"""
Verify that Python's CSC-1 reference produces the same bytes as the
JS implementation for the test fixtures used in cross-language.test.ts.

Run from repo root:
    python _ops/crovia-seal-js/test/_python_byte_identity_check.py

This file is for offline verification only; it doesn't run in CI.
"""
import os
import sys

# Locate reference impl regardless of cwd.
HERE = os.path.dirname(os.path.abspath(__file__))
REF = os.path.normpath(os.path.join(HERE, "..", "..", "..", "crovia-seal", "reference", "python"))
sys.path.insert(0, REF)

from crovia_seal.canonical import canonicalize  # type: ignore

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
    ("nested", {"z": {"y": 1, "x": 2}, "a": [{"d": 4, "c": 3}]},
     '{"a":[{"c":3,"d":4}],"z":{"x":2,"y":1}}'),
    ("ASCII vs non-ASCII keys", {"ä": 1, "a": 2}, '{"a":2,"ä":1}'),
    ("realistic AI output payload",
     {"model": "gpt-4o", "output": "Hello, world.",
      "params": {"temperature": "0.7", "top_p": "1.0"}},
     '{"model":"gpt-4o","output":"Hello, world.","params":{"temperature":"0.7","top_p":"1.0"}}'),
]

ok = True
for name, val, expected in FIXTURES:
    actual = canonicalize(val).decode("utf-8")
    if actual == expected:
        print(f"  ok    {name}")
    else:
        ok = False
        print(f"  FAIL  {name}")
        print(f"    expected: {expected!r}")
        print(f"    actual:   {actual!r}")

print()
print("ALL OK" if ok else "SOME FAILED")
sys.exit(0 if ok else 1)
