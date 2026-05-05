"""
CSC-1 — Crovia Seal Canonicalization v1.

Produces a fully deterministic UTF-8 byte representation of a JSON value.
CSC-1 is a strict subset of RFC 8785 (JCS): it adopts JCS's ordering and
string-escape rules, and FORBIDS floating-point numbers in signed payloads.
This eliminates the dependency on ECMA-262 7.1.12.1 number serialization,
which is the main source of cross-language portability risk in JCS.

Forbidding floats is not a practical restriction: the Seal specification
requires that all parameter values carried inside the signed payload be
encoded as strings (see SPEC.md Section 4.6).

Any input that would yield a non-canonical form raises a subclass of
CanonicalizationError. There is no "best effort" mode: CSC-1 is fail-closed
by design.
"""
from __future__ import annotations

from typing import Any, List

from crovia_seal.constants import JS_SAFE_INT_MAX, JS_SAFE_INT_MIN
from crovia_seal.errors import (
    DuplicateKey,
    NonCanonicalNumber,
    NonStringKey,
    UnsupportedType,
)


# --- String serialization ---------------------------------------------------

# Table of mandatory escape sequences per RFC 8259. All other characters
# outside the U+0000..U+001F range are emitted literally.
_ESCAPE_MAP = {
    0x22: '\\"',   # "
    0x5C: "\\\\",  # \
    0x08: "\\b",
    0x0C: "\\f",
    0x0A: "\\n",
    0x0D: "\\r",
    0x09: "\\t",
}


def _serialize_string(s: str) -> str:
    """Serialize a Python str to a canonical JSON string literal.

    Follows RFC 8785 Section 3.2.2.2: the seven short escapes (",\,b,f,n,r,t)
    are used for the corresponding code points; any other control character
    in U+0000..U+001F uses the \\u00XX form; all code points >= U+0020 are
    emitted literally (including non-ASCII, which will be UTF-8-encoded by
    the caller). Surrogate pairs are preserved as-is.
    """
    out: List[str] = ['"']
    for ch in s:
        cp = ord(ch)
        if cp < 0x20:
            esc = _ESCAPE_MAP.get(cp)
            if esc is not None:
                out.append(esc)
            else:
                out.append(f"\\u{cp:04x}")
        elif cp == 0x22 or cp == 0x5C:
            # These two are escaped even though >= 0x20
            out.append(_ESCAPE_MAP[cp])
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


# --- Number serialization (CSC-1: integers only) ----------------------------

def _serialize_number(n: int) -> str:
    """Serialize a Python int to its shortest decimal form.

    CSC-1 forbids floats; callers MUST pass int. We also enforce the
    JavaScript-safe integer range for maximum cross-language portability,
    matching RFC 8785 practice for whole numbers.

    Python `bool` is a subclass of int; we reject it here to avoid
    `True` sneaking through as `1`. Booleans must take the true/false path.
    """
    if isinstance(n, bool):
        # bool MUST be handled by the dispatcher, not here. Raising here
        # guards against mis-routing.
        raise UnsupportedType("bool must be serialized as true/false, not as int")
    if not isinstance(n, int):
        raise NonCanonicalNumber(
            f"CSC-1 permits only int numbers; got {type(n).__name__}"
        )
    if n < JS_SAFE_INT_MIN or n > JS_SAFE_INT_MAX:
        raise NonCanonicalNumber(
            f"integer {n} is outside the JS-safe range "
            f"[{JS_SAFE_INT_MIN}, {JS_SAFE_INT_MAX}]; "
            "encode large integers as strings"
        )
    # Python's str(int) already produces the shortest form with no leading
    # zeros and an explicit leading minus sign for negatives. For 0 it
    # produces "0" (not "-0"), which matches CSC-1 requirements.
    return str(n)


# --- Array / object serialization -------------------------------------------

def _serialize_array(arr: list) -> str:
    parts = [_serialize(v) for v in arr]
    return "[" + ",".join(parts) + "]"


def _serialize_object(obj: dict) -> str:
    # Reject non-string keys. Python dicts allow e.g. int keys, which JSON
    # does not. Silently stringifying them would mask a bug.
    for k in obj.keys():
        if not isinstance(k, str):
            raise NonStringKey(
                f"object key must be str, got {type(k).__name__}: {k!r}"
            )

    # RFC 8785 Section 3.2.3: keys are sorted ascending by UTF-16 code unit.
    # Python strings are Unicode scalar values; `sorted(..., key=lambda k: k.encode('utf-16-be'))`
    # gives the exact UTF-16 code-unit order. For BMP-only keys (the common
    # case), this is equivalent to `sorted(keys)`, but we use the explicit
    # encoding to be correct on supplementary-plane code points.
    def _utf16_key(k: str) -> bytes:
        return k.encode("utf-16-be")

    # Detect duplicate keys as a defense against dict constructions that
    # could merge silently. (A Python dict literal with duplicate keys
    # keeps the last one; we want to flag this.)
    seen = set()
    ordered_keys = []
    for k in obj.keys():
        if k in seen:
            raise DuplicateKey(f"duplicate object key: {k!r}")
        seen.add(k)
        ordered_keys.append(k)

    ordered_keys.sort(key=_utf16_key)

    parts = []
    for k in ordered_keys:
        parts.append(_serialize_string(k) + ":" + _serialize(obj[k]))
    return "{" + ",".join(parts) + "}"


# --- Dispatcher -------------------------------------------------------------

def _serialize(value: Any) -> str:
    """Serialize a single JSON value per CSC-1 rules."""
    # Order matters: bool before int (bool is subclass of int in Python).
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        return _serialize_string(value)
    if isinstance(value, int):
        return _serialize_number(value)
    if isinstance(value, float):
        raise NonCanonicalNumber(
            "CSC-1 forbids float in signed payloads; "
            "encode numeric parameters as strings (e.g. temperature=\"0.7\")"
        )
    if isinstance(value, list) or isinstance(value, tuple):
        return _serialize_array(list(value))
    if isinstance(value, dict):
        return _serialize_object(value)
    raise UnsupportedType(
        f"CSC-1 cannot serialize value of type {type(value).__name__}"
    )


# --- Public API -------------------------------------------------------------

def canonicalize(value: Any) -> bytes:
    """Produce the CSC-1 UTF-8 byte sequence for the given JSON-like value.

    Accepts nested structures of: None, bool, int (within JS safe range),
    str, list/tuple, dict (with str keys only). Any other type — including
    float — raises CanonicalizationError.

    The output is deterministic: two Python objects that are logically equal
    as JSON will canonicalize to the same bytes. This is the property that
    makes signing meaningful.
    """
    text = _serialize(value)
    return text.encode("utf-8")
