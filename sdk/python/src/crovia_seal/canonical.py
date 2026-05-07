"""
CSC-1 — Crovia Seal Canonicalization v1.

Strict subset of RFC 8785 (JCS):
  - Object keys sorted by UTF-16 code-unit order
  - String escapes per RFC 8259 (mandatory short escapes only)
  - Integers only (floats forbidden in signed payloads)
  - No insignificant whitespace

Output is byte-identical to the JavaScript SDK (@crovia/seal). Any
divergence between the two implementations is a bug.
"""
from __future__ import annotations

from typing import Any, List

# JS-safe integer range: [-(2^53 - 1), 2^53 - 1].
JS_SAFE_INT_MAX = (1 << 53) - 1
JS_SAFE_INT_MIN = -((1 << 53) - 1)


class CanonicalizationError(ValueError):
    """Raised for any input CSC-1 refuses to serialize."""


_ESCAPE_MAP = {
    0x22: '\\"',
    0x5C: "\\\\",
    0x08: "\\b",
    0x0C: "\\f",
    0x0A: "\\n",
    0x0D: "\\r",
    0x09: "\\t",
}


def _serialize_string(s: str) -> str:
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
            out.append(_ESCAPE_MAP[cp])
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _serialize_number(n: int) -> str:
    if isinstance(n, bool):
        # bool is a subclass of int in Python — must be routed to true/false.
        raise CanonicalizationError("bool must be serialized as true/false")
    if not isinstance(n, int):
        raise CanonicalizationError(
            f"CSC-1 permits only int numbers; got {type(n).__name__}"
        )
    if n < JS_SAFE_INT_MIN or n > JS_SAFE_INT_MAX:
        raise CanonicalizationError(
            f"integer {n} outside JS-safe range [{JS_SAFE_INT_MIN}, {JS_SAFE_INT_MAX}]; "
            "encode large integers as strings"
        )
    return str(n)


def _serialize_array(arr: list) -> str:
    return "[" + ",".join(_serialize(v) for v in arr) + "]"


def _serialize_object(obj: dict) -> str:
    for k in obj.keys():
        if not isinstance(k, str):
            raise CanonicalizationError(
                f"object key must be str, got {type(k).__name__}"
            )
    seen = set()
    keys = []
    for k in obj.keys():
        if k in seen:
            raise CanonicalizationError(f"duplicate object key: {k!r}")
        seen.add(k)
        keys.append(k)
    # RFC 8785 §3.2.3: keys sorted by UTF-16 code-unit value.
    keys.sort(key=lambda k: k.encode("utf-16-be"))
    parts = [_serialize_string(k) + ":" + _serialize(obj[k]) for k in keys]
    return "{" + ",".join(parts) + "}"


def _serialize(value: Any) -> str:
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
        raise CanonicalizationError(
            "CSC-1 forbids float in signed payloads; "
            'encode numeric parameters as strings (e.g. temperature="0.7")'
        )
    if isinstance(value, (list, tuple)):
        return _serialize_array(list(value))
    if isinstance(value, dict):
        return _serialize_object(value)
    raise CanonicalizationError(
        f"CSC-1 cannot serialize value of type {type(value).__name__}"
    )


def canonicalize(value: Any) -> bytes:
    """Canonicalize a JSON-compatible Python value to UTF-8 bytes.

    Output is deterministic and byte-identical to the @crovia/seal
    JavaScript SDK for every shared input.
    """
    return _serialize(value).encode("utf-8")
