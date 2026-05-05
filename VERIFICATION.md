# How to verify a Crovia Seal in three lines of Python

This page is the permanent, dependency-minimal guide for anyone — a
researcher, a journalist, a regulator, a court — who needs to verify a
Crovia Seal without trusting our infrastructure.

## What you need

- Python 3.9+
- The `cryptography` package (`pip install cryptography`)
- A Seal (a JSON object conforming to [SPEC.md](SPEC.md))
- The issuer's public key (published at a URL or obtained out of band)

No network access is required. No Crovia server is contacted.

## The three lines

```python
from crovia_seal import verify_seal
result = verify_seal(seal_dict, issuer_pubkey_hex=expected_pubkey_hex)
assert result.ok, result.errors
```

That is the entire check. The function returns a `VerifyResult` with
`ok=True` if and only if:

- The Seal conforms structurally to the v1 specification.
- The issuer's declared public key matches the one you pinned.
- The signature over the canonical payload validates under that public key.
- All optional witness signatures, if any, also validate.

## A fully standalone verifier (no Crovia package)

If you do not trust our reference package, the following ~60 lines of
Python replicate the essential logic. It uses only `hashlib`, `json`, and
the widely-audited `cryptography` library.

```python
import hashlib, json
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

DOMAIN = b"CROVIA-SEAL-v1\n"   # 15 bytes

def _canon(v):
    """Minimal CSC-1 canonicalizer. Rejects floats. Sorts object keys."""
    if v is None:  return b"null"
    if v is True:  return b"true"
    if v is False: return b"false"
    if isinstance(v, str):
        out = ['"']
        for ch in v:
            cp = ord(ch)
            if cp < 0x20:
                esc = {0x08:'\\b',0x0c:'\\f',0x0a:'\\n',0x0d:'\\r',0x09:'\\t'}.get(cp)
                out.append(esc if esc else f'\\u{cp:04x}')
            elif cp == 0x22: out.append('\\"')
            elif cp == 0x5c: out.append('\\\\')
            else: out.append(ch)
        out.append('"')
        return ''.join(out).encode('utf-8')
    if isinstance(v, bool): raise TypeError("bool handled above")
    if isinstance(v, int):
        if v < -(2**53)+1 or v > (2**53)-1:
            raise ValueError("int out of JS-safe range")
        return str(v).encode('utf-8')
    if isinstance(v, float):
        raise ValueError("float forbidden in CSC-1 payload")
    if isinstance(v, (list, tuple)):
        return b"[" + b",".join(_canon(x) for x in v) + b"]"
    if isinstance(v, dict):
        keys = sorted(v.keys(), key=lambda k: k.encode('utf-16-be'))
        return b"{" + b",".join(_canon(k) + b":" + _canon(v[k]) for k in keys) + b"}"
    raise TypeError(f"unsupported type: {type(v).__name__}")

def verify_seal_standalone(seal, pinned_pubkey_hex):
    if seal.get("issuer", {}).get("pubkey", {}).get("key_hex") != pinned_pubkey_hex.lower():
        return False, "issuer pubkey mismatch"
    stripped = {k: v for k, v in seal.items() if k not in ("signature", "witnesses")}
    payload = DOMAIN + _canon(stripped)
    try:
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pinned_pubkey_hex))
        sig = bytes.fromhex(seal["signature"]["sig_hex"])
        pub.verify(sig, payload)
        return True, None
    except InvalidSignature:
        return False, "invalid signature"
```

Save as `verify_seal_mini.py`, call with your Seal dict and pinned key.

## What this does *not* prove

A valid signature proves that the issuer claimed this input, output, and
metadata at the declared time. It does **not** prove:

- That the claim is true (the issuer could be lying about `generator.id`).
- That the output was actually produced by the claimed model (no oracle
  can prove this without cooperation from the model vendor).
- That the output is lawful, safe, or accurate.

A Seal is **evidence**, not **truth**. Its value lies in being
tamper-evident, time-anchored, and independently verifiable.

## What to do if verification fails

Inspect `result.errors`. Common failure modes:

| Error pattern                                | Meaning                                          |
| -------------------------------------------- | ------------------------------------------------ |
| `signature: invalid`                         | Seal bytes tampered after signing, OR wrong key. |
| `issuer public key mismatch`                 | Pinned key differs from Seal's declared key.     |
| `schema: seal_version must be ...`           | Not a v1 Seal, or field tampered.                |
| `schema: unknown top-level fields: [...]`    | Extra fields added after signing.                |
| `schema: missing required top-level fields`  | Stripped Seal, not verifiable.                   |
| `schema: chain.prev_seal_hash must be ...`   | Chain link malformed.                            |

A failure is binary: either the Seal is cryptographically valid or it is
not. There is no "partial trust".

## Reporting suspected misbehavior

If you verify a Seal whose issuer you believe has behaved maliciously
(e.g., issued two Seals with the same `chain.sequence` and different
`prev_seal_hash`), preserve both Seals and their raw JSON. Contact:

- The issuer's published disclosure channel.
- Any transparency-log operators that anchor the issuer's Seals.
- (Optionally) the CROVIA Research team at info@croviatrust.com.

The append-only chain means such evidence is non-repudiable: the issuer
cannot deny having produced both Seals under their key.
