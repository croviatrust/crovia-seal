"""
Seal issuance and verification.

Two public entry points:

    emit_seal(...)  -> dict     # create and sign a new Seal
    verify_seal(seal, issuer_pubkey_hex=None) -> VerifyResult

All cryptographic bytes flow through `crovia_seal.canonical` and
`crovia_seal.keys`. This module is strictly about *composing* the Seal
object, applying the signing payload rule (domain separation), and
performing the exhaustive verification checks specified in SPEC.md.
"""
from __future__ import annotations

import base64
import hashlib
import os
import re
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from crovia_seal.canonical import canonicalize
from crovia_seal.constants import (
    ALLOWED_MODALITIES,
    CANON_ID,
    PAYLOAD_HASH_ALG,
    RANDOM_B32_CHARS,
    RANDOM_BYTES,
    SEAL_ID_REGEX,
    SEAL_VERSION,
    SIGNATURE_ALG,
    SIGNATURE_DOMAIN,
    SIGNATURE_DOMAIN_BYTES,
)
from crovia_seal.errors import (
    ChainError,
    SchemaError,
    VerificationError,
)
from crovia_seal.keys import IssuerKey, load_public_key


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
_HEX128_RE = re.compile(r"^[0-9a-f]{128}$")
_B32_RE = re.compile(r"^[A-Z2-7]{26}$")
_SEAL_ID_RE = re.compile(SEAL_ID_REGEX)
_SHA256_PREFIX = "sha256:"


def _sha256_hex(data: bytes) -> str:
    """Return the lowercase-hex SHA-256 digest of `data`."""
    return hashlib.sha256(data).hexdigest()


def _sha256_prefixed(data: bytes) -> str:
    """Return 'sha256:<hex>' used throughout the Seal schema."""
    return _SHA256_PREFIX + _sha256_hex(data)


def _random_b32(nbytes: int = RANDOM_BYTES) -> str:
    """Cryptographically-secure base32 identifier, no padding."""
    raw = secrets.token_bytes(nbytes)
    b32 = base64.b32encode(raw).decode("ascii").rstrip("=")
    # b32 is already uppercase A-Z/2-7 per RFC 4648.
    assert _B32_RE.match(b32), "b32 alphabet invariant violated"
    return b32


def _now_rfc3339_ms() -> str:
    """RFC 3339 UTC timestamp with millisecond precision, e.g.
    '2026-04-15T12:34:56.789Z'."""
    now = datetime.now(tz=timezone.utc)
    # Truncate microseconds to milliseconds without rounding.
    ms = now.microsecond // 1000
    return now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{ms:03d}Z"


def _new_seal_id() -> str:
    year = datetime.now(tz=timezone.utc).year
    return f"cs_{year}_{_random_b32()}"


# ---------------------------------------------------------------------------
# Payload (domain-separated signing input)
# ---------------------------------------------------------------------------

def compute_payload(seal: Dict[str, Any]) -> bytes:
    """Return the exact byte sequence that is signed.

    Payload = SIGNATURE_DOMAIN_BYTES ||  CSC1(seal \\ {signature, witnesses})

    Both `signature` and `witnesses` are stripped before canonicalization:
    signature is computed over the payload itself, and witnesses are
    independent co-signatures over the same payload.
    """
    if not isinstance(seal, dict):
        raise TypeError("seal must be a dict")
    stripped = {k: v for k, v in seal.items() if k not in ("signature", "witnesses")}
    return SIGNATURE_DOMAIN_BYTES + canonicalize(stripped)


def compute_seal_hash(seal: Dict[str, Any]) -> str:
    """Return 'sha256:<hex>' of the signing payload.

    Used as the value of `chain.prev_seal_hash` in the next Seal from
    the same issuer.
    """
    return _sha256_prefixed(compute_payload(seal))


# ---------------------------------------------------------------------------
# Schema validation
# ---------------------------------------------------------------------------

_REQUIRED_TOP = ("seal_version", "seal_id", "issuer", "subject",
                 "generator", "timestamp", "chain", "signature")
_OPTIONAL_TOP = ("checks", "anchor", "witnesses")
_ALLOWED_TOP = frozenset(_REQUIRED_TOP + _OPTIONAL_TOP)


def _require(cond: bool, msg: str) -> None:
    if not cond:
        raise SchemaError(msg)


# ---------------------------------------------------------------------------
# Anchor: polymorphic schema
# ---------------------------------------------------------------------------
# Three recognized kinds:
#
#   - "crovia-tlog-legacy" (absence of `kind`): original 5-key shape preserved
#     for backward compatibility with pre-beacon clients.
#   - "crovia-tlog": modern Crovia Transparency Log (RFC 6962) inclusion proof
#     with log_id, leaf_index, tree_size, audit_path, sth.
#   - "crovia-beacon": drand-style public randomness beacon anchor that proves
#     a lower bound on the seal's emission time.
#
# Unknown kinds are REJECTED (fail-closed) so future extensions cannot be
# smuggled in silently. Adding a new kind is a spec-level decision.

def _validate_anchor(an: Any) -> None:
    _require(isinstance(an, dict), "anchor must be object if present")
    if "kind" not in an:
        # Legacy shape: exactly the 5 transparency-log fields.
        _require(set(an.keys()) == {"log_url", "merkle_root", "merkle_proof",
                                    "log_index", "root_signed_at"},
                 "legacy anchor must have exactly the 5 specified keys")
        _require(isinstance(an["log_url"], str) and an["log_url"],
                 "anchor.log_url must be non-empty string")
        _require(isinstance(an["merkle_root"], str)
                 and an["merkle_root"].startswith(_SHA256_PREFIX)
                 and _HEX64_RE.match(an["merkle_root"][len(_SHA256_PREFIX):]),
                 "anchor.merkle_root must be 'sha256:<64 hex>'")
        _require(isinstance(an["merkle_proof"], list),
                 "anchor.merkle_proof must be array")
        for item in an["merkle_proof"]:
            _require(isinstance(item, str) and item.startswith(_SHA256_PREFIX)
                     and _HEX64_RE.match(item[len(_SHA256_PREFIX):]),
                     "each merkle_proof element must be 'sha256:<64 hex>'")
        _require(isinstance(an["log_index"], int) and not isinstance(an["log_index"], bool)
                 and an["log_index"] >= 0,
                 "anchor.log_index must be non-negative integer")
        _require(isinstance(an["root_signed_at"], str),
                 "anchor.root_signed_at must be string")
        return

    kind = an["kind"]
    _require(isinstance(kind, str), "anchor.kind must be string")
    if kind == "crovia-tlog":
        # Transparency log inclusion proof.
        _require({"kind", "log_id", "leaf_index", "tree_size", "audit_path", "sth"}
                 .issubset(an.keys()),
                 "crovia-tlog anchor missing required fields")
        _require(isinstance(an["log_id"], str) and an["log_id"], "anchor.log_id required")
        _require(isinstance(an["leaf_index"], int) and an["leaf_index"] >= 0,
                 "anchor.leaf_index must be non-negative int")
        _require(isinstance(an["tree_size"], int) and an["tree_size"] > an["leaf_index"],
                 "anchor.tree_size must be int > leaf_index")
        _require(isinstance(an["audit_path"], list), "anchor.audit_path must be list")
        for h in an["audit_path"]:
            _require(isinstance(h, str) and len(h) == 64 and all(c in "0123456789abcdef" for c in h),
                     "audit_path entries must be 64-char lowercase hex")
        _require(isinstance(an["sth"], dict), "anchor.sth must be object")
    elif kind == "crovia-beacon":
        _require("beacon" in an and isinstance(an["beacon"], dict), "beacon anchor requires 'beacon' object")
        b = an["beacon"]
        for k in ("chain_hash", "round", "randomness", "signature"):
            _require(k in b, f"beacon.{k} is required")
        _require(isinstance(b["round"], int) and b["round"] >= 1,
                 "beacon.round must be positive int")
        _require(isinstance(b["chain_hash"], str) and b["chain_hash"],
                 "beacon.chain_hash must be non-empty string")
        _require(isinstance(b["randomness"], str) and b["randomness"],
                 "beacon.randomness must be non-empty string")
        _require(isinstance(b["signature"], str) and b["signature"],
                 "beacon.signature must be non-empty string")
        if "chain" in an:
            _require(isinstance(an["chain"], dict), "anchor.chain must be object")
        if "not_emitted_before" in an:
            _require(isinstance(an["not_emitted_before"], str),
                     "anchor.not_emitted_before must be string")
    else:
        raise SchemaError(f"unknown anchor.kind: {kind!r}")


def _validate_structure(seal: Dict[str, Any]) -> None:
    """Raise SchemaError if the Seal violates SPEC Section 4."""
    _require(isinstance(seal, dict), "seal must be a JSON object")

    # Unknown top-level fields MUST fail (SPEC 4.1, fail-closed).
    extra = set(seal.keys()) - _ALLOWED_TOP
    _require(not extra, f"unknown top-level fields: {sorted(extra)}")
    missing = [k for k in _REQUIRED_TOP if k not in seal]
    _require(not missing, f"missing required top-level fields: {missing}")

    # seal_version
    _require(seal["seal_version"] == SEAL_VERSION,
             f"seal_version must be {SEAL_VERSION!r}")

    # seal_id
    _require(isinstance(seal["seal_id"], str) and _SEAL_ID_RE.match(seal["seal_id"]),
             "seal_id must match cs_YYYY_<26 base32 chars>")

    # issuer
    iss = seal["issuer"]
    _require(isinstance(iss, dict), "issuer must be object")
    _require(set(iss.keys()) == {"id", "pubkey"}, "issuer must have exactly {id, pubkey}")
    _require(isinstance(iss["id"], str) and iss["id"], "issuer.id must be non-empty string")
    pk = iss["pubkey"]
    _require(isinstance(pk, dict) and set(pk.keys()) == {"alg", "key_hex"},
             "issuer.pubkey must have exactly {alg, key_hex}")
    _require(pk["alg"] == SIGNATURE_ALG, f"issuer.pubkey.alg must be {SIGNATURE_ALG!r}")
    _require(isinstance(pk["key_hex"], str) and _HEX64_RE.match(pk["key_hex"]),
             "issuer.pubkey.key_hex must be 64 lowercase hex chars")

    # subject
    sub = seal["subject"]
    _require(isinstance(sub, dict), "subject must be object")
    _require(set(sub.keys()) == {"input_hash", "output_hash", "input_len", "output_len", "modality"},
             "subject must have exactly {input_hash, output_hash, input_len, output_len, modality}")
    for fh in ("input_hash", "output_hash"):
        v = sub[fh]
        _require(isinstance(v, str) and v.startswith(_SHA256_PREFIX)
                 and _HEX64_RE.match(v[len(_SHA256_PREFIX):]),
                 f"subject.{fh} must be 'sha256:<64 hex>'")
    for fl in ("input_len", "output_len"):
        _require(isinstance(sub[fl], int) and not isinstance(sub[fl], bool) and sub[fl] >= 0,
                 f"subject.{fl} must be non-negative integer")
    _require(sub["modality"] in ALLOWED_MODALITIES,
             f"subject.modality must be one of {sorted(ALLOWED_MODALITIES)}")

    # generator
    gen = seal["generator"]
    _require(isinstance(gen, dict), "generator must be object")
    _require(set(gen.keys()) == {"id", "version", "weights_hash", "params"},
             "generator must have exactly {id, version, weights_hash, params}")
    _require(isinstance(gen["id"], str) and gen["id"], "generator.id must be non-empty string")
    _require(gen["version"] is None or isinstance(gen["version"], str),
             "generator.version must be string or null")
    _require(gen["weights_hash"] is None or (
        isinstance(gen["weights_hash"], str)
        and gen["weights_hash"].startswith(_SHA256_PREFIX)
        and _HEX64_RE.match(gen["weights_hash"][len(_SHA256_PREFIX):])
    ), "generator.weights_hash must be 'sha256:<64 hex>' or null")
    _require(isinstance(gen["params"], dict), "generator.params must be object")
    for k, v in gen["params"].items():
        _require(isinstance(k, str), "generator.params keys must be strings")
        _require(isinstance(v, str),
                 f"generator.params[{k!r}] must be string "
                 "(encode numeric params as strings per SPEC 4.6)")

    # timestamp
    ts = seal["timestamp"]
    _require(isinstance(ts, dict), "timestamp must be object")
    _require(set(ts.keys()) == {"emitted_at", "nonce"},
             "timestamp must have exactly {emitted_at, nonce}")
    _require(isinstance(ts["emitted_at"], str)
             and re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$", ts["emitted_at"]),
             "timestamp.emitted_at must be RFC 3339 UTC with ms precision")
    _require(isinstance(ts["nonce"], str) and _B32_RE.match(ts["nonce"]),
             "timestamp.nonce must be 26 RFC 4648 base32 chars")

    # chain
    ch = seal["chain"]
    _require(isinstance(ch, dict), "chain must be object")
    _require(set(ch.keys()) == {"prev_seal_hash", "sequence"},
             "chain must have exactly {prev_seal_hash, sequence}")
    _require(isinstance(ch["sequence"], int) and not isinstance(ch["sequence"], bool)
             and ch["sequence"] >= 0,
             "chain.sequence must be non-negative integer")
    if ch["sequence"] == 0:
        _require(ch["prev_seal_hash"] is None,
                 "chain.prev_seal_hash must be null for sequence==0 (genesis)")
    else:
        psh = ch["prev_seal_hash"]
        _require(isinstance(psh, str) and psh.startswith(_SHA256_PREFIX)
                 and _HEX64_RE.match(psh[len(_SHA256_PREFIX):]),
                 "chain.prev_seal_hash must be 'sha256:<64 hex>' for sequence>=1")

    # checks (optional, free-form object)
    if "checks" in seal:
        _require(isinstance(seal["checks"], dict), "checks must be object if present")

    # anchor (optional, polymorphic)
    if "anchor" in seal:
        _validate_anchor(seal["anchor"])

    # signature
    sig = seal["signature"]
    _require(isinstance(sig, dict), "signature must be object")
    _require(set(sig.keys()) == {"alg", "canon", "domain", "payload_hash_alg", "sig_hex"},
             "signature must have exactly the 5 specified keys")
    _require(sig["alg"] == SIGNATURE_ALG, f"signature.alg must be {SIGNATURE_ALG!r}")
    _require(sig["canon"] == CANON_ID, f"signature.canon must be {CANON_ID!r}")
    _require(sig["domain"] == SIGNATURE_DOMAIN,
             f"signature.domain must be {SIGNATURE_DOMAIN!r}")
    _require(sig["payload_hash_alg"] == PAYLOAD_HASH_ALG,
             f"signature.payload_hash_alg must be {PAYLOAD_HASH_ALG!r}")
    _require(isinstance(sig["sig_hex"], str) and _HEX128_RE.match(sig["sig_hex"]),
             "signature.sig_hex must be 128 lowercase hex chars")

    # witnesses (optional)
    if "witnesses" in seal:
        wl = seal["witnesses"]
        _require(isinstance(wl, list), "witnesses must be array if present")
        for i, w in enumerate(wl):
            _require(isinstance(w, dict), f"witnesses[{i}] must be object")
            _require(set(w.keys()) == {"id", "pubkey", "sig_hex"},
                     f"witnesses[{i}] must have exactly {{id, pubkey, sig_hex}}")
            _require(isinstance(w["id"], str) and w["id"],
                     f"witnesses[{i}].id must be non-empty string")
            wpk = w["pubkey"]
            _require(isinstance(wpk, dict) and set(wpk.keys()) == {"alg", "key_hex"},
                     f"witnesses[{i}].pubkey must have exactly {{alg, key_hex}}")
            _require(wpk["alg"] == SIGNATURE_ALG,
                     f"witnesses[{i}].pubkey.alg must be {SIGNATURE_ALG!r}")
            _require(isinstance(wpk["key_hex"], str) and _HEX64_RE.match(wpk["key_hex"]),
                     f"witnesses[{i}].pubkey.key_hex must be 64 hex chars")
            _require(isinstance(w["sig_hex"], str) and _HEX128_RE.match(w["sig_hex"]),
                     f"witnesses[{i}].sig_hex must be 128 hex chars")


# ---------------------------------------------------------------------------
# Issuance
# ---------------------------------------------------------------------------

def emit_seal(
    *,
    issuer_key: IssuerKey,
    input_bytes: bytes,
    output_bytes: bytes,
    modality: str,
    generator_id: str,
    generator_version: Optional[str] = None,
    generator_weights_hash: Optional[str] = None,
    generator_params: Optional[Dict[str, str]] = None,
    sequence: int = 0,
    prev_seal_hash: Optional[str] = None,
    checks: Optional[Dict[str, Any]] = None,
    anchor: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Compose and sign a new Seal.

    All required fields are inputs; the function computes hashes,
    timestamps, and the signature. The resulting dict is a fully
    specification-conformant Seal (validates via `_validate_structure`
    before return).

    Args:
        issuer_key: The IssuerKey that will sign the Seal.
        input_bytes: Raw bytes of the AI model's input (prompt, image, etc.).
        output_bytes: Raw bytes of the AI model's output.
        modality: One of ALLOWED_MODALITIES.
        generator_id: Identifier of the model (e.g., "openai/gpt-4o").
        generator_version: Optional version string (e.g., "2024-08-06").
        generator_weights_hash: Optional 'sha256:<hex>' of model weights.
        generator_params: Optional dict of string-valued parameters.
        sequence: Chain sequence number. 0 for genesis.
        prev_seal_hash: 'sha256:<hex>' of the previous Seal's payload,
            or None for genesis.
        checks: Optional analytical claims (memorization, safety, ...).
        anchor: Optional transparency-log inclusion proof.

    Returns:
        A conformant Seal dictionary ready for serialization.
    """
    if not isinstance(input_bytes, (bytes, bytearray)):
        raise TypeError("input_bytes must be bytes")
    if not isinstance(output_bytes, (bytes, bytearray)):
        raise TypeError("output_bytes must be bytes")
    if modality not in ALLOWED_MODALITIES:
        raise ValueError(f"modality must be one of {sorted(ALLOWED_MODALITIES)}")
    if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 0:
        raise ValueError("sequence must be non-negative integer")

    if sequence == 0 and prev_seal_hash is not None:
        raise ValueError("genesis Seal (sequence==0) must have prev_seal_hash=None")
    if sequence > 0 and prev_seal_hash is None:
        raise ValueError("non-genesis Seal (sequence>=1) requires prev_seal_hash")

    params = dict(generator_params or {})
    for k, v in params.items():
        if not isinstance(k, str) or not isinstance(v, str):
            raise TypeError("generator_params must be Dict[str, str]")

    unsigned: Dict[str, Any] = {
        "seal_version": SEAL_VERSION,
        "seal_id": _new_seal_id(),
        "issuer": {
            "id": issuer_key.issuer_id,
            "pubkey": {"alg": SIGNATURE_ALG, "key_hex": issuer_key.public_hex},
        },
        "subject": {
            "input_hash": _sha256_prefixed(bytes(input_bytes)),
            "output_hash": _sha256_prefixed(bytes(output_bytes)),
            "input_len": len(input_bytes),
            "output_len": len(output_bytes),
            "modality": modality,
        },
        "generator": {
            "id": generator_id,
            "version": generator_version,
            "weights_hash": generator_weights_hash,
            "params": params,
        },
        "timestamp": {
            "emitted_at": _now_rfc3339_ms(),
            "nonce": _random_b32(),
        },
        "chain": {
            "prev_seal_hash": prev_seal_hash,
            "sequence": sequence,
        },
    }
    if checks is not None:
        unsigned["checks"] = checks
    if anchor is not None:
        unsigned["anchor"] = anchor

    payload = compute_payload(unsigned)  # domain-separated
    sig = issuer_key.sign(payload)
    unsigned["signature"] = {
        "alg": SIGNATURE_ALG,
        "canon": CANON_ID,
        "domain": SIGNATURE_DOMAIN,
        "payload_hash_alg": PAYLOAD_HASH_ALG,
        "sig_hex": sig.hex(),
    }

    # Defense in depth: run the full validator on the Seal we are about to
    # return. If this fails, something in our own composition is wrong.
    _validate_structure(unsigned)
    return unsigned


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------

@dataclass
class VerifyResult:
    """Outcome of verify_seal().

    `ok` is the only field that matters for accept/reject decisions.
    The other fields aid debugging and logging.
    """
    ok: bool
    seal_id: Optional[str] = None
    issuer_id: Optional[str] = None
    issuer_pubkey_hex: Optional[str] = None
    witness_count: int = 0
    errors: List[str] = field(default_factory=list)

    def raise_if_failed(self) -> None:
        if not self.ok:
            raise VerificationError("; ".join(self.errors) or "verification failed")


def verify_seal(
    seal: Dict[str, Any],
    *,
    issuer_pubkey_hex: Optional[str] = None,
    require_witnesses: int = 0,
) -> VerifyResult:
    """Verify a Seal against the specification.

    Checks performed:
      1. Structural conformance (Section 4 of SPEC).
      2. Signature over the exact canonical payload.
      3. issuer.pubkey.key_hex matches the caller-provided issuer_pubkey_hex,
         if given. This prevents a rogue issuer from presenting a validly
         self-signed Seal that points at an attacker-controlled key.
      4. All witness signatures, if any, validate against the same payload.
      5. At least `require_witnesses` witness signatures validate.

    Chain integrity (prev_seal_hash consistency across a sequence of Seals)
    is NOT checked here. Use `verify_chain(...)` for that (to be added).

    Returns a VerifyResult. Call .raise_if_failed() to convert to exception.
    """
    result = VerifyResult(ok=False)

    # Step 1: structure
    try:
        _validate_structure(seal)
    except SchemaError as e:
        result.errors.append(f"schema: {e}")
        return result

    result.seal_id = seal["seal_id"]
    result.issuer_id = seal["issuer"]["id"]
    result.issuer_pubkey_hex = seal["issuer"]["pubkey"]["key_hex"]

    # Step 3: pinned issuer public key
    if issuer_pubkey_hex is not None:
        if issuer_pubkey_hex.lower() != result.issuer_pubkey_hex:
            result.errors.append(
                f"issuer public key mismatch: "
                f"seal claims {result.issuer_pubkey_hex}, "
                f"caller pinned {issuer_pubkey_hex.lower()}"
            )
            return result

    # Step 2: signature
    try:
        payload = compute_payload(seal)
    except Exception as e:
        result.errors.append(f"payload-construction: {e}")
        return result

    try:
        pub = load_public_key(result.issuer_pubkey_hex)
        sig_bytes = bytes.fromhex(seal["signature"]["sig_hex"])
        from cryptography.exceptions import InvalidSignature
        try:
            pub.verify(sig_bytes, payload)
        except InvalidSignature:
            result.errors.append("signature: invalid")
            return result
    except Exception as e:
        result.errors.append(f"signature-verification: {e}")
        return result

    # Step 4 & 5: witnesses
    witnesses = seal.get("witnesses", []) or []
    valid_witnesses = 0
    for i, w in enumerate(witnesses):
        try:
            wpub = load_public_key(w["pubkey"]["key_hex"])
            wsig = bytes.fromhex(w["sig_hex"])
            from cryptography.exceptions import InvalidSignature
            try:
                wpub.verify(wsig, payload)
                valid_witnesses += 1
            except InvalidSignature:
                result.errors.append(f"witness[{i}] signature: invalid")
                return result
        except Exception as e:
            result.errors.append(f"witness[{i}] verification: {e}")
            return result
    result.witness_count = valid_witnesses

    if valid_witnesses < require_witnesses:
        result.errors.append(
            f"require_witnesses={require_witnesses} but only "
            f"{valid_witnesses} valid witness signatures present"
        )
        return result

    result.ok = True
    return result
