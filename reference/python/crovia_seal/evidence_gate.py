"""Verify independent Crovia Seal check results for a recipient-owned request."""

import hashlib
import re
import secrets
import time
from typing import Optional

from crovia_seal.canonical import canonicalize
from crovia_seal.constants import JS_SAFE_INT_MAX
from crovia_seal.keys import IssuerKey
from crovia_seal.seal import emit_seal, verify_seal

PROFILE = "crovia.evidence-gate.v1"
MAX_TTL = 3600
MAX_CHECKS = 32
IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/@-]{0,127}")
HEX_256 = re.compile(r"[0-9a-f]{64}")


def _matches(pattern, value):
    return isinstance(value, str) and pattern.fullmatch(value) is not None


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _fields(value, *fields):
    return isinstance(value, dict) and value.keys() == set(fields)


def _require(condition, message):
    if not condition:
        raise ValueError(message)


def _clock(now):
    if now is None:
        return int(time.time())
    _require(type(now) is int and now >= 0, "now must be a nonnegative integer")
    return now


def _validate_policy(policy):
    _require(_fields(policy, "profile", "audience", "action", "required"), "invalid policy fields")
    _require(policy["profile"] == PROFILE, "unsupported policy profile")
    for field in ("audience", "action"):
        _require(_matches(IDENTIFIER, policy[field]), f"invalid policy {field}")
    required = policy["required"]
    _require(isinstance(required, dict) and 1 <= len(required) <= MAX_CHECKS, "invalid required checks")
    for name, issuer in required.items():
        _require(_matches(IDENTIFIER, name), "invalid check name")
        _require(_fields(issuer, "issuer_id", "public_key"), "invalid issuer fields")
        _require(_matches(IDENTIFIER, issuer["issuer_id"]), "invalid issuer ID")
        _require(_matches(HEX_256, issuer["public_key"]), "invalid issuer key")


def create_challenge(policy: dict, artifact: bytes, *, ttl: int = 300, now: Optional[int] = None) -> dict:
    """Create a request for this artifact. The recipient retains the authoritative copy."""
    _validate_policy(policy)
    _require(type(ttl) is int and 1 <= ttl <= MAX_TTL, "ttl must be in 1..3600 seconds")
    issued_at = _clock(now)
    _require(issued_at <= JS_SAFE_INT_MAX - ttl, "challenge clock is out of range")
    return {
        "profile": PROFILE,
        "audience": policy["audience"],
        "action": policy["action"],
        "policy_hash": _digest(canonicalize(policy)),
        "artifact_hash": _digest(artifact),
        "nonce": secrets.token_hex(32),
        "issued_at": issued_at,
        "expires_at": issued_at + ttl,
    }


def _request_bytes(policy, challenge, artifact, now):
    _validate_policy(policy)
    _require(
        _fields(challenge, "profile", "audience", "action", "policy_hash", "artifact_hash",
                "nonce", "issued_at", "expires_at"),
        "invalid challenge fields",
    )
    _require(challenge["profile"] == PROFILE, "unsupported challenge profile")
    _require(challenge["audience"] == policy["audience"], "challenge audience mismatch")
    _require(challenge["action"] == policy["action"], "challenge action mismatch")
    _require(challenge["policy_hash"] == _digest(canonicalize(policy)), "challenge policy mismatch")
    _require(challenge["artifact_hash"] == _digest(artifact), "challenge artifact mismatch")
    _require(_matches(HEX_256, challenge["nonce"]), "invalid challenge nonce")
    issued, expires = challenge["issued_at"], challenge["expires_at"]
    _require(type(issued) is int and type(expires) is int and 1 <= expires - issued <= MAX_TTL,
             "invalid challenge lifetime")
    _require(expires <= JS_SAFE_INT_MAX, "challenge clock is out of range")
    _require(0 <= issued <= _clock(now) < expires, "challenge inactive or expired")
    return canonicalize(challenge)


def attest_check(policy: dict, challenge: dict, artifact: bytes, check: str,
                 passed: bool, issuer: IssuerKey, *, now: Optional[int] = None) -> dict:
    """Sign the result of a check already performed by this trusted issuer."""
    request = _request_bytes(policy, challenge, artifact, now)
    _require(type(passed) is bool, "passed must be a boolean")
    _require(check in policy["required"], "check is not in the policy")
    pin = policy["required"][check]
    _require(
        issuer.issuer_id == pin["issuer_id"] and issuer.public_hex == pin["public_key"],
        "issuer is not pinned for this check",
    )
    return emit_seal(
        issuer_key=issuer,
        input_bytes=request,
        output_bytes=artifact,
        modality="multimodal",
        generator_id=PROFILE,
        checks={PROFILE: {"check": check, "passed": passed}},
    )


def evaluate(policy: dict, challenge: dict, artifact: bytes, receipts: list,
             *, now: Optional[int] = None) -> dict:
    """Evaluate all required checks using only recipient-pinned issuers and request data."""
    request = _request_bytes(policy, challenge, artifact, now)
    _require(isinstance(receipts, list) and len(receipts) <= MAX_CHECKS, "invalid receipt list")
    pending = set(policy["required"])
    failed = set()
    invalid = []
    verified = {}
    request_hash = _digest(request)
    for index, seal in enumerate(receipts):
        claims = seal.get("checks") if isinstance(seal, dict) else None
        claim = claims.get(PROFILE) if isinstance(claims, dict) else None
        if not _fields(claim, "check", "passed") or type(claim["passed"]) is not bool:
            invalid.append({"index": index, "reason": "invalid claim"})
            continue
        check = claim["check"]
        if not isinstance(check, str) or check not in pending:
            invalid.append({"index": index, "reason": "unexpected or duplicate check"})
            continue
        pin = policy["required"][check]
        result = verify_seal(seal, issuer_pubkey_hex=pin["public_key"])
        if not result.ok or result.issuer_id != pin["issuer_id"]:
            invalid.append({"index": index, "reason": "invalid signature, seal or issuer"})
            continue
        subject = seal["subject"]
        if (
            seal["generator"]["id"] != PROFILE
            or subject["modality"] != "multimodal"
            or subject["input_hash"] != request_hash
            or subject["input_len"] != len(request)
            or subject["output_hash"] != challenge["artifact_hash"]
            or subject["output_len"] != len(artifact)
        ):
            invalid.append({"index": index, "reason": "request or artifact binding mismatch"})
            continue
        pending.remove(check)
        verified[check] = result.seal_id
        if not claim["passed"]:
            failed.add(check)

    return {
        "profile": PROFILE,
        "status": "ready" if not (pending or failed or invalid) else "blocked",
        "request_hash": request_hash,
        "missing": sorted(pending),
        "failed": sorted(failed),
        "invalid": invalid,
        "verified": verified,
    }


def _unique_object(pairs):
    obj = {}
    for key, value in pairs:
        _require(key not in obj, f"duplicate JSON key: {key}")
        obj[key] = value
    return obj


def _load_json(path):
    import json
    with open(path, "rb") as stream:
        limit = 2 * 1024 * 1024
        raw = stream.read(limit + 1)
    _require(len(raw) <= limit, "JSON file exceeds 2 MiB")
    return json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)


def main():
    import argparse
    import json
    from pathlib import Path

    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_subparsers(dest="command", required=True)
    challenge_parser = actions.add_parser("challenge", help="create a recipient-owned request")
    verify_parser = actions.add_parser("verify", help="check signed results against a retained request")
    for action in (challenge_parser, verify_parser):
        action.add_argument("--policy", required=True, type=Path)
        action.add_argument("--artifact", required=True, type=Path)
    challenge_parser.add_argument("--ttl", type=int, default=300)
    verify_parser.add_argument("--challenge", required=True, type=Path)
    verify_parser.add_argument("receipts", nargs="*", type=Path)

    args = parser.parse_args()
    try:
        policy = _load_json(args.policy)
        artifact = args.artifact.read_bytes()
        if args.command == "challenge":
            print(json.dumps(create_challenge(policy, artifact, ttl=args.ttl), sort_keys=True))
            return 0
        _require(len(args.receipts) <= MAX_CHECKS, "too many receipt files")
        result = evaluate(policy, _load_json(args.challenge), artifact,
                          [_load_json(path) for path in args.receipts])
    except (OSError, ValueError, RecursionError) as exc:
        print(json.dumps({"profile": PROFILE, "status": "error", "reason": str(exc)}, sort_keys=True))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0 if result["status"] == "ready" else 1


if __name__ == "__main__":
    raise SystemExit(main())
