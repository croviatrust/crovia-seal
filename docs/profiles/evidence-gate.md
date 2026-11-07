# Crovia Evidence Gate v1

A recipient asks for evidence about one artifact before acting on it. Each
configured issuer attests to its own check. The recipient can then evaluate
the receipts offline and get a structured result with missing, failed and
invalid evidence separated.

## Python

```python
from crovia_seal import generate_issuer_key
from crovia_seal.evidence_gate import PROFILE, attest_check, create_challenge, evaluate

# In production the checker holds this key and the recipient pins its public key.
checker = generate_issuer_key("urn:crovia:seal-issuer:test-runner")
policy = {
    "profile": PROFILE,
    "audience": "release-service",
    "action": "promote",
    "required": {
        "unit-tests": {"issuer_id": checker.issuer_id, "public_key": checker.public_hex},
    },
}
artifact = b"immutable artifact bytes"
challenge = create_challenge(policy, artifact)

# The checker performs the configured test on the exact artifact before signing.
test_passed = artifact.startswith(b"immutable ")
receipt = attest_check(policy, challenge, artifact, "unit-tests", test_passed, checker)

# Use the policy and challenge retained by the recipient.
decision = evaluate(policy, challenge, artifact, [receipt])
assert decision["status"] == "ready"
```

The verifier accepts exactly one valid receipt for each configured check.
The issuer identity and Ed25519 public key come from the recipient's policy.
For key rotation, change the policy and create a fresh challenge. A received
policy or challenge may be relayed to a checker. The accepting runtime
takes its authoritative copy from its own configuration and request state.

## CLI

```sh
python -m crovia_seal.evidence_gate challenge \
  --policy policy.json --artifact candidate.bin > challenge.json
python -m crovia_seal.evidence_gate verify \
  --policy policy.json --artifact candidate.bin --challenge challenge.json unit-seal.json
```

Exit 0 means ready. Exit 1 means blocked by evidence. Exit 2 means an input or
challenge error. The command writes one JSON object. The caller should require
both a successful exit and the expected response before using the same bytes or
their immutable content address. CLI artifact files are read into memory.

## Profile wire format

`profile` is `crovia.evidence-gate.v1`. Policy fields are `profile`,
`audience`, `action` and `required`. The latter maps 1–32 check names to
objects with `issuer_id` and a lowercase 32-byte hex `public_key`. Audience,
action, check name and issuer ID use ASCII identifiers matching
`[A-Za-z0-9][A-Za-z0-9._:/@-]{0,127}`. The reference issuer helper creates
IDs in the `urn:crovia:seal-issuer:` namespace.

The challenge has exactly `profile`, `audience`, `action`, `policy_hash`,
`artifact_hash`, `nonce`, `issued_at` and `expires_at`. Hashes use lowercase
`sha256:<64 hex>`. The policy is hashed over CSC-1 canonical bytes. The
artifact is hashed over its raw bytes. The nonce is 32 random bytes encoded
in lowercase hex. Times are whole Unix seconds, valid from `issued_at`
inclusive to `expires_at` exclusive. Lifetime is 1–3600 seconds.

Each `crovia.seal.v1` receipt has `generator.id` equal to the profile,
uses `multimodal` for the opaque artifact, and carries
`checks["crovia.evidence-gate.v1"] = {"check": "<name>", "passed": true|false}`.
The Seal input is the CSC-1 canonical challenge. The Seal output is the exact
artifact. The verifier checks both subject hashes and lengths, the pinned
signature and issuer ID, and the claim. Policy downgrade, substitution and
cross-request replay fail because they change the authoritative challenge or
its binding. This profile changes no core Seal fields.

Readiness means the configured check issuers signed passing results for this
request. Correctness of the checks depends on the issuers and their
implementations. This verifier can run repeatedly. The acting system owns
authority, one-time consumption and any transaction that performs the effect.
