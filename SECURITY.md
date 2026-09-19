# Security Policy

The Crovia Seal makes one claim: a `crovia.seal.v1` object verifies if and only if
its CSC-1 canonical payload was signed, under the domain separator `CROVIA-SEAL-v1`,
by the Ed25519 key of the issuer it names. `docs/` holds the threat model.

## Reporting

Please report signature, canonicalization, key-handling or verifier-bypass issues
privately to **trust@croviatrust.com** (general contact: info@croviatrust.com).
Do not open public issues for these. We acknowledge within 72 hours and publish a
fix and a conformance vector that reproduces the issue.

## Scope

- `reference/python`, `reference/typescript` (verifiers and emitters)
- `conformance/` vectors — a missing negative vector is a security issue
- `integrations/seal-svc` (the public issuer at seal.croviatrust.com)

Out of scope: the `receipt/` packages (`crovia.receipt.v1`), which are not Seals.
