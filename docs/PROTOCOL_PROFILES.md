# Crovia Seal protocol profiles

## Status

The current repository implementation is aligned with
`draft-crovia-seal-01`. This is an Internet-Draft revision, not an IETF
standard or an IETF endorsement. The revision must be named explicitly in
conformance reports and public claims.

## Profiles

| Profile | `seal_version` | Purpose | New issuance |
|---|---|---|---|
| Draft-01 | `crovia.seal.v1` | Current reference and conformance vectors | Allowed |
| Legacy v1 | `crovia-seal-v1` | Verification of historical production records | Forbidden |
| Unknown or mixed | any | Future, malformed, or ambiguous data | Reject |

The two identifiers are intentionally different. Implementations MUST NOT infer
a profile from a signature that happens to verify.

## Verification result vocabulary

Public and machine-readable verification results should use exactly one of:

- `VALID_DRAFT`: structurally conformant to draft-01 and cryptographically valid.
- `VALID_LEGACY`: recognized historical profile and cryptographically valid.
- `INVALID`: recognized profile whose structure or cryptography fails.
- `UNSUPPORTED_PROFILE`: no supported profile identifier.
- `AMBIGUOUS_FORMAT`: markers from multiple profiles or an identifier/shape mismatch.

All outcomes except the two `VALID_*` values are rejection outcomes. A caller
requiring draft conformance MUST accept only `VALID_DRAFT`.

## Historical records

Existing legacy seals are immutable evidence. Migration MUST NOT rewrite their
JSON bytes, identifiers, timestamps, signatures, or storage log entries.
Implementations may produce a separate migration attestation containing the
SHA-256 digest of the original legacy bytes and a new draft-01 signature. Such
an attestation links records; it does not retroactively make the legacy record
draft-conformant.

## Issuance transition

1. Preserve the legacy log as read-only input.
2. Deploy a dual verifier that classifies before cryptographic verification.
3. Run draft-01 issuance in a non-public canary and verify every emitted seal
   with the independent reference implementation.
4. Change the public emitter only after CI, canary, rollback, and key-handling
   checks pass.
5. Continue serving historical records with an explicit legacy label.

The production API must never emit a legacy profile after the transition.
