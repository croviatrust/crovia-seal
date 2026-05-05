# Conformance Test Vectors

Every conformant Crovia Seal implementation MUST pass the tests below. They
verify three properties:

1. **Canonicalization determinism.** Given the JSON values in
   `vectors/v1/canonicalization_inputs/*.json`, the implementation MUST
   produce exactly the bytes in `vectors/v1/canonicalization_outputs/*.txt`.
2. **Signature determinism.** Given a fixed Ed25519 seed and the Seals in
   `vectors/v1/seals/*.unsigned.json`, the implementation MUST produce the
   signatures in `vectors/v1/seals/*.signature.hex`. Ed25519 is deterministic
   per RFC 8032, so signatures are reproducible.
3. **Payload format.** Given a signed Seal, `compute_payload(seal)` MUST
   start with the exact 15 bytes `CROVIA-SEAL-v1\n` and its SHA-256 MUST
   equal the value in `vectors/v1/seals/*.payload_sha256.hex`.

## Running the conformance suite

```bash
cd reference/python
pip install -e .
pytest ../../conformance/runner -v
```

## Reference issuer

The conformance vectors use a fixed deterministic issuer:

    issuer_id  = urn:crovia:seal-issuer:conformance
    seed       = deadbeef...deadbeef (32 bytes, DEMO ONLY)
    public_hex = derived per Ed25519 (RFC 8032)

This key MUST NEVER be used in production; it is published for the sole
purpose of letting any implementation reproduce the test vectors.

## Adding new vectors

When the specification gains a new field, a new test vector must be added
that exercises it. Deletion of vectors is only permitted across major
spec versions (v2, v3, ...).
