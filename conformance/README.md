# Conformance Test Vectors

Every conformant Crovia Seal implementation MUST pass the suite below. The
vectors live in `vectors/v1/` and are the normative companion of
[`SPEC.md`](../SPEC.md) and of `draft-crovia-seal`. They are also published,
byte-identical, at <https://croviatrust.com/registry/seal/spec/> (the page the
Internet-Draft points to), with a
[`manifest.json`](https://croviatrust.com/registry/seal/spec/vectors/v1/manifest.json)
listing the SHA-256 of every file. Each vector there can be opened directly in
the browser verifier.

The suite checks three properties:

1. **Canonicalization determinism.** For each case in
   `vectors/v1/canonical_cases.json` the implementation MUST produce exactly
   the stated CSC-1 bytes, or fail with the stated error (floats, duplicate
   keys, non-string keys). 26 cases.
2. **Signature determinism.** For each `vectors/v1/seal_NNN_*.json` the
   implementation MUST reproduce `seal_NNN_*.payload.hex` from the Seal and
   verify `seal_NNN_*.signature.hex` under the issuer key in
   `vectors/v1/issuer.public.hex`. Ed25519 is deterministic (RFC 8032), so a
   signer with the demo seed reproduces the signatures byte for byte. 10 seals.
3. **Fail closed.** Every file under `vectors/v1/invalid/` MUST be rejected
   with the error class named in `invalid/index.json`; the `.note.md` next to
   each file explains what was broken. 5 cases.

## Running the suite

```bash
pip install -e reference/python
python3 conformance/run_conformance.py
# ALL 41 TESTS PASSED
```

`run_conformance.py` is the oracle for other implementations: a non-Python
verifier MUST reproduce every byte in `vectors/v1/` and MUST reject every file
under `vectors/v1/invalid/`.

## Reference issuer

The vectors are signed by a fixed, published demo issuer:

    issuer_id  = urn:crovia:seal-issuer:conformance   (vectors/v1/issuer.id.txt)
    public_hex = vectors/v1/issuer.public.hex
    seed       = published in generate_vectors.py, DEMO ONLY

This key MUST NEVER sign anything else; it exists so that anyone can regenerate
the vectors. A public log that contains only this issuer contains no
production Seals.

## Adding new vectors

When the specification gains an additive field, add a vector that exercises it
(`generate_vectors.py`, `generate_vectors_extended.py`) and regenerate. Vectors
are never deleted within `crovia.seal.v1`; removal is only permitted across
major versions (`v2`, `v3`, ...). After regenerating, rebuild the public page
from the countersign repository so the site mirror and its manifest match:

```bash
python3 tools/build_seal_spec.py --seal-repo /path/to/crovia-seal
```
