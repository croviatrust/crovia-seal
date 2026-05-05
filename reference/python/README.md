# crovia-seal (Python reference)

Reference implementation of Crovia Seal v1.

## Install

```bash
pip install -e .
# for tests
pip install -e ".[test]"
```

## Smoke test (reproduces a signed Seal end-to-end)

```bash
python examples/demo_hp.py
```

## Test suite

```bash
pytest -v
```

Covers:

- **test_canonical.py** — CSC-1 canonicalization determinism, every edge
  case: controls, non-ASCII, supplementary-plane code points, JS-safe
  integer bounds, float rejection, duplicate-key detection, UTF-16 key
  sort order.
- **test_seal.py** — happy path: structural shape, round-trip verify,
  pinned vs unpinned verification, chain composition, optional fields
  (`checks`, `anchor`).
- **test_tamper.py** — adversarial vectors: every field tamper must be
  detected, downgrade attempts on version/algorithm/domain must be
  detected, cross-protocol signature replay must fail, key substitution
  with signature rewrite is detected only by pinned verification (as
  specified).

## Public API

```python
from crovia_seal import (
    generate_issuer_key, load_issuer_key, load_public_key,
    emit_seal, verify_seal,
    compute_payload, compute_seal_hash,
    canonicalize,
    VerifyResult,
    CroviaSealError, CanonicalizationError, SchemaError, VerificationError, ChainError,
)
```

## Dependencies

- `cryptography` — for Ed25519. Widely audited, maintained by PyCA.
- Python stdlib only otherwise (`hashlib`, `base64`, `secrets`, `re`, `dataclasses`).

No network, no file I/O, no randomness outside key and nonce generation.

## Threat model

See [../../SPEC.md §9](../../SPEC.md) for the full threat model. Summary:

- Signature replay across protocols: prevented by domain separation.
- JSON malleability: eliminated by CSC-1.
- Field tampering: all non-signature fields are covered by the signature.
- Version downgrade: `seal_version` is inside the signed payload.
- Key substitution: mitigated by pinned-key verification (`issuer_pubkey_hex`).
- Chain rollback: issuer hash chain is append-only and fork-detectable.

## License

Apache 2.0. Specification text is additionally CC0 (see [../../LICENSE](../../LICENSE)).
