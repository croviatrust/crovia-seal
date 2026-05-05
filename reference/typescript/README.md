# @crovia/seal (TypeScript reference)

TypeScript/JavaScript reference implementation of
[Crovia Seal v1](../../SPEC.md).

Byte-identical to the Python reference for every signed payload. Cross-language
conformance is enforced by shared test vectors (see `tests/conformance.test.ts`).

## Runtime

- Node.js >= 18 (uses Web Crypto API or node:crypto for randomness)
- Modern browsers (no Node-specific APIs in the package exports)

## Install

```bash
npm install
npm run build
```

## Demo (end-to-end)

```bash
npm run demo
```

Reproduces the Python `examples/demo_hp.py` in TypeScript: generates a
deterministic issuer, signs a genesis Seal, self-verifies, tampers, re-verifies,
chains a second Seal.

## Tests

```bash
npm test
```

The test suite has four tiers:

| Suite                       | Tests | Purpose                                                    |
| --------------------------- | ----- | ---------------------------------------------------------- |
| `tests/canonical.test.ts`   | 28    | CSC-1 determinism, exact byte match with Python.           |
| `tests/seal.test.ts`        | 18    | Happy-path issuance and verification.                      |
| `tests/tamper.test.ts`      | 20    | All adversarial vectors from the Python suite.             |
| `tests/conformance.test.ts` |  6+   | Load Python-generated fixtures, assert identical bytes.    |

**Cross-language conformance** requires the Python fixtures to exist. Before
running `tests/conformance.test.ts`, generate them once:

```bash
# From the repository root:
cd reference/python
pip install -e .
python ../../conformance/generate_vectors.py
```

This writes `conformance/vectors/v1/seal_001_genesis.json` and friends. The TS
conformance test reads those files and asserts bit-identical output.

## Public API

```ts
import {
  generateIssuerKey, loadIssuerKey, loadPublicKey,
  emitSeal, verifySeal,
  computePayload, computeSealHash,
  canonicalize,
  type Seal, type VerifyResult, type IssuerKey,
} from '@crovia/seal';
```

## Dependencies

- `@noble/ed25519` - pure JS Ed25519, audited, zero transitive deps.
- `@noble/hashes` - pure JS SHA-256/SHA-512, same author, same guarantees.

No other runtime dependencies. No fetch, no filesystem, no timers.

## License

Apache 2.0. Specification text is additionally CC0 (see [../../LICENSE](../../LICENSE)).
