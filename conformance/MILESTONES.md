# Conformance Milestones

Chronological record of the reference implementation's test health.
Each entry is an immutable attestation: the commit tagged at that point
MUST reproduce the stated result.

---

## 2026-04 — Python reference, first green

**Environment**

- Windows 10+, Python 3.11.4
- `cryptography` 41.0.7
- `pytest` 9.0.2, `pluggy` 1.6.0, `pytest-cov` 7.1.0

**Command**

```
pytest -v
```

**Result**

```
collected 66 items

tests/test_canonical.py ............................                [ 42%]
tests/test_seal.py ..................                                [ 69%]
tests/test_tamper.py ....................                            [100%]

66 passed in 0.36s
```

**Coverage breakdown**

| Suite              | Tests | Domain                                                  |
| ------------------ | ----- | ------------------------------------------------------- |
| `test_canonical`   | 28    | CSC-1 determinism: primitives, integers, strings,       |
|                    |       | arrays, objects, UTF-16 key order, float rejection,     |
|                    |       | NaN/Inf rejection, duplicate-key detection.             |
| `test_seal`        | 18    | Happy-path issuance + verify; pinned pubkey; chain      |
|                    |       | composition; optional `checks` and `anchor` fields;     |
|                    |       | issuer_id validation; deterministic key load.           |
| `test_tamper`      | 20    | 19 adversarial vectors, each MUST be rejected:          |
|                    |       | subject/generator/chain tampering, version and          |
|                    |       | algorithm downgrade, bit-flip on signature, key         |
|                    |       | substitution with sig rewrite (pinned-key check),       |
|                    |       | cross-protocol replay, unknown top-level field,         |
|                    |       | required-field stripping. Plus one pin test for         |
|                    |       | Python duplicate-key semantics.                         |

**Significance**

This is the baseline against which every future reference implementation
(TypeScript, Go, Rust) will be compared. Any implementation that does
not produce byte-identical signatures for the conformance vectors and
does not pass the equivalent test matrix is non-conformant.

---

## 2026-04 - TypeScript reference, first green + cross-language conformance

**Environment**

- Windows, Node.js 18.16.1 (npm 10.2.3)
- `@noble/ed25519` 2.x, `@noble/hashes` 1.x
- `vitest` 1.6, `typescript` 5.3

**Commands**

```
npm install
npm run build        # 0 errors
npm run demo         # end-to-end OK
npm test             # full suite
```

**Result**

```
  Test Files  4 passed (4)
       Tests  110 passed (110)
    Duration  818ms
```

**Coverage breakdown**

| Suite                       | Tests | Purpose                                                 |
| --------------------------- | ----- | ------------------------------------------------------- |
| `tests/canonical.test.ts`   |  33   | CSC-1 determinism: primitives, integers, strings,       |
|                             |       | arrays, objects, UTF-16 key order, float rejection,     |
|                             |       | NaN/Inf rejection, supplementary-plane code points,     |
|                             |       | Uint8Array/Set/Map/Date rejection (plain-object check), |
|                             |       | `Object.create(null)` acceptance.                       |
| `tests/seal.test.ts`        |  19   | Happy-path issuance and verification; pinned pubkey;    |
|                             |       | chain composition; optional `checks` and `anchor`.      |
| `tests/tamper.test.ts`      |  19   | All adversarial vectors from Python: subject/generator/ |
|                             |       | chain tampering, version/algorithm/domain downgrade,    |
|                             |       | bit-flip, key substitution with sig rewrite,            |
|                             |       | cross-protocol replay, field injection/removal.         |
| `tests/conformance.test.ts` |  39   | **Cross-language conformance**: load Python fixtures,   |
|                             |       | recompute payload in TS, verify signature, re-sign with |
|                             |       | same deterministic seed, assert byte-identical output.  |

**Significance**

Cross-language byte-identity between the Python and TypeScript reference
implementations is achieved. The same issuer public key is derived from
the same 32-byte seed in both languages:

    ff57575dc7af8bfc4d0837cc1ce2017b686a88145dc5579a958e3462fe9a908e

The signing payloads for both conformance vectors
(`seal_001_genesis.payload.hex` = 747 bytes,
 `seal_002_chained.payload.hex` = 783 bytes) are byte-identical, and the
Ed25519 signatures (deterministic per RFC 8032) are byte-identical as
well.

This demonstrates the Crovia Seal v1 specification is implementable
across languages without ambiguity. Subsequent reference implementations
(Go, Rust) MUST pass the same conformance vectors.

**Security fixes applied during TypeScript porting**

1. `src/canonical.ts` - the dispatcher originally classified Uint8Array,
   Set, and Map as generic objects, producing silent but non-intended
   serializations (`{"0":1,"1":2}` for Uint8Array, `{}` for Set). Fixed
   by introducing a strict `_isPlainObject` check that rejects non-plain
   objects with `UnsupportedType`. `Object.create(null)` remains accepted.
2. `src/util/random.ts` - the Node fallback used CommonJS `require` which
   is unavailable in ES modules, breaking demos on Node < 19. Replaced
   with a delegation to `@noble/hashes/utils.randomBytes` (already a
   transitive dependency), keeping the module ESM-pure.
