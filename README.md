# Crovia Seal

[![IETF Internet-Draft](https://img.shields.io/badge/IETF-draft--crovia--seal--00-1ec5ff?style=flat-square)](https://datatracker.ietf.org/doc/draft-crovia-seal/)
[![Conformance](https://github.com/croviatrust/crovia-seal/actions/workflows/conformance.yml/badge.svg)](https://github.com/croviatrust/crovia-seal/actions/workflows/conformance.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg?style=flat-square)](https://opensource.org/licenses/Apache-2.0)
[![Spec: CC0](https://img.shields.io/badge/Spec-CC0-lightgrey.svg?style=flat-square)](https://creativecommons.org/publicdomain/zero/1.0/)

**A tamper-evident provenance receipt for AI outputs.**

Every AI output in the world — text, code, image, audio — should carry a small,
cryptographically sealed receipt proving *who* generated it, *when*, *from what input*,
and *whether* it matches known memorized material.

Crovia Seal is that receipt. It is:

- **Universal** — a compact JSON sidecar (~500 bytes) attachable to any AI output.
- **Verifiable offline** — Ed25519 + canonical JSON. Three lines of Python, no network.
- **Tamper-evident** — any modification to output or seal invalidates the signature.
- **Chainable** — each seal references the previous seal from the same issuer,
  forming an append-only hash chain detectable without a central log.
- **Algorithm-agile** — optional post-quantum signatures (Dilithium/Falcon) in the same schema.
- **Composable** — optional co-signatures from independent witnesses (consortium model).
- **Open** — Apache 2.0, open standard, reference implementations in multiple languages.

## Why it matters

AI outputs are generated billions of times per day with zero forensic trail.
When one causes harm — a copyright claim, a defamation lawsuit, a regulatory
inquiry — the evidence needed to reconstruct *what happened* has already
evaporated. The logprobs are gone. The model state is gone. The input–output
link is unverifiable.

Crovia Seal fixes this, by design, without requiring cooperation from model
vendors. The seal can be emitted **client-side** (by a proxy, by a browser
extension, by an IDE plugin). It becomes the DKIM of the AI era: silent,
ubiquitous, eventually mandatory.

## What Crovia Seal is **not**

- **Not a judge.** A seal does not decide whether an output is copyright
  infringement, or toxic, or factually correct. It records facts; others judge.
- **Not a detector.** Detection signals *may* be embedded (memorization check,
  safety probe) but the seal's validity is independent of their accuracy.
- **Not a blockchain.** No proof-of-work, no token, no consensus protocol.
  Merkle + Ed25519 + optional anchoring is sufficient and orders of magnitude cheaper.
- **Not surveillance.** A seal commits to hashes of input/output, not the
  content itself. Privacy-preserving checks (via optional ZK proof bundle)
  are supported in the extended spec.

## Repository layout

```
crovia-seal/
  SPEC.md                       Canonical specification (IETF draft style)
  VERIFICATION.md               "How anyone verifies a seal in 3 lines of Python"
  ADOPT.md                      Migration guide for vendors and integrators
  LICENSE                       Apache 2.0 (code) + CC0 (specification text)
  standards/
    draft-crovia-seal-00.{xml,txt,html}   IETF Internet-Draft (filed 2026-05-04)
    draft-crovia-seal-01.{xml,txt,html}   Editorial revision (ASCII-clean)
  reference/
    python/                     Reference implementation (`crovia_seal` package)
  conformance/
    generate_vectors.py         Generates the canonical test vectors
    generate_vectors_extended.py  Adds modality / chain / negative-test vectors
    run_conformance.py          End-to-end test runner (41 cases)
    vectors/v1/                 Committed test fixtures
  docs/
    THREAT_MODEL.md             Adversary model, attack scenarios, mitigations
  integrations/                 OpenAI, Anthropic, Google native proxy adapters
  .github/workflows/            CI: conformance on push, weekly on schedule
```

## Quick start

```bash
git clone https://github.com/croviatrust/crovia-seal.git
cd crovia-seal/reference/python
pip install -e .

# 30-second demo: emit + mutate + re-verify
python examples/demo_hp.py

# Run the full conformance suite (41 tests)
cd ../..
python conformance/run_conformance.py
# expected: ALL 41 TESTS PASSED
```

The demo generates an Ed25519 keypair, creates a seal over a known copyrighted
passage (used as a test fixture), prints the seal, mutates a single byte of the
payload, and shows that verification now fails with a precise error.

## Conformance for non-Python implementations

A TypeScript / Go / Rust / Java implementation is conformant iff:

1. For every entry in `conformance/vectors/v1/canonical_cases.json`, the
   implementation's `canonicalize(input)` produces exactly `expected_hex`
   bytes.
2. For every `seal_NNN_*.json` in `conformance/vectors/v1/`, the
   implementation's `verify_seal(seal)` returns success.
3. For every file in `conformance/vectors/v1/invalid/`, the implementation
   refuses the seal (any error is acceptable; failure mode MUST be
   fail-closed, not silent acceptance).

Deterministic regeneration: anyone can re-run
`python conformance/generate_vectors.py && python conformance/generate_vectors_extended.py`
and the bytes MUST be identical to those committed.

## Specification status

- **IETF Internet-Draft**: [`draft-crovia-seal-00`](https://datatracker.ietf.org/doc/draft-crovia-seal/)
  filed 2026-05-04 under the *Independent Submission* stream (Informational).
- **Reference implementation**: Python 3.10+, see `reference/python/`.
- **Conformance suite**: 41 cross-language test vectors
  (26 canonicalization cases + 10 valid signed seals + 5 fail-closed negative tests).
  Run `python conformance/run_conformance.py` after `pip install -e reference/python`.
- **Public verifier**: [croviatrust.com/check.html](https://croviatrust.com/check.html)
- **Trust root**: [seal.croviatrust.com/trust-root.json](https://seal.croviatrust.com/trust-root.json)

## Threat model

See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md). Summary of in-scope attacks:
signature replay (mitigated by domain separation), JSON malleability (mitigated
by CSC-1 canonicalization), field tampering (signature covers all non-signature
fields), version downgrade (`seal_version` is signed), chain rollback (issuer
hash chain detects), key substitution (trust root published, co-signing
optional).

## License

Apache 2.0. The specification text is dedicated to the public domain under CC0
to maximize reuse by standards bodies.

---

*Crovia Seal is maintained by Crovia Trust as an open standard.*
*Issuer keys used in production are published at* [`seal.croviatrust.com/trust-root.json`](https://seal.croviatrust.com/trust-root.json).
*Standards-track work happens in the IETF datatracker:* [`draft-crovia-seal`](https://datatracker.ietf.org/doc/draft-crovia-seal/).
*Feedback, implementation reports, and conformance test results are welcome via GitHub Issues.*
