# Crovia Seal

[![IETF Internet-Draft](https://img.shields.io/badge/IETF-draft--crovia--seal--01-1ec5ff?style=flat-square)](https://datatracker.ietf.org/doc/draft-crovia-seal/)
[![Conformance](https://github.com/croviatrust/crovia-seal/actions/workflows/conformance.yml/badge.svg)](https://github.com/croviatrust/crovia-seal/actions/workflows/conformance.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg?style=flat-square)](https://opensource.org/licenses/Apache-2.0)
[![Spec: CC0](https://img.shields.io/badge/Spec-CC0-lightgrey.svg?style=flat-square)](https://creativecommons.org/publicdomain/zero/1.0/)

**Crovia records what AI providers disclose about training data, and the
absence of it, as signed, Bitcoin-anchored facts.** This repository is the
Seal standard: the tamper-evident receipt format every Crovia artifact is
delivered in, its IETF draft, reference implementations, conformance vectors
and integrations.

## One format

There is exactly one thing called a Crovia Seal: a `crovia.seal.v1` JSON
object, ~500 bytes, Ed25519-signed over the CSC-1 canonical form of its
payload with the domain separator `CROVIA-SEAL-v1`.

```json
{"seal_version":"crovia.seal.v1","seal_id":"cs_2026_…","issuer":{…},"subject":{…},
 "generator":{…},"timestamp":{…},"chain":{…},"signature":{"alg":"ed25519","canon":"csc-1",
 "domain":"CROVIA-SEAL-v1","payload_hash_alg":"sha256","sig_hex":"…"}}
```

Verify one offline, in three lines, with the reference package:

```python
from crovia_seal import verify_seal
result = verify_seal(seal_dict)
print(result.ok, result.issuer_id, result.errors)
```

Or paste it into the public verifier: https://croviatrust.com/registry/seal/verify/

## Who issues Seals today

| Issuer | id | What it seals |
|---|---|---|
| [Causari](https://github.com/croviatrust/causari) | `urn:crovia:seal-issuer:causari` | Code changes made by AI agents (production, Rust) |
| Crovia Trust | `urn:crovia:seal-issuer:crovia-trust` | Ledger batches, LACUNA records, TACET silence proofs |
| You | your URN | Anything: run `crovia_seal.emit_seal(...)` with your key |

Issuer keys are published in the trust root: https://seal.croviatrust.com/trust-root.json

## Repository layout

```
SPEC.md                   Normative specification v0.5 (CC0)
VERIFICATION.md           Verifier requirements and test procedure
ADOPT.md                  Integration guide for issuers
standards/                IETF Internet-Draft sources and renders (draft-crovia-seal-00/-01)
reference/python/         crovia_seal — reference implementation (PyPI: crovia-seal)
conformance/              Vectors every implementation must pass
receipt/                  Crovia Receipt (crovia.receipt.v1): the lightweight
                          client-side receipt that is NOT a Seal; see receipt/README.md
integrations/             seal-svc (public issuer), proxy (OpenAI-compatible), tlog (RFC 6962 log)
docs/                     Threat model
ops/                      Deployment scripts for the issuer service
```

`receipt/` was previously published as `crovia-seal` 0.1.0 on PyPI and
`@crovia/seal` 0.1.0 on npm. Those packages produce `crovia.receipt.v1`
objects, which are useful but are not Seals and do not verify with
`verify_seal`. They are republished as `crovia-receipt` / `@crovia/receipt`;
the names `crovia-seal` and `@crovia/seal` now carry the reference
implementation, so that `pip install crovia-seal` gives you `verify_seal`.

## Conformance

```bash
pip install -e reference/python
python3 conformance/run_conformance.py     # every vector must pass
```

CI runs the suite on every push and weekly. A verifier is conformant only if
it rejects every negative vector: unknown fields, wrong domain, non-canonical
input, out-of-range integers, non-genesis chains without `prev_seal_hash`.

## Status

- Specification: v0.5, frozen for `crovia.seal.v1`; changes go to `v2`.
- Internet-Draft: `draft-crovia-seal-01` submitted.
- Reference: Python 0.5.x, TypeScript 0.5.x.
- Production: Causari (since 2026-05), Crovia Trust issuer service (`seal.croviatrust.com`).

## Crovia surfaces

| Surface | URL |
|---|---|
| Ledger and registry | https://croviatrust.com/registry/ |
| LACUNA (absence records) | https://croviatrust.com/registry/lacuna/ |
| Crovia Seal: spec, verifier, log | https://croviatrust.com/registry/seal/ |
| Issuer trust root | https://seal.croviatrust.com/trust-root.json |
| Machine-readable index | https://croviatrust.com/llms.txt |
| MCP server | https://croviatrust.com/mcp |
| Canon (source of truth for all of the above) | https://github.com/croviatrust/countersign/blob/main/CANON.md |

Repositories: [crovia-seal](https://github.com/croviatrust/crovia-seal) (the standard) ·
[crovia-core-engine](https://github.com/croviatrust/crovia-core-engine) (the substrate) ·
[countersign](https://github.com/croviatrust/countersign) (witnessing and TACET) ·
[crovia-evidence-lab](https://github.com/croviatrust/crovia-evidence-lab) (public data) ·
[causari](https://github.com/croviatrust/causari) (sibling product: code provenance).

Crovia records facts about public surfaces. It does not infer intent, allege
wrongdoing or enforce compliance. Contact: info@croviatrust.com.
