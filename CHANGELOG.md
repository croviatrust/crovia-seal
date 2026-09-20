# Changelog

All notable changes to Crovia Seal are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.6.0] - 2026-09-20

### Changed

- **seal-svc issues real Seals.** `integrations/seal-svc` now emits `crovia.seal.v1` objects through the reference implementation (`emit_seal`), self-verifies each Seal before persisting it, and keeps one hash chain per issuer key (`chain.prev_seal_hash`, `chain.sequence`). The old service signed an ad-hoc object (`seal_version: "crovia-seal-v1"`, `sl_` ids, `"Ed25519:<hex>"` signature) that no verifier accepted. Request shape is unchanged (`output_text`, `input_hash`, `generator`); `input_text` and `modality` are new optional fields; `input_hash` now requires `input_len`. Old objects remain retrievable and are flagged `legacy: true`.
- **`sdk/` is now `receipt/`.** The lightweight client-side receipt (`crovia.receipt.v1`) was published as `crovia-seal` 0.1.0 (PyPI) and `@crovia/seal` 0.1.0 (npm), which made a Receipt look like a Seal. The packages are renamed `crovia-receipt` / `@crovia/receipt` 0.2.0 (import `crovia_receipt`). Wire format unchanged. The name `crovia-seal` belongs to the reference implementation only.
- README rewritten around the single format, the issuers in production and the canonical Crovia surfaces. `llms.txt` no longer hard-codes headline figures; it points at the live endpoints.

### Removed

- `sdk/python/crovia_seal/` + `setup.py`: a second, PyNaCl-based `crovia-verify` CLI for a third seal shape (`sl_` ids) that no live surface produces.

### Fixed

- `SyntaxWarning: invalid escape sequence` in `crovia_seal.canonical` under Python 3.12.

## [0.5.0] - 2026-04-18

### Added

- **Crovia Proxy** (`integrations/proxy/`): OpenAI-compatible drop-in proxy that seals every response. Streaming and non-streaming supported. Automatic CIM injection into response text. Optional drand beacon anchoring.
- **Crovia Transparency Log** (`integrations/tlog/`): RFC 6962 append-only Merkle log with inclusion and consistency proofs. SQLite storage. Ed25519-signed STHs. Python sync + async client libraries.
- **Crovia Beacon Anchor** (`crovia_seal.beacon`): every Seal can embed a drand Quicknet round, producing a verifiable lower bound on emission time. This makes back-dating impossible even for a compromised issuer.
- **Polymorphic anchor schema**: `anchor.kind` discriminator supports `crovia-tlog`, `crovia-beacon`, and legacy shape (backward compatible).
- **Multi-host browser detector**: Claude, Gemini, Perplexity (in addition to ChatGPT). New `HostAdapter` abstraction in `content/detector-base.ts`.
- **Python CIM port** (`crovia_seal.stego`): byte-identical to the TypeScript implementation. 6 cross-language conformance vectors shipped under `conformance/vectors/cim/v1.json`.
- **Docker Compose** full stack (proxy + tlog). `docker-compose.yml` at repo root.
- **ADOPT.md**: "use Crovia in 60 seconds" adoption guide for 4 personas (AI companies, users, verifiers, infra operators).
- Initial specification draft (SPEC.md v0.5).
- Python reference implementation (`crovia-seal` 0.5.0).
- CSC-1 canonicalization (strict subset of RFC 8785; no floats in signed payload).
- Domain-separated signing payload (`CROVIA-SEAL-v1\n` prefix).
- Issuer hash chain (per-issuer append-only sequence with `prev_seal_hash`).
- Optional witness co-signatures (consortium model).
- Optional transparency-log anchor with Merkle inclusion proof.
- Comprehensive pytest suite covering canonicalization, happy-path issuance
  and verification, and adversarial tamper vectors.
- VERIFICATION.md: standalone three-line verifier + ~60-line from-scratch
  verifier for auditors.

### Notes
- **Not yet stable.** Field names and schema may change before 1.0.
- Post-quantum signature support (`pq_signature`) is reserved in the spec
  but not implemented.
- Transparency-log server implementation is separate from this package.
