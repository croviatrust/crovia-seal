# Changelog

All notable changes to Crovia Seal are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
