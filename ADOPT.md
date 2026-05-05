# Adopt Crovia Seal in 60 seconds

> **The open, permissionless, self-hosted provenance protocol for AI-generated content.**
> Zero vendor lock-in. Zero server dependency. Every piece of the stack runs on your laptop.

Crovia Seal makes every AI output cryptographically attributable, tamper-evident, and
**impossible to back-date** — using only standards you can audit yourself:
RFC 3629 UTF-8, RFC 6962 Merkle trees, Ed25519 signatures (RFC 8032),
drand public randomness beacons, and a small amount of Crovia-original innovation
(CIM zero-width steganography, CSC-1 canonicalization).

---

## What you get

| Component | What it does | Path |
|---|---|---|
| **Core library (Python)** | Emit / verify Seal v1 receipts, CSC-1 canonicalization, CIM steganography, drand beacon anchor | `reference/python/` |
| **Core library (TypeScript)** | Same API, byte-identical cross-language | `reference/typescript/` |
| **Browser extension (MV3)** | One-click sealing on ChatGPT / Claude / Gemini / Perplexity + universal verifier page | `integrations/browser-extension/` |
| **OpenAI-compatible proxy** | Drop-in replacement for `api.openai.com` that seals every response | `integrations/proxy/` |
| **Transparency Log server** | RFC 6962 append-only Merkle log with inclusion & consistency proofs | `integrations/tlog/` |

Every component has a full test suite. At HEAD: **208 tests passing** across 4 packages.

---

## 60-second adoption paths

### Path 1 — I'm an AI company

Add one flag to your deployment: put the Crovia proxy between your model and the public
internet. Every response you serve now carries a cryptographic receipt.

```bash
pip install -e integrations/proxy
CROVIA_UPSTREAM_URL=http://your-model:8000 \
CROVIA_INJECT_CIM=true \
CROVIA_BEACON_ANCHOR=true \
crovia-proxy --port 443
```

You can prove to auditors, regulators, and users that a given text is or is not
authentically from your system, regardless of the path it travelled.

### Path 2 — I'm an individual user

Load the browser extension (see `integrations/browser-extension/README.md`). Every time
you use ChatGPT, Claude, Gemini, or Perplexity, a **Seal** button appears next to
each answer. One click → the response is sealed with your local Ed25519 key and copied
to your clipboard with an invisible Crovia Invisible Mark that survives paste operations.

### Path 3 — I'm a verifier (journalist / lawyer / academic)

You received a text that claims to be from an AI. Open the extension's **Universal Verifier**
and paste it. If a CIM is present, you see the `seal_id`. Ask the issuer (or the
transparency log operator) for the full Seal, and verify it offline:

```python
from crovia_seal import verify_seal
import json

seal = json.loads(open("received.seal.json").read())
vr = verify_seal(seal, issuer_pubkey_hex="<pinned key>")
assert vr.ok, vr.errors
```

### Path 4 — I want auditable infrastructure

Run the transparency log. Any issuer can submit their seals; any verifier can prove
a seal was (or was not) submitted, and that the log has not re-written history:

```bash
pip install -e integrations/tlog
crovia-tlog --port 7979

# From anywhere:
curl http://localhost:7979/v1/sth          # signed tree head
curl http://localhost:7979/.well-known/crovia-tlog.json   # operator identity
```

---

## Why this wins without permission

Crovia Seal is permissionless by design:

1. **No central server**: you generate your own Ed25519 key, sign your own seals, run your own tlog.
2. **No gatekeeper**: no API key, no rate limit, no registration.
3. **No rents**: Apache-2.0 license on code, CC0 on the specification.
4. **No blockchain**: the protocol uses only battle-tested primitives (Ed25519, SHA-256, Merkle, drand).

If OpenAI never integrates Crovia, adopters still win: the proxy sits in front of the model.
If Google blocks the extension, the CIM still works because it's standard Unicode.
If a regulator mandates a single operator, anyone can run one and the protocol remains the same.

This is the **same adoption curve that took HTTPS from 0% to 95%**: every new actor has a
selfish reason to join, and the value grows quadratically with the installed base.

---

## Architectural invariants (the guarantees)

These are not aspirations. They are tested on every commit.

| # | Invariant | Test(s) |
|---|---|---|
| 1 | Python and TypeScript implementations sign **byte-identical** payloads | `reference/typescript/tests/conformance.test.ts` |
| 2 | CIM mark encoding is **byte-identical** in Python and TypeScript | `stego.conformance.test.ts` (13 vectors) |
| 3 | CIM recovers **one bit flipped** as a tamper (CRC-16) | `test_stego.py::test_flipping_single_*bit_fails_crc` |
| 4 | Transparency log matches the 8 RFC 6962 **known-answer roots** | `test_merkle.py::test_rfc6962_known_roots` |
| 5 | A consistency proof for one branch of history **cannot validate** a diverging branch | `test_merkle.py::test_consistency_rejects_divergent_history` |
| 6 | A Seal with a beacon anchor **fails verification** if the beacon round is mutated | `test_beacon.py::test_beacon_anchor_round_trips_*` |
| 7 | Seal self-verification runs on every emission path (proxy, extension, CLI) | sprinkled across `test_sealer.py`, `test_server.py`, extension `background.ts` |
| 8 | Append-only database is enforced by **schema** (no UPDATE/DELETE in code) | `storage.py` (auditable), `test_storage.py` |

---

## The CIM, the Beacon, the CSC-1: what's truly novel

Most of Crovia is standards plumbed together. Three pieces are genuinely original:

### Crovia Invisible Mark (CIM)

A 152-code-point zero-width payload that carries a 130-bit Seal id + a 16-bit CRC,
bracketed by two distinct BOM-based markers so parsers cannot confuse start and end.
Stable across copy-paste through browsers, Word, Slack, email, PDF.

See `SPEC.md` §3 and `reference/python/crovia_seal/stego.py`.

### Crovia Stable Canonicalization v1 (CSC-1)

A strict subset of RFC 8785 that **forbids floats** entirely and enforces deterministic
byte serialization. This is what makes the Python and TypeScript signatures byte-identical
and what makes offline verification possible without framework dependencies.

See `SPEC.md` §2 and `reference/python/crovia_seal/canonical.py`.

### Crovia Beacon Anchor

Every seal can embed a recent drand round. Because the round number N can only be produced
after genesis_time + (N − 1) × 3 s, a seal carrying round N **cannot have existed** before
that UTC instant. This kills back-dating even for a compromised issuer.

See `reference/python/crovia_seal/beacon.py`.

---

## What's next

- **Sprint 9** — drand BLS offline verifier (remove the last network dependency at verify time)
- **Sprint 10** — Rust port of the core library (for embedded/firmware deployments)
- **Sprint 11** — Browser extension: push-to-tlog button, multi-issuer identity management
- **Sprint 12** — Crovia Badge: HTML/CSS component that renders a seal status on any page

---

## License

- Code: Apache-2.0
- Specification: CC0

Permissionless. Forever.
