# @crovia/seal

**Immutable continuity receipts for evolving AI systems.**

Tiny, offline, cryptographic primitive. Sign any JSON payload, get a verifiable receipt. No network call required.

## Install

```bash
npm install @crovia/seal
```

## Use

```ts
import { seal, verify, generateKeySync } from "@crovia/seal";

const key = generateKeySync();

// Sign any JSON payload.
const receipt = await seal(
  { model: "gpt-4o", output: "Hello, world." },
  { key },
);

// Verify with the original payload (full check).
const result = await verify(receipt, { model: "gpt-4o", output: "Hello, world." });
console.log(result.valid); // true
```

## What you get

- **Cryptographic signature** — Ed25519, byte-identical with the Python reference.
- **Stable receipt id** — `cr_YYYY_<26 base32>`, collision-resistant.
- **Continuity** — chain receipts via `prevReceipt` to get an immutable lineage.
- **Offline by default** — no network. Works in CI, behind firewalls, in isolated envs.
- **Public continuity graph** — opt-in via `register(receipt)` to publish to the Crovia substrate.

## Continuity chain

```ts
const r1 = await seal({ version: 1, content: "..." }, { key });
const r2 = await seal({ version: 2, content: "..." }, { key, prevReceipt: r1 });
const r3 = await seal({ version: 3, content: "..." }, { key, prevReceipt: r2 });

// Verify the whole chain.
import { verifyChain } from "@crovia/seal";
const result = await verifyChain([r1, r2, r3]);
```

## Optional: publish to the substrate

```ts
import { register } from "@crovia/seal";

const r = await seal(payload, { key });
const ack = await register(r); // posts to https://croviatrust.com/api/anchor
console.log(ack.accepted, ack.anchorId);
```

This is the only call that touches the network. `seal()` and `verify()` never do.

## Receipt format (`crovia.receipt.v1`)

```json
{
  "v": "crovia.receipt.v1",
  "id": "cr_2026_AB23CD45EF67GH89IJ012KLMN3",
  "issued_at": "2026-05-07T15:43:57.123Z",
  "payload_hash": "sha256:<64 hex>",
  "payload_alg": "sha256",
  "prev": null,
  "seq": 0,
  "signer": "<64 hex Ed25519 pubkey>",
  "sig_alg": "ed25519",
  "canon": "csc-1",
  "domain": "CROVIA-RECEIPT-v1",
  "sig": "<128 hex Ed25519 signature>"
}
```

The signature covers `b"CROVIA-RECEIPT-v1\n" || csc1(receipt without sig)`.

## License

Apache-2.0.

## Spec & reference impls

- Spec: <https://croviatrust.com/seal>
- Python equivalent: `pip install crovia-seal`
- Source: <https://github.com/croviatrust/crovia-seal/tree/main/sdk/javascript>
