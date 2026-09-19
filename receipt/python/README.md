# crovia-seal

**Immutable continuity receipts for evolving AI systems.**

Tiny, offline, cryptographic primitive. Sign any JSON payload, get a verifiable receipt. No network call required.

Byte-identical with the JavaScript SDK [`@crovia/seal`](https://www.npmjs.com/package/@crovia/seal) — receipts produced in either language verify in both.

## Install

```bash
pip install crovia-seal
```

To enable the optional public-substrate `register()` call:

```bash
pip install "crovia-seal[register]"
```

## Use

```python
from crovia_seal import seal, verify, generate_key

key = generate_key()

# Sign any JSON payload.
receipt = seal(
    {"model": "gpt-4o", "output": "Hello, world."},
    key=key,
)

# Verify with the original payload (full check).
result = verify(receipt, {"model": "gpt-4o", "output": "Hello, world."})
print(result.valid)  # True
```

## What you get

- **Cryptographic signature** — Ed25519, byte-identical with the JavaScript SDK.
- **Stable receipt id** — `cr_YYYY_<26 base32>`, collision-resistant.
- **Continuity** — chain receipts via `prev_receipt` to get an immutable lineage.
- **Offline by default** — no network. Works in CI, behind firewalls, in isolated envs.
- **Public continuity graph** — opt-in via `register(receipt)` to publish to the Crovia substrate.

## Continuity chain

```python
r1 = seal({"version": 1, "content": "..."}, key=key)
r2 = seal({"version": 2, "content": "..."}, key=key, prev_receipt=r1)
r3 = seal({"version": 3, "content": "..."}, key=key, prev_receipt=r2)

from crovia_seal import verify_chain
result = verify_chain([r1, r2, r3])
```

## Optional: publish to the substrate

```python
from crovia_seal import register

ack = register(receipt)  # POSTs to https://croviatrust.com/api/anchor
print(ack.accepted, ack.anchor_id)
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
- JavaScript equivalent: `npm install @crovia/seal`
- Source: <https://github.com/croviatrust/crovia-seal/tree/main/sdk/python>
