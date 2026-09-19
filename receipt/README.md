# Crovia Receipt

`receipt/` holds the two implementations of **Crovia Receipt** (`crovia.receipt.v1`), a lightweight,
offline, client-side signed receipt for AI outputs. Python and JavaScript produce byte-identical receipts.

| | Package | Import |
|---|---|---|
| Python | `crovia-receipt` | `from crovia_receipt import seal, verify` |
| JavaScript | `@crovia/receipt` | `import { seal, verify } from "@crovia/receipt"` |

**A Receipt is not a Seal.** The Crovia standard, the registry, the IETF draft and the web verifier
all speak `crovia.seal.v1`; Receipts do not verify with `verify_seal`. Use Receipts when you need a
cheap self-attestation with no issuer service; use Seals when a third party must be able to verify.
See the repository [README](../README.md) for the full map.

History: these packages were first published as `crovia-seal` 0.1.0 and `@crovia/seal` 0.1.0, which
made the two objects look interchangeable. They were renamed in 0.2.0; nothing in the wire format changed.
