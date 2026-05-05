# Crovia Seal Specification

**Version:** 0.5 (draft, pre-IETF)
**Status:** implementation-complete, spec frozen except for additive fields
**Authors:** CROVIA Research
**Date:** 2026-04

This document specifies **Crovia Seal v1**, a compact, tamper-evident JSON
receipt that may be attached to any AI-generated output to record its
provenance in a cryptographically verifiable form.

The key words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, **MAY**, and
**OPTIONAL** in this document are to be interpreted as described in RFC 2119
and RFC 8174.

## 1. Introduction

### 1.1 Purpose

Crovia Seal defines a standard, cross-vendor, cross-platform receipt format
for AI outputs. A Seal MUST enable any third party, given only the Seal itself
and the issuer's public key, to determine:

1. That the Seal has not been tampered with since issuance.
2. That the Seal's signer possessed the private key corresponding to the
   claimed public key at issuance time.
3. That the input hash, output hash, generator identity, and any analytical
   claims embedded in the Seal are as asserted by the issuer.
4. That the Seal forms a consistent link in the issuer's append-only hash chain.
5. (Optionally) That the Seal was included in a public transparency log as of
   a given time.

### 1.2 Design principles

- **Record, do not judge.** The Seal MUST NOT encode verdicts on lawfulness,
  harm, or quality. It MAY embed analytical signals with explicit confidence.
- **Verify offline.** The core verification path MUST require no network access.
- **Composable.** The schema MUST permit optional extensions (co-signatures,
  post-quantum signatures, transparency anchors) without breaking base verifiers.
- **Canonical.** The exact bytes that are signed MUST be derivable from the
  Seal by a single, fully specified canonicalization algorithm.
- **Defensive by default.** All cryptographic operations MUST use
  domain separation; no signed payload may be replayed in another protocol.
- **Fail closed.** Any unrecognized field or algorithm MUST cause verification
  to fail unless the verifier explicitly opts into permissive mode.

### 1.3 Out of scope

- Detection of AI-generated content from the output alone (no watermarking).
- Judgments about copyright, fairness, accuracy, or safety.
- Revocation: a Seal, once emitted, is an immutable historical record.
  Issuers are identified by public key; key rotation is handled by the
  transparency log, not by Seal-level revocation.

## 2. Terminology

- **Seal**: a single JSON object conforming to Section 4.
- **Issuer**: the entity producing and signing Seals; identified by its
  long-term Ed25519 public key (or successor per Section 8).
- **Witness**: an optional co-signer of a Seal (Section 6).
- **Subject**: the input/output pair that the Seal describes.
- **Generator**: the AI model or system that produced the output.
- **Chain**: the per-issuer append-only sequence of Seals (Section 5).
- **Anchor**: an optional proof that the Seal was included in a public
  transparency log (Section 7).
- **CSC-1**: Crovia Seal Canonicalization v1 (Section 3).
- **Payload**: the exact byte sequence over which a signature is computed
  (Section 3.3).

## 3. Canonicalization (CSC-1)

### 3.1 Motivation

JSON is syntactically flexible: whitespace, key ordering, number formatting,
and string escape choices can vary while producing the same logical value.
A signature over a JSON text requires an unambiguous serialization.

CSC-1 is a **strict subset** of RFC 8785 (JSON Canonicalization Scheme, JCS).
It adopts the deterministic ordering and escaping rules of JCS but **forbids
floating-point numbers** in signed payloads, sidestepping the edge cases of
ECMA-262 number serialization. This restriction does not constrain use cases
(continuous parameters such as `temperature` MUST be encoded as strings
when carried inside the signed payload).

### 3.2 Rules

A CSC-1-serialized JSON value is a UTF-8 byte sequence produced as follows:

1. **`null`** → `null`
2. **`true`** / **`false`** → `true` / `false`
3. **integers** (Python `int`, JSON number with no fractional part, within
   `[-2^53 + 1, 2^53 - 1]`) → shortest decimal representation, no leading zeros,
   no `+` sign.
4. **strings** → UTF-8 JSON string literal using only the escapes required by
   RFC 8259: `\"`, `\\`, `\b`, `\f`, `\n`, `\r`, `\t`, and `\u00XX` for
   U+0000..U+001F. All other code points MUST be emitted literally.
5. **arrays** → `[` followed by canonicalized elements separated by `,`
   followed by `]`. No interior whitespace.
6. **objects** → `{` followed by `"key":value` pairs separated by `,`
   followed by `}`. Keys MUST be sorted ascending by their UTF-16 code-unit
   sequence (equivalent to JavaScript `Array.prototype.sort` on strings).
   No interior whitespace.
7. **floats, NaN, Infinity, `-0`** → MUST cause serialization to fail with
   `NonCanonicalNumber`.
8. **duplicate object keys** → MUST cause serialization to fail with
   `DuplicateKey`.
9. **non-string object keys** → MUST cause serialization to fail with
   `NonStringKey`.

### 3.3 Signing payload

Given a Seal `S`, the signing payload `P(S)` is computed as:

```
P(S) = DOMAIN || 0x0A || CSC1(S \ {signature, witnesses})
```

where:

- `DOMAIN` = the ASCII string `"CROVIA-SEAL-v1"` (14 bytes).
- `0x0A` = a single newline byte, acting as an unambiguous separator.
- `S \ {signature, witnesses}` = the Seal with the `signature` and `witnesses`
  top-level fields removed (they are computed over the payload, not part of it).
- `CSC1(...)` = the UTF-8 serialization per Section 3.2.

The `DOMAIN` prefix ensures that a signature over `P(S)` cannot be replayed as
a valid signature in any other protocol that does not use the same prefix.
Implementations MUST NOT omit the prefix. Verifiers MUST reject any Seal
whose signature was produced without the prefix.

## 4. Seal structure

### 4.1 Top-level fields

A conformant Seal is a JSON object with exactly the top-level fields listed
below. Unknown top-level fields MUST cause verification to fail.

| Field          | Required | Type   | Section |
| -------------- | -------- | ------ | ------- |
| `seal_version` | MUST     | string | 4.2     |
| `seal_id`      | MUST     | string | 4.3     |
| `issuer`       | MUST     | object | 4.4     |
| `subject`      | MUST     | object | 4.5     |
| `generator`    | MUST     | object | 4.6     |
| `timestamp`    | MUST     | object | 4.7     |
| `chain`        | MUST     | object | 4.8     |
| `checks`       | OPTIONAL | object | 4.9     |
| `anchor`       | OPTIONAL | object | 4.10    |
| `signature`    | MUST     | object | 4.11    |
| `witnesses`    | OPTIONAL | array  | 6       |

### 4.2 `seal_version`

The literal string `"crovia.seal.v1"`. Any other value MUST cause verification
to fail.

### 4.3 `seal_id`

A string matching the regular expression `^cs_[0-9]{4}_[A-Z2-7]{26}$`:
prefix `cs_`, 4-digit issuance year, underscore, 26 RFC 4648 base32
characters (alphabet A–Z, 2–7, no padding) encoding 16 random bytes
(128 bits). The random bytes MUST be produced by a cryptographically secure
source.

### 4.4 `issuer`

```
{
  "id":     string,           ; urn:crovia:seal-issuer:<name> recommended
  "pubkey": { "alg":"ed25519", "key_hex": string }
}
```

`key_hex` is 64 lowercase hexadecimal characters (32 raw bytes, Ed25519
public key per RFC 8032). Other algorithms are reserved for Section 8.

### 4.5 `subject`

```
{
  "input_hash":  "sha256:" + 64 lowercase hex chars,
  "output_hash": "sha256:" + 64 lowercase hex chars,
  "input_len":   integer,    ; byte length of input
  "output_len":  integer,    ; byte length of output
  "modality":    string      ; one of: "text","code","image","audio","multimodal"
}
```

The Seal does NOT carry the content itself. The hashes commit to the content;
verifiers who possess the content can re-hash and compare.

### 4.6 `generator`

```
{
  "id":             string,          ; e.g. "openai/gpt-4o"
  "version":        string | null,   ; e.g. "2024-08-06"
  "weights_hash":   string | null,   ; if available
  "params":         object           ; key→string map of generation parameters
}
```

All parameter values MUST be strings in the signed payload (per Section 3.1
restriction). Numeric values like `temperature=0.7` MUST be encoded as
`"0.7"`.

### 4.7 `timestamp`

```
{
  "emitted_at": string,   ; RFC 3339 UTC, millisecond precision, e.g. "2026-04-15T12:34:56.789Z"
  "nonce":      string    ; 26 RFC 4648 base32 chars (16 random bytes)
}
```

### 4.8 `chain`

```
{
  "prev_seal_hash": "sha256:" + 64 hex chars | null,
  "sequence":       integer (>= 0)
}
```

`prev_seal_hash` is the SHA-256 over the canonical payload (`P(S_prev)`) of
the immediately preceding Seal from the same issuer, or `null` for the
genesis Seal (`sequence == 0`). Verifiers that track issuer chains MUST
detect gaps or forks.

### 4.9 `checks` (OPTIONAL)

Free-form object carrying analytical claims such as memorization checks,
safety probes, toxicity scores. The schema for specific check types is
defined in separate check specifications; the seal itself imposes no
constraints on the content beyond CSC-1 compatibility.

Example:

```
{
  "memorization": {
    "db_version": "crovia-memdb-2026-04-15",
    "method":     "ngram-lsh-v1",
    "matches":    0,
    "max_conf":   "0.03"
  }
}
```

Each check produced by an issuer is signed along with the rest of the Seal;
its validity as evidence depends on the method's own robustness, which is
out of scope for this specification.

### 4.10 `anchor` (OPTIONAL)

```
{
  "log_url":      string,
  "merkle_root":  "sha256:" + 64 hex chars,
  "merkle_proof": [ "sha256:" + hex, ... ],
  "log_index":    integer (>= 0),
  "root_signed_at": string (RFC 3339 UTC)
}
```

The anchor commits the Seal to a public transparency log. The log operator's
signature over `merkle_root` is not part of this Seal and MUST be fetched
separately from `log_url`.

### 4.11 `signature`

```
{
  "alg":              "ed25519",
  "canon":            "csc-1",
  "domain":           "CROVIA-SEAL-v1",
  "payload_hash_alg": "sha256",
  "sig_hex":          string     ; 128 hex chars (64 raw bytes)
}
```

The signature is computed as `Ed25519_sign(privkey, P(S))` where `P(S)` is
defined in Section 3.3. Implementations MUST NOT hash the payload before
signing; Ed25519 internally handles the hash (SHA-512). The
`payload_hash_alg` field is informational, indicating the algorithm used
to derive `prev_seal_hash` and other SHA-256 digests in the Seal.

## 5. Issuer hash chain

Each issuer maintains a per-issuer-key append-only sequence of Seals.
`chain.sequence` starts at 0 for the genesis Seal and increments by 1 for
each subsequent Seal. `chain.prev_seal_hash` MUST be:

- `null` for `sequence == 0`.
- `"sha256:" + hex(SHA256(P(S_prev)))` for `sequence >= 1`, where `S_prev`
  is the Seal with sequence number `sequence - 1` from the same issuer key.

Verifiers that follow an issuer's chain MUST detect:

- **Fork**: two Seals with the same issuer key and same `chain.sequence`
  but different `prev_seal_hash`. This is non-repudiable evidence of
  issuer misbehavior or key compromise.
- **Gap**: missing sequence numbers. A verifier with partial history SHOULD
  obtain the missing Seals from the transparency log before accepting.

## 6. Witnesses (OPTIONAL)

```
"witnesses": [
  {
    "id":      string,
    "pubkey":  { "alg":"ed25519", "key_hex": string },
    "sig_hex": string
  },
  ...
]
```

A witness signs the same canonical payload `P(S)` as the issuer. Witness
signatures are OPTIONAL and additive: a Seal with no witnesses is valid;
a Seal with invalid witness signatures is invalid overall (fail-closed).

Typical witnesses: consortium co-signers (civil-society organizations,
academic institutions, regulatory observers). Witnesses endorse the Seal
without endorsing its content.

## 7. Transparency log (informative)

A conformant transparency log accepts Seals and periodically publishes a
signed Merkle root over the Seals it has received. Implementations of the
log API are outside the scope of this document; see `docs/TRANSPARENCY_LOG.md`.

## 8. Algorithm agility (post-quantum)

Future versions of this specification MAY permit alternative signature
algorithms (e.g., Dilithium, Falcon) by extending the `signature.alg`
vocabulary. A Seal MAY additionally carry a `pq_signature` top-level field
with an independent post-quantum signature over the same payload `P(S)`.
Verifiers that support only Ed25519 MUST ignore `pq_signature` and rely on
`signature`. Verifiers MAY REQUIRE both signatures to validate (strict mode).

## 9. Security considerations

### 9.1 Replay across protocols

Prevented by domain separation (Section 3.3). A signature on `P(S)` cannot
be reinterpreted as a valid signature on a payload of any other protocol
that does not use the exact same 14-byte `CROVIA-SEAL-v1` prefix followed
by a newline.

### 9.2 Replay within the protocol

A Seal is a historical record; "replay" of a Seal is a semantic issue, not
a cryptographic one. The `seal_id`, `timestamp`, and `chain.sequence` fields
make each Seal unique. Verifiers that track seen seal IDs can detect
duplication attempts.

### 9.3 JSON malleability

Eliminated by CSC-1 (Section 3). Any tool that reorders keys, adds
whitespace, or re-escapes strings produces a different byte sequence and
hence an invalid signature.

### 9.4 Field tampering

The signature covers every field except `signature` and `witnesses`, which
are themselves cryptographic. Adding, modifying, or deleting any field
invalidates the signature.

### 9.5 Key compromise

If an issuer key is compromised, the attacker can issue valid Seals until
the compromise is detected and the key is revoked in the transparency log's
trust root. The issuer hash chain MAY reveal the compromise if the attacker
issues a forking Seal.

### 9.6 Downgrade

`seal_version`, `signature.alg`, `signature.canon`, and `signature.domain`
are all inside the signed payload. An attacker cannot negotiate a weaker
algorithm without producing a wholly new signature.

### 9.7 Canonicalization ambiguity

CSC-1 forbids floats in the signed payload precisely to avoid the numeric
edge cases of JCS. Strings carrying numeric values MUST use a documented
format (see Section 4.6).

### 9.8 Hash choice

SHA-256 is used for all digests (content commitments, chain links).
Migration to SHA-3 or BLAKE3 is anticipated in a future minor version; the
`payload_hash_alg` field signals the choice.

### 9.9 Randomness

All random values (`seal_id` suffix, `timestamp.nonce`) MUST be produced by
a cryptographically secure source (e.g., `os.urandom`, `secrets` in Python,
`crypto.randomBytes` in Node.js).

### 9.10 Content privacy

The Seal commits to input/output hashes, never content. Content-bearing
fields such as `generator.params` are in the clear; issuers MUST NOT place
sensitive user data in these fields.

## 10. IANA considerations

This document registers the media type `application/vnd.crovia.seal+json`
(TBD) and the URN namespace `urn:crovia:seal-issuer:` (TBD).

## 11. References

### 11.1 Normative

- **RFC 2119**, RFC 8174 — key words
- **RFC 3339** — timestamps
- **RFC 4648** — base32 encoding
- **RFC 8032** — Ed25519 signature algorithm
- **RFC 8259** — JSON
- **RFC 8785** — JCS (superset; CSC-1 is a strict subset)

### 11.2 Informative

- C2PA Content Credentials Specification v1.3
- Certificate Transparency (RFC 9162)
- Sigstore (Rekor transparency log design)

## Appendix A. Reference signing ceremony

Normative test-vectors are in `conformance/vectors/`. An interactive
demonstration is available via `reference/python/examples/demo_hp.py`.
