# Crovia Seal — Threat Model

**Status:** working draft, v0.5
**Companion to:** [SPEC.md](../SPEC.md) §0.5
**License:** CC0 (public domain dedication)

This document enumerates the adversaries Crovia Seal is designed to resist,
the attacks they may attempt, and the mitigations the protocol provides.
It is intentionally narrow: a seal answers *"who issued this output, when,
over what input/output bytes, with what generator?"* — and nothing else.
Out-of-scope claims (e.g. "the model told the truth") are documented as
non-goals, not silently absorbed.

---

## 1. Trust assumptions

The protocol assumes:

1. **Issuer key custody.** The Ed25519 private key of the issuer is held by a
   party that does not leak it. Compromise of this key collapses the system
   for all seals issued under that key until the next key rotation.
2. **Trust-root publication channel integrity.** Verifiers fetch the issuer's
   public key from a published trust-root (HTTPS-served JSON, optionally
   pinned, optionally cross-published to Bitcoin). An attacker who controls
   both DNS and TLS for the verifier's view of the trust-root can substitute
   keys; the protocol does not by itself prevent this — it relies on
   well-known anchoring (DNSSEC, certificate transparency, BTC inscription).
3. **Verifier-side cryptography.** SHA-256 second-preimage and Ed25519
   forgery are computationally infeasible for the lifetime of the deployment.
   PQ-Seal (separate spec) addresses post-quantum threat.

The protocol does **not** assume:

* That the generator (the AI vendor) is honest about *what* it is generating.
  The seal binds bytes; it does not opine on truthfulness.
* That the user sealing an output had any control over the model's training
  data or its outputs.
* That intermediate transports preserve every byte. CIM markers are
  resilient to most intermediates but not all (see §3.4).

---

## 2. Attacker capabilities

We consider three attacker classes, in order of increasing capability:

### A — Reader

Has only the ability to read text already produced. Cannot interact with
issuer, generator, or trust-root infrastructure.

Goals: extract metadata about the output (model, vendor, time of issue),
forge a believable "this output was sealed" claim about an unsealed text.

### B — Network adversary

Can intercept and rewrite traffic between user and issuer, between user and
trust-root, between user and any verifier. May serve different trust-roots
to different verifiers (selective view).

Goals: substitute issuer key, replay or mix-and-match seals, downgrade
clients to ignore signatures.

### C — Compromised issuer

Has stolen or coerced the issuer's private key, or operates a rogue issuer
that managed to publish an apparently-legitimate trust-root entry.

Goals: produce arbitrary seals over arbitrary text, attribute them to any
vendor/model, antedate or postdate them.

---

## 3. Attacks in scope and mitigations

### 3.1 Replay (Reader)

**Attack.** Reader takes a real seal and applies it to a different output,
hoping that downstream consumers compare only the `seal_id` and `signature`
without re-running the full verification.

**Mitigation.** The signed payload includes `subject.output_hash` and
`subject.input_hash`. A correct verifier MUST recompute SHA-256 over the
clean output bytes and compare to `output_hash` before reporting "verified".
The Crovia reference verifier (`/check.html`) treats hash-mismatch as
**warn**, not ok, and surfaces it prominently.

### 3.2 Mix-and-match (Reader)

**Attack.** Reader splices a sealed paragraph into a longer unsealed
document, copy-pasting only the CIM markers along with the small sealed
fragment. Downstream tools that don't isolate the sealed substring are
fooled.

**Mitigation.** CIM markers carry only the `seal_id`. The seal binds the
*entire* output bytes that were sealed (`output_length` is also signed).
Verifiers MUST report the canonical sealed text length and the verifier UI
SHOULD display the sealed text in a separate pane so the user can compare.
The Crovia `/check.html` shows `output_length` in bytes prominently in the
seal detail.

### 3.3 Trust-root substitution (Network adversary)

**Attack.** Adversary serves a trust-root with a different `pubkey` to the
victim verifier, then signs forged seals with the corresponding private key.

**Mitigation.**
- DNSSEC + HTTPS pin the trust-root delivery channel.
- Verifiers SHOULD compare the trust-root pubkey against an out-of-band
  reference (e.g. a hardcoded fingerprint, or a Bitcoin Ordinals inscription
  of the trust-root SHA-256). The CV-PSI federation (§P4 in the roadmap)
  cross-publishes trust-roots across multiple independent operators so
  selective substitution becomes detectable.
- The reference Crovia trust-root will be inscribed on Bitcoin under the
  Ordinals protocol (P5 milestone) so any verifier can reach a third-party
  copy independently of croviatrust.com.

### 3.4 CIM stripping (Network adversary or naive intermediates)

**Attack.** A messaging app, blogging platform, or document editor strips
zero-width characters from the text before delivery, removing the seal
identifier from the output. Now the verifier cannot find any seal.

**Mitigation.**
- This is a **known limitation**. The protocol's response is graceful:
  the verifier UI reports *"no Crovia CIM marker found in this text"* and
  exposes the *Seal ID* tab so the user can paste the id directly if they
  have it from another channel (e.g. the issuer's receipt, an email trail).
- Issuers SHOULD also publish seals through redundant channels: an HTTP
  receipt, an email, a downloadable JSON. The seal_id is the canonical
  identifier; CIM is a convenience.

### 3.5 Pre-image collision on the output (theoretical)

**Attack.** Adversary finds two outputs `O1` and `O2` such that
SHA-256(O1) = SHA-256(O2), then issues a seal over O1 and presents O2.

**Mitigation.** SHA-256 second-preimage resistance. No public attack is
known. PQ-Seal will add SHA-3 + Dilithium for 30-year insurance.

### 3.6 Issuer key compromise (Compromised issuer)

**Attack.** Adversary obtains the issuer private key and signs arbitrary
seals.

**Mitigation.**
- The trust-root JSON includes a `revocation_url` and a `not_before` /
  `not_after` validity window. After a key rotation the previous key is
  marked revoked.
- Per-key seals are bounded: seals signed before the revocation timestamp
  remain valid, but the verifier MUST display a warning if the verifier's
  current time is past the revocation date.
- All seals issued by Crovia's reference issuer are appended to a public
  Merkle log (P4 milestone). Anomalous spikes are visible.

### 3.7 Antedating / postdating (Compromised issuer)

**Attack.** A rogue issuer signs a seal claiming `issued_at = 2020-01-01`
to fabricate a "this AI text existed before X event" provenance, or claims
a future date to predate other claims.

**Mitigation.**
- `issued_at` is signed by the issuer alone. Without external anchoring the
  field is only as trustworthy as the issuer.
- For evidentiary use, seals MUST be cross-anchored: included in a Merkle
  batch that is then inscribed in a Bitcoin Ordinals (P5) at a known block
  height. Bitcoin's chain provides a globally-witnessed lower bound on the
  seal's existence time.
- Verifiers operating in evidentiary mode MUST check the Bitcoin anchor of
  the seal and reject seals whose anchor block is older than the stated
  `issued_at`.

### 3.8 Cross-issuer impersonation

**Attack.** A second issuer publishes a trust-root with `issuer.id =
"urn:crovia:seal-issuer:crovia-trust"` (the same as Crovia's) at a different
URL, and convinces some verifiers to use it.

**Mitigation.**
- Verifiers MUST compare the `issuer.pubkey` field of the seal against the
  trust-root's `issuer.pubkey` field. The Crovia issuer's pubkey is
  documented at multiple independent locations (this site, the GitHub
  README, Bitcoin inscription).
- The eventual deployment of CT-style logs for trust-roots makes silent
  forks visible.

---

## 4. Out of scope

The Crovia Seal explicitly does NOT:

1. Attest to the truthfulness of the output. Hallucinations are sealed
   exactly as faithful answers are.
2. Bind the user's identity. The seal does not authenticate "Alice asked"
   or "Bob received". Optional `issuer_app` is opaque metadata, not
   authenticated.
3. Restrict copying or use. The seal is informational; it does not
   constrain reuse, redistribution, or quotation.
4. Provide DRM. Stripping the seal does not break the text.
5. Encrypt the output. Seals are over plaintext.

These are deliberate. A protocol that quietly mixed any of these into its
threat model would be misunderstood by users.

---

## 5. Reportable findings

If you discover a vulnerability that allows seal forgery, signature
acceptance over modified bytes, or trust-root substitution that the
protocol's documented mitigations do not catch, please report it to
`security@croviatrust.com` with subject `[Seal-Vuln]`. We commit to a
public disclosure timeline of 90 days from receipt unless an extension is
mutually agreed.

---

## 6. Changelog

* **v0.5 (2026-05-04).** First public draft.
