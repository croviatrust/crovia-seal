# Contributing to Crovia Seal

Crovia Seal is an open standard. We welcome:

- **Implementation reports** — "I built it in [language], here are my conformance test results"
- **Spec feedback** — gaps, ambiguities, missing edge cases, security concerns
- **New conformance vectors** — particularly for adversarial / edge-case inputs
- **Native integrations** — proxy adapters, browser extensions, IDE plugins
- **Translations of the spec** — once the English text is RFC-stable

## Where to send what

| What | Where |
|---|---|
| Bug in reference implementation | GitHub Issue, label `bug` |
| Question about the spec | GitHub Discussion, category `Q&A` |
| Proposed normative change | GitHub Issue, label `spec`, prefix title `[SPEC]` |
| Security vulnerability | Email **security@croviatrust.com** (PGP key on the website) — please **do not** open a public issue |
| Implementation announcement | GitHub Discussion, category `Show & Tell` |
| IETF mailing list discussion | `i-d-announce@ietf.org` (general) or directly to the document shepherd |

## Conformance reports

If you have built a Crovia Seal implementation, please run the conformance
suite and post the result. The minimum bar is:

```
canonicalization cases:  26/26 pass
valid seal vectors:      10/10 pass
invalid (fail-closed):    5/5 pass
```

To report:

1. Open a GitHub Discussion in `Show & Tell`.
2. Title it: `Implementation report — <language> — <short impl name>`.
3. Body MUST include:
   - **Repository or package URL** (where the source lives).
   - **Language and runtime version** (e.g., Go 1.23, Node 20, Rust 1.79).
   - **Output of the conformance run** (counts and any failures).
   - **License** of your implementation.
   - **Cryptographic primitives used** (Ed25519 library, SHA-256 source).

We will list verified implementations on the website with a link back.

## Proposing a spec change

The reference text lives in two places:

- `SPEC.md` — the editable Markdown source maintained in this repository.
- `standards/draft-crovia-seal-NN.xml` — the IETF Internet-Draft, regenerated
  each revision from the same SPEC content.

For a normative change:

1. Open an Issue describing **the problem** (not your preferred solution).
2. Wait for at least one round of discussion. Many "obvious" changes turn
   out to break canonical determinism or open a security regression.
3. Open a Pull Request that updates **both** `SPEC.md` and the corresponding
   `draft-crovia-seal-XX.xml` for the next revision.
4. The PR MUST include either (a) a new conformance vector that demonstrates
   the change, or (b) a clear argument for why no vector is needed.

We aim for spec changes between IETF revisions to be **rare and small**.
Cosmetic / editorial changes can land freely.

## Coding standards (reference implementation)

The Python reference is the **normative oracle** — its byte-for-byte output
is what every other implementation MUST match. Therefore:

- Changes to `reference/python/crovia_seal/canonical.py` or `seal.py` MUST
  preserve byte-identity of all committed vectors. The CI workflow enforces
  this by regenerating vectors and `git diff`-ing against the committed set.
- If a change is genuinely required (e.g., a bug in a corner case),
  regenerate vectors **in the same PR** and document the rationale.
- Run `python -m pip install -e .` and `python -m pytest` (when tests exist)
  before opening a PR.

## Code of conduct

Be precise. Be polite. Argue from spec text and test vectors, not from
preference. We follow the [IETF Code of Conduct](https://www.ietf.org/about/groups/iesg/statements/code-of-conduct/).

## License of contributions

By submitting a contribution you agree to license:

- **Code**: under Apache 2.0 (matching `LICENSE`).
- **Specification text**: under CC0 1.0 (so any standards body may incorporate it).

Both are explicitly permissive to enable the widest possible adoption.
