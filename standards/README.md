# Crovia Seal — Standards Track

This directory hosts the IETF Internet-Draft submissions for the Crovia
Seal protocol.

## Files

* `draft-crovia-seal-01.xml`  &mdash; current revision, canonical xml2rfc v3 source (RFC 7991);
  posted to the datatracker on 2026-05-05:
  <https://datatracker.ietf.org/doc/draft-crovia-seal/>
* `draft-crovia-seal-01.txt` / `.html`  &mdash; rendered forms of the current revision
* `draft-crovia-seal-00.*`  &mdash; previous revision, kept for the record

`crovia.seal.v1` objects and the conformance vectors in this repository track
draft-01. The draft is an Internet-Draft, not an IETF standard.

## Building

If you have `xml2rfc` v3 installed:

```
xml2rfc draft-crovia-seal-01.xml --text --html
```

The generated `.txt` and `.html` should be checked in alongside the `.xml`.

## Submission

Once an editorial pass is complete and the document is reviewed:

1. Run `idnits draft-crovia-seal-00.txt` to catch boilerplate / style nits.
2. Submit at <https://datatracker.ietf.org/submit/> as a "new draft".
3. Cross-post the announcement to `last-call@ietf.org` and the relevant
   AI / security area mailing lists (e.g. `cfrg`, `core`, `art`).

## Versioning

Each new revision increments the `-NN` suffix. Substantive changes between
revisions are summarised in the `## Changelog` section near the end of the
draft.
