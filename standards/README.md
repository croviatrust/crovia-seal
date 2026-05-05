# Crovia Seal — Standards Track

This directory hosts the IETF Internet-Draft submissions for the Crovia
Seal protocol.

## Files

* `draft-crovia-seal-00.xml`  &mdash; canonical xml2rfc v3 source (RFC 7991)
* `draft-crovia-seal-00.txt`  &mdash; rendered plain-text form (the form submitted
  to <https://datatracker.ietf.org/submit/>)

## Building

If you have `xml2rfc` v3 installed:

```
xml2rfc draft-crovia-seal-00.xml --text --html
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
