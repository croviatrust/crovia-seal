# Crovia Seal — Operational Hygiene

This directory documents the operational practices that protect the public surface
of the Crovia Seal protocol against silent regressions.

## Background

After the IETF `draft-crovia-seal-01` submission on 2026-05-05, three production
bugs went undetected for hours because no automated end-to-end probe was running
against the public consumer pages:

1. **`check.html`** — `ed.hashes.sha512 = sha512` (wrong noble-ed25519 v2.x API)
   crashed the module before any click handler attached. Result: every button on
   the consumer landing page silently did nothing.
2. **Verifier 404** — proof bundles were regenerated daily, so any axiom emitted
   in the last 24h returned 404 from the public verifier.
3. **`seal.croviatrust.com/v1/seal/*` CORS** — both nginx and the FastAPI app
   set `Access-Control-Allow-Origin: *`, producing a duplicate `*, *` header
   that browsers reject. `curl` ignored it; users could not.

All three were fixed within the same session, but the underlying cause is the
same: **no continuous probe was simulating an external visitor**. The script in
this directory addresses that.

## `smoke_public.sh`

A self-contained Bash probe that exercises every public-facing surface a
consumer or IETF reviewer would touch:

| Surface                                         | What is checked                                                  |
| ----------------------------------------------- | ---------------------------------------------------------------- |
| `croviatrust.com/check.html`                    | HTTP 200, contains `ed.etc.sha512Sync` (correct API), no broken hook |
| `croviatrust.com/registry/v/`                   | HTTP 200, contains the new "every hour at :15 UTC" copy           |
| `croviatrust.com/registry/substrate/`           | HTTP 200, contains the `operational` filter logic                 |
| `croviatrust.com/registry/chains/`              | HTTP 200, contains the defensive refetch logic                    |
| `seal.croviatrust.com/trust-root.json`          | HTTP 200 + JSON shape (`trust_root_version`)                      |
| `…/registry/data/substrate/ots_anchors.json`    | HTTP 200 + `n_bitcoin` field present                              |
| `…/registry/data/substrate/chains.json`         | HTTP 200 + `axiom_ids` field present                              |
| `…/registry/data/substrate/collectors.json`     | HTTP 200 + `collectors` field present                             |
| `seal.croviatrust.com/v1/seal/<sample>`         | HTTP 200 + valid seal JSON (`seal_version`)                       |
| `seal.croviatrust.com/v1/seal/<sample>` (CORS)  | **Exactly one** `Access-Control-Allow-Origin` header              |
| `…/proof/<shard>/<known-axiom>.json`            | HTTP 200, proof bundle resolves                                   |

Each check has a `must_contain` and a `must_not_contain` marker so we can detect
regressions like "the broken `ed.hashes.sha512` symbol returned to the file".

## Schedule

Cron runs the script every 15 minutes:

```
*/15 * * * * /opt/crovia/scripts/smoke_public.sh
```

Worst-case detection latency is therefore 15 minutes, down from "indefinite"
before this script existed.

## Output

Two artefacts are written each run:

1. **`/var/www/registry/data/_smoke.json`** — public, machine-readable status
   (HTTP-served at `https://croviatrust.com/registry/data/_smoke.json`).
   Schema:

   ```json
   {
     "schema": "crovia.smoke_public.v1",
     "checked_at": "2026-05-05T18:30:00Z",
     "n_checks": 11,
     "n_failed": 0,
     "ok": true,
     "results": [
       { "name": "check.html",  "url": "...", "status": 200, "ok": 1, "reason": "" },
       ...
     ]
   }
   ```

2. **`/var/log/crovia/smoke_public.log`** — one line per run, plus the failing
   results expanded under each non-zero run.

## Exit codes

- `0` — all checks pass.
- `2` — at least one check failed (cron MAILTO will deliver the script output).

## Adding a new check

Add a `check "<name>" "<url>" "<must_contain>" "<must_not_contain>"` line near
the other checks. For CORS-sensitive endpoints, also add a `check_cors` line so
the duplicate-`*` regression cannot recur.
