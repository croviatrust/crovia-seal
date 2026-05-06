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

## `disk_guard.sh`

Disk-pressure watchdog that runs every 15 minutes (offset by 7 min from the
smoke probe to avoid a thundering herd). It writes a public status JSON at
`https://croviatrust.com/registry/data/_disk_guard.json` and is itself checked
by `smoke_public.sh`, so a disk-pressure regression surfaces in the same
dashboard as the public-page regressions.

Severity ladder:

| Root disk | Severity   | Action taken                                          |
| --------- | ---------- | ----------------------------------------------------- |
| `< 85%`   | `ok`       | Log line only.                                        |
| `>= 85%`  | `warn`     | Archive PostgreSQL backups older than the last 3 to the Hetzner Cloud Volume. |
| `>= 95%`  | `critical` | Truncate `btmp/btmp.1`, `journalctl --vacuum-time=3d`, `docker system prune -af`, `apt-get clean`, truncate any `/var/log/crovia/*.log` >100MB to its last 10MB. |

The `actions_taken` array in the status JSON records exactly which mitigations
fired on the most recent run, so the audit trail is self-documenting.

## Post-mortem 2026-05-06 — `/dev/sda1` 100% full + SSH starvation

Around 17:25 CEST the production server (`CroviaTrsut-1`, CX43) became
unreachable: SSH connections timed out during banner exchange, the public
pages stopped responding, and Hetzner's metric panel showed 300% CPU and
1.5 GB/s sustained disk reads.

**Root cause**: `/dev/sda1` was 100% full (23 MB free of 38 GB). ext4 in
out-of-space conditions enters a panic-scan mode where every allocation
requires a near-exhaustive read of the free-blocks bitmap, which produced
the 1.5 GB/s sustained read figure. With the disk pinned, sshd could not
finish even its TCP banner exchange.

**Contributing factors** (the things that filled the disk):

1. `/root/.latent_cache` (2.7 GB of orphaned tensor binaries from March)
   was never cleaned up after a refactor that moved the live cache to a
   bind-mounted location on the Cloud Volume.
2. `/opt/crovia/venv` (300 MB) was a stale duplicate of `/opt/crovia/.venv`
   left behind from a January migration.
3. Two daily PostgreSQL dumps (`tpr_backup_*.sql.gz`, ~265 MB each) had
   accumulated on root instead of being rotated to the volume.
4. `/var/log/btmp` had grown to 90 MB of failed-login records, evidence of
   an active SSH brute-force attempt that was a constant secondary I/O
   drain.

**Recovery** (executed 17:32–17:45 CEST):

1. Power-cycled the host via Hetzner Console (the only path with the
   filesystem in panic).
2. Killed any in-flight `axiom_proof_regen.sh` and wrapped the cron entry
   in `flock -n /var/lock/crovia.regen.lock` so multiple runs cannot stack.
3. Archived the orphaned latent cache, the stale venv, and the older
   PostgreSQL dump to the Cloud Volume; truncated `btmp`/`btmp.1`.
4. Expanded the Cloud Volume from 49 GB to 100 GB on the Hetzner side and
   ran `resize2fs /dev/sdb` online (no remount).
5. Migrated `/var/www/registry/data/substrate/proof/` (1.1 GB, written
   hourly by the regen, read by every public verifier hit) to the Cloud
   Volume with a symlink so the public URL is unchanged. This both freed
   space on root and offloaded the regen's hot-path I/O.
6. Promoted `disk_guard.sh` from a passive logger into an active
   auto-mitigator with the severity ladder documented above and exposed
   its status as a public JSON consumed by the smoke probe.

**Final state**: root 87%/4.8 GB free, volume 44%/53 GB free, smoke 12/12
green, load average 0.77.

**Lessons that became checks**:

- The smoke probe now hits `/registry/data/_disk_guard.json` and fails on
  `"severity":"critical"`. Disk pressure now surfaces with the same 15-min
  detection latency as broken JS or duplicate CORS headers.
- The hourly regen cannot stack on itself any more (`flock`).
- Hot-path artefacts that grow without bound (proof bundles) live on the
  Cloud Volume, never on the root device.

## Adding a new check

Add a `check "<name>" "<url>" "<must_contain>" "<must_not_contain>"` line near
the other checks. For CORS-sensitive endpoints, also add a `check_cors` line so
the duplicate-`*` regression cannot recur.
