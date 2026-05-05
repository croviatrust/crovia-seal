#!/usr/bin/env bash
# smoke_public.sh — public-surface smoke tests, runs every 15 min.
# Goal: catch regressions like the 2026-05-05 incidents within 15min,
# not 24h. Writes a status JSON consumed by /registry/_smoke.json.
set -u
LOG=/var/log/crovia/smoke_public.log
OUT=/var/www/registry/data/_smoke.json
TS=$(date -u +%Y-%m-%dT%H:%M:%SZ)
FAILED=0
declare -a RESULTS

check() {
  local name="$1" url="$2" must_contain="$3" must_not="$4"
  local body status
  body=$(curl -s -m 12 -w "\n%{http_code}" -H "Origin: https://croviatrust.com" "$url" 2>/dev/null || echo $"\n000")
  status=$(echo "$body" | tail -1)
  body=$(echo "$body" | head -n -1)
  local ok="1"
  local reason=""
  if [ "$status" != "200" ]; then ok="0"; reason="http_$status"; fi
  if [ -n "$must_contain" ] && ! echo "$body" | grep -qF "$must_contain"; then ok="0"; reason="${reason:-missing_marker}"; fi
  if [ -n "$must_not" ] && echo "$body" | grep -qF "$must_not"; then ok="0"; reason="${reason:-bad_marker_present}"; fi
  if [ "$ok" = "0" ]; then FAILED=$((FAILED+1)); fi
  RESULTS+=("{\"name\":\"$name\",\"url\":\"$url\",\"status\":$status,\"ok\":$ok,\"reason\":\"$reason\"}")
}

check_cors() {
  local name="$1" url="$2"
  local hdrs acao_count
  hdrs=$(curl -s -m 12 -D - -o /dev/null -H "Origin: https://croviatrust.com" "$url" 2>/dev/null)
  acao_count=$(echo "$hdrs" | grep -ci "^access-control-allow-origin:")
  local ok="1" reason=""
  if [ "$acao_count" -ne 1 ]; then ok="0"; reason="acao_count=$acao_count"; FAILED=$((FAILED+1)); fi
  RESULTS+=("{\"name\":\"$name\",\"url\":\"$url\",\"acao_count\":$acao_count,\"ok\":$ok,\"reason\":\"$reason\"}")
}

# --- consumer-facing pages: must load, NOT have JS-error markers ---
check "check.html"        "https://croviatrust.com/check.html"                      "ed.etc.sha512Sync"     "ed.hashes.sha512"
check "verifier"          "https://croviatrust.com/registry/v/"                     "every hour at :15 UTC" "04:15 UTC<"
check "substrate cockpit" "https://croviatrust.com/registry/substrate/"             "operational"           ""
check "chains explorer"   "https://croviatrust.com/registry/chains/"                "refreshing manifest"   ""

# --- public data feeds: must be valid JSON with expected shape ---
check "trust-root"        "https://seal.croviatrust.com/trust-root.json"            "trust_root_version"   ""
check "ots_anchors"       "https://croviatrust.com/registry/data/substrate/ots_anchors.json" "n_bitcoin"      ""
check "chains.json"       "https://croviatrust.com/registry/data/substrate/chains.json"      "axiom_ids"      ""
check "collectors.json"   "https://croviatrust.com/registry/data/substrate/collectors.json"  "collectors"     ""

# --- seal API: must be reachable AND return single ACAO header ---
SAMPLE_SEAL=sl_0caa8c89d4cb4e9e344c978fdb3031bce9094732
check "seal_api_get"      "https://seal.croviatrust.com/v1/seal/$SAMPLE_SEAL"       "seal_version"          ""
check_cors "seal_api_cors" "https://seal.croviatrust.com/v1/seal/$SAMPLE_SEAL"

# --- proof bundle coverage: a known-good axiom must resolve ---
KNOWN_AXIOM=axm_5db69ee63ae0333bc6e6342aef40b1aa12dbf5cbeacabe1df8bd23ad848fb9b7
check "proof_bundle"      "https://croviatrust.com/registry/data/substrate/proof/5d/${KNOWN_AXIOM}.json" "axiom_id" ""

# --- write status JSON ---
n=${#RESULTS[@]}
joined=$(IFS=,; echo "${RESULTS[*]}")
cat > "$OUT" <<JSON
{
  "schema": "crovia.smoke_public.v1",
  "checked_at": "$TS",
  "n_checks": $n,
  "n_failed": $FAILED,
  "ok": $([ $FAILED -eq 0 ] && echo true || echo false),
  "results": [$joined]
}
JSON
chmod 644 "$OUT"

echo "[$TS] $n checks, $FAILED failed" >> "$LOG"
if [ $FAILED -gt 0 ]; then
  echo "[$TS] FAILURES:" >> "$LOG"
  for r in "${RESULTS[@]}"; do
    if echo "$r" | grep -q "\"ok\":0"; then echo "  $r" >> "$LOG"; fi
  done
fi
exit $([ $FAILED -eq 0 ] && echo 0 || echo 2)
