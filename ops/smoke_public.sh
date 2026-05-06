#!/usr/bin/env bash
# smoke_public.sh — public-surface smoke tests, runs every 15 min.
# Goal: catch regressions like the 2026-05-05/06 incidents within 15min.
# Writes /var/www/registry/data/_smoke.json (machine-readable, public).
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
  local esc_url=$(echo -n "$url" | sed "s|\"|\\\\\"|g")
  RESULTS+=("{\"name\":\"$name\",\"url\":\"$esc_url\",\"status\":$status,\"ok\":$ok,\"reason\":\"$reason\"}")
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

# ============================================================================
# CONSUMER PAGES — must load + contain page-unique title fragment
# (anti-regressions on critical pages also have must_not_contain markers)
# ============================================================================
C="https://croviatrust.com"

# Homepage + brand pages
check "home"               "$C/"                         "Signed Temporal Ledger"               ""
check "check.html"         "$C/check.html"               "Is this AI output"                    "ed.hashes.sha512"
check "whitepaper"         "$C/whitepaper.html"          "Evidence Infrastructure"              ""
check "how-to-read"        "$C/how-to-read.html"         "How to Read Crovia"                   ""
check "absence-clock"      "$C/absence-clock.html"       "Silence Observatory"                  ""
check "alive"              "$C/alive.html"               "System is Alive"                      ""

# Registry index + 19 sub-pages
check "registry"           "$C/registry/"                "Training Provenance"                  ""
check "registry/provenance"      "$C/registry/provenance/"      "Provenance Graph"              ""
check "registry/compliance"      "$C/registry/compliance/"      "Compliance"                    ""
check "registry/enterprise"      "$C/registry/enterprise/"      "Enterprise Intelligence"       ""
check "registry/chains"          "$C/registry/chains/"          "refreshing manifest"           ""
check "registry/forensics"       "$C/registry/forensics/"       "Forensic Dossiers"             ""
check "registry/verify"          "$C/registry/verify/"          "Crovia Passport"               ""
check "registry/substrate"       "$C/registry/substrate/"       "operational"                   ""
check "registry/ranking"         "$C/registry/ranking/"         "Compliance Ranking"            ""
check "registry/v"               "$C/registry/v/"               "every hour at :15 UTC"         "04:15 UTC<"
check "registry/diamond"         "$C/registry/diamond/"         "Diamond Archive"               ""
check "registry/lineage"         "$C/registry/lineage/"         "Disclosure Lineage"            ""
check "registry/cep"             "$C/registry/cep/"             "CEP Terminal"                  ""
check "registry/omissions"       "$C/registry/omissions/"       "Registry Observer"             ""
check "registry/risk"            "$C/registry/risk/"            "Dataset Risk Index"            ""
check "registry/tpa"             "$C/registry/tpa/"             "Temporal Proof of Absence"     ""
check "registry/pont"            "$C/registry/pont/"            "Proof of Non-Training"         ""
check "registry/seal"            "$C/registry/seal/"            "Open Provenance Receipt"       ""
check "registry/seal/spec"       "$C/registry/seal/spec/"       "Seal Specification"            ""
check "registry/seal/threat-model" "$C/registry/seal/threat-model/" "Seal Threat Model"          ""

# Seal subdomain
check "seal_root"          "https://seal.croviatrust.com/"        "Crovia Seal Trust Root"      ""
check "trust-root.json"    "https://seal.croviatrust.com/trust-root.json"     "trust_root_version"   ""
check "trust-root.sig.json" "https://seal.croviatrust.com/trust-root.sig.json" "signature_hex"      ""
check "seal_health"        "https://seal.croviatrust.com/health"  ""                              ""

# ============================================================================
# DATA FEEDS — must be valid JSON with expected shape
# ============================================================================
check "ots_anchors"        "$C/registry/data/substrate/ots_anchors.json" "n_bitcoin"             ""
check "chains.json"        "$C/registry/data/substrate/chains.json"      "axiom_ids"             ""
check "collectors.json"    "$C/registry/data/substrate/collectors.json"  "collectors"            ""

# ============================================================================
# SEAL API — reachable + exactly one ACAO header (anti 2026-05-05 dup-CORS)
# ============================================================================
SAMPLE_SEAL=sl_0caa8c89d4cb4e9e344c978fdb3031bce9094732
check "seal_api_get"       "https://seal.croviatrust.com/v1/seal/$SAMPLE_SEAL"   "seal_version"   ""
check_cors "seal_api_cors" "https://seal.croviatrust.com/v1/seal/$SAMPLE_SEAL"

# ============================================================================
# PROOF BUNDLE COVERAGE — known axiom must resolve
# ============================================================================
KNOWN_AXIOM=axm_5db69ee63ae0333bc6e6342aef40b1aa12dbf5cbeacabe1df8bd23ad848fb9b7
check "proof_bundle"       "$C/registry/data/substrate/proof/5d/${KNOWN_AXIOM}.json" "axiom_id"   ""

# ============================================================================
# HOST DISK HEALTH — anti 2026-05-06 disk-full incident
# ============================================================================
check "disk_guard"         "$C/registry/data/_disk_guard.json"           "severity"              "critical"

# ============================================================================
# Aggregate output
# ============================================================================
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
