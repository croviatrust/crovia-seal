#!/usr/bin/env bash
# disk_guard.sh — monitor root usage, mitigate at 90%, page at 95%.
# Run every 15 min via cron.
set -u
LOG=/var/log/crovia/disk_guard.log
STATUS=/var/www/registry/data/_disk_guard.json
TS=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

ROOT_USE=$(df -P / | awk "NR==2{gsub(\"%\",\"\",\$5); print \$5}")
ROOT_AVAIL_MB=$(df -P / | awk "NR==2{print int(\$4/1024)}")
VOL_USE=$(df -P /mnt/HC_Volume_104726399 2>/dev/null | awk "NR==2{gsub(\"%\",\"\",\$5); print \$5}")
VOL_AVAIL_MB=$(df -P /mnt/HC_Volume_104726399 2>/dev/null | awk "NR==2{print int(\$4/1024)}")
ACTIONS=()

# CRITICAL: 95%+ — auto-clean aggressively
if [ "$ROOT_USE" -ge 95 ]; then
  echo "$TS CRITICAL root_usage=${ROOT_USE}%, executing emergency cleanup" >> "$LOG"
  # truncate brute-force logs (always safe)
  truncate -s 0 /var/log/btmp /var/log/btmp.1 2>/dev/null && ACTIONS+=("truncated_btmp")
  # vacuum journals beyond 3 days
  journalctl --vacuum-time=3d >/dev/null 2>&1 && ACTIONS+=("journal_vacuum_3d")
  # docker prune (containers stopped)
  docker system prune -af --filter "until=24h" >/dev/null 2>&1 && ACTIONS+=("docker_prune")
  # apt cache
  apt-get clean >/dev/null 2>&1 && ACTIONS+=("apt_clean")
  # truncate big crovia logs (rotate manually)
  for f in /var/log/crovia/*.log; do
    if [ -f "$f" ] && [ $(stat -c %s "$f") -gt 104857600 ]; then  # >100MB
      tail -c 10485760 "$f" > "${f}.tmp" && mv "${f}.tmp" "$f"
      ACTIONS+=("truncated_$(basename $f)")
    fi
  done
fi

# WARN: 85%+ — preventive (keep last few backup files)
if [ "$ROOT_USE" -ge 85 ]; then
  cd /opt/crovia/backups/postgres 2>/dev/null && {
    # keep only last 3 dumps
    ls -t tpr_backup_*.sql.gz 2>/dev/null | tail -n +4 | while read f; do
      mv "$f" /mnt/HC_Volume_104726399/safety_backups/ 2>/dev/null && ACTIONS+=("archived_$(basename $f)")
    done
  }
fi

ACTIONS_JSON=$(printf "%s\n" "${ACTIONS[@]}" | python3 -c "import sys,json; print(json.dumps([l.strip() for l in sys.stdin if l.strip()]))")
SEVERITY="ok"
[ "$ROOT_USE" -ge 85 ] && SEVERITY="warn"
[ "$ROOT_USE" -ge 95 ] && SEVERITY="critical"

cat > "$STATUS" <<JSON
{
  "schema": "crovia.disk_guard.v1",
  "checked_at": "$TS",
  "root_used_pct": $ROOT_USE,
  "root_avail_mb": $ROOT_AVAIL_MB,
  "volume_used_pct": ${VOL_USE:-null},
  "volume_avail_mb": ${VOL_AVAIL_MB:-null},
  "severity": "$SEVERITY",
  "actions_taken": $ACTIONS_JSON
}
JSON
chmod 644 "$STATUS"
echo "$TS root=${ROOT_USE}% avail=${ROOT_AVAIL_MB}MB severity=$SEVERITY actions=${#ACTIONS[@]}" >> "$LOG"
