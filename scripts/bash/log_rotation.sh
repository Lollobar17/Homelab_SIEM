#!/usr/bin/env bash
# scripts/bash/log_rotation.sh
# Rotates and compresses SIEM log files to prevent unbounded disk usage.
# Run from project ROOT: bash scripts/bash/log_rotation.sh
#
# Schedule with cron (daily at 02:00):
#   0 2 * * * cd /path/to/Homelab_SIEM && bash scripts/bash/log_rotation.sh >> logs/rotation.log 2>&1
#
# Options:
#   --dry-run    Show what would be rotated without doing anything
#   --force      Rotate all logs regardless of size threshold

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LOGS_DIR="$ROOT_DIR/logs"
ARCHIVE_DIR="$LOGS_DIR/archive"

SIZE_THRESHOLD_MB="${LOG_ROTATION_SIZE_MB:-10}"
RETENTION_DAYS="${LOG_RETENTION_DAYS:-30}"

DRY_RUN=false
FORCE=false

for arg in "$@"; do
  case $arg in
    --dry-run) DRY_RUN=true ;;
    --force)   FORCE=true ;;
  esac
done

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'
BOLD='\033[1m'; NC='\033[0m'

ROTATED=0
DELETED=0
SKIPPED=0

echo ""
echo -e "${BOLD}  HomeLab SIEM — Log Rotation${NC}"
echo    "  $(date '+%Y-%m-%d %H:%M:%S')"
$DRY_RUN && echo -e "  ${YELLOW}[DRY RUN] No files will be modified.${NC}"
echo    "  ─────────────────────────────────────────"

mkdir -p "$ARCHIVE_DIR"

_rotate() {
  local log_path="$1"
  local log_name
  log_name="$(basename "$log_path")"

  if [ ! -f "$log_path" ]; then return; fi

  local size_bytes size_mb
  size_bytes=$(wc -c < "$log_path")
  size_mb=$(( size_bytes / 1024 / 1024 ))

  if ! $FORCE && [ "$size_mb" -lt "$SIZE_THRESHOLD_MB" ]; then
    echo -e "  ${CYAN}[SKIP]${NC}   $log_name — ${size_mb}MB < threshold ${SIZE_THRESHOLD_MB}MB"
    ((SKIPPED++))
    return
  fi

  local ts archive_name archive_path
  ts=$(date '+%Y%m%d_%H%M%S')
  archive_name="${log_name%.log}_${ts}.log.gz"
  archive_path="$ARCHIVE_DIR/$archive_name"

  echo -e "  ${GREEN}[ROTATE]${NC} $log_name — ${size_mb}MB → $archive_name"

  if ! $DRY_RUN; then
    gzip -c "$log_path" > "$archive_path"
    truncate -s 0 "$log_path"
    echo "# Log rotated at $(date '+%Y-%m-%d %H:%M:%S') — archived to $archive_name" > "$log_path"
  fi

  ((ROTATED++))
}

echo -e "\n${BOLD}  [1] Rotating logs (threshold: ${SIZE_THRESHOLD_MB}MB)${NC}"

_rotate "$LOGS_DIR/siem.log"
_rotate "$LOGS_DIR/azure_collector.log"
_rotate "$LOGS_DIR/azure_activity_collector.log"
_rotate "$LOGS_DIR/flask_access.log"
_rotate "$LOGS_DIR/rotation.log"

echo -e "\n${BOLD}  [2] Purging archives older than ${RETENTION_DAYS} days${NC}"

if [ -d "$ARCHIVE_DIR" ]; then
  while IFS= read -r old_file; do
    echo -e "  ${YELLOW}[DELETE]${NC} $(basename "$old_file")"
    if ! $DRY_RUN; then rm -f "$old_file"; fi
    ((DELETED++))
  done < <(find "$ARCHIVE_DIR" -name "*.log.gz" -mtime "+${RETENTION_DAYS}" 2>/dev/null)

  if [ "$DELETED" -eq 0 ]; then
    echo -e "  ${CYAN}[SKIP]${NC}   No archives older than ${RETENTION_DAYS} days found."
  fi
else
  echo -e "  ${CYAN}[SKIP]${NC}   Archive directory does not exist yet."
fi

echo -e "\n${BOLD}  [3] Archive status${NC}"

if [ -d "$ARCHIVE_DIR" ] && [ "$(ls -A "$ARCHIVE_DIR" 2>/dev/null)" ]; then
  archive_total=$(du -sh "$ARCHIVE_DIR" 2>/dev/null | cut -f1)
  archive_count=$(find "$ARCHIVE_DIR" -name "*.log.gz" | wc -l)
  echo -e "  ${CYAN}[INFO]${NC}   $archive_count archive(s) — total size: $archive_total"
else
  echo -e "  ${CYAN}[INFO]${NC}   No archives yet."
fi

echo ""
echo    "  ─────────────────────────────────────────"
echo -e "  ${BOLD}Results:${NC}  rotated ${ROTATED}  |  deleted ${DELETED}  |  skipped ${SKIPPED}"
$DRY_RUN && echo -e "  ${YELLOW}Dry run — no files were modified.${NC}"
echo    "  ─────────────────────────────────────────"
echo ""
