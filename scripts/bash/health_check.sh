#!/usr/bin/env bash
# scripts/bash/health_check.sh
# Checks the health of the full HomeLab SIEM stack.
# Run from project ROOT: bash scripts/bash/health_check.sh
#
# Exit codes:
#   0 — all checks passed
#   1 — one or more checks failed

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LOGS_DIR="$ROOT_DIR/logs"
SIEM_PID="$LOGS_DIR/siem.pid"
AZURE_PID="$LOGS_DIR/azure_collector.pid"
ACTIVITY_PID="$LOGS_DIR/azure_activity_collector.pid"
SIEM_URL="${SIEM_INGEST_URL:-http://localhost:5000}"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

PASS=0
FAIL=0

_ok()   { echo -e "  ${GREEN}[OK]${NC}    $1"; ((PASS++)); }
_fail() { echo -e "  ${RED}[FAIL]${NC}  $1"; ((FAIL++)); }
_warn() { echo -e "  ${YELLOW}[WARN]${NC}  $1"; }
_info() { echo -e "  ${CYAN}[INFO]${NC}  $1"; }

echo ""
echo -e "${BOLD}  HomeLab SIEM — Health Check${NC}"
echo    "  $(date '+%Y-%m-%d %H:%M:%S')"
echo    "  ─────────────────────────────────────────"

# ── 1. Process checks ────────────────────────
echo -e "\n${BOLD}  [1] Processes${NC}"

if [ -f "$SIEM_PID" ] && kill -0 "$(cat "$SIEM_PID")" 2>/dev/null; then
  _ok "SIEM (app.py) running — PID $(cat "$SIEM_PID")"
else
  _fail "SIEM (app.py) is NOT running"
fi

if [ -f "$AZURE_PID" ] && kill -0 "$(cat "$AZURE_PID")" 2>/dev/null; then
  _ok "Azure Flow collector running — PID $(cat "$AZURE_PID")"
else
  _warn "Azure Flow collector not running (expected if --no-azure)"
fi

if [ -f "$ACTIVITY_PID" ] && kill -0 "$(cat "$ACTIVITY_PID")" 2>/dev/null; then
  _ok "Azure Activity collector running — PID $(cat "$ACTIVITY_PID")"
else
  _warn "Azure Activity collector not running"
fi

# ── 2. HTTP endpoint checks ──────────────────
echo -e "\n${BOLD}  [2] HTTP Endpoints${NC}"

_check_endpoint() {
  local label="$1"
  local url="$2"
  local expected_code="${3:-200}"

  if command -v curl &>/dev/null; then
    local code
    code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 3 "$url" 2>/dev/null || echo "000")
    if [ "$code" = "$expected_code" ]; then
      _ok "$label → HTTP $code"
    else
      _fail "$label → HTTP $code (expected $expected_code)"
    fi
  else
    _warn "curl not found — skipping $label check"
  fi
}

_check_endpoint "GET /api/health"  "$SIEM_URL/api/health"  "200"
_check_endpoint "GET /api/stats"   "$SIEM_URL/api/stats"   "200"
_check_endpoint "GET /api/events"  "$SIEM_URL/api/events"  "200"
_check_endpoint "GET /api/alerts"  "$SIEM_URL/api/alerts"  "200"

# ── 3. Log file checks ───────────────────────
echo -e "\n${BOLD}  [3] Log Files${NC}"

_check_log() {
  local label="$1"
  local path="$2"
  local warn_size_mb="${3:-50}"

  if [ ! -f "$path" ]; then
    _warn "$label not found (may not have started yet): $path"
    return
  fi

  local size_bytes size_mb
  size_bytes=$(wc -c < "$path")
  size_mb=$(( size_bytes / 1024 / 1024 ))

  if [ "$size_mb" -ge "$warn_size_mb" ]; then
    _warn "$label is ${size_mb}MB — consider running: bash scripts/bash/log_rotation.sh"
  else
    _ok "$label exists (${size_mb}MB)"
  fi
}

_check_log "siem.log"                   "$LOGS_DIR/siem.log"                   50
_check_log "azure_collector.log"        "$LOGS_DIR/azure_collector.log"        50
_check_log "azure_activity_collector"   "$LOGS_DIR/azure_activity_collector.log" 50
_check_log "flask_access.log"           "$LOGS_DIR/flask_access.log"           20

# ── 4. Storage check ─────────────────────────
echo -e "\n${BOLD}  [4] Storage${NC}"

DB_PATH="$ROOT_DIR/data/siem.db"
if [ -f "$DB_PATH" ]; then
  local_size=$(du -sh "$DB_PATH" 2>/dev/null | cut -f1)
  _ok "Database found — $local_size ($DB_PATH)"
else
  _warn "Database not found at $DB_PATH"
fi

FREE_KB=$(df "$ROOT_DIR" | awk 'NR==2 {print $4}')
FREE_GB=$(( FREE_KB / 1024 / 1024 ))
if [ "$FREE_GB" -lt 1 ]; then
  _fail "Low disk space — ${FREE_GB}GB free on partition"
else
  _ok "Disk space — ${FREE_GB}GB free"
fi

# ── 5. Azure credentials check ───────────────
echo -e "\n${BOLD}  [5] Azure${NC}"

if [ -n "${AZURE_STORAGE_CONNECTION_STRING:-}" ]; then
  _ok "AZURE_STORAGE_CONNECTION_STRING set via environment"
elif [ -f "$ROOT_DIR/config.json" ] && grep -q "AZURE_STORAGE_CONNECTION_STRING" "$ROOT_DIR/config.json" 2>/dev/null; then
  _ok "AZURE_STORAGE_CONNECTION_STRING found in config.json"
else
  _warn "AZURE_STORAGE_CONNECTION_STRING not found (required for Azure collectors)"
fi

# ── 6. Python environment ────────────────────
echo -e "\n${BOLD}  [6] Python Environment${NC}"

VENV_ACTIVATE=""
for candidate in \
  "$ROOT_DIR/.venv/bin/activate" \
  "$ROOT_DIR/.venv/Scripts/activate"; do
  if [ -f "$candidate" ]; then
    VENV_ACTIVATE="$candidate"
    break
  fi
done

if [ -n "$VENV_ACTIVATE" ]; then
  source "$VENV_ACTIVATE"
  _ok "Virtual environment found"
else
  _fail "Virtual environment not found"
fi

for pkg in flask requests azure-storage-blob; do
  pkg_import=$(echo "$pkg" | sed 's/-/_/g' | sed 's/azure_storage_blob/azure.storage.blob/')
  if python -c "import $pkg_import" 2>/dev/null; then
    _ok "Package: $pkg"
  else
    _fail "Package missing: $pkg — run: pip install $pkg"
  fi
done

# ── Summary ──────────────────────────────────
echo ""
echo    "  ─────────────────────────────────────────"
echo -e "  ${BOLD}Results:${NC}  ${GREEN}${PASS} passed${NC}  |  ${RED}${FAIL} failed${NC}"
echo    "  ─────────────────────────────────────────"
echo ""

if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
exit 0
