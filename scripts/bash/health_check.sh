#!/usr/bin/env bash
# scripts/bash/health_check.sh
# Checks the health of the full HomeLab SIEM stack.
# Run from project ROOT: bash scripts/bash/health_check.sh

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LOGS_DIR="$ROOT_DIR/logs"
SIEM_PID="$LOGS_DIR/siem.pid"
AZURE_PID="$LOGS_DIR/azure_collector.pid"
ACTIVITY_PID="$LOGS_DIR/azure_activity_collector.pid"
SENTINEL_PID="$LOGS_DIR/sentinel_collector.pid"
CALDERA_PID="$LOGS_DIR/caldera_collector.pid"
SIEM_URL="${SIEM_INGEST_URL:-http://localhost:5000}"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

PASS=0; FAIL=0

_ok()   { echo -e "  ${GREEN}[OK]${NC}    $1"; ((PASS++)); }
_fail() { echo -e "  ${RED}[FAIL]${NC}  $1"; ((FAIL++)); }
_warn() { echo -e "  ${YELLOW}[WARN]${NC}  $1"; }
_info() { echo -e "  ${CYAN}[INFO]${NC}  $1"; }

echo ""
echo -e "${BOLD}  HomeLab SIEM — Health Check${NC}"
echo    "  $(date '+%Y-%m-%d %H:%M:%S')"
echo    "  ─────────────────────────────────────────"

# ── 1. Processes ─────────────────────────────
echo -e "\n${BOLD}  [1] Processes${NC}"

if [ -f "$SIEM_PID" ] && kill -0 "$(cat "$SIEM_PID")" 2>/dev/null; then
  _ok "SIEM (app.py) running — PID $(cat "$SIEM_PID")"
else
  _fail "SIEM (app.py) is NOT running"
fi

if [ -f "$AZURE_PID" ] && kill -0 "$(cat "$AZURE_PID")" 2>/dev/null; then
  _ok "Azure Flow collector running — PID $(cat "$AZURE_PID")"
else
  _warn "Azure Flow collector not running"
fi

if [ -f "$ACTIVITY_PID" ] && kill -0 "$(cat "$ACTIVITY_PID")" 2>/dev/null; then
  _ok "Azure Activity collector running — PID $(cat "$ACTIVITY_PID")"
else
  _warn "Azure Activity collector not running"
fi

if [ -f "$SENTINEL_PID" ] && kill -0 "$(cat "$SENTINEL_PID")" 2>/dev/null; then
  _ok "Sentinel collector running — PID $(cat "$SENTINEL_PID")"
else
  _warn "Sentinel collector not running"
fi

if [ -f "$CALDERA_PID" ] && kill -0 "$(cat "$CALDERA_PID")" 2>/dev/null; then
  _ok "Caldera collector running — PID $(cat "$CALDERA_PID")"
else
  _warn "Caldera collector not running"
fi

# ── 2. HTTP Endpoints ────────────────────────
echo -e "\n${BOLD}  [2] HTTP Endpoints${NC}"

_check_endpoint() {
  local label="$1" url="$2" expected="${3:-200}"
  if command -v curl &>/dev/null; then
    local code
    code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 3 "$url" 2>/dev/null || echo "000")
    if [ "$code" = "$expected" ]; then _ok "$label → HTTP $code"
    else _fail "$label → HTTP $code (expected $expected)"; fi
  else
    _warn "curl not found — skipping $label"
  fi
}

_check_endpoint "GET /api/health"    "$SIEM_URL/api/health"    "200"
_check_endpoint "GET /api/stats"     "$SIEM_URL/api/stats"     "200"
_check_endpoint "GET /api/v1/stats"  "$SIEM_URL/api/v1/stats"  "200"
_check_endpoint "GET /api/events"    "$SIEM_URL/api/events"    "200"
_check_endpoint "GET /api/alerts"    "$SIEM_URL/api/alerts"    "200"

# ── 3. Log Files ─────────────────────────────
echo -e "\n${BOLD}  [3] Log Files${NC}"

_check_log() {
  local label="$1" path="$2" warn_mb="${3:-50}"
  if [ ! -f "$path" ]; then _warn "$label not found: $path"; return; fi
  local size_bytes size_mb
  size_bytes=$(wc -c < "$path")
  size_mb=$(( size_bytes / 1024 / 1024 ))
  if [ "$size_mb" -ge "$warn_mb" ]; then
    _warn "$label is ${size_mb}MB — run: bash scripts/bash/log_rotation.sh"
  else
    _ok "$label exists (${size_mb}MB)"
  fi
}

_check_log "siem.log"                      "$LOGS_DIR/siem.log"                      50
_check_log "azure_collector.log"           "$LOGS_DIR/azure_collector.log"           50
_check_log "azure_activity_collector.log"  "$LOGS_DIR/azure_activity_collector.log"  50
_check_log "sentinel_collector.log"        "$LOGS_DIR/sentinel_collector.log"        20
_check_log "caldera_collector.log"         "$LOGS_DIR/caldera_collector.log"         10
_check_log "flask_access.log"              "$LOGS_DIR/flask_access.log"              20

# ── 4. Storage ───────────────────────────────
echo -e "\n${BOLD}  [4] Storage${NC}"

DB_PATH="$ROOT_DIR/data/siem.db"
if [ -f "$DB_PATH" ]; then
  local_size=$(du -sh "$DB_PATH" 2>/dev/null | cut -f1)
  _ok "Database found — $local_size"
else
  _warn "Database not found at $DB_PATH"
fi

FREE_KB=$(df "$ROOT_DIR" | awk 'NR==2 {print $4}')
FREE_GB=$(( FREE_KB / 1024 / 1024 ))
if [ "$FREE_GB" -lt 1 ]; then
  _fail "Low disk space — ${FREE_GB}GB free"
else
  _ok "Disk space — ${FREE_GB}GB free"
fi

# ── 5. Azure + Sentinel credentials ──────────
echo -e "\n${BOLD}  [5] Azure & Sentinel${NC}"

if [ -f "$ROOT_DIR/config.json" ] && python3 -c "import json; d=json.load(open('$ROOT_DIR/config.json')); assert d.get('AZURE_STORAGE_CONNECTION_STRING')" 2>/dev/null; then
  _ok "AZURE_STORAGE_CONNECTION_STRING found in config.json"
else
  _warn "AZURE_STORAGE_CONNECTION_STRING not configured"
fi

if [ -f "$ROOT_DIR/config.json" ] && python3 -c "import json; d=json.load(open('$ROOT_DIR/config.json')); assert d.get('SENTINEL_CLIENT_ID')" 2>/dev/null; then
  _ok "Sentinel credentials found in config.json"
else
  _warn "Sentinel credentials not configured"
fi

if [ -f "$ROOT_DIR/config.json" ] && python3 -c "import json; d=json.load(open('$ROOT_DIR/config.json')); assert d.get('CALDERA_API_KEY')" 2>/dev/null; then
  _ok "Caldera API key found in config.json"
  CALDERA_URL=$(python3 -c "import json; d=json.load(open('$ROOT_DIR/config.json')); print(d.get('CALDERA_URL','http://127.0.0.1:8888'))" 2>/dev/null || echo "http://127.0.0.1:8888")
  if command -v curl &>/dev/null; then
    code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 3 -H "KEY: $(python3 -c "import json; print(json.load(open('$ROOT_DIR/config.json')).get('CALDERA_API_KEY',''))")" "$CALDERA_URL/api/v2/operations" 2>/dev/null || echo "000")
    if [ "$code" = "200" ]; then _ok "Caldera API reachable — HTTP $code"
    else _warn "Caldera API not reachable — HTTP $code"; fi
  fi
else
  _warn "Caldera credentials not configured"
fi

# ── 6. Python Environment ────────────────────
echo -e "\n${BOLD}  [6] Python Environment${NC}"

VENV_ACTIVATE=""
for candidate in "$ROOT_DIR/.venv/bin/activate" "$ROOT_DIR/.venv/Scripts/activate"; do
  if [ -f "$candidate" ]; then VENV_ACTIVATE="$candidate"; break; fi
done

if [ -n "$VENV_ACTIVATE" ]; then
  source "$VENV_ACTIVATE"
  _ok "Virtual environment found"
else
  _fail "Virtual environment not found"
fi

for pkg in flask requests azure-storage-blob msal; do
  pkg_import=$(echo "$pkg" | sed 's/-/_/g' | sed 's/azure_storage_blob/azure.storage.blob/')
  if python -c "import $pkg_import" 2>/dev/null; then _ok "Package: $pkg"
  else _fail "Package missing: $pkg — run: pip install $pkg"; fi
done

# ── Summary ──────────────────────────────────
echo ""
echo    "  ─────────────────────────────────────────"
echo -e "  ${BOLD}Results:${NC}  ${GREEN}${PASS} passed${NC}  |  ${RED}${FAIL} failed${NC}"
echo    "  ─────────────────────────────────────────"
echo ""

[ "$FAIL" -gt 0 ] && exit 1
exit 0
