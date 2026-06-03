#!/usr/bin/env bash
# scripts/bash/start_azure_collector.sh
# Starts azure_collector.py and azure_activity_collector.py as background processes.
# Run from project ROOT: bash scripts/bash/start_azure_collector.sh

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LOGS_DIR="$ROOT_DIR/logs"
FLOW_LOG="$LOGS_DIR/azure_collector.log"
FLOW_PID="$LOGS_DIR/azure_collector.pid"
ACTIVITY_LOG="$LOGS_DIR/azure_activity_collector.log"
ACTIVITY_PID="$LOGS_DIR/azure_activity_collector.pid"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

echo -e "${GREEN}=== HomeLab SIEM — Azure Collectors ===${NC}"

# ── Virtual environment ──────────────────────
VENV_ACTIVATE=""
for candidate in \
  "$ROOT_DIR/.venv/bin/activate" \
  "$ROOT_DIR/.venv/Scripts/activate"; do
  if [ -f "$candidate" ]; then
    VENV_ACTIVATE="$candidate"
    break
  fi
done

if [ -z "$VENV_ACTIVATE" ]; then
  echo -e "${RED}[ERROR] Virtual environment not found in .venv/${NC}"
  exit 1
fi

source "$VENV_ACTIVATE"

# ── Dependencies ─────────────────────────────
python -c "import azure.storage.blob" 2>/dev/null || {
  echo -e "${YELLOW}[WARN]  azure-storage-blob not found — installing...${NC}"
  pip install azure-storage-blob --quiet
}
python -c "import requests" 2>/dev/null || {
  echo -e "${YELLOW}[WARN]  requests not found — installing...${NC}"
  pip install requests --quiet
}

# ── Config check ─────────────────────────────
CONFIG_OK=false
if [ -f "$ROOT_DIR/config.json" ] && grep -q "AZURE_STORAGE_CONNECTION_STRING" "$ROOT_DIR/config.json" 2>/dev/null; then
  CONFIG_OK=true
fi
[ -n "${AZURE_STORAGE_CONNECTION_STRING:-}" ] && CONFIG_OK=true

if ! $CONFIG_OK; then
  echo -e "${RED}[ERROR] AZURE_STORAGE_CONNECTION_STRING not found in config.json${NC}"
  exit 1
fi

mkdir -p "$LOGS_DIR"
cd "$ROOT_DIR"

# ── Start Flow Logs collector ─────────────────
if [ -f "$FLOW_PID" ] && kill -0 "$(cat "$FLOW_PID")" 2>/dev/null; then
  echo -e "${YELLOW}[WARN]  Azure Flow collector already running (PID $(cat "$FLOW_PID")).${NC}"
else
  rm -f "$FLOW_PID"
  echo -e "${GREEN}[INFO]  Starting azure_collector.py...${NC}"
  nohup python azure_collector.py >> "$FLOW_LOG" 2>&1 &
  echo $! > "$FLOW_PID"
  sleep 1
  if kill -0 "$(cat "$FLOW_PID")" 2>/dev/null; then
    echo -e "${GREEN}[OK]    Azure Flow collector started (PID $(cat "$FLOW_PID"))${NC}"
  else
    echo -e "${RED}[ERROR] Azure Flow collector crashed. Check: tail -20 $FLOW_LOG${NC}"
  fi
fi

# ── Start Activity Log collector ──────────────
if [ -f "$ACTIVITY_PID" ] && kill -0 "$(cat "$ACTIVITY_PID")" 2>/dev/null; then
  echo -e "${YELLOW}[WARN]  Azure Activity collector already running (PID $(cat "$ACTIVITY_PID")).${NC}"
else
  rm -f "$ACTIVITY_PID"
  echo -e "${GREEN}[INFO]  Starting azure_activity_collector.py...${NC}"
  nohup python azure_activity_collector.py >> "$ACTIVITY_LOG" 2>&1 &
  echo $! > "$ACTIVITY_PID"
  sleep 1
  if kill -0 "$(cat "$ACTIVITY_PID")" 2>/dev/null; then
    echo -e "${GREEN}[OK]    Azure Activity collector started (PID $(cat "$ACTIVITY_PID"))${NC}"
  else
    echo -e "${RED}[ERROR] Azure Activity collector crashed. Check: tail -20 $ACTIVITY_LOG${NC}"
  fi
fi

echo ""
echo "  Tail logs:"
echo "    Flow     →  tail -f $FLOW_LOG"
echo "    Activity →  tail -f $ACTIVITY_LOG"
echo "  Stop all   →  bash scripts/bash/stop_siem.sh"
