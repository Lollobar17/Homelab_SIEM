#!/usr/bin/env bash
# scripts/start_siem.sh
# Starts the full HomeLab SIEM stack (Flask app + Azure collector).
# Run from project ROOT: bash scripts/start_siem.sh
#
# Optional flags:
#   --no-azure     Skip Azure collector (run SIEM only)
#   --debug        Enable Flask debug mode (SIEM_DEBUG=1)

set -euo pipefail

# ── Path resolution (works on Windows, Linux, WSL) ──
# Scripts live in scripts/ (one level below root)
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LOGS_DIR="$ROOT_DIR/logs"
SIEM_LOG="$LOGS_DIR/siem.log"
SIEM_PID="$LOGS_DIR/siem.pid"
AZURE_PID="$LOGS_DIR/azure_collector.pid"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

RUN_AZURE=true
DEBUG_MODE=false

for arg in "$@"; do
  case $arg in
    --no-azure) RUN_AZURE=false ;;
    --debug)    DEBUG_MODE=true ;;
  esac
done

echo -e "${CYAN}"
echo "  ██╗  ██╗ ██████╗ ███╗   ███╗███████╗██╗      █████╗ ██████╗ "
echo "  ██║  ██║██╔═══██╗████╗ ████║██╔════╝██║     ██╔══██╗██╔══██╗"
echo "  ███████║██║   ██║██╔████╔██║█████╗  ██║     ███████║██████╔╝"
echo "  ██╔══██║██║   ██║██║╚██╔╝██║██╔══╝  ██║     ██╔══██║██╔══██╗"
echo "  ██║  ██║╚██████╔╝██║ ╚═╝ ██║███████╗███████╗██║  ██║██████╔╝"
echo "  ╚═╝  ╚═╝ ╚═════╝ ╚═╝     ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝╚═════╝ "
echo -e "${NC}"
echo -e "${GREEN}  HomeLab SIEM — Startup Script (Azure Edition)${NC}"
echo    "  $(date '+%Y-%m-%d %H:%M:%S')"
echo    "  ─────────────────────────────────────────"

# ── Virtual environment ──────────────────────
VENV_ACTIVATE=""
for candidate in \
  "$ROOT_DIR/.venv/bin/activate" \
  "$ROOT_DIR/.venv/Scripts/activate" \
  "$ROOT_DIR/.venv-linux/bin/activate"; do
  if [ -f "$candidate" ]; then
    VENV_ACTIVATE="$candidate"
    break
  fi
done

if [ -z "$VENV_ACTIVATE" ]; then
  echo -e "${RED}[ERROR] Virtual environment not found.${NC}"
  echo "        Create it with: python3 -m venv .venv"
  exit 1
fi

source "$VENV_ACTIVATE"
echo -e "${GREEN}[OK]${NC}    Virtual environment activated"

# ── Dependencies ─────────────────────────────
MISSING=()
python -c "import flask"    2>/dev/null || MISSING+=("flask")
python -c "import requests" 2>/dev/null || MISSING+=("requests")
if [ ${#MISSING[@]} -gt 0 ]; then
  echo -e "${YELLOW}[WARN]  Missing packages: ${MISSING[*]} — installing...${NC}"
  pip install "${MISSING[@]}" --quiet
fi
if $RUN_AZURE; then
  python -c "import azure.storage.blob" 2>/dev/null || {
    echo -e "${YELLOW}[WARN]  azure-storage-blob not found — installing...${NC}"
    pip install azure-storage-blob --quiet
  }
fi
echo -e "${GREEN}[OK]${NC}    Dependencies verified"

mkdir -p "$LOGS_DIR"

# ── Check if SIEM already running ───────────
if [ -f "$SIEM_PID" ]; then
  OLD_PID=$(cat "$SIEM_PID")
  if kill -0 "$OLD_PID" 2>/dev/null; then
    echo -e "${YELLOW}[WARN]  SIEM already running (PID $OLD_PID).${NC}"
    echo "        Stop it first: bash scripts/stop_siem.sh"
    exit 0
  else
    rm -f "$SIEM_PID"
  fi
fi

# ── Start SIEM ───────────────────────────────
cd "$ROOT_DIR"
$DEBUG_MODE && export SIEM_DEBUG=1 && echo -e "${YELLOW}[INFO]  Debug mode enabled${NC}"

echo -e "${CYAN}[....] Starting SIEM (app.py)...${NC}"
nohup python app.py >> "$SIEM_LOG" 2>&1 &
echo $! > "$SIEM_PID"
sleep 2

if kill -0 "$(cat "$SIEM_PID")" 2>/dev/null; then
  echo -e "${GREEN}[OK]${NC}    SIEM running   — PID $(cat "$SIEM_PID") — http://localhost:5000"
else
  echo -e "${RED}[ERROR] SIEM crashed. Check: tail -30 $SIEM_LOG${NC}"
  exit 1
fi

# ── Start Azure Collector ────────────────────
if $RUN_AZURE; then
  CONFIG_OK=false
  if [ -f "$ROOT_DIR/config.json" ]; then
    python -c "import json; d=json.load(open('$ROOT_DIR/config.json')); assert d.get('AZURE_STORAGE_CONNECTION_STRING')" 2>/dev/null && CONFIG_OK=true
  fi
  [ -n "${AZURE_STORAGE_CONNECTION_STRING:-}" ] && CONFIG_OK=true

  if ! $CONFIG_OK; then
    echo -e "${YELLOW}[SKIP]  Azure collector skipped — AZURE_STORAGE_CONNECTION_STRING not set.${NC}"
  else
    if [ -f "$AZURE_PID" ] && kill -0 "$(cat "$AZURE_PID")" 2>/dev/null; then
      echo -e "${YELLOW}[WARN]  Azure collector already running (PID $(cat "$AZURE_PID")).${NC}"
    else
      AZURE_LOG="$LOGS_DIR/azure_collector.log"
      echo -e "${CYAN}[....] Starting Azure collector...${NC}"
      nohup python azure_collector.py >> "$AZURE_LOG" 2>&1 &
      echo $! > "$AZURE_PID"
      sleep 1
      if kill -0 "$(cat "$AZURE_PID")" 2>/dev/null; then
        echo -e "${GREEN}[OK]${NC}    Azure collector running — PID $(cat "$AZURE_PID")"
      else
        echo -e "${RED}[ERROR] Azure collector crashed. Check: tail -30 $AZURE_LOG${NC}"
      fi
    fi
  fi
else
  echo -e "${YELLOW}[SKIP]  Azure collector skipped (--no-azure flag).${NC}"
fi

# ── Summary ──────────────────────────────────
echo ""
echo    "  ─────────────────────────────────────────"
echo -e "  ${GREEN}Stack started successfully.${NC}"
echo    ""
echo    "  Dashboard     →  http://localhost:5000"
echo    "  SIEM log      →  tail -f $SIEM_LOG"
[ -f "$AZURE_PID" ] && echo "  Azure log     →  tail -f $LOGS_DIR/azure_collector.log"
echo    ""
echo    "  Stop all      →  bash scripts/bash/stop_siem.sh"
echo    "  Health check  →  bash scripts/bash/health_check.sh"
echo    "  ─────────────────────────────────────────"
