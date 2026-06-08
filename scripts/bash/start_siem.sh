#!/usr/bin/env bash
# scripts/bash/start_siem.sh
# Starts the full HomeLab SIEM stack.
# Run from project ROOT: bash scripts/bash/start_siem.sh
#
# Flags:
#   --no-azure      Skip Azure + Sentinel collectors
#   --no-sentinel   Skip only Sentinel collector
#   --no-caldera    Skip Caldera collector
#   --with-caldera  Start Caldera collector (needs CALDERA_API_KEY)
#   --debug         Enable Flask debug mode

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LOGS_DIR="$ROOT_DIR/logs"
SIEM_LOG="$LOGS_DIR/siem.log"
SIEM_PID="$LOGS_DIR/siem.pid"
AZURE_PID="$LOGS_DIR/azure_collector.pid"
ACTIVITY_PID="$LOGS_DIR/azure_activity_collector.pid"
SENTINEL_PID="$LOGS_DIR/sentinel_collector.pid"
CALDERA_PID="$LOGS_DIR/caldera_collector.pid"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

RUN_AZURE=true
RUN_SENTINEL=true
RUN_CALDERA=auto
DEBUG_MODE=false

for arg in "$@"; do
  case $arg in
    --no-azure)    RUN_AZURE=false; RUN_SENTINEL=false ;;
    --no-sentinel) RUN_SENTINEL=false ;;
    --no-caldera)  RUN_CALDERA=false ;;
    --with-caldera) RUN_CALDERA=true ;;
    --debug)       DEBUG_MODE=true ;;
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
echo -e "${GREEN}  HomeLab SIEM — Startup Script (Azure + Sentinel Edition)${NC}"
echo    "  $(date '+%Y-%m-%d %H:%M:%S')"
echo    "  ─────────────────────────────────────────"

# ── Virtual environment ──────────────────────
VENV_ACTIVATE=""
for candidate in \
  "$ROOT_DIR/.venv/bin/activate" \
  "$ROOT_DIR/.venv/Scripts/activate"; do
  if [ -f "$candidate" ]; then VENV_ACTIVATE="$candidate"; break; fi
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
[ ${#MISSING[@]} -gt 0 ] && pip install "${MISSING[@]}" --quiet
if $RUN_AZURE; then
  python -c "import azure.storage.blob" 2>/dev/null || pip install azure-storage-blob --quiet
fi
if $RUN_SENTINEL; then
  python -c "import msal" 2>/dev/null || pip install msal --quiet
fi
echo -e "${GREEN}[OK]${NC}    Dependencies verified"

mkdir -p "$LOGS_DIR"

# ── Check already running ────────────────────
if [ -f "$SIEM_PID" ]; then
  OLD_PID=$(cat "$SIEM_PID")
  if kill -0 "$OLD_PID" 2>/dev/null; then
    echo -e "${YELLOW}[WARN]  SIEM already running (PID $OLD_PID).${NC}"
    echo "        Stop it first: bash scripts/bash/stop_siem.sh"
    exit 0
  else rm -f "$SIEM_PID"; fi
fi

# ── Start SIEM ───────────────────────────────
cd "$ROOT_DIR"
$DEBUG_MODE && export SIEM_DEBUG=1

echo -e "${CYAN}[....] Starting SIEM (app.py)...${NC}"
nohup python app.py >> "$SIEM_LOG" 2>&1 &
echo $! > "$SIEM_PID"
sleep 2

if kill -0 "$(cat "$SIEM_PID")" 2>/dev/null; then
  echo -e "${GREEN}[OK]${NC}    SIEM running — PID $(cat "$SIEM_PID") — http://localhost:5000"
else
  echo -e "${RED}[ERROR] SIEM crashed. Check: tail -30 $SIEM_LOG${NC}"; exit 1
fi

# ── Start Azure collectors ───────────────────
if $RUN_AZURE; then
  CONFIG_OK=false
  [ -f "$ROOT_DIR/config.json" ] && python -c "import json; d=json.load(open('$ROOT_DIR/config.json')); assert d.get('AZURE_STORAGE_CONNECTION_STRING')" 2>/dev/null && CONFIG_OK=true
  [ -n "${AZURE_STORAGE_CONNECTION_STRING:-}" ] && CONFIG_OK=true

  if ! $CONFIG_OK; then
    echo -e "${YELLOW}[SKIP]  Azure collectors skipped — AZURE_STORAGE_CONNECTION_STRING not set.${NC}"
  else
    for collector in azure_collector azure_activity_collector; do
      pid_file="$LOGS_DIR/${collector}.pid"
      log_file="$LOGS_DIR/${collector}.log"
      if [ -f "$pid_file" ] && kill -0 "$(cat "$pid_file")" 2>/dev/null; then
        echo -e "${YELLOW}[WARN]  $collector already running.${NC}"
      else
        rm -f "$pid_file"
        echo -e "${CYAN}[....] Starting $collector.py...${NC}"
        nohup python "azure_siem/${collector}.py" >> "$log_file" 2>&1 &
        echo $! > "$pid_file"
        sleep 1
        if kill -0 "$(cat "$pid_file")" 2>/dev/null; then
          echo -e "${GREEN}[OK]${NC}    $collector running — PID $(cat "$pid_file")"
        else
          echo -e "${RED}[ERROR] $collector crashed. Check: tail -20 $log_file${NC}"
        fi
      fi
    done
  fi
else
  echo -e "${YELLOW}[SKIP]  Azure collectors skipped (--no-azure).${NC}"
fi

# ── Start Sentinel collector ─────────────────
if $RUN_SENTINEL; then
  SENT_OK=false
  [ -f "$ROOT_DIR/config.json" ] && python -c "import json; d=json.load(open('$ROOT_DIR/config.json')); assert d.get('SENTINEL_CLIENT_ID')" 2>/dev/null && SENT_OK=true

  if ! $SENT_OK; then
    echo -e "${YELLOW}[SKIP]  Sentinel collector skipped — credentials not configured.${NC}"
  else
    if [ -f "$SENTINEL_PID" ] && kill -0 "$(cat "$SENTINEL_PID")" 2>/dev/null; then
      echo -e "${YELLOW}[WARN]  Sentinel collector already running.${NC}"
    else
      rm -f "$SENTINEL_PID"
      SENT_LOG="$LOGS_DIR/sentinel_collector.log"
      echo -e "${CYAN}[....] Starting sentinel_collector.py...${NC}"
      nohup python azure_siem/sentinel/sentinel_collector.py >> "$SENT_LOG" 2>&1 &
      echo $! > "$SENTINEL_PID"
      sleep 1
      if kill -0 "$(cat "$SENTINEL_PID")" 2>/dev/null; then
        echo -e "${GREEN}[OK]${NC}    Sentinel collector running — PID $(cat "$SENTINEL_PID")"
      else
        echo -e "${RED}[ERROR] Sentinel collector crashed. Check: tail -20 $SENT_LOG${NC}"
      fi
    fi
  fi
else
  echo -e "${YELLOW}[SKIP]  Sentinel collector skipped (--no-sentinel).${NC}"
fi

# ── Start Caldera collector (lightweight purple-team bridge) ──
if [ "$RUN_CALDERA" != "false" ]; then
  CALDERA_OK=false
  [ -f "$ROOT_DIR/config.json" ] && python -c "import json; d=json.load(open('$ROOT_DIR/config.json')); assert d.get('CALDERA_API_KEY')" 2>/dev/null && CALDERA_OK=true
  [ -n "${CALDERA_API_KEY:-}" ] && CALDERA_OK=true

  if [ "$RUN_CALDERA" = "auto" ] && ! $CALDERA_OK; then
    echo -e "${YELLOW}[SKIP]  Caldera collector skipped — CALDERA_API_KEY not set.${NC}"
  elif [ "$RUN_CALDERA" = "true" ] && ! $CALDERA_OK; then
    echo -e "${RED}[ERROR] --with-caldera set but CALDERA_API_KEY missing.${NC}"
  elif $CALDERA_OK; then
    if [ -f "$CALDERA_PID" ] && kill -0 "$(cat "$CALDERA_PID")" 2>/dev/null; then
      echo -e "${YELLOW}[WARN]  Caldera collector already running.${NC}"
    else
      rm -f "$CALDERA_PID"
      CALDERA_LOG="$LOGS_DIR/caldera_collector.log"
      echo -e "${CYAN}[....] Starting caldera_collector.py...${NC}"
      nohup python scripts/caldera_collector.py >> "$CALDERA_LOG" 2>&1 &
      echo $! > "$CALDERA_PID"
      sleep 1
      if kill -0 "$(cat "$CALDERA_PID")" 2>/dev/null; then
        echo -e "${GREEN}[OK]${NC}    Caldera collector running — PID $(cat "$CALDERA_PID")"
      else
        echo -e "${RED}[ERROR] Caldera collector crashed. Check: tail -20 $CALDERA_LOG${NC}"
      fi
    fi
  fi
else
  echo -e "${YELLOW}[SKIP]  Caldera collector skipped (--no-caldera).${NC}"
fi

# ── Summary ──────────────────────────────────
echo ""
echo    "  ─────────────────────────────────────────"
echo -e "  ${GREEN}Stack started successfully.${NC}"
echo    ""
echo    "  Dashboard     →  http://localhost:5000"
echo    "  SIEM log      →  tail -f $SIEM_LOG"
echo    ""
echo    "  Stop all      →  bash scripts/bash/stop_siem.sh"
echo    "  Health check  →  bash scripts/bash/health_check.sh"
echo    "  ─────────────────────────────────────────"
