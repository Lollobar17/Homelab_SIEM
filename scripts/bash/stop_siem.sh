#!/usr/bin/env bash
# scripts/bash/stop_siem.sh
# Cleanly stops the full SIEM stack (app.py + Azure collectors).
# Run from project ROOT: bash scripts/bash/stop_siem.sh

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LOGS_DIR="$ROOT_DIR/logs"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

echo -e "${RED}=== HomeLab SIEM — Shutdown ===${NC}"

_stop_pid() {
  local label="$1"
  local pid_file="$2"

  if [ ! -f "$pid_file" ]; then
    echo -e "${YELLOW}[SKIP]  $label — PID file not found.${NC}"
    return
  fi

  local pid
  pid=$(cat "$pid_file")

  if kill -0 "$pid" 2>/dev/null; then
    kill "$pid"
    sleep 1
    if kill -0 "$pid" 2>/dev/null; then
      kill -9 "$pid"
      echo -e "${YELLOW}[WARN]  $label (PID $pid) force-killed.${NC}"
    else
      echo -e "${GREEN}[OK]${NC}    $label (PID $pid) stopped."
    fi
  else
    echo -e "${YELLOW}[SKIP]  $label — process $pid was not running.${NC}"
  fi

  rm -f "$pid_file"
}

_stop_pid "SIEM (app.py)"             "$LOGS_DIR/siem.pid"
_stop_pid "Azure Flow Collector"      "$LOGS_DIR/azure_collector.pid"
_stop_pid "Azure Activity Collector"  "$LOGS_DIR/azure_activity_collector.pid"

echo -e "${GREEN}Done.${NC}"
