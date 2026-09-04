#!/usr/bin/env python3
"""
simulate_caldera.py — Test Caldera rules without a live Caldera server.

Posts synthetic purple-team events to /api/v1/ingress.

Usage:
    python simulate_caldera.py
    python simulate_caldera.py --host http://localhost:5000 --burst 5
    python simulate_caldera.py --scenario lateral
"""

import argparse
import random
import sys
import time
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from siem.caldera_parser import parse_caldera_record  # noqa: E402

SCENARIOS = {
    "basic": [
        {"ability_name": "whoami", "host": "192.168.1.50", "platform": "linux",
         "technique_id": "T1033", "tactic": "discovery"},
    ],
    "lateral": [
        {"ability_name": "PsExec lateral", "host": "10.0.0.12", "platform": "windows",
         "technique_id": "T1021.002", "tactic": "lateral-movement", "command": "psexec \\\\target"},
    ],
    "persistence": [
        {"ability_name": "Create registry run key", "host": "10.0.0.12",
         "technique_id": "T1098", "tactic": "persistence"},
    ],
    "execution": [
        {"ability_name": "Run PowerShell", "host": "192.168.1.55",
         "technique_id": "T1059.001", "command": "powershell -enc ..."},
    ],
    "exfil": [
        {"ability_name": "Exfil staged data", "host": "192.168.1.60",
         "technique_id": "T1048", "tactic": "exfiltration"},
    ],
    "full": None,  # all of the above
}


def _build_events(scenario: str) -> list[dict]:
    op = {"id": "sim-op-1", "name": "simulated-operation", "state": "running"}
    keys = list(SCENARIOS.keys()) if scenario == "full" else [scenario]
    records = []
    for key in keys:
        if key == "full":
            continue
        records.extend(SCENARIOS.get(key, []))
    events = []
    for rec in records:
        ev = parse_caldera_record(rec, op)
        if ev:
            events.append(ev)
    return events


def main():
    parser = argparse.ArgumentParser(description="Simulate Caldera events for SIEM testing")
    parser.add_argument("--host", default="http://localhost:5000")
    parser.add_argument("--scenario", default="full", choices=list(SCENARIOS.keys()))
    parser.add_argument("--burst", type=int, default=1, help="Repeat scenario N times")
    args = parser.parse_args()

    url = f"{args.host.rstrip('/')}/api/v1/ingress"
    events = _build_events(args.scenario)
    if not events:
        print("No events for scenario:", args.scenario)
        return 1

    total_alerts = 0
    for n in range(args.burst):
        payload = {
            "events": [
                {
                    "message": e["raw"],
                    "source": e["source"],
                    "source_ip": e["fields"].get("src_ip"),
                    "event_type": e["fields"]["event_type"],
                    "timestamp": e["timestamp"],
                    "category": e["category"],
                    "fields": e["fields"],
                }
                for e in events
            ],
            "detect": True,
        }
        r = requests.post(url, json=payload, timeout=15)
        if r.status_code != 201:
            print(f"HTTP {r.status_code}: {r.text[:200]}")
            return 1
        alerts = sum(x.get("alerts", 0) for x in r.json().get("results", []))
        total_alerts += alerts
        print(f"Batch {n + 1}: {len(events)} events → {alerts} alert(s)")
        if n + 1 < args.burst:
            time.sleep(0.5)

    print(f"Done. {total_alerts} total alert(s). Check dashboard → Events (purple_team).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
