#!/usr/bin/env python3
"""
arachne_collector.py — ArachneC2 Event Collector
Reads JSONL events from ArachneC2 simulator and forwards them to HomeLab SIEM.

Usage:
    python3 arachne_collector.py [--log /tmp/arachne-events.jsonl] [--siem http://localhost:5000]

Place in: scripts/arachne_collector.py
"""

import argparse
import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import requests

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)
logger = logging.getLogger(__name__)

# ── Event normalization ────────────────────────────────────────────────────────

def normalize_beacon(raw: dict) -> dict:
    return {
        "timestamp": raw.get("timestamp", datetime.now(timezone.utc).isoformat()),
        "source": "arachne_c2",
        "source_ip": "127.0.0.1",
        "destination_ip": raw.get("target_url", "").split("//")[-1].split(":")[0] or "unknown",
        "event_type": "c2_beacon",
        "severity": "HIGH",
        "category": "c2_communication",
        "message": (
            f"C2 beacon from node {raw.get('node_id', 'unknown')} "
            f"to {raw.get('target_url', 'unknown')} "
            f"(mimic={raw.get('mimic_host', '')}, "
            f"success={raw.get('success', False)})"
        ),
        "fields": {
            "node_id": raw.get("node_id"),
            "mimic_domain": raw.get("mimic_host"),
            "user_agent": raw.get("user_agent"),
            "jitter_ms": raw.get("jitter_ms"),
            "success": raw.get("success"),
            "tactic": "C2",
            "technique": "T1071.001",  # Application Layer Protocol: Web
        }
    }


def normalize_peer(raw: dict) -> dict:
    event_type = raw.get("event_type", "peer_communication")
    severity = "CRITICAL" if event_type == "lateral_movement" else "HIGH"
    technique = "T1021" if event_type == "lateral_movement" else "T1090"

    return {
        "timestamp": raw.get("timestamp", datetime.now(timezone.utc).isoformat()),
        "source": "arachne_c2",
        "source_ip": "127.0.0.1",
        "destination_ip": raw.get("peer_address", "unknown"),
        "event_type": event_type,
        "severity": severity,
        "category": "c2_communication",
        "message": (
            f"ArachneC2 {event_type}: node {raw.get('node_id', 'unknown')} "
            f"→ {raw.get('peer_address', 'unknown')} "
            f"[{raw.get('message_type', '')}] "
            f"(success={raw.get('success', False)}, latency={raw.get('latency_ms', 0)}ms)"
        ),
        "fields": {
            "node_id": raw.get("node_id"),
            "peer_address": raw.get("peer_address"),
            "message_type": raw.get("message_type"),
            "latency_ms": raw.get("latency_ms"),
            "success": raw.get("success"),
            "tactic": "LateralMovement" if event_type == "lateral_movement" else "C2",
            "technique": technique,
        }
    }


def normalize_exfil(raw: dict) -> dict:
    return {
        "timestamp": raw.get("timestamp", datetime.now(timezone.utc).isoformat()),
        "source": "arachne_c2",
        "source_ip": "127.0.0.1",
        "destination_ip": raw.get("target_ip", "unknown"),
        "event_type": "data_exfiltration",
        "severity": "CRITICAL",
        "category": "exfiltration",
        "message": (
            f"ArachneC2 data exfiltration: chunk {raw.get('chunk_index', 0)}/{raw.get('total_chunks', 0)} "
            f"({raw.get('chunk_size_kb', 0)}KB) → {raw.get('target_ip', 'unknown')} "
            f"[{raw.get('mimetype', '')}] "
            f"(success={raw.get('success', False)})"
        ),
        "fields": {
            "node_id": raw.get("node_id"),
            "target_ip": raw.get("target_ip"),
            "chunk_index": raw.get("chunk_index"),
            "total_chunks": raw.get("total_chunks"),
            "chunk_size_kb": raw.get("chunk_size_kb"),
            "mimetype": raw.get("mimetype"),
            "protocol": raw.get("protocol"),
            "success": raw.get("success"),
            "tactic": "Exfiltration",
            "technique": "T1048",  # Exfiltration Over Alternative Protocol
        }
    }


NORMALIZERS = {
    "beacon":         normalize_beacon,
    "peer_comm":      normalize_peer,
    "lateral":        normalize_peer,
    "exfil":          normalize_exfil,
    "c2_beacon":      normalize_beacon,
    "peer_communication": normalize_peer,
    "lateral_movement":   normalize_peer,
    "data_exfiltration":  normalize_exfil,
}


def normalize_event(raw: dict) -> Optional[dict]:
    event_type = raw.get("event_type", "")
    normalizer = NORMALIZERS.get(event_type)
    if normalizer:
        return normalizer(raw)
    # Fallback for unknown types
    return {
        "timestamp": raw.get("timestamp", datetime.now(timezone.utc).isoformat()),
        "source": "arachne_c2",
        "source_ip": "127.0.0.1",
        "event_type": event_type or "unknown",
        "severity": "MEDIUM",
        "category": "c2_communication",
        "message": f"ArachneC2 event: {json.dumps(raw)[:200]}",
        "fields": raw,
    }


# ── SIEM ingestion ─────────────────────────────────────────────────────────────

def send_batch(events: list, siem_url: str, session: requests.Session) -> bool:
    if not events:
        return True
    url = f"{siem_url.rstrip('/')}/api/v1/ingress"
    try:
        resp = session.post(url, json=events, timeout=10)
        if resp.status_code in (200, 201):
            logger.info(f"Sent {len(events)} events to SIEM")
            return True
        else:
            logger.warning(f"SIEM returned {resp.status_code}: {resp.text[:100]}")
            return False
    except requests.RequestException as e:
        logger.error(f"Failed to send to SIEM: {e}")
        return False


# ── Tail log file ──────────────────────────────────────────────────────────────

def tail_and_ingest(log_path: str, siem_url: str, batch_size: int = 10, poll_interval: float = 2.0):
    path = Path(log_path)
    session = requests.Session()
    session.headers.update({"Content-Type": "application/json"})

    logger.info(f"Watching {log_path} → {siem_url}")
    logger.info(f"Batch size: {batch_size}, Poll interval: {poll_interval}s")

    # Track file position
    file_pos = 0
    if path.exists():
        file_pos = path.stat().st_size  # start from end (don't replay old events)

    batch = []

    while True:
        try:
            if not path.exists():
                time.sleep(poll_interval)
                continue

            with open(path, 'r') as f:
                f.seek(file_pos)
                new_lines = f.readlines()
                file_pos = f.tell()

            for line in new_lines:
                line = line.strip()
                if not line:
                    continue
                try:
                    raw = json.loads(line)
                    event = normalize_event(raw)
                    if event:
                        batch.append(event)
                except json.JSONDecodeError as e:
                    logger.debug(f"JSON parse error: {e}")

            if len(batch) >= batch_size:
                send_batch(batch, siem_url, session)
                batch = []

        except Exception as e:
            logger.error(f"Error reading log: {e}")

        time.sleep(poll_interval)

        # Flush remaining events periodically
        if batch:
            send_batch(batch, siem_url, session)
            batch = []


# ── CLI ────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="ArachneC2 → SIEM Collector")
    parser.add_argument("--log", default="/tmp/arachne-events.jsonl",
                        help="Path to ArachneC2 JSONL event log")
    parser.add_argument("--siem", default="http://localhost:5000",
                        help="SIEM base URL")
    parser.add_argument("--batch-size", type=int, default=10,
                        help="Events per batch")
    parser.add_argument("--poll", type=float, default=2.0,
                        help="Poll interval in seconds")
    args = parser.parse_args()

    try:
        tail_and_ingest(args.log, args.siem, args.batch_size, args.poll)
    except KeyboardInterrupt:
        logger.info("Collector stopped.")
        sys.exit(0)


if __name__ == "__main__":
    main()
