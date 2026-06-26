#!/usr/bin/env python3
"""
scripts/falco_collector.py — Falco Alert Collector
Reads Falco alerts (HTTP webhook or JSONL file) and forwards them to HomeLab SIEM.

Usage:
    # Webhook mode (recommended for K8s):
    python3 falco_collector.py --mode webhook --port 2801 --siem http://localhost:5000

    # File mode (for testing):
    python3 falco_collector.py --mode file --log /var/log/falco/falco.json --siem http://localhost:5000
"""

import argparse
import json
import logging
import sys
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from threading import Thread
from typing import Optional

import requests

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)

FALCO_MITRE_MAP = {
    "Terminal shell in container":              ("T1059", "Execution"),
    "Launch Privileged Container":              ("T1611", "PrivilegeEscalation"),
    "Container Drift Detected":                 ("T1525", "Persistence"),
    "Read sensitive file untrusted":            ("T1552", "CredentialAccess"),
    "Write below etc":                          ("T1562.001", "DefenseEvasion"),
    "Write below binary dir":                   ("T1574", "Persistence"),
    "Modify binary dirs":                       ("T1574", "Persistence"),
    "Outbound Connection to C2":                ("T1071", "CommandAndControl"),
    "Network connection outside local subnet":  ("T1048", "Exfiltration"),
    "Unexpected network connection":            ("T1071", "CommandAndControl"),
    "Privilege Escalation via Sudo":            ("T1548.003", "PrivilegeEscalation"),
    "Drop and execute new binary in container": ("T1059", "Execution"),
    "Detect crypto miners":                     ("T1496", "Impact"),
    "Read environment variable from /proc":     ("T1552.007", "CredentialAccess"),
    "Container escape":                         ("T1611", "PrivilegeEscalation"),
    "Symlink created over sensitive file":      ("T1574.009", "Persistence"),
    "Ptrace anti-debug attempt":                ("T1055.008", "DefenseEvasion"),
    "Suspicious cron modification":             ("T1053.003", "Persistence"),
}

SEVERITY_MAP = {
    "EMERGENCY": "CRITICAL",
    "ALERT":     "CRITICAL",
    "CRITICAL":  "CRITICAL",
    "ERROR":     "HIGH",
    "WARNING":   "HIGH",
    "NOTICE":    "MEDIUM",
    "INFO":      "LOW",
    "DEBUG":     "LOW",
}

def normalize_falco_alert(raw: dict) -> Optional[dict]:
    try:
        rule_name = raw.get("rule", "unknown")
        output    = raw.get("output", "")
        priority  = raw.get("priority", "WARNING").upper()
        fields    = raw.get("output_fields", {}) or {}
        tags      = raw.get("tags", [])
        time_str  = raw.get("time", datetime.now(timezone.utc).isoformat())

        severity = SEVERITY_MAP.get(priority, "MEDIUM")

        source_ip = (
            fields.get("fd.cip") or
            fields.get("fd.rip") or
            fields.get("connection", "").split(":")[0] or
            "unknown"
        )
        dest_ip        = fields.get("fd.sip", "unknown")
        container_id   = fields.get("container.id", "host")[:12]
        container_name = fields.get("container.name", "host")
        proc_name      = fields.get("proc.name", "unknown")
        proc_cmdline   = fields.get("proc.cmdline", "")
        user_name      = fields.get("user.name", "unknown")
        k8s_ns         = fields.get("k8s.ns.name", "")
        k8s_pod        = fields.get("k8s.pod.name", "")

        mitre_technique, mitre_tactic = FALCO_MITRE_MAP.get(rule_name, ("T1055", "unknown"))

        context_parts = []
        if container_name and container_name != "host":
            context_parts.append(f"container={container_name}")
        if k8s_pod:
            context_parts.append(f"pod={k8s_pod}")
        if k8s_ns:
            context_parts.append(f"ns={k8s_ns}")
        if proc_name:
            context_parts.append(f"proc={proc_name}")
        if user_name:
            context_parts.append(f"user={user_name}")
        context = " ".join(context_parts)

        message = f"Falco alert [{rule_name}]: {output[:300]}"
        if context:
            message += f" | {context}"

        return {
            "timestamp":      time_str,
            "source":         "falco",
            "source_ip":      source_ip,
            "destination_ip": dest_ip,
            "event_type":     f"falco_{rule_name.lower().replace(' ', '_')}",
            "severity":       severity,
            "category":       "runtime_security",
            "message":        message,
            "fields": {
                "rule":           rule_name,
                "priority":       priority,
                "container_id":   container_id,
                "container_name": container_name,
                "proc_name":      proc_name,
                "proc_cmdline":   proc_cmdline[:200],
                "user":           user_name,
                "k8s_namespace":  k8s_ns,
                "k8s_pod":        k8s_pod,
                "tags":           tags,
                "tactic":         mitre_tactic,
                "technique":      mitre_technique,
                "raw_output":     output[:500],
            }
        }
    except Exception as e:
        logger.error(f"Failed to normalize Falco alert: {e}")
        return None


class SIEMClient:
    def __init__(self, base_url: str):
        self.url = f"{base_url.rstrip('/')}/api/v1/ingress"
        self.session = requests.Session()
        self.session.headers.update({"Content-Type": "application/json"})
        self.buffer = []
        self.batch_size = 10

    def send(self, event: dict):
        self.buffer.append(event)
        if len(self.buffer) >= self.batch_size:
            self.flush()

    def flush(self):
        if not self.buffer:
            return
        batch = self.buffer[:]
        self.buffer.clear()
        try:
            resp = self.session.post(self.url, json=batch, timeout=10)
            if resp.status_code in (200, 201):
                logger.info(f"Sent {len(batch)} Falco alerts to SIEM")
            else:
                logger.warning(f"SIEM returned {resp.status_code}")
        except requests.RequestException as e:
            logger.error(f"Failed to send to SIEM: {e}")


def make_webhook_handler(siem: SIEMClient):
    class FalcoWebhookHandler(BaseHTTPRequestHandler):
        def do_POST(self):
            try:
                length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(length)
                raw = json.loads(body)
                event = normalize_falco_alert(raw)
                if event:
                    siem.send(event)
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'{"status":"ok"}')
            except Exception as e:
                logger.error(f"Webhook handler error: {e}")
                self.send_response(500)
                self.end_headers()

        def log_message(self, format, *args):
            pass

    return FalcoWebhookHandler


def run_webhook(port: int, siem: SIEMClient):
    handler = make_webhook_handler(siem)
    server = HTTPServer(("0.0.0.0", port), handler)
    logger.info(f"Falco webhook listener on port {port}")

    def flusher():
        while True:
            time.sleep(5)
            siem.flush()
    Thread(target=flusher, daemon=True).start()
    server.serve_forever()


def run_file_tail(log_path: str, siem: SIEMClient, poll_interval: float = 1.0):
    path = Path(log_path)
    logger.info(f"Tailing Falco log: {log_path}")
    file_pos = path.stat().st_size if path.exists() else 0

    while True:
        try:
            if not path.exists():
                time.sleep(poll_interval)
                continue
            with open(path, 'r') as f:
                f.seek(file_pos)
                lines = f.readlines()
                file_pos = f.tell()
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                try:
                    raw = json.loads(line)
                    event = normalize_falco_alert(raw)
                    if event:
                        siem.send(event)
                except json.JSONDecodeError:
                    pass
            siem.flush()
        except Exception as e:
            logger.error(f"File tail error: {e}")
        time.sleep(poll_interval)


def main():
    parser = argparse.ArgumentParser(description="Falco → SIEM Collector")
    parser.add_argument("--mode",  choices=["webhook", "file"], default="webhook")
    parser.add_argument("--port",  type=int, default=2801)
    parser.add_argument("--log",   default="/var/log/falco/falco.json")
    parser.add_argument("--siem",  default="http://localhost:5000")
    parser.add_argument("--batch", type=int, default=10)
    args = parser.parse_args()

    siem = SIEMClient(args.siem)
    siem.batch_size = args.batch

    try:
        if args.mode == "webhook":
            run_webhook(args.port, siem)
        else:
            run_file_tail(args.log, siem)
    except KeyboardInterrupt:
        siem.flush()
        logger.info("Falco collector stopped.")
        sys.exit(0)


if __name__ == "__main__":
    main()
