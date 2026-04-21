"""
collector.py — Log Collector
Watches log files and a UDP syslog socket for incoming events.
"""

import os
import re
import time
import socket
import threading
import logging
from datetime import datetime
from pathlib import Path
from urllib.parse import unquote
from siem.storage import store_event
from siem.detector import analyze_event

logger = logging.getLogger("siem.collector")

# ──────────────────────────────────────────────
#  File tail watcher
# ──────────────────────────────────────────────

class LogFileTailer(threading.Thread):
    """Continuously tails one log file and feeds lines to the pipeline."""

    def __init__(self, path: str, source_name: str):
        super().__init__(daemon=True)
        self.path = path
        self.source_name = source_name

    def run(self):
        logger.info(f"[Tailer] Watching {self.path}")
        # Wait for file to exist — important for files created after startup
        # (e.g. logs/flask_access.log created on first Flask request)
        while not Path(self.path).exists():
            logger.debug(f"[Tailer] Waiting for {self.path} to exist...")
            time.sleep(1)
        logger.info(f"[Tailer] File found, starting tail: {self.path}")
        try:
            with open(self.path, "r", encoding="utf-8", errors="replace") as f:
                f.seek(0, 2)          # jump to end
                while True:
                    line = f.readline()
                    if line:
                        _process_raw_line(line.strip(), self.source_name)
                    else:
                        time.sleep(0.3)
        except Exception as e:
            logger.error(f"[Tailer] Error on {self.path}: {e}")


# ──────────────────────────────────────────────
#  UDP Syslog receiver (RFC 3164 / RFC 5424)
# ──────────────────────────────────────────────

class SyslogReceiver(threading.Thread):
    """Listens on UDP 514 (or configured port) for syslog datagrams."""

    def __init__(self, host: str = "0.0.0.0", port: int = 5140):
        super().__init__(daemon=True)
        self.host = host
        self.port = port

    def run(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((self.host, self.port))
        logger.info(f"[Syslog] Listening on udp://{self.host}:{self.port}")
        while True:
            try:
                data, addr = sock.recvfrom(4096)
                line = data.decode("utf-8", errors="replace").strip()
                _process_raw_line(line, source=f"syslog:{addr[0]}")
            except Exception as e:
                logger.error(f"[Syslog] Receive error: {e}")


# ──────────────────────────────────────────────
#  Shared processing pipeline
# ──────────────────────────────────────────────

def _process_raw_line(raw: str, source: str):
    """Parse a raw log line into a structured event and run detection."""
    if not raw:
        return
    # Strip ANSI escape codes
    raw = re.sub(r'\x1b\[[0-9;]*m', '', raw)
    
    event = parse_log_line(raw, source)
    alerts = analyze_event(event)
    event["alerts"] = alerts
    store_event(event)

    if alerts:
        for a in alerts:
            logger.warning(f"[ALERT] {a['rule']} | {a['severity']} | {raw[:120]}")


def parse_log_line(raw: str, source: str) -> dict:
    """
    Best-effort parser — tries SSH/auth, Apache/Nginx, kernel, then falls
    back to a generic structure so nothing is ever dropped.
    """
    timestamp = datetime.utcnow().isoformat()
    base = {
        "timestamp": timestamp,
        "source": source,
        "raw": raw,
        "category": "generic",
        "fields": {}
    }

    # ── SSH / auth.log ──────────────────────────────────────────────────
    m = re.search(
        r"(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>[\d:]+).*"
        r"(?P<process>sshd|sudo|su)\[?(?P<pid>\d*)\]?:\s+(?P<msg>.+)",
        raw
    )
    if m:
        base["category"] = "auth"
        base["fields"] = {
            "process": m.group("process"),
            "pid": m.group("pid"),
            "message": m.group("msg"),
        }
        # Extract IP if present
        ip = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", m.group("msg"))
        if ip:
            base["fields"]["src_ip"] = ip.group(1)
        return base

    # ── Apache / Nginx access log ───────────────────────────────────────
    m = re.match(
        r'(?P<ip>[\d.]+) - .* \[(?P<dt>[^\]]+)\] '
        r'"(?P<method>\w+) (?P<path>\S+)[^"]*" (?P<status>\d{3})( \d+)?',
        raw
    )
    if m:
        base["category"] = "web"
        path_full = m.group("path")
        path = path_full.split("?")[0] if "?" in path_full else path_full
        query = path_full.split("?", 1)[1] if "?" in path_full else ""
        query_decoded = unquote(query)
        base["fields"] = {
            "src_ip": m.group("ip"),

            "method": m.group("method"),
            "path": path,
            "query": query_decoded,
            "full_uri": path_full,
            "status": int(m.group("status")),
"size": 0,
        }
        return base

    # ── Flask / Werkzeug access log (G-05, G-06) ────────────────────────
    # Format: 127.0.0.1 - - [01/Jan/2026 12:00:00] "GET /api/events HTTP/1.1" 200 -
    m = re.match(
        r'(?P<ip>[\d.]+) - - \[(?P<dt>[^\]]+)\] '
        r'"(?P<method>\w+) (?P<path>\S+)[^"]*" (?P<status>\d{3})',
        raw
    )
    if m:
        base["category"] = "web"
        path_full = m.group("path")
        path = path_full.split("?")[0] if "?" in path_full else path_full
        query = path_full.split("?", 1)[1] if "?" in path_full else ""
        query_decoded = unquote(query)
        base["fields"] = {
            "src_ip": m.group("ip"),
            "method": m.group("method"),
            "path": path,
            "query": query_decoded,
            "full_uri": path_full,
            "status": int(m.group("status")),
            "size": 0,
            "source": "flask",
        }
        return base

    # ── Kernel / dmesg ──────────────────────────────────────────────────
    m = re.match(r"\[[\d. ]+\]\s+(?P<msg>.+)", raw)
    if m:
        base["category"] = "kernel"
        base["fields"]["message"] = m.group("msg")
        return base

    # ── Syslog with priority ─────────────────────────────────────────────
    m = re.match(r"<(?P<pri>\d+)>(?P<rest>.+)", raw)
    if m:
        base["category"] = "syslog"
        base["fields"]["priority"] = int(m.group("pri"))
        base["fields"]["message"] = m.group("rest").strip()
        return base

    # Generic fallback
    base["fields"]["message"] = raw
    return base


# ──────────────────────────────────────────────
#  Public bootstrap function
# ──────────────────────────────────────────────

def start_collectors(config: dict):
    """Start all configured collectors from the app config."""
    # Syslog UDP listener
    if config.get("syslog_enabled", True):
        SyslogReceiver(
            host=config.get("syslog_host", "0.0.0.0"),
            port=config.get("syslog_port", 5140)
        ).start()

    # File tailers
    for entry in config.get("watch_files", []):
        path = entry if isinstance(entry, str) else entry.get("path", "")
        name = (entry.get("name", Path(path).name)
                if isinstance(entry, dict) else Path(path).name)
        if path:
            LogFileTailer(path, name).start()
