"""
detector.py — Detection Engine
Evaluates structured events against a set of rules and returns alerts.
"""

import re
import time
import logging
from collections import defaultdict, deque
from datetime import datetime, timezone
from siem.geoip import lookup as geoip_lookup

logger = logging.getLogger("siem.detector")

# ──────────────────────────────────────────────
#  In-memory state for rate-based rules
# ──────────────────────────────────────────────

_counters: dict[str, deque] = defaultdict(lambda: deque())   # key → list of timestamps
_WINDOW = 60   # seconds for sliding-window rules


def _count_recent(key: str, now: float, window: int = _WINDOW) -> int:
    """Return how many events with `key` occurred in the last `window` seconds."""
    dq = _counters[key]
    cutoff = now - window
    while dq and dq[0] < cutoff:
        dq.popleft()
    dq.append(now)
    return len(dq)


# ──────────────────────────────────────────────
#  Rule definitions
# ──────────────────────────────────────────────

RULES = [
    # ── Authentication ────────────────────────────────────────────────────

    {
        "id": "AUTH-001",
        "name": "SSH Brute Force",
        "description": "More than 5 failed SSH login attempts from the same IP in 60 seconds.",
        "severity": "HIGH",
        "category": "auth",
        "mitre": "T1110",
        "match": lambda e: (
            e.get("category") == "auth"
            and "failed" in e.get("fields", {}).get("message", "").lower()
            and "ssh" in e.get("fields", {}).get("process", "").lower()
        ),
        "threshold": lambda e: _count_recent(
            f"ssh_fail:{e['fields'].get('src_ip','unknown')}",
            time.time()
        ) >= 5,
    },

    {
        "id": "AUTH-002",
        "name": "Root Login Attempt",
        "description": "Someone tried to log in as root via SSH.",
        "severity": "HIGH",
        "category": "auth",
        "mitre": "T1110",  # G-02 fix: T1078 → T1110 (Brute Force is more accurate)
        "match": lambda e: (
            e.get("category") == "auth"
            and re.search(r"(invalid user root|failed.*root|root.*failed)", 
                        e.get("fields", {}).get("message", ""), re.I) is not None
        ),
        "threshold": None,
    },

    {
        "id": "AUTH-003",
        "name": "Successful Root Login",
        "description": "Root successfully authenticated.",
        "severity": "CRITICAL",
        "category": "auth",
        "mitre": "T1078.003",
        "match": lambda e: (
            e.get("category") == "auth"
            and re.search(r"accepted.*root", 
            e.get("fields", {}).get("message", ""), re.I) is not None
        ),
        "threshold": None, 
    },

    {
        "id": "AUTH-004",
        "name": "Sudo Privilege Escalation",
        "description": "A user ran a command with sudo.",
        "severity": "MEDIUM",
        "category": "auth",
        "mitre": "T1548.003",
        "match": lambda e: (
            e.get("category") == "auth"
            and e.get("fields", {}).get("process", "") == "sudo"
            and "command" in e.get("fields", {}).get("message", "").lower()
        ),
        "threshold": None,
    },

    # G-04: Brute force volume correlation rule — T1110
    # Triggers CRITICAL when >10 failed SSH attempts from same IP in 60 seconds
    {
        "id": "AUTH-005",
        "name": "SSH Brute Force — High Volume",
        "description": "More than 10 failed SSH login attempts from the same IP in 60 seconds. Likely automated attack.",
        "severity": "CRITICAL",
        "category": "auth",
        "mitre": "T1110",
        "match": lambda e: (
            e.get("category") == "auth"
            and "failed" in e.get("fields", {}).get("message", "").lower()
        ),
        "threshold": lambda e: _count_recent(
            f"ssh_fail_volume:{e['fields'].get('src_ip','unknown')}",
            time.time()
        ) >= 10,
    },

    # G-07: Successful login after multiple failures → CRITICAL
    {
        "id": "AUTH-006",
        "name": "Successful Login After Failures",
        "description": "Successful authentication after repeated failures — possible credential compromise.",
        "severity": "CRITICAL",
        "category": "auth",
        "mitre": "T1110",
        "match": lambda e: (
            e.get("category") == "auth"
            and re.search(r"accepted password|accepted publickey",
                        e.get("fields", {}).get("message", ""), re.I) is not None
        ),
        "threshold": lambda e: _count_recent(
            f"ssh_fail:{e['fields'].get('src_ip','unknown')}",
            time.time(),
            window=300
        ) >= 3,
    },

    # ── Web ───────────────────────────────────────────────────────────────

    {
        "id": "WEB-001",
        "name": "HTTP Scanner / Directory Traversal",
        "description": "Request path contains traversal patterns.",
        "severity": "MEDIUM",
        "category": "web",
        "mitre": "T1083",
        "match": lambda e: (
            e.get("category") == "web"
            and re.search(r"\.\./|%2e%2e|etc/passwd|/proc/self", 
                        e.get("fields", {}).get("path", ""), re.I) is not None
        ),
        "threshold": None,
    },

    {
        "id": "WEB-002",
        "name": "Web Brute Force (4xx Flood)",
        "description": "More than 20 HTTP 4xx responses from the same IP in 60 seconds.",
        "severity": "MEDIUM",
        "category": "web",
        "mitre": "T1110",
        "match": lambda e: (
            e.get("category") == "web"
            and 400 <= e.get("fields", {}).get("status", 0) < 500
        ),
        "threshold": lambda e: _count_recent(
            f"web_4xx:{e['fields'].get('src_ip','unknown')}",
            time.time()
        ) >= 20,
    },

    {
        "id": "WEB-003",
        "name": "SQL Injection Attempt",
"description": "SQL injection patterns detected in path/query/full URI (handles URL-encoded payloads).",
        "severity": "HIGH",
        "category": "web",
        "mitre": "T1190",
        "match": lambda e: (
            e.get("category") == "web"
            and any(re.search(
r"(union|select|insert|drop|delete|update|or 1=|and 1=|benchmark|sleep|waitfor|pg_sleep|dbms_pipe|extractvalue|order by|--|/\*\*|; --|exec|xp_cmdshell|cast|chr|1' OR '1'='1|UNION SELECT| SLEEP| DROP TABLE)",

                target, re.I
            ) is not None for target in [
                e.get("fields", {}).get("path", ""),
                e.get("fields", {}).get("query", ""),
                e.get("fields", {}).get("full_uri", "")
            ])
        ),
        "threshold": None,
    },

    {
        "id": "WEB-004",
        "name": "Web Brute Force — High Volume",
        "description": "More than 50 HTTP 4xx responses from the same IP in 60 seconds. CRITICAL threshold.",
        "severity": "CRITICAL",
        "category": "web",
        "mitre": "T1110",
        "match": lambda e: (
            e.get("category") == "web"
            and 400 <= e.get("fields", {}).get("status", 0) < 500
        ),
        "threshold": lambda e: _count_recent(
            f"web_4xx:{e['fields'].get('src_ip','unknown')}",
            time.time()
        ) >= 50,
    },

    # ── Kernel / System ───────────────────────────────────────────────────

    {
        "id": "SYS-001",
        "name": "OOM Killer Activated",
        "description": "The Linux kernel killed a process due to out-of-memory.",
        "severity": "MEDIUM",
        "category": "kernel",
        "mitre": None,
        "match": lambda e: (
            e.get("category") == "kernel"
            and "oom" in e.get("fields", {}).get("message", "").lower()
        ),
        "threshold": None,
    },

    {
        "id": "SYS-002",
        "name": "Segmentation Fault",
        "description": "A process crashed with a segfault.",
        "severity": "LOW",
        "category": "kernel",
        "mitre": None,
        "match": lambda e: (
            e.get("category") == "kernel"
            and "segfault" in e.get("fields", {}).get("message", "").lower()
        ),
        "threshold": None,
    },
]


# ──────────────────────────────────────────────
#  Public API
# ──────────────────────────────────────────────

def analyze_event(event: dict) -> list[dict]:
    """Run all rules against an event; return a list of triggered alerts."""
    alerts = []
    source_for_geo = event.get("fields", {}).get("src_ip") or event.get("raw", "")
    geo_data = geoip_lookup(source_for_geo)
    for rule in RULES:
        try:
            if rule["match"](event):
                if rule["threshold"] is None or rule["threshold"](event):
                    alerts.append({
                        "rule":        rule["id"],
                        "name":        rule["name"],
                        "description": rule["description"],
                        "severity":    rule["severity"],
                        "mitre":       rule.get("mitre"),
                        "source_ip":   event.get("fields", {}).get("src_ip"),  # G-03 fix
                        "geo": geo_data,  # Add geo info to alerts
                        "timestamp":   datetime.now(timezone.utc).isoformat(),
                    })
        except Exception as exc:
            logger.debug(f"Rule {rule['id']} evaluation error: {exc}")
    return alerts


def get_rules() -> list[dict]:
    """Return rule metadata (no lambdas) for the API."""
    return [
        {
            "id":          r["id"],
            "name":        r["name"],
            "description": r["description"],
            "severity":    r["severity"],
            "category":    r["category"],
            "mitre":       r.get("mitre"),
        }
        for r in RULES
    ]
