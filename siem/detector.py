"""
detector.py — Detection Engine
Evaluates structured events against a set of rules and returns alerts.
"""

import os
import re
import time
import logging
import threading
import math
from collections import defaultdict, deque
from datetime import datetime, timezone
from siem.geoip import lookup as geoip_lookup
from siem.notifier import send_alert as discord_notify

logger = logging.getLogger("siem.detector")

# ──────────────────────────────────────────────
#  In-memory state for rate-based rules
# ──────────────────────────────────────────────

_counters: dict[str, deque] = defaultdict(lambda: deque())   # key → list of timestamps
_WINDOW = 60   # seconds for sliding-window rules
_COUNTER_LOCK = threading.Lock()


def _count_recent(key: str, now: float, window: int = _WINDOW, record: bool = True) -> int:
    """Return count for `key` in `window` seconds; optionally record current event."""
    with _COUNTER_LOCK:
        dq = _counters[key]
        cutoff = now - window
        while dq and dq[0] < cutoff:
            dq.popleft()
        if record:
            dq.append(now)
        return len(dq)


# ──────────────────────────────────────────────
#  TLS analysis helpers (used by NET rules)
# ──────────────────────────────────────────────

_KNOWN_BAD_JA3 = {
    "e7d705a3286e19ea42f587b6e7359082",  # Dridex
    "6734f37431670b3ab4292b8f60f29984",  # Trickbot
    "1aa7bf845b0e18f9b627b5b36a48a553",  # Cobalt Strike
    "72a589da586844d7f0818ce684948eea",  # Metasploit
    "a0e9f5d64349fb13191bc781f81f42e1",  # Generic RAT
}

# TLS version hex values considered deprecated
# 0x0301 = TLS 1.0, 0x0302 = TLS 1.1
_DEPRECATED_TLS_HEX = {"0x0301", "0x0302"}


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((f / n) * math.log2(f / n) for f in freq.values())


def _extract_ja3_from_raw(raw: str) -> str:
    """Extract ja3=<hash> value from a raw TLS_EVENT log line."""
    m = re.search(r"ja3=([a-f0-9]{32})", raw)
    return m.group(1) if m else ""


def _extract_sni_from_raw(raw: str) -> str:
    """Extract sni=<value> from a raw TLS_EVENT log line."""
    m = re.search(r"sni=(\S+)", raw)
    return m.group(1) if m else ""


def _extract_tls_version_from_raw(raw: str) -> str:
    """Extract tls_version=<value> from a raw TLS_EVENT log line."""
    m = re.search(r"tls_version=(\S+)", raw)
    return m.group(1) if m else ""


def _is_deprecated_tls(raw: str) -> bool:
    """
    Returns True if the raw log line contains a deprecated TLS version.
    Handles both human-readable (TLSv1, TLSv1.1) and hex formats (0x0301, 0x0302)
    as exported by Wireshark GUI JSON.
    """
    ver = _extract_tls_version_from_raw(raw)
    if not ver:
        return False
    # Hex format — Wireshark GUI JSON export
    if ver in _DEPRECATED_TLS_HEX:
        return True
    # Human-readable format — Tshark or manual entries
    if re.match(r"TLSv1(\s*$|\.1)", ver):
        return True
    return False


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
        "mitre": "T1110",
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
            window=300,
            record=False
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

    # ── Network / TLS ─────────────────────────────────────────────────────

    {
        "id": "NET-001",
        "name": "Deprecated TLS Version Detected",
        "description": (
            "A TLS session was negotiated using TLS 1.0 (0x0301) or TLS 1.1 (0x0302). "
            "These versions have known cryptographic weaknesses (BEAST, POODLE) "
            "and their presence is a compliance finding under NIST SP 800-52r2 and PCI DSS."
        ),
        "severity": "MEDIUM",
        "category": "network",
        "mitre": "T1573",
        "match": lambda e: (
            "TLS_EVENT" in e.get("raw", "")
            and _is_deprecated_tls(e.get("raw", ""))
        ),
        "threshold": None,
    },

    {
        "id": "NET-002",
        "name": "High-Entropy SNI — Potential DGA Domain",
        "description": (
            "The SNI field contains a high-entropy hostname characteristic of "
            "Domain Generation Algorithm (DGA) malware used to randomise C2 domains "
            "and evade static blocklists."
        ),
        "severity": "HIGH",
        "category": "network",
        "mitre": "T1071.001",
        "match": lambda e: (
            "TLS_EVENT" in e.get("raw", "")
            and _shannon_entropy(
                _extract_sni_from_raw(e.get("raw", "")).split(".")[0]
            ) > 3.8
        ),
        "threshold": None,
    },

    {
        "id": "NET-003",
        "name": "Known Malicious JA3 Fingerprint",
        "description": (
            "The TLS Client Hello matches a JA3 fingerprint associated with "
            "known malware families (Dridex, Trickbot, Cobalt Strike, Metasploit). "
            "JA3 hashes the TLS handshake parameters to fingerprint the client implementation."
        ),
        "severity": "HIGH",
        "category": "network",
        "mitre": "T1071",
        "match": lambda e: (
            "TLS_EVENT" in e.get("raw", "")
            and _extract_ja3_from_raw(e.get("raw", "")) in _KNOWN_BAD_JA3
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
                        "source_ip":   event.get("fields", {}).get("src_ip"),
                        "geo":         geo_data,
                        "timestamp":   datetime.now(timezone.utc).isoformat(),
                    })
                    _discord_notify_if_configured(alerts[-1])
        except Exception as exc:
            logger.debug(f"Rule {rule['id']} evaluation error: {exc}")
    return alerts


def _discord_notify_if_configured(alert: dict):
    """Send Discord notification if webhook is configured."""
    webhook = os.getenv("DISCORD_WEBHOOK_URL", "")
    if not webhook:
        logger.debug("[Discord] Skipping notification — DISCORD_WEBHOOK_URL not set")
        return
    logger.info(f"[Discord] Sending alert {alert.get('rule')} to webhook …")
    ok = discord_notify(alert, webhook_url=webhook, min_severity="HIGH")
    if not ok:
        logger.warning(f"[Discord] Notification failed for {alert.get('rule')}")


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
