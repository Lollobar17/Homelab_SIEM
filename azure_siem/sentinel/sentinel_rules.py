"""
azure_siem/sentinel_rules.py — Microsoft Sentinel Detection Rules
Phase 3: Sentinel SecurityAlert and SecurityIncident rules

HOW TO INTEGRATE IN detector.py:
    from azure_siem.sentinel_rules import SENTINEL_RULES
    RULES = RULES + SENTINEL_RULES
"""

import time
import threading
from collections import defaultdict, deque

# ── Counters ─────────────────────────────────
_sent_counters = defaultdict(deque)
_SENT_LOCK = threading.Lock()
_SENT_WINDOW = 300

def _sent_count(key, now, window=_SENT_WINDOW):
    with _SENT_LOCK:
        dq = _sent_counters[key]
        cutoff = now - window
        while dq and dq[0] < cutoff:
            dq.popleft()
        dq.append(now)
        return len(dq)

# ── Helpers ──────────────────────────────────
def _is_sentinel(e):
    return e.get("source", "").startswith("azure:sentinel")

def _event_type(e):
    return e.get("fields", {}).get("event_type", "")

def _severity(e):
    return e.get("fields", {}).get("severity", "").upper()

def _tactics(e):
    return str(e.get("fields", {}).get("tactics", "")).lower()

def _status(e):
    return str(e.get("fields", {}).get("status", "")).lower()

# ── Rules ─────────────────────────────────────
SENTINEL_RULES = [

    # ── SENT-001: Any Sentinel HIGH/CRITICAL alert ────────────────────────
    # Forward all high severity Sentinel alerts to SIEM
    # MITRE: varies per alert
    {
        "id":          "SENT-001",
        "name":        "Sentinel: High/Critical Security Alert",
        "description": (
            "Microsoft Sentinel generated a HIGH or CRITICAL severity alert. "
            "Sentinel's ML and analytics rules detected anomalous behavior "
            "in your Azure environment."
        ),
        "severity":    "HIGH",
        "category":    "cloud",
        "mitre":       "T1078",
        "match": lambda e: (
            _is_sentinel(e)
            and _event_type(e) == "SENTINEL_ALERT"
            and _severity(e) in ("HIGH", "CRITICAL")
        ),
        "threshold": None,
    },

    # ── SENT-002: Sentinel CRITICAL alert ────────────────────────────────
    {
        "id":          "SENT-002",
        "name":        "Sentinel: Critical Security Alert",
        "description": (
            "Microsoft Sentinel generated a CRITICAL severity alert. "
            "Immediate investigation required."
        ),
        "severity":    "CRITICAL",
        "category":    "cloud",
        "mitre":       "T1078",
        "match": lambda e: (
            _is_sentinel(e)
            and _event_type(e) == "SENTINEL_ALERT"
            and _severity(e) == "CRITICAL"
        ),
        "threshold": None,
    },

    # ── SENT-003: Sentinel Incident created ──────────────────────────────
    # MITRE: T1078.004 — Valid Accounts: Cloud Accounts
    {
        "id":          "SENT-003",
        "name":        "Sentinel: Security Incident Created",
        "description": (
            "Microsoft Sentinel created a new security incident. "
            "Incidents aggregate related alerts into a single investigation unit. "
            "MITRE ATT&CK: T1078.004."
        ),
        "severity":    "HIGH",
        "category":    "cloud",
        "mitre":       "T1078.004",
        "match": lambda e: (
            _is_sentinel(e)
            and _event_type(e) == "SENTINEL_INCIDENT"
            and _status(e) in ("new", "active")
        ),
        "threshold": None,
    },

    # ── SENT-004: Lateral movement tactic ────────────────────────────────
    # MITRE: T1021 — Remote Services
    {
        "id":          "SENT-004",
        "name":        "Sentinel: Lateral Movement Detected",
        "description": (
            "Sentinel alert with LateralMovement tactic detected. "
            "Attacker may be moving across your Azure environment. "
            "MITRE ATT&CK: T1021 — Remote Services."
        ),
        "severity":    "CRITICAL",
        "category":    "cloud",
        "mitre":       "T1021",
        "match": lambda e: (
            _is_sentinel(e)
            and _event_type(e) == "SENTINEL_ALERT"
            and "lateralmovement" in _tactics(e)
        ),
        "threshold": None,
    },

    # ── SENT-005: Persistence tactic ─────────────────────────────────────
    # MITRE: T1098 — Account Manipulation
    {
        "id":          "SENT-005",
        "name":        "Sentinel: Persistence Tactic Detected",
        "description": (
            "Sentinel alert with Persistence tactic detected. "
            "Attacker may be establishing long-term access to your environment. "
            "MITRE ATT&CK: T1098 — Account Manipulation."
        ),
        "severity":    "CRITICAL",
        "category":    "cloud",
        "mitre":       "T1098",
        "match": lambda e: (
            _is_sentinel(e)
            and _event_type(e) == "SENTINEL_ALERT"
            and "persistence" in _tactics(e)
        ),
        "threshold": None,
    },

    # ── SENT-006: Exfiltration tactic ────────────────────────────────────
    # MITRE: T1048 — Exfiltration Over Alternative Protocol
    {
        "id":          "SENT-006",
        "name":        "Sentinel: Exfiltration Tactic Detected",
        "description": (
            "Sentinel alert with Exfiltration tactic detected. "
            "Possible data theft in progress. "
            "MITRE ATT&CK: T1048."
        ),
        "severity":    "CRITICAL",
        "category":    "cloud",
        "mitre":       "T1048",
        "match": lambda e: (
            _is_sentinel(e)
            and _event_type(e) == "SENTINEL_ALERT"
            and "exfiltration" in _tactics(e)
        ),
        "threshold": None,
    },

    # ── SENT-007: Multiple Sentinel alerts in 5 min ───────────────────────
    # MITRE: T1110 — Brute Force
    {
        "id":          "SENT-007",
        "name":        "Sentinel: Alert Storm (5+ alerts in 5 min)",
        "description": (
            "More than 5 Sentinel alerts generated within 5 minutes. "
            "May indicate an active attack or automated scanning. "
            "MITRE ATT&CK: T1110."
        ),
        "severity":    "CRITICAL",
        "category":    "cloud",
        "mitre":       "T1110",
        "match": lambda e: (
            _is_sentinel(e)
            and _event_type(e) == "SENTINEL_ALERT"
        ),
        "threshold": lambda e: _sent_count(
            "sentinel_alert_storm", time.time()
        ) >= 5,
    },

]
