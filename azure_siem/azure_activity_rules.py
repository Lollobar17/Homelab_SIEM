"""
azure_siem/azure_activity_rules.py — Azure Activity Log Detection Rules
Phase 2: Cloud governance and security monitoring

HOW TO INTEGRATE IN detector.py:
    from azure_siem.azure_activity_rules import AZURE_ACTIVITY_RULES
    RULES = RULES + AZURE_ACTIVITY_RULES
"""

import time
import threading
from collections import defaultdict, deque

# ── Counters ─────────────────────────────────
_act_counters = defaultdict(deque)
_ACT_LOCK = threading.Lock()
_ACT_WINDOW = 300

def _act_count(key, now, window=_ACT_WINDOW):
    with _ACT_LOCK:
        dq = _act_counters[key]
        cutoff = now - window
        while dq and dq[0] < cutoff:
            dq.popleft()
        dq.append(now)
        return len(dq)

# ── Helpers ──────────────────────────────────
def _is_activity(e):
    return e.get("source", "").startswith("azure:activity_log")

def _event_type(e):
    return e.get("fields", {}).get("event_type", "")

def _caller(e):
    return e.get("fields", {}).get("caller", "")

def _status(e):
    return e.get("fields", {}).get("status", "").upper()

def _status_ok(e):
    """Returns True if operation completed or started — covers both Azure status formats."""
    return _status(e) in ("SUCCEEDED", "SUCCESS", "START", "STARTED")

# ── Rules ────────────────────────────────────
AZURE_ACTIVITY_RULES = [

    # ── CLOUD-008: NSG rule modified ─────────────────────────────────────
    # MITRE: T1562.007 — Disable or Modify Cloud Firewall
    {
        "id":          "CLOUD-008",
        "name":        "Activity: NSG Rule Modified",
        "description": (
            "A Network Security Group rule was added or modified. "
            "Unauthorized NSG changes can expose services to the internet. "
            "MITRE ATT&CK: T1562.007 — Disable or Modify Cloud Firewall."
        ),
        "severity":    "HIGH",
        "category":    "cloud",
        "mitre":       "T1562.007",
        "match": lambda e: (
            _is_activity(e)
            and _event_type(e) in ("NSG_RULE_MODIFIED", "NSG_RULE_DELETED", "NSG_MODIFIED")
            and _status_ok(e)
        ),
        "threshold": None,
    },

    # ── CLOUD-009: Storage access keys listed ────────────────────────────
    # MITRE: T1552.005 — Cloud Instance Metadata API
    {
        "id":          "CLOUD-009",
        "name":        "Activity: Storage Account Keys Listed",
        "description": (
            "Storage account access keys were listed. "
            "This operation retrieves credentials that grant full access "
            "to all data in the storage account. "
            "MITRE ATT&CK: T1552.005."
        ),
        "severity":    "HIGH",
        "category":    "cloud",
        "mitre":       "T1552.005",
        "match": lambda e: (
            _is_activity(e)
            and _event_type(e) == "STORAGE_KEYS_LISTED"
            and _status_ok(e)
        ),
        "threshold": None,
    },

    # ── CLOUD-010: Diagnostic setting deleted ────────────────────────────
    # MITRE: T1562.008 — Disable Cloud Logs
    {
        "id":          "CLOUD-010",
        "name":        "Activity: Diagnostic Setting Deleted (Log Tampering)",
        "description": (
            "An Azure diagnostic setting was deleted. "
            "This disables log collection and may indicate an attacker "
            "attempting to cover their tracks. "
            "MITRE ATT&CK: T1562.008 — Disable Cloud Logs."
        ),
        "severity":    "CRITICAL",
        "category":    "cloud",
        "mitre":       "T1562.008",
        "match": lambda e: (
            _is_activity(e)
            and _event_type(e) == "DIAGNOSTIC_DELETED"
            and _status_ok(e)
        ),
        "threshold": None,
    },

    # ── CLOUD-011: Role assignment added ─────────────────────────────────
    # MITRE: T1098.003 — Additional Cloud Roles
    {
        "id":          "CLOUD-011",
        "name":        "Activity: New Role Assignment (Privilege Escalation)",
        "description": (
            "A new Azure RBAC role was assigned. "
            "Unauthorized role assignments can grant elevated access "
            "to resources or the entire subscription. "
            "MITRE ATT&CK: T1098.003 — Additional Cloud Roles."
        ),
        "severity":    "CRITICAL",
        "category":    "cloud",
        "mitre":       "T1098.003",
        "match": lambda e: (
            _is_activity(e)
            and _event_type(e) == "ROLE_ASSIGNED"
            and _status_ok(e)
        ),
        "threshold": None,
    },

    # ── CLOUD-012: VM deleted ─────────────────────────────────────────────
    # MITRE: T1485 — Data Destruction
    {
        "id":          "CLOUD-012",
        "name":        "Activity: Virtual Machine Deleted",
        "description": (
            "An Azure Virtual Machine was deleted. "
            "Unexpected VM deletion may indicate destructive activity "
            "or unauthorized access. "
            "MITRE ATT&CK: T1485 — Data Destruction."
        ),
        "severity":    "CRITICAL",
        "category":    "cloud",
        "mitre":       "T1485",
        "match": lambda e: (
            _is_activity(e)
            and _event_type(e) == "VM_DELETED"
            and _status_ok(e)
        ),
        "threshold": None,
    },

    # ── CLOUD-013: VM started ─────────────────────────────────────────────
    # MITRE: T1078.004 — Valid Accounts: Cloud Accounts
    {
        "id":          "CLOUD-013",
        "name":        "Activity: Virtual Machine Started",
        "description": (
            "An Azure Virtual Machine was started. "
            "Unexpected VM starts may indicate unauthorized use of cloud resources. "
            "MITRE ATT&CK: T1078.004 — Valid Accounts: Cloud Accounts."
        ),
        "severity":    "MEDIUM",
        "category":    "cloud",
        "mitre":       "T1078.004",
        "match": lambda e: (
            _is_activity(e)
            and _event_type(e) == "VM_STARTED"
            and _status_ok(e)
        ),
        "threshold": None,
    },

    # ── CLOUD-014: Multiple failed operations ────────────────────────────
    # MITRE: T1110 — Brute Force
    {
        "id":          "CLOUD-014",
        "name":        "Activity: Multiple Failed Operations (API Brute Force)",
        "description": (
            "More than 5 failed Azure API operations from the same caller "
            "within 5 minutes. May indicate unauthorized access attempts. "
            "MITRE ATT&CK: T1110 — Brute Force."
        ),
        "severity":    "HIGH",
        "category":    "cloud",
        "mitre":       "T1110",
        "match": lambda e: (
            _is_activity(e)
            and _status(e) in ("FAILED", "FAILURE")
        ),
        "threshold": lambda e: _act_count(
            f"act_failed:{_caller(e)}", time.time()
        ) >= 5,
    },

]
