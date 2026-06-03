"""
azure/azure_rules.py — Azure NSG Flow Log Detection Rules
Phase 1: Azure-specific CLOUD-* rules

HOW TO INTEGRATE IN detector.py:
1. Add this import at the top of detector.py:
from azure_rules_pkg.azure_rules import AZURE_RULES
2. Append at the end of the RULES list:
       RULES = RULES + AZURE_RULES

These rules use category="cloud" and source starting with "azure:"
so they never interfere with existing AUTH/WEB/SYS/NET rules.

Key difference from AWS rules:
- Azure flow tuples include direction (INBOUND/OUTBOUND)
- Action is normalized to ACCEPT/REJECT by azure_collector.py
- NSG name and rule name are available in fields
"""

import re
import time
import threading
from collections import defaultdict, deque

# ──────────────────────────────────────────────
#  Per-source rate counters (separate from detector.py)
# ──────────────────────────────────────────────

_azure_counters: dict[str, deque] = defaultdict(deque)
_AZURE_LOCK = threading.Lock()
_AZURE_WINDOW = 300  # 5-minute window


def _azure_count(key: str, now: float, window: int = _AZURE_WINDOW) -> int:
    with _AZURE_LOCK:
        dq = _azure_counters[key]
        cutoff = now - window
        while dq and dq[0] < cutoff:
            dq.popleft()
        dq.append(now)
        return len(dq)

# ──────────────────────────────────────────────
#  Field extractors
# ──────────────────────────────────────────────

def _is_azure(e: dict) -> bool:
    return (
        e.get("category") == "cloud"
        or e.get("source", "").startswith("azure:")
    )


def _action(e: dict) -> str:
    fields = e.get("fields", {})
    if "action" in fields:
        return str(fields["action"]).upper()
    m = re.search(r"action=(\w+)", e.get("raw", ""))
    return m.group(1).upper() if m else ""


def _dst_port(e: dict) -> int:
    fields = e.get("fields", {})
    if "dst_port" in fields:
        try:
            return int(fields["dst_port"])
        except (ValueError, TypeError):
            pass
    m = re.search(r"dst=[\d.]+:(\d+)", e.get("raw", ""))
    return int(m.group(1)) if m else 0


def _src_ip(e: dict) -> str:
    return e.get("fields", {}).get("src_ip", "") or ""


def _direction(e: dict) -> str:
    return str(e.get("fields", {}).get("direction", "")).upper()


def _bytes(e: dict) -> int:
    return int(e.get("fields", {}).get("bytes", 0) or 0)


# ──────────────────────────────────────────────
#  Azure Detection Rules
# ──────────────────────────────────────────────

AZURE_RULES = [

    # ── CLOUD-001: SSH REJECT inbound ────────────────────────────────────
    # Single SSH connection attempt rejected by NSG
    # MITRE: T1110 — Brute Force
    {
        "id":          "CLOUD-001",
        "name":        "NSG: SSH REJECT from external IP",
        "description": (
            "Inbound SSH traffic (port 22) rejected by Azure NSG. "
            "Possible brute force attempt or reconnaissance against the VM. "
            "MITRE ATT&CK: T1110 — Brute Force."
        ),
        "severity":    "HIGH",
        "category":    "cloud",
        "mitre":       "T1110",
        "match": lambda e: (
            _is_azure(e)
            and _action(e) == "REJECT"
            and _dst_port(e) == 22
            and _direction(e) in ("INBOUND", "")
        ),
        "threshold": None,
    },

    # ── CLOUD-002: SSH Brute Force (high volume) ─────────────────────────
    # 10+ SSH REJECTs from same IP in 5 minutes
    # MITRE: T1110 — Brute Force
    {
        "id":          "CLOUD-002",
        "name":        "NSG: SSH Brute Force (High Volume)",
        "description": (
            "More than 10 SSH connection attempts rejected from the same IP "
            "within 5 minutes. Automated brute force attack against Azure VM. "
            "MITRE ATT&CK: T1110 — Brute Force."
        ),
        "severity":    "CRITICAL",
        "category":    "cloud",
        "mitre":       "T1110",
        "match": lambda e: (
            _is_azure(e)
            and _action(e) == "REJECT"
            and _dst_port(e) == 22
        ),
        "threshold": lambda e: _azure_count(
            f"azure_ssh_reject:{_src_ip(e)}", time.time()
        ) >= 10,
    },

    # ── CLOUD-003: RDP traffic detected (port 3389) ──────────────────────
    # RDP should never be exposed on Azure VMs
    # MITRE: T1021.001 — Remote Desktop Protocol
    {
        "id":          "CLOUD-003",
        "name":        "NSG: RDP Traffic Detected (port 3389)",
        "description": (
            "Traffic to port 3389 (RDP) detected in Azure VNet. "
            "RDP should never be exposed on public-facing VMs — "
            "violates Least Privilege principle. "
            "MITRE ATT&CK: T1021.001."
        ),
        "severity":    "HIGH",
        "category":    "cloud",
        "mitre":       "T1021.001",
        "match": lambda e: (
            _is_azure(e)
            and _dst_port(e) == 3389
        ),
        "threshold": None,
    },

    # ── CLOUD-004: Port scan (15+ REJECTs from same IP in 5 min) ─────────
    # Reconnaissance pattern against the VM perimeter
    # MITRE: T1046 — Network Service Discovery
    {
        "id":          "CLOUD-004",
        "name":        "NSG: Port Scan Detected",
        "description": (
            "More than 15 inbound connections rejected from the same IP "
            "within 5 minutes. Classic port scanning pattern for "
            "cloud perimeter reconnaissance. "
            "MITRE ATT&CK: T1046 — Network Service Discovery."
        ),
        "severity":    "HIGH",
        "category":    "cloud",
        "mitre":       "T1046",
        "match": lambda e: (
            _is_azure(e)
            and _action(e) == "REJECT"
            and _direction(e) in ("INBOUND", "")
        ),
        "threshold": lambda e: _azure_count(
            f"azure_reject:{_src_ip(e)}", time.time()
        ) >= 15,
    },

    # ── CLOUD-005: Database port exposed (3306/5432/1433/27017) ──────────
    # Databases should never receive direct internet traffic
    # MITRE: T1190 — Exploit Public-Facing Application
    {
        "id":          "CLOUD-005",
        "name":        "NSG: Database Port Exposed to Internet",
        "description": (
            "Traffic to database ports detected: MySQL (3306), "
            "PostgreSQL (5432), MSSQL (1433), MongoDB (27017). "
            "Database services should never be directly reachable "
            "from the internet. "
            "MITRE ATT&CK: T1190."
        ),
        "severity":    "CRITICAL",
        "category":    "cloud",
        "mitre":       "T1190",
        "match": lambda e: (
            _is_azure(e)
            and _dst_port(e) in (3306, 5432, 1433, 27017)
            and _direction(e) in ("INBOUND", "")
        ),
        "threshold": None,
    },

    # ── CLOUD-006: High outbound volume (possible data exfiltration) ──────
    # Single OUTBOUND flow with anomalous byte count
    # MITRE: T1048 — Exfiltration Over Alternative Protocol
    {
        "id":          "CLOUD-006",
        "name":        "NSG: Anomalous Outbound Volume (Possible Exfiltration)",
        "description": (
            "Single outbound flow with transfer exceeding 500MB. "
            "Volume anomaly that may indicate data exfiltration from VM. "
            "MITRE ATT&CK: T1048 — Exfiltration Over Alternative Protocol."
        ),
        "severity":    "HIGH",
        "category":    "cloud",
        "mitre":       "T1048",
        "match": lambda e: (
            _is_azure(e)
            and _action(e) == "ACCEPT"
            and _direction(e) == "OUTBOUND"
            and _bytes(e) > 524_288_000  # 500 MB
        ),
        "threshold": None,
    },

    # ── CLOUD-007: Allowed inbound on non-standard port ──────────────────
    # ACCEPT on unexpected ports may indicate misconfigured NSG rules
    # MITRE: T1133 — External Remote Services
    {
        "id":          "CLOUD-007",
        "name":        "NSG: Unexpected Inbound Port Allowed",
        "description": (
            "Inbound connection accepted on a non-standard port "
            "(not 22, 80, 443). May indicate a misconfigured NSG rule "
            "exposing internal services. "
            "MITRE ATT&CK: T1133 — External Remote Services."
        ),
        "severity":    "MEDIUM",
        "category":    "cloud",
        "mitre":       "T1133",
        "match": lambda e: (
            _is_azure(e)
            and _action(e) == "ACCEPT"
            and _direction(e) == "INBOUND"
            and _dst_port(e) not in (22, 80, 443, 0)
        ),
        "threshold": None,
    },

]
