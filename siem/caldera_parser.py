"""
caldera_parser.py — Shared Caldera → SIEM event normalizer (stdlib only)

Used by scripts/caldera_collector.py and simulate_caldera.py.
Keeps field extraction in one place for consistent detection rules.
"""

import re
from datetime import datetime, timezone

_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")

# Cheap tactic hints from ability name when Caldera omits tactic metadata.
_TACTIC_HINTS = (
    ("lateral", "lateral-movement"),
    ("psexec", "lateral-movement"),
    ("wmi", "lateral-movement"),
    ("persist", "persistence"),
    ("scheduled", "persistence"),
    ("registry", "persistence"),
    ("exfil", "exfiltration"),
    ("download", "exfiltration"),
    ("powershell", "execution"),
    ("cmd", "execution"),
    ("bash", "execution"),
    ("discovery", "discovery"),
    ("scan", "discovery"),
)


def is_caldera_event(event: dict) -> bool:
    """Fast guard for detector — skip Caldera rules on normal traffic."""
    if event.get("source") == "caldera":
        return True
    if event.get("category") == "purple_team":
        return True
    return (event.get("fields") or {}).get("purple_team") is True


def _infer_tactic(ability: str, tactic: str, technique: str) -> str:
    if tactic:
        return tactic
    # Map common technique prefixes to tactic labels (no external lookup).
    tech = technique.upper()
    if tech.startswith("T1021"):
        return "lateral-movement"
    if tech.startswith("T1098"):
        return "persistence"
    if tech.startswith("T1048") or tech.startswith("T1041"):
        return "exfiltration"
    if tech.startswith("T1059") or tech.startswith("T1106"):
        return "execution"
    if tech.startswith("T1033") or tech.startswith("T1082"):
        return "discovery"
    low = ability.lower()
    for hint, name in _TACTIC_HINTS:
        if hint in low:
            return name
    return ""


def parse_caldera_record(record: dict, op: dict) -> dict | None:
    """
    Convert a Caldera operation event dict into internal SIEM event format.
    Returns None for empty/heartbeat records with no ability data.
    """
    ability = (
        record.get("ability_name")
        or record.get("ability")
        or record.get("name")
        or ""
    )
    if not ability and not record.get("command"):
        return None

    op_name = op.get("name") or op.get("id") or "operation"
    host = (
        record.get("host")
        or record.get("paw")
        or record.get("host_ip")
        or record.get("agent")
        or ""
    )
    technique = str(
        record.get("technique_id")
        or record.get("technique")
        or record.get("technique_name")
        or ""
    )[:32]
    tactic = str(
        record.get("tactic")
        or record.get("tactic_name")
        or ""
    )[:128]
    tactic = _infer_tactic(str(ability), tactic, technique)

    ts = record.get("timestamp") or record.get("time")
    if not ts:
        ts = datetime.now(timezone.utc).isoformat()

    command = str(record.get("command") or "")[:512]
    status = record.get("status")
    platform = str(record.get("platform") or "")[:32]
    src_ip = host if _IP_RE.match(str(host)) else ""

    raw = (
        f"CALDERA op={op_name} ability={ability or 'script'} host={host} "
        f"tactic={tactic} technique={technique}"
        + (f" cmd={command[:120]}" if command else "")
    )[:4096]

    return {
        "timestamp": ts,
        "source": "caldera",
        "category": "purple_team",
        "raw": raw,
        "fields": {
            "src_ip": src_ip,
            "event_type": "caldera.ability.executed",
            "ability_name": str(ability or "script")[:256],
            "technique_id": technique,
            "tactic": tactic,
            "operation": str(op_name)[:128],
            "operation_id": str(op.get("id", ""))[:64],
            "command": command,
            "platform": platform,
            "status": status,
            "purple_team": True,
        },
    }


def event_id(record: dict, op_id: str) -> str:
    for key in ("link_id", "id", "event_id"):
        val = record.get(key)
        if val:
            return f"{op_id}:{val}"
    ts = record.get("timestamp") or record.get("time") or ""
    ability = record.get("ability_name") or record.get("ability") or ""
    host = record.get("host") or record.get("paw") or ""
    return f"{op_id}:{ability}:{host}:{ts}"
